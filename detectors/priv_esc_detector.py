"""
SOCshield - Privilege Escalation Detector
Flags sudo/su/sudoers/suid/cap/cron patterns that indicate an attempt to gain
elevated privileges on a host.

Triggers (any one fires an alert):
- explicit "Privilege escalation attempt" line in the log
- `sudo su` / `sudo -i` / `sudo bash` invocations
- `su` to root (success or failure)
- SUID binary *created* (chmod u+s / chmod 4xxx)
- SUID binary *exploited* (root shell obtained)
- `/etc/sudoers` modification
- linux capability added to a binary/process
- cron persistence on a privileged path
- group addition to root/wheel/administrators

Optionally a rolling 60s per-user correlation raises severity if multiple
weak signals cluster in time.

Output: emits shared `Alert` objects from `app.models`. Detectors do not
touch the storage layer — persistence is the orchestrator's job.
"""

import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

# Make the repo root importable when run as `python detectors/x.py`
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.models import Alert, DETECTOR_PRIV_ESC
from app import mitre as _mitre

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "priv.log"

WINDOW_SECONDS = 60
CORRELATION_MIN_SIGNALS = 2   # distinct signals within window -> severity bump


LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>INFO|WARN|WARNING|ERROR|DEBUG)\s+"
    r"(?P<source>\S+)\s+"
    r"(?P<message>.+?)\s*$"
)
KV_RE = re.compile(r"(\w+)=([^\s\"]+)")
QUOTED_RE = re.compile(r"(\w+)=\"([^\"]*)\"")


# ---------- Internal data model ---------- #

@dataclass
class Signal:
    """A single suspicious indicator extracted from one log line."""
    timestamp: datetime
    user: str
    ip: str
    kind: str              # short tag, e.g. "SUDO_SU", "SU_TO_ROOT", "SUID_CREATE"
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    method: str            # matches the existing log "method=" value when present
    detail: str            # free-form evidence (cmd=, path=, target=, etc.)
    raw: str


# ---------- Parsing ---------- #

def _kvs(message: str) -> dict[str, str]:
    """Extract key=value pairs, supporting both bare and double-quoted values."""
    kvs = dict(KV_RE.findall(message))
    for k, v in QUOTED_RE.findall(message):
        kvs[k] = v
    return kvs


def _make_signal(ts: datetime, message: str, user: str, ip: str,
                 kind: str, severity: str, method: str, detail: str = "") -> Signal:
    return Signal(
        timestamp=ts,
        user=user or "?",
        ip=ip or "?",
        kind=kind,
        severity=severity,
        method=method,
        detail=detail,
        raw=message,
    )


def _scan_sudoers(cmd: str) -> bool:
    return bool(re.search(r"\b(vim|vi|nano|tee|echo|>>|>)\s+/etc/sudoers\b", cmd))


def _scan_suid_create(cmd: str) -> bool:
    return bool(re.search(r"chmod\s+(u\+s|4\d{3})\b", cmd)) or \
           bool(re.search(r"\bchmod\s+\+?s\b", cmd))


def parse_signals(path: Path) -> list[Signal]:
    signals: list[Signal] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = LINE_RE.match(line)
            if not match:
                continue

            ts = datetime.strptime(match.group("ts"), "%Y-%m-%d %H:%M:%S")
            level = match.group("level")
            message = match.group("message")
            kvs = _kvs(message)
            user = kvs.get("user", "")
            ip = kvs.get("ip", "")
            cmd = kvs.get("cmd", "")

            # 1) explicit escalation line — already labelled by producer
            if re.search(r"privilege escalation attempt", message, re.IGNORECASE):
                method = kvs.get("method", "UNKNOWN")
                signals.append(_make_signal(
                    ts, message, user, ip,
                    kind="EXPLICIT_ESCALATION",
                    severity="CRITICAL" if level == "ERROR" else "HIGH",
                    method=method,
                ))

            # 2) sudo su / sudo -i / sudo bash / sudo sh  -> shell as root
            if re.search(r"\bsudo\s+(su|-i|bash|sh|zsh|/bin/bash)\b", cmd):
                signals.append(_make_signal(
                    ts, message, user, ip,
                    kind="SUDO_SHELL",
                    severity="CRITICAL",
                    method="SUDO_SHELL",
                    detail=cmd,
                ))

            # 3) `su` to root attempt (success or failure)
            if re.search(r"\bsu\s+(-\s*)?root\b", message) or \
               (re.search(r"\bsu\b", cmd) and "target=root" in message):
                success = "success=true" in message or "success=1" in message
                signals.append(_make_signal(
                    ts, message, user, ip,
                    kind="SU_TO_ROOT",
                    severity="CRITICAL" if success else "HIGH",
                    method="SU",
                    detail=cmd or message,
                ))

            # 4) sudoers tampering
            if "sudoers" in message.lower() and any(
                tok in message.lower() for tok in ("modified", "tamper", "edit", "wrote")
            ):
                signals.append(_make_signal(
                    ts, message, user, ip,
                    kind="SUDOERS_TAMPER",
                    severity="CRITICAL",
                    method="SUDOERS_TAMPER",
                    detail=kvs.get("path", "/etc/sudoers"),
                ))

            # 5) SUID binary *created* by a user (chmod u+s)
            if _scan_suid_create(cmd) or re.search(r"chmod\s+[us]\+s\b", cmd):
                signals.append(_make_signal(
                    ts, message, user, ip,
                    kind="SUID_CREATE",
                    severity="HIGH",
                    method="SUID_SET",
                    detail=cmd,
                ))

            # 6) SUID enumeration / new SUID binary detected / SUID exploit
            if re.search(r"\bSUID\b", message) or "Root shell obtained" in message:
                kind = "SUID_EXPLOIT" if "Root shell obtained" in message \
                       or re.search(r"--exec\s+/bin/(ba)?sh", cmd) \
                       else "SUID_ENUM"
                sev = "CRITICAL" if kind == "SUID_EXPLOIT" else "MEDIUM"
                signals.append(_make_signal(
                    ts, message, user, ip,
                    kind=kind,
                    severity=sev,
                    method="SUID",
                    detail=cmd or kvs.get("path", ""),
                ))

            # 7) linux capability added
            if re.search(r"capability\s+added", message, re.IGNORECASE) or \
               re.search(r"\bsetcap\b", cmd):
                signals.append(_make_signal(
                    ts, message, user, ip,
                    kind="CAP_ADD",
                    severity="HIGH",
                    method="CAPABILITY",
                    detail=kvs.get("cap", cmd),
                ))

            # 8) group added to root/wheel/administrators
            if re.search(r"group\s+added", message, re.IGNORECASE):
                group = kvs.get("group", "")
                if group.lower() in {"root", "wheel", "sudo", "administrators", "admins"}:
                    signals.append(_make_signal(
                        ts, message, user, ip,
                        kind="GROUP_PRIV",
                        severity="HIGH",
                        method="GROUP_ADD",
                        detail=group,
                    ))

            # 9) cron persistence on a privileged path
            if re.search(r"cron\s+(job\s+)?added", message, re.IGNORECASE) or \
               re.search(r"\b(crontab|at\s+job)\b", cmd):
                if any(p in (kvs.get("target", "") or cmd)
                       for p in ("/etc/cron", "/var/spool/cron", "/etc/anacrontab")):
                    signals.append(_make_signal(
                        ts, message, user, ip,
                        kind="CRON_PERSIST",
                        severity="HIGH",
                        method="CRON",
                        detail=kvs.get("cmd", cmd),
                    ))

    return signals


# ---------- Correlation ---------- #

def correlate(signals: list[Signal]) -> list[Alert]:
    """Group signals per (user, ip) inside WINDOW_SECONDS, pick max severity,
    bump to CRITICAL if >= CORRELATION_MIN_SIGNALS distinct kinds cluster."""
    buckets: dict[tuple[str, str], list[Signal]] = defaultdict(list)
    for s in signals:
        buckets[(s.user, s.ip)].append(s)
    for key in buckets:
        buckets[key].sort(key=lambda s: s.timestamp)

    alerts: list[Alert] = []
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for (user, ip), items in buckets.items():
        i = 0
        raised: set[tuple[datetime, datetime]] = set()
        for j in range(len(items)):
            while items[j].timestamp - items[i].timestamp > timedelta(seconds=WINDOW_SECONDS):
                i += 1
            window = items[i:j + 1]
            distinct_kinds = {s.kind for s in window}
            if not window:
                continue

            # Severity = max individual severity, bump if correlated
            max_sev = max(window, key=lambda s: rank[s.severity]).severity
            correlated = len(distinct_kinds) >= CORRELATION_MIN_SIGNALS
            if correlated and rank[max_sev] < rank["CRITICAL"]:
                max_sev = "CRITICAL"

            methods = [s.method for s in window if s.method]
            method = methods[0] if methods else ""

            # Use first-seen window anchor for dedup
            anchor = window[0].timestamp
            key2 = (anchor, anchor)
            if key2 in raised:
                continue
            raised.add(key2)

            kinds_list = ",".join(sorted(distinct_kinds))
            evidence = " | ".join(
                f"{s.timestamp.strftime('%H:%M:%S')} {s.kind}: {s.detail or s.method}"
                for s in window
            )
            title_method = method or (sorted(distinct_kinds)[0] if distinct_kinds else "ESCALATION")
            if correlated:
                title_method = f"{title_method}+CORRELATED"

            alerts.append(Alert(
                timestamp=window[0].timestamp,
                source_ip=ip,
                detector=DETECTOR_PRIV_ESC,
                severity=max_sev,
                mitre_technique=_mitre.technique_for_detector(DETECTOR_PRIV_ESC),
                mitre_tactic=_mitre.tactic_for_detector(DETECTOR_PRIV_ESC),
                title=f"Privilege Escalation by {user}@{ip} via {title_method}",
                description=(
                    f"signals=[{kinds_list}] "
                    f"count={len(window)} "
                    f"first={window[0].timestamp.strftime('%H:%M:%S')} "
                    f"last={window[-1].timestamp.strftime('%H:%M:%S')} "
                    f"window={WINDOW_SECONDS}s "
                    f"correlated={'yes' if correlated else 'no'} "
                    f"evidence=[{evidence}]"
                ),
            ))

    alerts.sort(key=lambda a: (a.timestamp, a.source_ip))
    return alerts


# ---------- Entry point ---------- #

def run() -> list[Alert]:
    """Standalone detection entry point — no storage side effects."""
    if not LOG_PATH.exists():
        print(f"Log file not found: {LOG_PATH}", file=sys.stderr)
        return []
    signals = parse_signals(LOG_PATH)
    print(f"[info] priv-esc: parsed {len(signals)} escalation signal(s) from {LOG_PATH.name}")
    alerts = correlate(signals)
    print(f"[info] priv-esc: produced {len(alerts)} alert(s)")
    return alerts


def main() -> int:
    """Standalone CLI: print a one-line summary per alert. No DB writes."""
    alerts = run()
    for alert in alerts:
        print(alert.short())
    print(f"Total alerts: {len(alerts)}")
    return 0 if not any(a.severity == "CRITICAL" for a in alerts) else 2


if __name__ == "__main__":
    sys.exit(main())

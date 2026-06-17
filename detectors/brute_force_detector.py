"""
SOCshield - Brute Force Detector
Sliding 1-minute window detector for failed login attempts.

Rule: if an IP issues >= THRESHOLD failed logins within any rolling 60s
window, raise a BRUTE_FORCE alert.

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

from app.models import Alert, DETECTOR_BRUTE_FORCE
from app import mitre as _mitre

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "auth.log"

THRESHOLD = 3          # failed attempts inside 60s -> alert
WINDOW_SECONDS = 60
LEVELS_OF_SEVERITY = {
    3: "MEDIUM",
    5: "HIGH",
    8: "CRITICAL",
}

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>INFO|WARN|WARNING|ERROR|DEBUG)\s+"
    r"(?P<source>\S+)\s+"
    r"(?P<message>.+?)\s*$"
)
KV_RE = re.compile(r"(\w+)=([^\s]+)")


# ---------- Internal data model ---------- #

@dataclass
class FailedAttempt:
    timestamp: datetime
    ip: str
    user: str
    raw: str


# ---------- Parsing ---------- #

def parse_attempts(path: Path) -> list[FailedAttempt]:
    """Pull only WARN/ERROR failed-login lines from the auth log."""
    attempts: list[FailedAttempt] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = LINE_RE.match(line)
            if not match:
                continue
            level = match.group("level")
            message = match.group("message")
            if level not in {"WARN", "WARNING", "ERROR"}:
                continue
            if "Failed login" not in message and "Account locked" not in message:
                continue

            kvs = dict(KV_RE.findall(message))
            ip = kvs.get("ip")
            user = kvs.get("user")
            if not ip or not user:
                continue

            ts = datetime.strptime(match.group("ts"), "%Y-%m-%d %H:%M:%S")
            attempts.append(FailedAttempt(timestamp=ts, ip=ip, user=user, raw=line))
    return attempts


# ---------- Detection ---------- #

def severity_for(count: int) -> str:
    sev = "LOW"
    for threshold, label in sorted(LEVELS_OF_SEVERITY.items()):
        if count >= threshold:
            sev = label
    return sev


def detect_brute_force(attempts: list[FailedAttempt]) -> list[Alert]:
    """Sliding window: per-IP, every attempt's 60s window must hold >= THRESHOLD hits.

    Returns shared `Alert` instances ready for persistence.
    """
    by_ip: dict[str, list[FailedAttempt]] = defaultdict(list)
    for a in attempts:
        by_ip[a.ip].append(a)
    for ip in by_ip:
        by_ip[ip].sort(key=lambda a: a.timestamp)

    alerts: list[Alert] = []
    for ip, items in by_ip.items():
        if len(items) < THRESHOLD:
            continue

        i = 0
        raised: set[tuple[datetime, datetime]] = set()
        for j in range(len(items)):
            while items[j].timestamp - items[i].timestamp > timedelta(seconds=WINDOW_SECONDS):
                i += 1
            window_count = j - i + 1
            if window_count >= THRESHOLD:
                start = items[i].timestamp
                end = items[j].timestamp
                key = (start, end)
                if key in raised:
                    continue
                raised.add(key)

                window_items = items[i:j + 1]
                users = sorted({a.user for a in window_items})
                first = items[i].timestamp
                last = items[j].timestamp
                sev = severity_for(window_count)

                alerts.append(Alert(
                    timestamp=first,
                    source_ip=ip,
                    detector=DETECTOR_BRUTE_FORCE,
                    severity=sev,
                    mitre_technique=_mitre.technique_for_detector(DETECTOR_BRUTE_FORCE),
                    mitre_tactic=_mitre.tactic_for_detector(DETECTOR_BRUTE_FORCE),
                    title=f"Brute Force from {ip}: {window_count} attempts in 60s",
                    description=(
                        f"users=[{','.join(users)}] "
                        f"count={window_count} "
                        f"first={first.strftime('%H:%M:%S')} "
                        f"last={last.strftime('%H:%M:%S')} "
                        f"window={WINDOW_SECONDS}s"
                    ),
                ))
    alerts.sort(key=lambda a: (a.timestamp, a.source_ip))
    return alerts


# ---------- Entry point ---------- #

def run() -> list[Alert]:
    """Standalone detection entry point — no storage side effects.

    Returns the alerts this detector produced from its configured log.
    Useful for ad-hoc CLI use; the orchestrator calls the underlying
    `detect_brute_force()` directly with shared input.
    """
    if not LOG_PATH.exists():
        print(f"Log file not found: {LOG_PATH}", file=sys.stderr)
        return []
    attempts = parse_attempts(LOG_PATH)
    print(f"[info] brute-force: scanned {len(attempts)} failed-login events from {LOG_PATH.name}")
    alerts = detect_brute_force(attempts)
    print(f"[info] brute-force: produced {len(alerts)} alert(s)")
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

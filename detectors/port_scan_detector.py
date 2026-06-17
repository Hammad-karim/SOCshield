"""
SOCshield - Port Scan Detector
Detects horizontal/vertical port scans and SYN floods using a sliding window.

Rules:
- HORIZONTAL_SCAN: a single src hits >= UNIQUE_PORT_THRESHOLD distinct dst ports
  on a single dst host within WINDOW_SECONDS.
- VERTICAL_SCAN:   a single src hits >= UNIQUE_PORT_THRESHOLD distinct dst ports
  spread across multiple dst hosts within WINDOW_SECONDS.
- SYN_FLOOD:       >= SYN_FLOOD_THRESHOLD "SYN flood" events from one src to the
  same dst:dport within WINDOW_SECONDS.

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

from app.models import (
    Alert,
    DETECTOR_PORT_SCAN_HORIZONTAL,
    DETECTOR_PORT_SCAN_VERTICAL,
    DETECTOR_PORT_SCAN_SYN_FLOOD,
)
from app import mitre as _mitre

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "firewall.log"

WINDOW_SECONDS = 60
UNIQUE_PORT_THRESHOLD = 5   # distinct dst ports in window -> scan alert
SYN_FLOOD_THRESHOLD = 8     # SYN-flood events in window -> flood alert

SEVERITY_LADDER = {
    5: "MEDIUM",
    10: "HIGH",
    20: "CRITICAL",
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
class PortEvent:
    timestamp: datetime
    src: str
    dst: str
    dport: int
    proto: str
    kind: str   # "probe" | "synflood" | "other"
    raw: str


# ---------- Parsing ---------- #

def classify_message(message: str) -> str:
    lower = message.lower()
    if "syn flood" in lower:
        return "synflood"
    if "port probe" in lower or "port scan" in lower or "tcp/udp scan" in lower:
        return "probe"
    return "other"


def parse_events(path: Path) -> list[PortEvent]:
    events: list[PortEvent] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = LINE_RE.match(line)
            if not match:
                continue
            kind = classify_message(match.group("message"))
            if kind == "other":
                continue

            kvs = dict(KV_RE.findall(match.group("message")))
            try:
                event = PortEvent(
                    timestamp=datetime.strptime(match.group("ts"), "%Y-%m-%d %H:%M:%S"),
                    src=kvs.get("src", ""),
                    dst=kvs.get("dst", ""),
                    dport=int(kvs.get("dport", "0")),
                    proto=kvs.get("proto", ""),
                    kind=kind,
                    raw=line,
                )
            except ValueError:
                continue
            if not event.src or not event.dst or not event.dport:
                continue
            events.append(event)
    return events


# ---------- Helpers ---------- #

def severity_for(count: int) -> str:
    sev = "LOW"
    for threshold, label in sorted(SEVERITY_LADDER.items()):
        if count >= threshold:
            sev = label
    return sev


def _raise_if_new(alerts: list[Alert], raised: set, alert: Alert) -> None:
    """Suppress duplicate alerts for the same (type, src, first_seen)."""
    key = (alert.detector, alert.source_ip, alert.timestamp)
    if key in raised:
        return
    raised.add(key)
    alerts.append(alert)


def _format_ports(dports: list[int]) -> str:
    ports = ",".join(str(p) for p in sorted(dports)[:20])
    if len(dports) > 20:
        ports += f" ...(+{len(dports) - 20})"
    return ports


def _format_dsts(dsts: list[str]) -> str:
    if len(dsts) <= 3:
        return ",".join(dsts)
    return f"{len(dsts)} hosts"


# ---------- Detection ---------- #

def detect_horizontal_scans(events: list[PortEvent]) -> list[Alert]:
    """Same src -> same dst, distinct ports in window."""
    by_pair: dict[tuple[str, str], list[PortEvent]] = defaultdict(list)
    for e in events:
        if e.kind != "probe":
            continue
        by_pair[(e.src, e.dst)].append(e)
    for key in by_pair:
        by_pair[key].sort(key=lambda e: e.timestamp)

    alerts: list[Alert] = []
    raised: set = set()
    for (src, dst), items in by_pair.items():
        if len(items) < UNIQUE_PORT_THRESHOLD:
            continue
        i = 0
        for j in range(len(items)):
            while items[j].timestamp - items[i].timestamp > timedelta(seconds=WINDOW_SECONDS):
                i += 1
            window = items[i:j + 1]
            unique_ports = sorted({e.dport for e in window})
            if len(unique_ports) >= UNIQUE_PORT_THRESHOLD:
                first = items[i].timestamp
                last = items[j].timestamp
                sev = severity_for(len(unique_ports))
                _raise_if_new(alerts, raised, Alert(
                    timestamp=first,
                    source_ip=src,
                    detector=DETECTOR_PORT_SCAN_HORIZONTAL,
                    severity=sev,
                    mitre_technique=_mitre.technique_for_detector(DETECTOR_PORT_SCAN_HORIZONTAL),
                    mitre_tactic=_mitre.tactic_for_detector(DETECTOR_PORT_SCAN_HORIZONTAL),
                    title=f"Horizontal Port Scan from {src} -> {dst} ({len(unique_ports)} ports)",
                    description=(
                        f"dports=[{_format_ports(unique_ports)}] "
                        f"dsts=[{dst}] count={len(window)} "
                        f"first={first.strftime('%H:%M:%S')} "
                        f"last={last.strftime('%H:%M:%S')} "
                        f"window={WINDOW_SECONDS}s"
                    ),
                ))
    return alerts


def detect_vertical_scans(events: list[PortEvent]) -> list[Alert]:
    """Same src -> many dsts, distinct ports in window."""
    by_src: dict[str, list[PortEvent]] = defaultdict(list)
    for e in events:
        if e.kind != "probe":
            continue
        by_src[e.src].append(e)
    for src in by_src:
        by_src[src].sort(key=lambda e: e.timestamp)

    alerts: list[Alert] = []
    raised: set = set()
    for src, items in by_src.items():
        if len(items) < UNIQUE_PORT_THRESHOLD:
            continue
        i = 0
        for j in range(len(items)):
            while items[j].timestamp - items[i].timestamp > timedelta(seconds=WINDOW_SECONDS):
                i += 1
            window = items[i:j + 1]
            unique_dsts = sorted({e.dst for e in window})
            unique_ports = sorted({e.dport for e in window})
            if len(unique_dsts) >= 2 and len(unique_ports) >= UNIQUE_PORT_THRESHOLD:
                first = items[i].timestamp
                last = items[j].timestamp
                sev = severity_for(len(unique_ports))
                _raise_if_new(alerts, raised, Alert(
                    timestamp=first,
                    source_ip=src,
                    detector=DETECTOR_PORT_SCAN_VERTICAL,
                    severity=sev,
                    mitre_technique=_mitre.technique_for_detector(DETECTOR_PORT_SCAN_VERTICAL),
                    mitre_tactic=_mitre.tactic_for_detector(DETECTOR_PORT_SCAN_VERTICAL),
                    title=f"Vertical Port Scan from {src} ({len(unique_dsts)} hosts, {len(unique_ports)} ports)",
                    description=(
                        f"dports=[{_format_ports(unique_ports)}] "
                        f"dsts=[{_format_dsts(unique_dsts)}] "
                        f"count={len(window)} "
                        f"first={first.strftime('%H:%M:%S')} "
                        f"last={last.strftime('%H:%M:%S')} "
                        f"window={WINDOW_SECONDS}s"
                    ),
                ))
    return alerts


def detect_syn_floods(events: list[PortEvent]) -> list[Alert]:
    """Same src -> same dst:dport, many SYN-flood events in window."""
    by_target: dict[tuple[str, str, int], list[PortEvent]] = defaultdict(list)
    for e in events:
        if e.kind != "synflood":
            continue
        by_target[(e.src, e.dst, e.dport)].append(e)
    for key in by_target:
        by_target[key].sort(key=lambda e: e.timestamp)

    alerts: list[Alert] = []
    raised: set = set()
    for (src, dst, dport), items in by_target.items():
        if len(items) < SYN_FLOOD_THRESHOLD:
            continue
        i = 0
        for j in range(len(items)):
            while items[j].timestamp - items[i].timestamp > timedelta(seconds=WINDOW_SECONDS):
                i += 1
            count = j - i + 1
            if count >= SYN_FLOOD_THRESHOLD:
                first = items[i].timestamp
                last = items[j].timestamp
                sev = severity_for(count)
                _raise_if_new(alerts, raised, Alert(
                    timestamp=first,
                    source_ip=src,
                    detector=DETECTOR_PORT_SCAN_SYN_FLOOD,
                    severity=sev,
                    mitre_technique=_mitre.technique_for_detector(DETECTOR_PORT_SCAN_SYN_FLOOD),
                    mitre_tactic=_mitre.tactic_for_detector(DETECTOR_PORT_SCAN_SYN_FLOOD),
                    title=f"SYN Flood from {src} -> {dst}:{dport} ({count} SYNs)",
                    description=(
                        f"dports=[{dport}] dsts=[{dst}] count={count} "
                        f"first={first.strftime('%H:%M:%S')} "
                        f"last={last.strftime('%H:%M:%S')} "
                        f"window={WINDOW_SECONDS}s"
                    ),
                ))
    return alerts


# ---------- Entry point ---------- #

def run() -> list[Alert]:
    """Standalone detection entry point — no storage side effects."""
    if not LOG_PATH.exists():
        print(f"Log file not found: {LOG_PATH}", file=sys.stderr)
        return []
    events = parse_events(LOG_PATH)
    print(f"[info] port-scan: scanned {len(events)} probe/synflood events from {LOG_PATH.name}")

    alerts: list[Alert] = []
    alerts.extend(detect_horizontal_scans(events))
    alerts.extend(detect_vertical_scans(events))
    alerts.extend(detect_syn_floods(events))
    alerts.sort(key=lambda a: (a.timestamp, a.source_ip))

    print(f"[info] port-scan: produced {len(alerts)} alert(s)")
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

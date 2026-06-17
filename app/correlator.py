"""
SOCshield - Correlation Engine

Groups alerts by `source_ip`, sorts by timestamp, and detects multi-stage
attack chains (campaigns). Emits structured `Campaign` objects that the
report generator consumes.

Rules (per task spec):

    Rule A — PORT_SCAN + BRUTE_FORCE
        -> HIGH severity "recon-then-credential-attack" campaign

    Rule B — PORT_SCAN + BRUTE_FORCE + PRIV_ESC
        -> CRITICAL severity "intrusion" campaign

    Rule C — Multiple PRIV_ESC alerts at CRITICAL severity
        -> CRITICAL "insider threat candidate" campaign

Each rule independently produces a campaign when matched; multiple rules
matching the same IP produce multiple campaigns (different narratives).

Output (per spec):
    {
      "source_ip": "...",
      "risk": "...",
      "timeline": [...],
      "summary": "...",
      "alerts": [...],            # raw Alert objects for the report layer
      "rule_id": "A|B|C",
      "matched_detectors": [...],
      "narrative": "...",
      "generated_at": "<ISO8601>"
    }
"""

from __future__ import annotations

import logging
import sys
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Make sibling packages importable when run as a script
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.models import (  # noqa: E402
    Alert,
    DETECTOR_BRUTE_FORCE,
    DETECTOR_PRIV_ESC,
)
from app.models import (  # noqa: E402
    DETECTOR_PORT_SCAN_HORIZONTAL,
    DETECTOR_PORT_SCAN_VERTICAL,
    DETECTOR_PORT_SCAN_SYN_FLOOD,
)
from app import mitre as _mitre  # noqa: E402

logger = logging.getLogger("socshield.correlator")

# Detector-family groupings for rule matching
PORT_SCAN_DETECTORS: frozenset[str] = frozenset({
    DETECTOR_PORT_SCAN_HORIZONTAL,
    DETECTOR_PORT_SCAN_VERTICAL,
    DETECTOR_PORT_SCAN_SYN_FLOOD,
})


def _is_port_scan(detector: str) -> bool:
    return detector in PORT_SCAN_DETECTORS


def _is_brute_force(detector: str) -> bool:
    return detector == DETECTOR_BRUTE_FORCE


def _is_priv_esc(detector: str) -> bool:
    return detector == DETECTOR_PRIV_ESC


@dataclass
class Campaign:
    """One correlated attack chain (rule match)."""

    source_ip: str
    rule_id: str                       # "A" | "B" | "C"
    rule_name: str
    risk: str                          # LOW | MEDIUM | HIGH | CRITICAL
    matched_detectors: list[str] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    narrative: str = ""
    summary: str = ""
    generated_at: str = ""
    # Populated by threat_intel.enrichment.enrich_campaigns; uses a forward
    # ref (``Any``) to avoid a circular import (enrichment imports the
    # Campaign type only when necessary).
    threat_intel: Any = None
    # MITRE ATT&CK — populated by correlate() from the campaign's alerts.
    # `attack_path` is the ordered kill-chain list (Reconnaissance -> ...).
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    attack_path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON-friendly dict matching the spec output shape."""
        ti_payload: dict | None
        ti = self.threat_intel
        if ti is None:
            ti_payload = None
        elif hasattr(ti, "to_dict"):
            ti_payload = ti.to_dict()
        elif isinstance(ti, dict):
            ti_payload = ti
        else:
            # Best-effort fallback — should not be hit in practice
            ti_payload = getattr(ti, "__dict__", None)
        return {
            "source_ip": self.source_ip,
            "risk": self.risk,
            "timeline": self.timeline,
            "summary": self.summary,
            "alerts": [a.as_dict_full() for a in self.alerts],
            "narrative": self.narrative,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "matched_detectors": self.matched_detectors,
            "generated_at": self.generated_at,
            "threat_intel": ti_payload,
            "mitre_techniques": list(self.mitre_techniques),
            "mitre_tactics": list(self.mitre_tactics),
            "attack_path": list(self.attack_path),
        }


# ---------- Helpers ---------- #

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _group_by_ip(alerts: Iterable[Alert]) -> dict[str, list[Alert]]:
    grouped: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        grouped[a.source_ip].append(a)
    for ip in grouped:
        grouped[ip].sort(key=lambda a: a.timestamp)
    return grouped


def _families_present(alerts: list[Alert]) -> set[str]:
    """Return the set of detector *families* present for an IP
    (port_scan family is collapsed)."""
    fams: set[str] = set()
    for a in alerts:
        if _is_port_scan(a.detector):
            fams.add("PORT_SCAN")
        elif _is_brute_force(a.detector):
            fams.add("BRUTE_FORCE")
        elif _is_priv_esc(a.detector):
            fams.add("PRIV_ESC")
        else:
            fams.add(a.detector)
    return fams


def _build_timeline(alerts: list[Alert]) -> list[dict]:
    return [
        {
            "timestamp": a.timestamp.isoformat(sep=" ", timespec="seconds"),
            "detector": a.detector,
            "severity": a.severity,
            "title": a.title,
        }
        for a in alerts
    ]


def _max_severity(alerts: list[Alert]) -> str:
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not alerts:
        return "LOW"
    return max(alerts, key=lambda a: rank.get(a.severity, 0)).severity


def _format_narrative(rule_id: str, ip: str, alerts: list[Alert],
                      timeline: list[dict]) -> tuple[str, str]:
    """Produce (narrative, summary) strings from a rule match."""
    n = len(alerts)
    detectors = sorted({t["detector"] for t in timeline})
    first = timeline[0]["timestamp"] if timeline else "-"
    last = timeline[-1]["timestamp"] if timeline else "-"
    peak = _max_severity(alerts)

    if rule_id == "A":
        narrative = (
            f"Reconnaissance followed by credential attack from {ip}. "
            f"The source performed port scanning then brute-forced authentication "
            f"({n} alert(s) across {detectors}, peak severity {peak}). "
            f"Window: {first} -> {last}."
        )
        summary = f"Port scan + brute force campaign from {ip} ({n} alerts)"
    elif rule_id == "B":
        narrative = (
            f"Full intrusion chain from {ip}: port scan -> brute force -> privilege "
            f"escalation ({n} alert(s) across {detectors}, peak severity {peak}). "
            f"The source likely moved from external reconnaissance to internal "
            f"credential compromise and finally to host-level privilege escalation. "
            f"Window: {first} -> {last}."
        )
        summary = f"Intrusion campaign (scan+brute+privesc) from {ip} ({n} alerts)"
    elif rule_id == "C":
        # Count CRITICAL priv-esc events directly — trigger requires >=2 such alerts
        crit_events = [a for a in alerts
                       if a.severity == "CRITICAL" and a.detector == DETECTOR_PRIV_ESC]
        unique_titles = sorted({a.title for a in crit_events})
        narrative = (
            f"Insider-threat candidate at {ip}: {len(crit_events)} CRITICAL privilege-"
            f"escalation alert(s) across {len(unique_titles)} distinct escalation(s). "
            f"Multiple root-level acquisitions suggest a deliberate, multi-stage "
            f"insider action rather than opportunistic exploitation. "
            f"Window: {first} -> {last}."
        )
        summary = (
            f"Insider threat candidate at {ip} "
            f"({len(crit_events)} CRITICAL privesc)"
        )
    else:
        narrative = f"Campaign from {ip}: {n} alert(s) ({detectors})."
        summary = f"Campaign from {ip}"

    return narrative, summary


# ---------- Rule implementations ---------- #

def _rule_a(alerts: list[Alert]) -> Campaign | None:
    """PORT_SCAN + BRUTE_FORCE -> HIGH severity campaign."""
    scan = [a for a in alerts if _is_port_scan(a.detector)]
    bf   = [a for a in alerts if _is_brute_force(a.detector)]
    if not scan or not bf:
        return None
    combined = sorted(scan + bf, key=lambda a: a.timestamp)
    peak = _max_severity(combined)
    # Rule mandates HIGH; bump to CRITICAL only if individual alerts already are
    risk = "CRITICAL" if peak == "CRITICAL" else "HIGH"
    c = Campaign(
        source_ip=combined[0].source_ip,
        rule_id="A",
        rule_name="Reconnaissance + Credential Attack",
        risk=risk,
        matched_detectors=sorted({a.detector for a in combined}),
        alerts=combined,
        timeline=_build_timeline(combined),
        generated_at=_now_iso(),
    )
    _apply_narrative(c, "A", combined)
    return c


def _rule_b(alerts: list[Alert]) -> Campaign | None:
    """PORT_SCAN + BRUTE_FORCE + PRIV_ESC -> CRITICAL intrusion campaign."""
    scan = [a for a in alerts if _is_port_scan(a.detector)]
    bf   = [a for a in alerts if _is_brute_force(a.detector)]
    pe   = [a for a in alerts if _is_priv_esc(a.detector)]
    if not (scan and bf and pe):
        return None
    combined = sorted(scan + bf + pe, key=lambda a: a.timestamp)
    c = Campaign(
        source_ip=combined[0].source_ip,
        rule_id="B",
        rule_name="Full Intrusion Chain",
        risk="CRITICAL",
        matched_detectors=sorted({a.detector for a in combined}),
        alerts=combined,
        timeline=_build_timeline(combined),
        generated_at=_now_iso(),
    )
    _apply_narrative(c, "B", combined)
    return c


def _rule_c(alerts: list[Alert]) -> Campaign | None:
    """Multiple CRITICAL PRIV_ESC -> insider threat candidate."""
    crit_pe = [a for a in alerts if _is_priv_esc(a.detector) and a.severity == "CRITICAL"]
    if len(crit_pe) < 2:
        return None
    combined = sorted(crit_pe, key=lambda a: a.timestamp)
    c = Campaign(
        source_ip=combined[0].source_ip,
        rule_id="C",
        rule_name="Insider Threat Candidate",
        risk="CRITICAL",
        matched_detectors=sorted({a.detector for a in combined}),
        alerts=combined,
        timeline=_build_timeline(combined),
        generated_at=_now_iso(),
    )
    _apply_narrative(c, "C", combined)
    return c


def _apply_narrative(c: Campaign, rule_id: str, alerts: list[Alert]) -> None:
    """Mutate `c` in place with the narrative + summary + timeline + MITRE fields."""
    timeline = _build_timeline(alerts)
    n, s = _format_narrative(rule_id, c.source_ip, alerts, timeline)

    # MITRE enrichment — collect techniques/tactics from the campaign's alerts.
    detectors_in_play = [a.detector for a in alerts]
    techniques = _mitre.unique_techniques(detectors_in_play)
    tactics = _mitre.unique_tactics(detectors_in_play)
    attack_path = _mitre.attack_path(detectors_in_play)

    if attack_path:
        chain = " -> ".join(attack_path)
        n = f"{n} ATT&CK kill chain: {chain}."

    c.narrative = n
    c.summary = s
    c.timeline = timeline
    c.mitre_techniques = techniques
    c.mitre_tactics = tactics
    c.attack_path = attack_path


# ---------- Public entry point ---------- #

def correlate(alerts: Iterable[Alert]) -> list[Campaign]:
    """Run all rules across all IPs and return the matched campaigns.

    Multiple rules can fire on the same IP — each campaign is returned
    independently so the report layer can render them as separate incidents.
    """
    grouped = _group_by_ip(alerts)
    campaigns: list[Campaign] = []

    for ip, ip_alerts in grouped.items():
        families = _families_present(ip_alerts)
        # Rule B subsumes Rule A when all three detectors present — still emit
        # both campaigns because their narratives differ (B is the escalated view).
        if {"PORT_SCAN", "BRUTE_FORCE"}.issubset(families):
            c = _rule_a(ip_alerts)
            if c is not None:
                campaigns.append(c)
        if {"PORT_SCAN", "BRUTE_FORCE", "PRIV_ESC"}.issubset(families):
            c = _rule_b(ip_alerts)
            if c is not None:
                campaigns.append(c)
        if {"PRIV_ESC"}.issubset(families):
            c = _rule_c(ip_alerts)
            if c is not None:
                campaigns.append(c)

    # Newest-first ordering by IP's earliest alert timestamp
    campaigns.sort(key=lambda c: (c.alerts[0].timestamp, c.source_ip, c.rule_id))
    return campaigns


# ---------- Continuous (streaming) correlator ---------- #

class ContinuousCorrelator:
    """Incrementally maintain campaigns as new alerts arrive.

    On each `on_new_alert` invocation:
        - Append the new alert to internal history.
        - Re-run `correlate()` over the full history.
        - Diff against the previously-seen campaign set.
        - Emit `INCIDENT_CREATED` for new campaign_keys and
          `INCIDENT_UPDATED` for any campaign whose risk changed.

    Campaign key = (source_ip, rule_id) — same IP + same rule = same
    incident being updated rather than duplicated.
    """

    def __init__(self, bus: Any, metrics: Any | None = None) -> None:
        self.bus = bus
        self.metrics = metrics
        self._all_alerts: list[Alert] = []
        self._campaigns: dict[tuple[str, str], Campaign] = {}
        self._lock = threading.Lock()

    # ---------- Subscription wiring ---------- #

    def start(self) -> None:
        """Subscribe the alert handler to NEW_ALERT on the bus."""
        from app.event_bus import NEW_ALERT  # local import to avoid cycles
        self.bus.subscribe(NEW_ALERT, self._on_event)

    def stop(self) -> None:
        """No-op: bus.stop() handles dispatcher thread teardown."""
        return

    # ---------- Handler ---------- #

    def _on_event(self, event: Any) -> None:
        # The watcher publishes the Alert directly as payload; some callers
        # may publish a dict with an "alert" key — accept both.
        payload = event.payload
        if isinstance(payload, dict) and "alert" in payload:
            alert = payload["alert"]
        else:
            alert = payload
        if alert is None:
            return
        self.on_new_alert(alert)

    def on_new_alert(self, alert: Alert) -> None:
        """Process a single newly-detected alert. Public for direct callers."""
        from app.event_bus import (
            INCIDENT_CREATED,
            INCIDENT_UPDATED,
        )

        with self._lock:
            self._all_alerts.append(alert)
            # Track metric on every alert, even if it does not produce a campaign.
            if self.metrics is not None:
                self.metrics.record_alert(alert)

            fresh = correlate(self._all_alerts)
            fresh_map: dict[tuple[str, str], Campaign] = {
                (c.source_ip, c.rule_id): c for c in fresh
            }

            # INCIDENT_CREATED — campaign_key not seen before.
            for key, c in fresh_map.items():
                if key not in self._campaigns:
                    self._campaigns[key] = c
                    if self.metrics is not None:
                        self.metrics.record_incident(c)
                    self.bus.publish(INCIDENT_CREATED, c.to_dict())
                    logger.info(
                        "INCIDENT_CREATED ip=%s rule=%s risk=%s alerts=%d",
                        c.source_ip, c.rule_id, c.risk, len(c.alerts),
                    )
                    continue

                # INCIDENT_UPDATED — risk changed for an existing campaign.
                prev = self._campaigns[key]
                if prev.risk != c.risk:
                    self._campaigns[key] = c
                    if self.metrics is not None:
                        self.metrics.record_incident(c)
                    self.bus.publish(INCIDENT_UPDATED, c.to_dict())
                    logger.info(
                        "INCIDENT_UPDATED ip=%s rule=%s risk=%s->%s alerts=%d",
                        c.source_ip, c.rule_id, prev.risk, c.risk, len(c.alerts),
                    )
                else:
                    # Even when risk is unchanged, refresh alert list/timeline
                    # so a downstream consumer sees the latest evidence.
                    self._campaigns[key] = c

    # ---------- Read access ---------- #

    def current_campaigns(self) -> list[Campaign]:
        """Snapshot of currently-tracked campaigns (newest-first)."""
        with self._lock:
            return list(self._campaigns.values())

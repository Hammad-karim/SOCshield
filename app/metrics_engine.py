"""
SOCshield - Metrics Engine

Thread-safe runtime counters used by the service mode. Tracks alert /
incident rates, active attacker IPs, and CRITICAL alert totals. The
engine is a pure counter sink — it does not touch the database or the
event bus; subscribers call `record_alert` / `record_incident` directly.

Snapshot format (returned by `snapshot()`) is JSON-serializable so a
dashboard (future) or CLI printer can dump it without conversion.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from app.models import Alert
    from app.correlator import Campaign

logger = logging.getLogger("socshield.metrics")

ACTIVE_ATTACKER_WINDOW = timedelta(minutes=5)
ALERT_RATE_WINDOW = timedelta(seconds=60)
INCIDENT_RATE_WINDOW = timedelta(hours=1)


@dataclass
class _Counters:
    """Internal mutable state, guarded by MetricsEngine._lock."""

    alerts_total: int = 0
    critical_alerts: int = 0
    incidents_total: int = 0
    alert_timestamps: deque = field(default_factory=deque)
    incident_timestamps: deque = field(default_factory=deque)
    # source_ip -> most-recent alert timestamp (deque-trimmed by window)
    active_attackers: dict[str, datetime] = field(default_factory=dict)


class MetricsEngine:
    """Thread-safe runtime metrics for the service pipeline."""

    def __init__(
        self,
        active_window: timedelta = ACTIVE_ATTACKER_WINDOW,
        alert_window: timedelta = ALERT_RATE_WINDOW,
        incident_window: timedelta = INCIDENT_RATE_WINDOW,
    ) -> None:
        self._lock = threading.Lock()
        self._c = _Counters()
        self.active_window = active_window
        self.alert_window = alert_window
        self.incident_window = incident_window

    # ---------- Recording ---------- #

    def record_alert(self, alert: "Alert") -> None:
        """Record a newly detected alert."""
        now = datetime.now(timezone.utc)
        with self._lock:
            self._c.alerts_total += 1
            if alert.severity == "CRITICAL":
                self._c.critical_alerts += 1
            self._c.alert_timestamps.append(now)
            self._c.active_attackers[alert.source_ip] = now
            self._trim_locked(now)

    def record_incident(self, campaign: "Campaign") -> None:
        """Record a newly created or updated campaign/incident."""
        now = datetime.now(timezone.utc)
        with self._lock:
            self._c.incidents_total += 1
            self._c.incident_timestamps.append(now)
            self._trim_locked(now)

    def record_alerts(self, alerts: Iterable["Alert"]) -> None:
        for a in alerts:
            self.record_alert(a)

    # ---------- Snapshots ---------- #

    def snapshot(self) -> dict:
        """Return a JSON-serializable snapshot of the current metrics."""
        now = datetime.now(timezone.utc)
        with self._lock:
            self._trim_locked(now)
            active_cutoff = now - self.active_window
            active = sorted(
                ip for ip, ts in self._c.active_attackers.items() if ts >= active_cutoff
            )
            apm = sum(
                1 for ts in self._c.alert_timestamps if ts >= now - self.alert_window
            )
            iph = sum(
                1 for ts in self._c.incident_timestamps if ts >= now - self.incident_window
            )
            return {
                "alerts_total": self._c.alerts_total,
                "critical_alerts": self._c.critical_alerts,
                "alerts_per_minute": apm,
                "incidents_total": self._c.incidents_total,
                "incidents_per_hour": iph,
                "active_attacker_ips": active,
                "active_attacker_count": len(active),
            }

    # ---------- Internal ---------- #

    def _trim_locked(self, now: datetime) -> None:
        """Drop timestamps that fell out of the rolling windows.

        Must be called with `self._lock` held.
        """
        alert_cutoff = now - self.alert_window
        while self._c.alert_timestamps and self._c.alert_timestamps[0] < alert_cutoff:
            self._c.alert_timestamps.popleft()

        incident_cutoff = now - self.incident_window
        while self._c.incident_timestamps and self._c.incident_timestamps[0] < incident_cutoff:
            self._c.incident_timestamps.popleft()

        active_cutoff = now - self.active_window
        stale = [ip for ip, ts in self._c.active_attackers.items() if ts < active_cutoff]
        for ip in stale:
            self._c.active_attackers.pop(ip, None)


def format_snapshot_line(snap: dict) -> str:
    """One-line summary used by the service-mode metrics printer."""
    return (
        f"alerts={snap['alerts_total']} "
        f"({snap['alerts_per_minute']}/min, {snap['critical_alerts']} CRIT) | "
        f"incidents={snap['incidents_total']} "
        f"({snap['incidents_per_hour']}/hr) | "
        f"active_ips={snap['active_attacker_count']}"
    )

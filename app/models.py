"""
SOCshield - Shared data models.

All detectors emit `Alert` objects built from this single dataclass so they
can be persisted to the same SQLite table and queried uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


# Standard detector identifiers used in the `detector` column
DETECTOR_BRUTE_FORCE = "BRUTE_FORCE"
DETECTOR_PORT_SCAN_HORIZONTAL = "PORT_SCAN:HORIZONTAL"
DETECTOR_PORT_SCAN_VERTICAL = "PORT_SCAN:VERTICAL"
DETECTOR_PORT_SCAN_SYN_FLOOD = "PORT_SCAN:SYN_FLOOD"
DETECTOR_PRIV_ESC = "PRIV_ESC"

ALLOWED_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class Alert:
    """A security alert produced by a detector.

    Fields map 1:1 to the `alerts` SQLite table columns:
        timestamp   -> ISO 8601 string in DB
        source_ip   -> actor IP (attacker for network detectors,
                       actor host for privilege-escalation)
        detector    -> short detector identifier
        severity    -> LOW | MEDIUM | HIGH | CRITICAL
        title       -> one-line summary
        description -> full evidence string (free-form)
    """

    timestamp: datetime
    source_ip: str
    detector: str
    severity: str
    title: str
    description: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    # MITRE ATT&CK — auto-populated by detectors via app.mitre. Optional
    # in __init__ because the SQLite schema predates them (older rows have
    # neither column nor attribute).
    mitre_technique: str | None = None
    mitre_tactic: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(
                f"Invalid severity {self.severity!r}; must be one of {ALLOWED_SEVERITIES}"
            )

    # ---------- Serialization ---------- #

    def to_dict(self) -> dict[str, Any]:
        """Flat dict for DB insertion (extra column is ignored at the DB layer)."""
        return {
            "timestamp": self.timestamp.isoformat(sep=" ", timespec="seconds"),
            "source_ip": self.source_ip,
            "detector": self.detector,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
        }

    @classmethod
    def from_row(cls, row: Any) -> "Alert":
        """Build an Alert from a sqlite3.Row (or any mapping)."""
        ts_raw = row["timestamp"]
        try:
            timestamp = datetime.fromisoformat(ts_raw)
        except ValueError:
            # Fallback: tolerate "YYYY-MM-DD HH:MM:SS"
            timestamp = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
        return cls(
            timestamp=timestamp,
            source_ip=row["source_ip"],
            detector=row["detector"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"] or "",
        )

    # ---------- Display helpers ---------- #

    def short(self) -> str:
        """One-line summary suitable for CLI output."""
        ts = self.timestamp.strftime("%H:%M:%S")
        mitre = f" {self.mitre_technique}" if self.mitre_technique else ""
        return f"[{ts}] {self.severity:<8} {self.detector:<22} {self.source_ip:<16}{mitre} {self.title}"

    def as_dict_full(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat(sep=" ", timespec="seconds")
        return d

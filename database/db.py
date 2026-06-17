"""
SOCshield - SQLite alert store.

Schema is fixed by the project spec:
    id          INTEGER PRIMARY KEY
    timestamp   TEXT
    source_ip   TEXT
    detector    TEXT
    severity    TEXT
    title       TEXT
    description TEXT

All public functions take or return `app.models.Alert` instances so callers
don't deal with raw rows.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

# Repo root -> <repo>/database/db.py -> parents[1] is the repo root
BASE_DIR = Path(__file__).resolve().parent.parent
# Allow deployment to relocate the SQLite store via env (Docker volume mount).
# Resolution order:
#   1. SOCSHIELD_DB_PATH (absolute path to a .db file)
#   2. <repo>/database/alerts.db  (default, in-repo)
_DEFAULT_DB = BASE_DIR / "database" / "alerts.db"
DB_PATH = Path(os.environ.get("SOCSHIELD_DB_PATH", str(_DEFAULT_DB))).resolve()

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    detector    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ip  ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
"""


def _connect() -> sqlite3.Connection:
    """Open a SQLite connection with row dict access."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the alerts table and indexes if they don't exist. Idempotent."""
    with _connect() as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def save_alert(alert: Any) -> int:
    """Insert a single Alert. Returns the new row's id.

    Accepts any object with the Alert interface — uses `to_dict()` if the
    attribute exists, otherwise reads the dataclass fields directly.
    """
    if hasattr(alert, "to_dict"):
        row = alert.to_dict()
    else:
        # Defensive fallback for plain dataclass instances
        row = {
            "timestamp": alert.timestamp.isoformat(sep=" ", timespec="seconds"),
            "source_ip": alert.source_ip,
            "detector": alert.detector,
            "severity": alert.severity,
            "title": alert.title,
            "description": getattr(alert, "description", "") or "",
        }

    sql = (
        "INSERT INTO alerts (timestamp, source_ip, detector, severity, title, description) "
        "VALUES (:timestamp, :source_ip, :detector, :severity, :title, :description)"
    )
    with _connect() as conn:
        cur = conn.execute(sql, row)
        conn.commit()
        return cur.lastrowid


def get_all_alerts() -> list[Any]:
    """Return every alert, newest first."""
    # Local import to avoid a circular dependency at module-load time
    from app.models import Alert

    with _connect() as conn:
        cur = conn.execute(
            "SELECT id, timestamp, source_ip, detector, severity, title, description "
            "FROM alerts ORDER BY timestamp DESC, id DESC"
        )
        return [Alert.from_row(r) for r in cur.fetchall()]


def get_alerts_by_ip(ip: str) -> list[Any]:
    """Return alerts whose `source_ip` matches exactly, newest first."""
    from app.models import Alert

    with _connect() as conn:
        cur = conn.execute(
            "SELECT id, timestamp, source_ip, detector, severity, title, description "
            "FROM alerts WHERE source_ip = ? ORDER BY timestamp DESC, id DESC",
            (ip,),
        )
        return [Alert.from_row(r) for r in cur.fetchall()]


def get_alerts_by_time_range(start: datetime, end: datetime) -> list[Any]:
    """Return alerts with `timestamp` in [start, end] inclusive. Newest first."""
    from app.models import Alert

    start_s = start.isoformat(sep=" ", timespec="seconds")
    end_s = end.isoformat(sep=" ", timespec="seconds")
    with _connect() as conn:
        cur = conn.execute(
            "SELECT id, timestamp, source_ip, detector, severity, title, description "
            "FROM alerts WHERE timestamp BETWEEN ? AND ? "
            "ORDER BY timestamp DESC, id DESC",
            (start_s, end_s),
        )
        return [Alert.from_row(r) for r in cur.fetchall()]


# ---------- Convenience for ad-hoc inspection ---------- #

def count_alerts() -> int:
    """Cheap row count — useful for smoke tests."""
    with _connect() as conn:
        cur = conn.execute("SELECT COUNT(*) AS n FROM alerts")
        return int(cur.fetchone()["n"])


def clear_alerts() -> None:
    """Wipe the alerts table. Intended for tests / fresh-start runs only."""
    with _connect() as conn:
        conn.execute("DELETE FROM alerts")
        conn.commit()

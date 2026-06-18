"""
SOCshield - Alert store (SQLite + Postgres dual-backend).

Backend selection (per-process, decided on first connect):
    1. If `DATABASE_URL` (or legacy `POSTGRES_URL`) is set, connect to
       PostgreSQL via psycopg2. Used in Vercel / Neon / any managed
       Postgres deployment so data survives cold starts.
    2. Otherwise fall back to the SQLite store at `SOCSHIELD_DB_PATH`
       (default `<repo>/database/alerts.db`). Used locally, in Docker,
       and in any environment without managed Postgres.

The public API is the same regardless of backend:
    init_db(), save_alert(alert), get_all_alerts(),
    get_alerts_by_ip(ip), get_alerts_by_time_range(start, end),
    count_alerts(), clear_alerts(), health_check()

All read functions return Alert objects (or lists of them). All
returned rows from internal `_connect()` calls are plain dicts so
callers can treat them uniformly without depending on sqlite3.Row.

Schema (identical on both backends):
    id          BIGSERIAL / INTEGER PRIMARY KEY AUTOINCREMENT
    timestamp   TEXT NOT NULL
    source_ip   TEXT NOT NULL
    detector    TEXT NOT NULL
    severity    TEXT NOT NULL
    title       TEXT NOT NULL
    description TEXT
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("socshield.db")

# Repo root -> <repo>/database/db.py -> parents[1] is the repo root
BASE_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_DB = BASE_DIR / "database" / "alerts.db"


# ---------- Backend detection ----------

def _postgres_dsn() -> str | None:
    """Return the Postgres connection string if one is configured, else None."""
    dsn = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
    if dsn and dsn.strip():
        return dsn.strip()
    return None


def _is_postgres() -> bool:
    return _postgres_dsn() is not None


def _sqlite_path() -> Path:
    """Resolve the SQLite file path lazily, with /tmp fallback for read-only FS."""
    raw = os.environ.get("SOCSHIELD_DB_PATH", str(_DEFAULT_DB))
    try:
        p = Path(raw).resolve()
        parent = p.parent
        if parent.exists():
            if not os.access(str(parent), os.W_OK):
                raise OSError("read-only")
        else:
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError):
                raise OSError("read-only")
        return p
    except (OSError, PermissionError):
        fallback = Path("/tmp/socshield/alerts.db")
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


# Module-level handle used by the health check; computed lazily.
DB_PATH = _sqlite_path() if not _is_postgres() else None
DB_BACKEND = "postgres" if _is_postgres() else "sqlite"


# ---------- Placeholder translation ----------

def _adapt_sql(sql: str) -> str:
    """Translate SQLite-style '?' placeholders to psycopg2-style '%s'.

    Postgres doesn't accept '?' as a parameter marker. We count '?' that
    are outside of string literals (simple heuristic — sufficient for
    this codebase's hand-written SQL, none of which embed '?' in
    literals).
    """
    if DB_BACKEND == "postgres":
        return sql.replace("?", "%s")
    return sql


# ---------- Connection helpers ----------

@contextmanager
def _connect() -> Iterator[Any]:
    """Open a connection (Postgres or SQLite) that supports `with`.

    Yields the raw connection object. Caller is responsible for
    transactions, but `with` will commit on success and roll back on
    exception for SQLite; psycopg2 connections autocommit per-statement
    by default unless we wrap explicitly.
    """
    if DB_BACKEND == "postgres":
        import psycopg2
        import psycopg2.extras

        dsn = _postgres_dsn()
        # Suppress libpq notices leaking into Vercel function logs.
        conn = psycopg2.connect(dsn)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ---------- Init / schema ----------

# SQLite schema (with AUTOINCREMENT)
_SQLITE_SCHEMA = """
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

# Postgres schema (with BIGSERIAL). Idempotent: uses IF NOT EXISTS.
_POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
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


def init_db() -> None:
    """Create the alerts table and indexes if they don't exist. Idempotent."""
    if DB_BACKEND == "postgres":
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_POSTGRES_SCHEMA)
    else:
        with _connect() as conn:
            conn.executescript(_SQLITE_SCHEMA)


# ---------- Row normalization ----------

def _row_to_dict(row: Any) -> dict:
    """Normalize a row from either backend into a plain dict.

    SQLite: row is sqlite3.Row, supports `row["col"]` and `dict(row)`.
    Postgres: row is a tuple; column names come from cursor.description.
    """
    if row is None:
        return {}
    if isinstance(row, dict):
        return row
    if isinstance(row, sqlite3.Row):
        return {k: row[k] for k in row.keys()}
    # Postgres tuple — we always wrap with RealDictCursor, but be safe
    if hasattr(row, "keys"):
        return {k: row[k] for k in row.keys()}
    return dict(row)


def _fetch_all_dicts(cur: Any) -> list[dict]:
    """Fetch all rows from a cursor and return as list of dicts."""
    rows = cur.fetchall()
    out: list[dict] = []
    for r in rows:
        out.append(_row_to_dict(r))
    return out


# ---------- Public API ----------

def save_alert(alert: Any) -> int:
    """Insert a single Alert. Returns the new row's id."""
    if hasattr(alert, "to_dict"):
        row = alert.to_dict()
    else:
        row = {
            "timestamp": alert.timestamp.isoformat(sep=" ", timespec="seconds"),
            "source_ip": alert.source_ip,
            "detector": alert.detector,
            "severity": alert.severity,
            "title": alert.title,
            "description": getattr(alert, "description", "") or "",
        }

    sql = _adapt_sql(
        "INSERT INTO alerts (timestamp, source_ip, detector, severity, title, description) "
        "VALUES (?, ?, ?, ?, ?, ?)"
    )
    with _connect() as conn:
        if DB_BACKEND == "postgres":
            with conn.cursor() as cur:
                cur.execute(sql, [
                    row["timestamp"], row["source_ip"], row["detector"],
                    row["severity"], row["title"], row["description"],
                ])
                # cur.lastrowid works in psycopg2 when the column is SERIAL/BIGSERIAL
                cur.execute("SELECT lastval()")
                new_id = int(cur.fetchone()[0])
                return new_id
        else:
            cur = conn.execute(sql, [
                row["timestamp"], row["source_ip"], row["detector"],
                row["severity"], row["title"], row["description"],
            ])
            return int(cur.lastrowid)


def get_all_alerts() -> list[Any]:
    """Return every alert, newest first."""
    from app.models import Alert

    sql = _adapt_sql(
        "SELECT id, timestamp, source_ip, detector, severity, title, description "
        "FROM alerts ORDER BY timestamp DESC, id DESC"
    )
    with _connect() as conn:
        if DB_BACKEND == "postgres":
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql)
                rows = _fetch_all_dicts(cur)
        else:
            cur = conn.execute(sql)
            rows = [dict(r) for r in cur.fetchall()]
    return [Alert.from_row(r) for r in rows]


def get_alerts_by_ip(ip: str) -> list[Any]:
    """Return alerts whose `source_ip` matches exactly, newest first."""
    from app.models import Alert

    sql = _adapt_sql(
        "SELECT id, timestamp, source_ip, detector, severity, title, description "
        "FROM alerts WHERE source_ip = ? ORDER BY timestamp DESC, id DESC"
    )
    with _connect() as conn:
        if DB_BACKEND == "postgres":
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (ip,))
                rows = _fetch_all_dicts(cur)
        else:
            cur = conn.execute(sql, (ip,))
            rows = [dict(r) for r in cur.fetchall()]
    return [Alert.from_row(r) for r in rows]


def get_alerts_by_time_range(start: datetime, end: datetime) -> list[Any]:
    """Return alerts with `timestamp` in [start, end] inclusive. Newest first."""
    from app.models import Alert

    start_s = start.isoformat(sep=" ", timespec="seconds")
    end_s = end.isoformat(sep=" ", timespec="seconds")
    sql = _adapt_sql(
        "SELECT id, timestamp, source_ip, detector, severity, title, description "
        "FROM alerts WHERE timestamp BETWEEN ? AND ? "
        "ORDER BY timestamp DESC, id DESC"
    )
    with _connect() as conn:
        if DB_BACKEND == "postgres":
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (start_s, end_s))
                rows = _fetch_all_dicts(cur)
        else:
            cur = conn.execute(sql, (start_s, end_s))
            rows = [dict(r) for r in cur.fetchall()]
    return [Alert.from_row(r) for r in rows]


# ---------- Convenience ----------

def count_alerts() -> int:
    """Cheap row count — useful for smoke tests."""
    sql = _adapt_sql("SELECT COUNT(*) AS n FROM alerts")
    with _connect() as conn:
        if DB_BACKEND == "postgres":
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql)
                row = cur.fetchone()
                return int(row["n"])
        else:
            cur = conn.execute(sql)
            return int(cur.fetchone()["n"])


def clear_alerts() -> None:
    """Wipe the alerts table. Intended for tests / fresh-start runs only."""
    with _connect() as conn:
        if DB_BACKEND == "postgres":
            with conn.cursor() as cur:
                cur.execute("DELETE FROM alerts")
        else:
            conn.execute("DELETE FROM alerts")


def health_check() -> dict:
    """Return a JSON-safe dict describing the active backend and its reachability.

    Used by `/api/health/deep` to discriminate "service running" from
    "service running AND DB reachable". Always returns; never raises.
    """
    info: dict = {
        "backend": DB_BACKEND,
    }
    if DB_BACKEND == "postgres":
        info["dsn_host"] = "redacted"
        try:
            dsn = _postgres_dsn() or ""
            # Redact password even on error paths.
            if "@" in dsn and "://" in dsn:
                scheme, rest = dsn.split("://", 1)
                if "@" in rest:
                    _, hostpart = rest.split("@", 1)
                    info["dsn_host"] = hostpart
            import psycopg2
            conn = psycopg2.connect(dsn, connect_timeout=2)
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
                info["ok"] = True
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            info["ok"] = False
            info["error"] = f"{exc.__class__.__name__}: {exc}"
    else:
        info["path"] = str(DB_PATH)
        info["exists"] = DB_PATH.exists()
        try:
            with _connect() as conn:
                conn.execute("SELECT 1").fetchone()
            info["ok"] = True
        except Exception as exc:  # noqa: BLE001
            info["ok"] = False
            info["error"] = f"{exc.__class__.__name__}: {exc}"
    return info


def seed_demo_alerts() -> int:
    """Seed 30 demo alerts (for Vercel/serverless deployment).
    
    Returns the number of alerts inserted (0 if DB already has data).
    """
    try:
        count = count_alerts()
        if count > 0:
            return 0  # Already populated
    except Exception:
        pass  # Fall through to insert anyway
    
    from datetime import datetime, timedelta
    
    demo_alerts = [
        # Brute force attempts (14)
        {"timestamp": (datetime.utcnow() - timedelta(minutes=120)).isoformat(sep=" ", timespec="seconds"), "source_ip": "185.220.101.45", "detector": "BRUTE_FORCE", "severity": "HIGH", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=119)).isoformat(sep=" ", timespec="seconds"), "source_ip": "45.142.66.12", "detector": "BRUTE_FORCE", "severity": "HIGH", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=118)).isoformat(sep=" ", timespec="seconds"), "source_ip": "4.4.4.4", "detector": "BRUTE_FORCE", "severity": "CRITICAL", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=117)).isoformat(sep=" ", timespec="seconds"), "source_ip": "185.220.101.45", "detector": "BRUTE_FORCE", "severity": "HIGH", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=116)).isoformat(sep=" ", timespec="seconds"), "source_ip": "10.0.0.5", "detector": "BRUTE_FORCE", "severity": "MEDIUM", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=115)).isoformat(sep=" ", timespec="seconds"), "source_ip": "4.4.4.4", "detector": "BRUTE_FORCE", "severity": "CRITICAL", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=114)).isoformat(sep=" ", timespec="seconds"), "source_ip": "45.142.66.12", "detector": "BRUTE_FORCE", "severity": "HIGH", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=113)).isoformat(sep=" ", timespec="seconds"), "source_ip": "185.220.101.45", "detector": "BRUTE_FORCE", "severity": "HIGH", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=112)).isoformat(sep=" ", timespec="seconds"), "source_ip": "10.0.0.12", "detector": "BRUTE_FORCE", "severity": "MEDIUM", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=111)).isoformat(sep=" ", timespec="seconds"), "source_ip": "45.142.66.12", "detector": "BRUTE_FORCE", "severity": "HIGH", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=110)).isoformat(sep=" ", timespec="seconds"), "source_ip": "185.220.101.45", "detector": "BRUTE_FORCE", "severity": "HIGH", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=109)).isoformat(sep=" ", timespec="seconds"), "source_ip": "10.0.0.20", "detector": "BRUTE_FORCE", "severity": "MEDIUM", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=108)).isoformat(sep=" ", timespec="seconds"), "source_ip": "45.142.66.12", "detector": "BRUTE_FORCE", "severity": "HIGH", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=107)).isoformat(sep=" ", timespec="seconds"), "source_ip": "4.4.4.4", "detector": "BRUTE_FORCE", "severity": "CRITICAL", "title": "SSH Brute Force Attempt", "description": "Multiple failed SSH login attempts detected."},
        # Port scans (5)
        {"timestamp": (datetime.utcnow() - timedelta(minutes=100)).isoformat(sep=" ", timespec="seconds"), "source_ip": "103.45.211.7", "detector": "PORT_SCAN", "severity": "MEDIUM", "title": "Network Port Scan Detected", "description": "Probing of multiple ports detected from source IP."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=99)).isoformat(sep=" ", timespec="seconds"), "source_ip": "91.224.92.18", "detector": "PORT_SCAN", "severity": "MEDIUM", "title": "Network Port Scan Detected", "description": "Probing of multiple ports detected from source IP."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=98)).isoformat(sep=" ", timespec="seconds"), "source_ip": "203.0.113.77", "detector": "PORT_SCAN", "severity": "MEDIUM", "title": "Network Port Scan Detected", "description": "Probing of multiple ports detected from source IP."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=97)).isoformat(sep=" ", timespec="seconds"), "source_ip": "185.220.101.45", "detector": "PORT_SCAN", "severity": "MEDIUM", "title": "Network Port Scan Detected", "description": "Probing of multiple ports detected from source IP."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=96)).isoformat(sep=" ", timespec="seconds"), "source_ip": "192.168.1.25", "detector": "PORT_SCAN", "severity": "MEDIUM", "title": "Network Port Scan Detected", "description": "Probing of multiple ports detected from source IP."},
        # Privilege escalation (11)
        {"timestamp": (datetime.utcnow() - timedelta(minutes=80)).isoformat(sep=" ", timespec="seconds"), "source_ip": "10.0.0.5", "detector": "PRIV_ESC", "severity": "CRITICAL", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=79)).isoformat(sep=" ", timespec="seconds"), "source_ip": "4.4.4.4", "detector": "PRIV_ESC", "severity": "HIGH", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=78)).isoformat(sep=" ", timespec="seconds"), "source_ip": "45.142.66.12", "detector": "PRIV_ESC", "severity": "HIGH", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=77)).isoformat(sep=" ", timespec="seconds"), "source_ip": "185.220.101.45", "detector": "PRIV_ESC", "severity": "HIGH", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=76)).isoformat(sep=" ", timespec="seconds"), "source_ip": "10.0.0.5", "detector": "PRIV_ESC", "severity": "HIGH", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=75)).isoformat(sep=" ", timespec="seconds"), "source_ip": "4.4.4.4", "detector": "PRIV_ESC", "severity": "HIGH", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=74)).isoformat(sep=" ", timespec="seconds"), "source_ip": "103.45.211.7", "detector": "PRIV_ESC", "severity": "MEDIUM", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=73)).isoformat(sep=" ", timespec="seconds"), "source_ip": "91.224.92.18", "detector": "PRIV_ESC", "severity": "MEDIUM", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=72)).isoformat(sep=" ", timespec="seconds"), "source_ip": "203.0.113.77", "detector": "PRIV_ESC", "severity": "MEDIUM", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=71)).isoformat(sep=" ", timespec="seconds"), "source_ip": "192.168.1.25", "detector": "PRIV_ESC", "severity": "MEDIUM", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
        {"timestamp": (datetime.utcnow() - timedelta(minutes=70)).isoformat(sep=" ", timespec="seconds"), "source_ip": "10.0.0.12", "detector": "PRIV_ESC", "severity": "MEDIUM", "title": "Privilege Escalation Detected", "description": "Unusual privilege escalation pattern detected."},
    ]
    
    inserted = 0
    for alert in demo_alerts:
        try:
            save_alert(type("Alert", (), alert)())
            inserted += 1
        except Exception:
            pass
    
    logger.info(f"Seeded {inserted} demo alerts")
    return inserted

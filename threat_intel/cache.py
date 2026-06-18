"""
SOCshield - Threat-intel cache (SQLite + Postgres dual-backend).

Same dual-backend pattern as `database/db.py`:
    * If `DATABASE_URL` / `POSTGRES_URL` is set, use Postgres (Vercel/Neon).
    * Otherwise use SQLite at `SOCSHIELD_TI_CACHE_PATH` (local / Docker).

Public API:
    init_cache(), get(ip) -> dict|None, put(ip, payload, ttl_seconds=86400),
    clear(), health_check()

Schema (identical on both backends):
    ip           TEXT PRIMARY KEY
    payload      TEXT NOT NULL
    fetched_at   TEXT NOT NULL
    ttl_seconds  INTEGER NOT NULL
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger("socshield.ti_cache")

BASE_DIR: Path = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

_DEFAULT_CACHE = BASE_DIR / "threat_intel" / "cache.db"


# ---------- Backend detection ----------

def _postgres_dsn() -> str | None:
    dsn = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
    if dsn and dsn.strip():
        return dsn.strip()
    return None


def _is_postgres() -> bool:
    return _postgres_dsn() is not None


def _sqlite_path() -> Path:
    raw = os.environ.get("SOCSHIELD_TI_CACHE_PATH", str(_DEFAULT_CACHE))
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
        fallback = Path("/tmp/socshield/threat_intel_cache.db")
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


_CACHE_PATH: Path = _sqlite_path() if not _is_postgres() else None
CACHE_BACKEND = "postgres" if _is_postgres() else "sqlite"


def _adapt_sql(sql: str) -> str:
    if CACHE_BACKEND == "postgres":
        return sql.replace("?", "%s")
    return sql


@contextmanager
def _connect() -> Iterator[Any]:
    if CACHE_BACKEND == "postgres":
        import psycopg2
        import psycopg2.extras

        dsn = _postgres_dsn()
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
        conn = sqlite3.connect(str(_CACHE_PATH))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ---------- Schema ----------

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip           TEXT PRIMARY KEY,
    payload      TEXT NOT NULL,
    fetched_at   TEXT NOT NULL,
    ttl_seconds  INTEGER NOT NULL
);
"""

_POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip           TEXT PRIMARY KEY,
    payload      TEXT NOT NULL,
    fetched_at   TEXT NOT NULL,
    ttl_seconds  INTEGER NOT NULL
);
"""


def init_cache() -> None:
    if CACHE_BACKEND == "postgres":
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_POSTGRES_SCHEMA)
    else:
        with _connect() as conn:
            conn.executescript(_SQLITE_SCHEMA)


# ---------- Public API ----------

def get(ip: str) -> Optional[dict]:
    """Return the cached payload for `ip` if present and not expired, else None."""
    sql = _adapt_sql(
        "SELECT payload, fetched_at, ttl_seconds FROM threat_intel_cache WHERE ip = ?"
    )
    with _connect() as conn:
        if CACHE_BACKEND == "postgres":
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (ip,))
                row = cur.fetchone()
        else:
            cur = conn.execute(sql, (ip,))
            row = cur.fetchone()

    if row is None:
        return None

    if CACHE_BACKEND == "postgres":
        payload_str = row["payload"]
        fetched_at_str = row["fetched_at"]
        ttl = int(row["ttl_seconds"])
    else:
        payload_str = row["payload"]
        fetched_at_str = row["fetched_at"]
        ttl = int(row["ttl_seconds"])

    fetched_at = datetime.fromisoformat(fetched_at_str)
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    age_seconds = (now - fetched_at).total_seconds()
    if age_seconds >= ttl:
        return None

    return json.loads(payload_str)


def put(ip: str, payload: dict, ttl_seconds: int = 86400) -> None:
    """Upsert a payload for `ip` with the given TTL (default 24h)."""
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload_json = json.dumps(payload, separators=(",", ":"))

    if CACHE_BACKEND == "postgres":
        sql = (
            "INSERT INTO threat_intel_cache (ip, payload, fetched_at, ttl_seconds) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (ip) DO UPDATE SET "
            "  payload = EXCLUDED.payload, "
            "  fetched_at = EXCLUDED.fetched_at, "
            "  ttl_seconds = EXCLUDED.ttl_seconds"
        )
        params = (ip, payload_json, fetched_at, ttl_seconds)
    else:
        sql = (
            "INSERT INTO threat_intel_cache (ip, payload, fetched_at, ttl_seconds) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "  payload = excluded.payload, "
            "  fetched_at = excluded.fetched_at, "
            "  ttl_seconds = excluded.ttl_seconds"
        )
        params = (ip, payload_json, fetched_at, ttl_seconds)

    with _connect() as conn:
        if CACHE_BACKEND == "postgres":
            with conn.cursor() as cur:
                cur.execute(sql, params)
        else:
            conn.execute(sql, params)


def clear() -> None:
    """Wipe the cache table. Intended for tests / fresh-start runs only."""
    with _connect() as conn:
        if CACHE_BACKEND == "postgres":
            with conn.cursor() as cur:
                cur.execute("DELETE FROM threat_intel_cache")
        else:
            conn.execute("DELETE FROM threat_intel_cache")


def health_check() -> dict:
    """JSON-safe dict describing the cache backend reachability."""
    info: dict = {"backend": CACHE_BACKEND}
    if CACHE_BACKEND == "postgres":
        info["dsn_host"] = "redacted"
        try:
            dsn = _postgres_dsn() or ""
            if "@" in dsn and "://" in dsn:
                _, rest = dsn.split("://", 1)
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
        info["path"] = str(_CACHE_PATH) if _CACHE_PATH else None
        info["exists"] = _CACHE_PATH.exists() if _CACHE_PATH else False
        try:
            with _connect() as conn:
                conn.execute("SELECT 1").fetchone()
            info["ok"] = True
        except Exception as exc:  # noqa: BLE001
            info["ok"] = False
            info["error"] = f"{exc.__class__.__name__}: {exc}"
    return info

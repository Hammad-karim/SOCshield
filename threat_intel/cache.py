"""
SOCshield - SQLite-backed threat-intel cache.

Stores per-IP threat-intel payloads with a TTL so we don't hammer the
upstream provider for the same address on every check.

Schema is fixed by the project spec:
    ip           TEXT PRIMARY KEY
    payload      TEXT NOT NULL         (JSON-encoded dict)
    fetched_at   TEXT NOT NULL         (ISO-8601 UTC, seconds precision)
    ttl_seconds  INTEGER NOT NULL
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Repo root -> <repo>/threat_intel/cache.py -> parents[1] is the repo root.
# Ensure it's on sys.path so `from threat_intel.cache import ...` works
# regardless of where the interpreter was launched from.
BASE_DIR: Path = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Allow deployment to relocate the threat-intel cache via env (Docker volume).
_DEFAULT_CACHE = BASE_DIR / "threat_intel" / "cache.db"
_CACHE_PATH: Path = Path(os.environ.get("SOCSHIELD_TI_CACHE_PATH", str(_DEFAULT_CACHE))).resolve()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip           TEXT PRIMARY KEY,
    payload      TEXT NOT NULL,
    fetched_at   TEXT NOT NULL,
    ttl_seconds  INTEGER NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    """Open a SQLite connection with row dict access."""
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_CACHE_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_cache() -> None:
    """Create the cache table if it doesn't exist. Idempotent."""
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


def get(ip: str) -> Optional[dict]:
    """Return the cached payload for `ip` if present and not expired, else None."""
    with _connect() as conn:
        cur = conn.execute(
            "SELECT payload, fetched_at, ttl_seconds "
            "FROM threat_intel_cache WHERE ip = ?",
            (ip,),
        )
        row = cur.fetchone()

    if row is None:
        return None

    fetched_at = datetime.fromisoformat(row["fetched_at"])
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    age_seconds = (now - fetched_at).total_seconds()
    if age_seconds >= row["ttl_seconds"]:
        return None

    return json.loads(row["payload"])


def put(ip: str, payload: dict, ttl_seconds: int = 86400) -> None:
    """Upsert a payload for `ip` with the given TTL (default 24h)."""
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload_json = json.dumps(payload, separators=(",", ":"))

    with _connect() as conn:
        conn.execute(
            "INSERT INTO threat_intel_cache (ip, payload, fetched_at, ttl_seconds) "
            "VALUES (:ip, :payload, :fetched_at, :ttl_seconds) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "  payload = excluded.payload, "
            "  fetched_at = excluded.fetched_at, "
            "  ttl_seconds = excluded.ttl_seconds",
            {
                "ip": ip,
                "payload": payload_json,
                "fetched_at": fetched_at,
                "ttl_seconds": ttl_seconds,
            },
        )
        conn.commit()


def clear() -> None:
    """Wipe the cache table. Intended for tests / fresh-start runs only."""
    with _connect() as conn:
        conn.execute("DELETE FROM threat_intel_cache")
        conn.commit()

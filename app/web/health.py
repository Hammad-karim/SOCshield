"""
SOCshield - Runtime health registry.

The container / orchestrator needs a single, fast liveness + readiness
signal. This module is a tiny thread-safe singleton that the
monitoring service populates and the Flask routes expose via
`/api/health` and `/api/health/deep`.

Why not read from SQLite for the deep check? Because the deep check
must work even if the DB is the *thing* that's failing — the whole
point of `/health/deep` is to discriminate "service running" from
"service running AND DB reachable AND threat-intel reachable".

The registry never raises; it returns JSON-safe dicts.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Lazy imports — only resolved at call time so the module is cheap to import
# from the web layer even if the monitoring service hasn't started yet.

_startup_lock = threading.Lock()
_startup_at: float | None = None
_last_alert_at: float | None = None
_service_running: bool = False
_service_thread_alive: bool = False

# ---- Public API used by the service entrypoint -----------------


def mark_startup() -> None:
    """Called once by the service on boot."""
    global _startup_at, _service_running
    with _startup_lock:
        _startup_at = time.time()
        _service_running = True


def mark_alert() -> None:
    """Called for every persisted alert (best-effort)."""
    global _last_alert_at
    with _startup_lock:
        _last_alert_at = time.time()


def mark_service_thread(alive: bool) -> None:
    """Flip the service-thread heartbeat."""
    global _service_thread_alive
    with _startup_lock:
        _service_thread_alive = alive


def mark_shutdown() -> None:
    """Called on graceful shutdown."""
    global _service_running, _service_thread_alive
    with _startup_lock:
        _service_running = False
        _service_thread_alive = False


# ---- Health probes ---------------------------------------------


def _check_db() -> dict[str, Any]:
    """Open a short-lived connection (SQLite or Postgres) and SELECT 1.

    Returns ok/error. Uses the unified health_check() helper from the
    database module so the result includes the active backend
    (sqlite | postgres) — useful in Vercel where the dashboard runs
    on Postgres but operators may debug locally on SQLite.
    """
    from database import db as alerts_db

    return alerts_db.health_check()


def _check_threat_intel_cache() -> dict[str, Any]:
    """Check that the threat-intel cache backend is reachable."""
    from threat_intel import cache as ti_cache

    return ti_cache.health_check()


def _check_watcher_logs() -> dict[str, Any]:
    """Confirm the three watched log paths exist and are readable."""
    paths = {
        "auth":     os.environ.get("SOCSHIELD_AUTH_LOG"),
        "firewall": os.environ.get("SOCSHIELD_FIREWALL_LOG"),
        "priv":     os.environ.get("SOCSHIELD_PRIV_LOG"),
    }
    out: dict[str, Any] = {}
    for name, env_path in paths.items():
        # Fall back to the in-repo default if env not set.
        if not env_path:
            # Lazy import to avoid loading the watcher modules just for this.
            from app.watchers import auth_watcher, firewall_watcher, priv_watcher
            env_path = {
                "auth":     str(auth_watcher.LOG_PATH),
                "firewall": str(firewall_watcher.LOG_PATH),
                "priv":     str(priv_watcher.LOG_PATH),
            }[name]
        p = Path(env_path)
        entry: dict[str, Any] = {"path": str(p), "exists": p.exists()}
        if p.exists():
            try:
                with p.open("rb") as f:
                    f.read(1)
                entry["readable"] = True
            except OSError as exc:
                entry["readable"] = False
                entry["error"] = str(exc)
        out[name] = entry
    return out


def basic() -> dict[str, Any]:
    """Liveness probe. Always 200 unless the process is wedged."""
    now = datetime.now(timezone.utc)
    with _startup_lock:
        started = _startup_at
        last_alert = _last_alert_at
        service_running = _service_running
    return {
        "status": "ok",
        "timestamp": now.isoformat(timespec="seconds") + "Z",
        "uptime_seconds": round(time.time() - started, 1) if started else 0,
        "service_running": service_running,
        "last_alert_age_seconds": (
            round(time.time() - last_alert, 1) if last_alert else None
        ),
    }


def deep() -> dict[str, Any]:
    """Readiness probe. Returns ok=True only if every subsystem is healthy."""
    db_info = _check_db()
    ti_info = _check_threat_intel_cache()
    logs_info = _check_watcher_logs()

    components = {
        "database":        db_info.get("ok", False),
        "threat_intel":    ti_info.get("ok", False),
        "watcher_logs":    all(v.get("exists") for v in logs_info.values()),
        "service_running": _service_running,
    }
    overall_ok = all(components.values())
    with _startup_lock:
        last_alert = _last_alert_at
    return {
        "status": "ok" if overall_ok else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z",
        "components": components,
        "details": {
            "database":     db_info,
            "threat_intel": ti_info,
            "watcher_logs": logs_info,
        },
        "service_running":     _service_running,
        "service_thread_alive": _service_thread_alive,
        "last_alert_age_seconds": (
            round(time.time() - last_alert, 1) if last_alert else None
        ),
    }

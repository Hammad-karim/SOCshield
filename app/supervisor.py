"""
SOCshield - Production supervisor.

Runs the long-running monitoring service in a background thread and
the Flask dashboard in the foreground. This is the entry point used
by the container (`entrypoint.sh exec python -m app.supervisor`) and
the recommended way to deploy SOCshield in a single process.

Why a thread instead of two processes?
    * One PID = one container = one signal target. `docker stop` then
      sends SIGTERM to a single process and we shut down cleanly.
    * Shared memory: the dashboard and the service share the health
      registry, the event bus, and the DB connection pool.
    * The Flask app can serve `/api/summary` and `/api/health/deep`
      with live data the service is producing in the same process.

Failure handling:
    * If the service thread dies, the dashboard keeps running so the
      operator can see the health endpoint reflect the degradation.
    * If the Flask app dies, the supervisor exits non-zero and the
      container restarts (Docker's restart policy).

This module does NOT modify detection or correlation logic — it's a
deployment wiring layer.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure the repo root is on sys.path regardless of CWD.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _setup_logging() -> logging.Logger:
    """One logger, file + console, plain text. Idempotent."""
    LOGS_DIR = Path(os.environ.get("SOCSHIELD_LOGS_DIR", str(_REPO_ROOT / "logs"))).resolve()
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("socshield.supervisor")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.handlers.RotatingFileHandler(
        str(LOGS_DIR / "supervisor.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.propagate = False
    return logger


# A custom signal the supervisor uses to ask the service thread to stop.
# The event bus has its own stop() method; we trigger it via an attribute
# on the running service (None if not yet started).
class _ServiceHandle:
    """Lightweight handle to the running service for signal handling."""

    def __init__(self) -> None:
        self.run_fn = None  # bound run_service()
        self.thread: threading.Thread | None = None
        self.alive = threading.Event()

    def request_stop(self) -> None:
        """Send SIGTERM-equivalent to the service thread.

        The service installs its own signal handlers in run_service();
        for the in-process model we just set a flag the main loop polls
        via a small shim.
        """
        self.alive.clear()


def _run_service_thread(handle: _ServiceHandle, logger: logging.Logger) -> None:
    """Run the monitoring service in this thread."""
    from app.service import run_service  # local import to avoid startup cost

    handle.alive.set()
    try:
        # run_service() takes a stop_after_seconds; instead we let the
        # supervisor's signal handler call handle.request_stop(), but
        # run_service's existing loop doesn't observe it. We use a
        # tiny monkey-patch: register a thread-safe stop callback via
        # the bus. Simplest path: re-implement the same loop using the
        # existing service helpers but with our own stop event.
        _run_service_with_handle(handle, logger)
    except Exception:  # noqa: BLE001
        logger.exception("service thread crashed")
    finally:
        handle.alive.clear()
        try:
            from app.web.health import mark_service_thread, mark_shutdown
            mark_service_thread(False)
            mark_shutdown()
        except Exception:
            pass


def _run_service_with_handle(handle: _ServiceHandle, logger: logging.Logger) -> None:
    """Re-implements run_service()'s main loop but honors handle.alive.

    We can't trivially share signal handlers between the service and
    the dashboard thread, so we duplicate the wire-up here with a
    shared stop event.
    """
    from database import db as alerts_db
    from app.event_bus import EventBus, INCIDENT_CREATED, INCIDENT_UPDATED
    from app.metrics_engine import MetricsEngine, format_snapshot_line
    from app.correlator import ContinuousCorrelator
    from app.watchers.auth_watcher import build_watcher as build_auth
    from app.watchers.firewall_watcher import build_watcher as build_fw
    from app.watchers.priv_watcher import build_watcher as build_priv

    # Best-effort DB init (the dashboard also init_db()s on app create).
    try:
        alerts_db.init_db()
    except Exception:
        logger.exception("DB init failed — continuing in dry-run mode")

    bus = EventBus()
    metrics = MetricsEngine()
    correlator = ContinuousCorrelator(bus=bus, metrics=metrics)

    # Incident logger
    def _on_incident(event) -> None:
        p = event.payload
        ip = getattr(p, "source_ip", None) or (p.get("source_ip") if isinstance(p, dict) else "?")
        rule = getattr(p, "rule_id", None) or (p.get("rule_id") if isinstance(p, dict) else "?")
        risk = getattr(p, "risk", None) or (p.get("risk") if isinstance(p, dict) else "?")
        logger.info("[%s] ip=%s rule=%s risk=%s", event.topic, ip, rule, risk)

    bus.subscribe(INCIDENT_CREATED, _on_incident)
    bus.subscribe(INCIDENT_UPDATED, _on_incident)

    # DB persister + alert heartbeat
    from app.event_bus import NEW_ALERT

    def _on_alert(event) -> None:
        payload = event.payload
        alert = payload.get("alert") if isinstance(payload, dict) else payload
        if alert is None:
            return
        try:
            alerts_db.save_alert(alert)
        except Exception:
            logger.exception("DB persist failed for alert %r", alert)
        else:
            try:
                from app.web.health import mark_alert
                mark_alert()
            except Exception:
                pass

    bus.subscribe(NEW_ALERT, _on_alert)

    correlator.start()
    bus.start()

    watchers = [build_auth(bus), build_fw(bus), build_priv(bus)]
    for w in watchers:
        logger.info("starting watcher %s on %s", w.name, w.path)
        w.start()

    logger.info("service thread running")
    started_at = datetime.now(timezone.utc)
    last_print = 0.0
    metrics_interval = 5.0

    try:
        while handle.alive.is_set():
            now = time.monotonic()
            if now - last_print >= metrics_interval:
                snap = metrics.snapshot()
                logger.info("metrics %s", format_snapshot_line(snap))
                last_print = now
            handle.alive.wait(timeout=0.5)
    finally:
        logger.info("stopping watchers...")
        for w in watchers:
            w.stop()
        for w in watchers:
            w.join(timeout=3.0)
        logger.info("stopping event bus...")
        bus.stop(timeout=3.0)
        runtime = (datetime.now(timezone.utc) - started_at).total_seconds()
        logger.info("service thread exited after %.1fs", runtime)


def main() -> int:
    logger = _setup_logging()
    logger.info("=== SOCshield supervisor starting ===")
    logger.info("Python: %s", sys.version.split()[0])
    logger.info("CWD: %s", os.getcwd())
    logger.info("Repo: %s", _REPO_ROOT)
    logger.info("DB:  %s", os.environ.get("SOCSHIELD_DB_PATH", "<default>"))
    logger.info("TI:   %s", os.environ.get("SOCSHIELD_TI_CACHE_PATH", "<default>"))
    logger.info("Reports: %s", os.environ.get("SOCSHIELD_REPORTS_DIR", "<default>"))
    logger.info("Logs:    %s", os.environ.get("SOCSHIELD_LOGS_DIR", "<default>"))

    # ---- Sanity: init the DB on the main thread (race-free) ----
    try:
        from database import db as alerts_db
        from threat_intel import cache as ti_cache
        alerts_db.init_db()
        ti_cache.init_cache()
        logger.info("database initialized: %s", alerts_db.DB_PATH)
    except Exception:
        logger.exception("database initialization failed")
        return 1

    # ---- Start the monitoring service in a background thread ----
    handle = _ServiceHandle()
    svc_thread = threading.Thread(
        target=_run_service_thread,
        args=(handle, logger),
        name="socshield-monitor",
        daemon=True,
    )
    svc_thread.start()
    handle.thread = svc_thread
    logger.info("monitor thread started (tid=%s)", svc_thread.ident)

    # ---- Signal handling — stop service then exit dashboard ----
    stop_requested = threading.Event()

    def _request_stop(signum, frame) -> None:  # noqa: ARG001
        logger.info("received signal %d — initiating graceful shutdown", signum)
        stop_requested.set()
        handle.request_stop()

    try:
        signal.signal(signal.SIGINT, _request_stop)
        signal.signal(signal.SIGTERM, _request_stop)
    except ValueError:
        # signal only works in main thread; we are, so this is unexpected
        logger.warning("could not install signal handlers")

    # ---- Start the Flask dashboard (blocks) ----
    from app.web import create_app
    flask_app = create_app()
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"

    logger.info("dashboard listening on http://%s:%d/ (debug=%s)", host, port, debug)

    # Use Flask's built-in server (dev). In production a real WSGI server
    # (gunicorn / uwsgi) should be placed behind a reverse proxy. The
    # image installs gunicorn and the entrypoint can be told to use it
    # via SOCSHIELD_SERVER=gunicorn.
    server_kind = os.environ.get("SOCSHIELD_SERVER", "flask").lower()

    try:
        if server_kind == "gunicorn":
            from gunicorn.app.wsgiapp import WSGIApplication
            gunicorn_app = WSGIApplication()
            gunicorn_app.load_wsgiapp = lambda: flask_app
            # Bind / workers via the gunicorn command-line semantics
            gunicorn_app.cfg.set("bind", f"{host}:{port}")
            gunicorn_app.cfg.set("workers", int(os.environ.get("GUNICORN_WORKERS", "2")))
            gunicorn_app.cfg.set("threads", int(os.environ.get("GUNICORN_THREADS", "4")))
            gunicorn_app.cfg.set("timeout", int(os.environ.get("GUNICORN_TIMEOUT", "60")))
            gunicorn_app.cfg.set("accesslog", "-")
            gunicorn_app.cfg.set("errorlog",  "-")
            gunicorn_app.run()
        else:
            # werkzeug-serving app.run() blocks until SIGTERM. We use
            # threaded=True so the in-process service thread continues
            # to run; the reloader is off in production.
            flask_app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt — shutting down")
    finally:
        logger.info("stopping service thread...")
        handle.request_stop()
        svc_thread.join(timeout=5.0)
        if svc_thread.is_alive():
            logger.warning("service thread did not exit cleanly")
        logger.info("=== SOCshield supervisor stopped ===")

    return 0


if __name__ == "__main__":
    sys.exit(main())

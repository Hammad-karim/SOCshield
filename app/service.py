"""
SOCshield - Long-running service mode

Wires the runtime pieces together:

    log files -> watchers -> event bus -> continuous correlator -> metrics
                                          |
                                          v
                                    incident updates

Run via `python main.py --service` or directly `python -m app.service`.
Stops on SIGINT / SIGTERM, or after `stop_after_seconds` (used by tests).

The batch pipeline (orchestrator + reports + MITRE coverage) is NOT
invoked here — service mode focuses on streaming detection only.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure repo root on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from database import db as alerts_db  # noqa: E402
from app.event_bus import EventBus, INCIDENT_CREATED, INCIDENT_UPDATED  # noqa: E402
from app.metrics_engine import MetricsEngine, format_snapshot_line  # noqa: E402
from app.correlator import ContinuousCorrelator  # noqa: E402
from app.watchers.auth_watcher import build_watcher as build_auth  # noqa: E402
from app.watchers.firewall_watcher import build_watcher as build_fw  # noqa: E402
from app.watchers.priv_watcher import build_watcher as build_priv  # noqa: E402

# Logs directory is env-overridable (Docker volume mount).
LOGS_DIR = Path(os.environ.get("SOCSHIELD_LOGS_DIR", str(_REPO_ROOT / "logs"))).resolve()
SERVICE_LOG_PATH = LOGS_DIR / "service.log"


def _setup_logging() -> logging.Logger:
    """File + console logger. Idempotent (safe to call from main() too)."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("socshield.service")
    if logger.handlers:
        return logger  # already configured
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.handlers.RotatingFileHandler(
        str(SERVICE_LOG_PATH), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.propagate = False
    return logger


def _setup_structured_logging() -> logging.Logger:
    """JSON-line structured logger for containerized execution.

    Emits one JSON object per line to stdout (12-factor app convention).
    Falls back silently if the json module is unavailable (it never is
    in Python 3.12 — defensive only).
    """
    import json
    import io

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("socshield.events")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:  # noqa: D401
            payload = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z",
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)
            return json.dumps(payload, separators=(",", ":"))

    sh = logging.StreamHandler(io.StringIO())  # type: ignore[arg-type]
    # We want to write to actual stdout, not an in-memory buffer; replace.
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(_JsonFormatter())
    logger.addHandler(sh)
    logger.propagate = False
    return logger


def _wire_incident_logger(bus: EventBus, logger: logging.Logger) -> None:
    """Subscribe a console+file logger for INCIDENT_* events."""

    def _on(event) -> None:
        p = event.payload if not isinstance(event.payload, dict) else event.payload
        topic = event.topic
        ip = getattr(p, "source_ip", None) or (p.get("source_ip") if isinstance(p, dict) else "?")
        rule = getattr(p, "rule_id", None) or (p.get("rule_id") if isinstance(p, dict) else "?")
        risk = getattr(p, "risk", None) or (p.get("risk") if isinstance(p, dict) else "?")
        logger.info("[%s] %s ip=%s rule=%s risk=%s", topic, topic, ip, rule, risk)

    bus.subscribe(INCIDENT_CREATED, _on)
    bus.subscribe(INCIDENT_UPDATED, _on)


def _wire_db_persister(bus: EventBus, logger: logging.Logger) -> None:
    """Persist every NEW_ALERT to the SQLite store."""
    from app.event_bus import NEW_ALERT

    def _on(event) -> None:
        payload = event.payload
        # Watchers publish the Alert directly; correlator may publish a dict.
        alert = payload.get("alert") if isinstance(payload, dict) else payload
        if alert is None:
            return
        try:
            alerts_db.save_alert(alert)
        except Exception:
            logger.exception("DB persist failed for alert %r", alert)
        else:
            # Update the runtime health registry (best-effort; never raises).
            try:
                from app.web.health import mark_alert
                mark_alert()
            except Exception:
                pass

    bus.subscribe(NEW_ALERT, _on)


def run_service(stop_after_seconds: float | None = None) -> int:
    """Start the real-time monitoring service. Returns a POSIX exit code."""
    logger = _setup_logging()
    logger.info("=== SOCshield service starting ===")

    # Runtime health registry — best-effort; the web layer is optional in
    # service-only deployments.
    try:
        from app.web.health import mark_service_thread, mark_startup
        mark_startup()
        mark_service_thread(True)
    except Exception:
        logger.debug("health registry unavailable", exc_info=True)

    # 1. Storage
    try:
        alerts_db.init_db()
    except Exception:
        logger.exception("DB init failed — continuing in dry-run mode")

    # 2. Runtime primitives
    bus = EventBus()
    metrics = MetricsEngine()
    correlator = ContinuousCorrelator(bus=bus, metrics=metrics)

    # Wire incident-event logging AND the DB persister BEFORE we start the bus.
    _wire_incident_logger(bus, logger)
    _wire_db_persister(bus, logger)

    # 3. Correlator subscribes to NEW_ALERT
    correlator.start()

    # 4. Start the bus dispatcher threads
    bus.start()

    # 5. Start the three log watchers
    watchers = [
        build_auth(bus),
        build_fw(bus),
        build_priv(bus),
    ]
    for w in watchers:
        logger.info("starting watcher %s on %s", w.name, w.path)
        w.start()

    # 6. Signal handling
    stop_event = threading.Event()

    def _request_stop(signum, frame):  # noqa: ARG001
        logger.info("received signal %d — initiating graceful shutdown", signum)
        stop_event.set()

    try:
        signal.signal(signal.SIGINT, _request_stop)
        signal.signal(signal.SIGTERM, _request_stop)
    except ValueError:
        # signal can only be installed from main thread; ignore in tests
        pass

    # Optional auto-stop for tests
    if stop_after_seconds is not None and stop_after_seconds > 0:
        def _auto_stop():
            time.sleep(stop_after_seconds)
            logger.info("auto-stop after %.1fs", stop_after_seconds)
            stop_event.set()
        threading.Thread(target=_auto_stop, name="auto-stop", daemon=True).start()

    # 7. Main loop: print metrics periodically + wait for stop
    metrics_interval = 5.0
    last_print = 0.0
    started_at = datetime.now(timezone.utc)
    logger.info("service running — Ctrl-C to stop")

    try:
        while not stop_event.is_set():
            now = time.monotonic()
            if now - last_print >= metrics_interval:
                snap = metrics.snapshot()
                logger.info("metrics %s", format_snapshot_line(snap))
                last_print = now
            stop_event.wait(timeout=0.5)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt — initiating graceful shutdown")
        stop_event.set()

    # 8. Graceful shutdown
    logger.info("stopping watchers...")
    for w in watchers:
        w.stop()
    for w in watchers:
        w.join(timeout=3.0)

    logger.info("stopping event bus...")
    bus.stop(timeout=3.0)

    # Mark the service thread as exited in the health registry.
    try:
        from app.web.health import mark_service_thread, mark_shutdown
        mark_service_thread(False)
        mark_shutdown()
    except Exception:
        pass

    runtime = (datetime.now(timezone.utc) - started_at).total_seconds()
    final = metrics.snapshot()
    logger.info("=== SOCshield service stopped after %.1fs ===", runtime)
    logger.info("final metrics %s", format_snapshot_line(final))

    return 0


if __name__ == "__main__":
    sys.exit(run_service())

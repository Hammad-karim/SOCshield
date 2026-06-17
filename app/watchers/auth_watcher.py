"""
SOCshield - Auth Watcher

Tails the auth log file, hands new lines to the brute-force detector
(`detectors.brute_force_detector`), and publishes any resulting `Alert`
objects on the supplied event bus.

Design notes
------------
The detector's `parse_attempts(path)` reads from a file path. The watcher
receives already-buffered complete lines from `TailWatcher`, so we write
those lines to a small scratch file and let the detector parse them with
its existing logic. This avoids re-implementing the regex parser and keeps
the watcher as a thin adapter.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

# Ensure repo root on sys.path so `from detectors.*` resolves when this
# module is executed directly (e.g., `python -m app.watchers.auth_watcher`).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.models import Alert  # noqa: E402
from app.watchers.base import TailWatcher  # noqa: E402
from detectors import brute_force_detector  # noqa: E402

logger = logging.getLogger(__name__)

# Path resolution: env override (SOCSHIELD_AUTH_LOG) > in-repo default.
LOG_PATH = Path(
    os.environ.get(
        "SOCSHIELD_AUTH_LOG",
        str(Path(_REPO_ROOT) / "logs" / "auth.log"),
    )
).resolve()


def _write_scratch(lines: list[str]) -> Path:
    """Materialize the in-memory line buffer to a temp file for the detector.

    Using NamedTemporaryFile(delete=False) so the detector can open the path
    on its own; we unlink after use.
    """
    fd, name = tempfile.mkstemp(prefix="socshield_auth_", suffix=".log")
    try:
        with open(fd, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line)
                if not line.endswith("\n"):
                    f.write("\n")
    except Exception:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


class AuthWatcher(TailWatcher):
    """TailWatcher subclass that reuses the brute-force detector."""

    def process_lines(self, lines: list[str]) -> list[Alert]:
        scratch = _write_scratch(lines)
        try:
            attempts = brute_force_detector.parse_attempts(scratch)
            alerts = brute_force_detector.detect_brute_force(attempts)
        finally:
            scratch.unlink(missing_ok=True)

        logger.debug(
            "auth_watcher: %d line(s) -> %d attempt(s) -> %d alert(s)",
            len(lines), len(attempts), len(alerts),
        )
        return alerts


def build_watcher(bus: Any) -> AuthWatcher:
    """Factory: build an AuthWatcher wired to the SOCshield event bus."""
    return AuthWatcher(
        name="auth-watcher",
        path=LOG_PATH,
        process_lines=AuthWatcher.process_lines,  # bound at instantiation
        poll_interval=1.0,
        bus=bus,
    )


# ---------- Self-test ---------- #

if __name__ == "__main__":
    import time

    from app.event_bus import EventBus, NEW_ALERT

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    bus = EventBus()
    received: list[Any] = []

    def on_alert(event):
        received.append(event)
        logger.info("BUS[%s] %s", event.topic, event.payload.get("title"))

    bus.subscribe(NEW_ALERT, on_alert)
    bus.start()

    # Seek to EOF *before* starting so the watcher only sees lines written
    # during this self-test (avoids re-emitting historical alerts on first
    # poll, which would break the "exactly 1 new alert" assertion).
    try:
        eof_offset = LOG_PATH.stat().st_size
    except FileNotFoundError:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        LOG_PATH.write_text("", encoding="utf-8")
        eof_offset = 0

    watcher = AuthWatcher(
        name="auth-watcher-selftest",
        path=LOG_PATH,
        process_lines=AuthWatcher.process_lines,
        poll_interval=0.2,
        bus=bus,
    )
    watcher.offset = eof_offset
    watcher.start()

    # Brief settle so any startup race is done.
    time.sleep(0.5)
    pre_count = len(received)
    logger.info("baseline alerts consumed = %d", pre_count)

    # Append a single new line that the brute-force detector will key off.
    # Use a never-before-seen IP so the alert is unambiguously new.
    new_line = (
        "2026-06-17 23:59:59 WARN  auth    Failed login attempt "
        "user=watchertest ip=203.0.113.77\n"
    )
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(new_line)
    logger.info("appended 1 line to %s", LOG_PATH)

    # Wait 2s as required by the spec.
    time.sleep(2.0)
    post_count = len(received)
    delta = post_count - pre_count
    logger.info("post-append alerts consumed = %d (delta=%d)", post_count, delta)

    watcher.stop()
    watcher.join(timeout=2.0)
    bus.stop()

    assert delta == 1, f"expected exactly 1 new alert, got {delta}"
    print(f"SELFTEST_OK delta={delta}")

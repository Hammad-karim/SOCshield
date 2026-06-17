"""
SOCshield - Privilege Escalation Watcher

Tails the priv log file, hands new lines to the privilege-escalation
detector (`detectors.priv_esc_detector`), and publishes any resulting
`Alert` objects on the supplied event bus.

Reuses the detector's `parse_signals` + `correlate` functions so the
real-time path produces identical alerts to the batch path.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

# Ensure repo root on sys.path so `from detectors.*` resolves when this
# module is executed directly (e.g., `python -m app.watchers.priv_watcher`).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.models import Alert  # noqa: E402
from app.watchers.base import TailWatcher  # noqa: E402
from detectors import priv_esc_detector  # noqa: E402

logger = logging.getLogger(__name__)

# Path resolution: env override (SOCSHIELD_PRIV_LOG) > in-repo default.
LOG_PATH = Path(
    os.environ.get(
        "SOCSHIELD_PRIV_LOG",
        str(Path(_REPO_ROOT) / "logs" / "priv.log"),
    )
).resolve()


def _write_scratch(lines: list[str]) -> Path:
    """Materialize the in-memory line buffer to a temp file for the detector.

    `parse_signals` opens the path directly; we hand it a real file on disk.
    """
    fd, name = tempfile.mkstemp(prefix="socshield_priv_", suffix=".log")
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


class PrivWatcher(TailWatcher):
    """TailWatcher subclass that reuses the privilege-escalation detector."""

    def process_lines(self, lines: list[str]) -> list[Alert]:
        scratch = _write_scratch(lines)
        try:
            signals = priv_esc_detector.parse_signals(scratch)
            alerts = priv_esc_detector.correlate(signals)
        finally:
            scratch.unlink(missing_ok=True)

        logger.debug(
            "priv_watcher: %d line(s) -> %d signal(s) -> %d alert(s)",
            len(lines), len(signals), len(alerts),
        )
        return alerts


def build_watcher(bus: Any) -> PrivWatcher:
    """Factory: build a PrivWatcher wired to the SOCshield event bus."""
    return PrivWatcher(
        name="priv-watcher",
        path=LOG_PATH,
        process_lines=PrivWatcher.process_lines,
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

    bus.subscribe(NEW_ALERT, on_alert)
    bus.start()

    try:
        eof_offset = LOG_PATH.stat().st_size
    except FileNotFoundError:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        LOG_PATH.write_text("", encoding="utf-8")
        eof_offset = 0

    watcher = PrivWatcher(
        name="priv-watcher-selftest",
        path=LOG_PATH,
        process_lines=PrivWatcher.process_lines,
        poll_interval=0.2,
        bus=bus,
    )
    watcher.offset = eof_offset
    watcher.start()

    time.sleep(0.5)
    pre_count = len(received)
    logger.info("baseline alerts consumed = %d", pre_count)

    # Append a single `sudo su` line for a fresh user — PrivEsc detector
    # has no threshold on `SUDO_SHELL` so this single line fires 1 alert.
    new_line = (
        "2026-06-17 23:59:59 INFO  priv  Command executed "
        "user=watchertest cmd=\"sudo su\" ip=203.0.113.77\n"
    )
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(new_line)
    logger.info("appended 1 line to %s", LOG_PATH)

    time.sleep(2.0)
    post_count = len(received)
    delta = post_count - pre_count
    logger.info("post-append alerts consumed = %d (delta=%d)", post_count, delta)

    watcher.stop()
    watcher.join(timeout=2.0)
    bus.stop()

    assert delta == 1, f"expected exactly 1 new alert, got {delta}"
    print(f"SELFTEST_OK delta={delta}")

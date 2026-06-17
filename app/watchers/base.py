"""Base TailWatcher implementation for SOCshield log watchers.

Provides TailWatcher, a threading.Thread subclass that tails a file, buffers
partial lines across ticks, and emits Alert objects via an optional bus.
"""

import logging
import sys
import threading
import time
from pathlib import Path

# Ensure repo root on sys.path so `app.*` imports resolve when this module
# is executed directly (e.g., `python -m app.watchers.base`).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

logger = logging.getLogger(__name__)


class TailWatcher(threading.Thread):
    """Tail a file and emit Alerts for each completed line."""

    def __init__(
        self,
        name: str,
        path: Path,
        process_lines,
        poll_interval: float = 1.0,
        bus=None,
        start_from_eof: bool = True,
    ):
        super().__init__(name=name, daemon=True)
        self.name = name
        self.path = Path(path)
        self.process_lines = process_lines
        self.poll_interval = poll_interval
        self.bus = bus
        self.start_from_eof = start_from_eof

        self._stop_event = threading.Event()
        self._buffer = ""
        # Default to 0; if `start_from_eof` is set, the run loop will seek
        # to the current end-of-file on the first iteration before reading.
        self.offset = 0
        self._lock = threading.Lock()
        self._initialised = False

    def stop(self) -> None:
        """Signal the run loop to exit at the next opportunity."""
        self._stop_event.set()

    def _emit_alerts(self, alerts):
        """Publish alerts on the bus if provided, returning the list unchanged."""
        if not alerts:
            return alerts
        if self.bus is not None:
            # Lazy import so this base module stays independent of the bus.
            try:
                from app.event_bus import NEW_ALERT  # type: ignore
            except Exception:
                NEW_ALERT = "NEW_ALERT"
            for alert in alerts:
                try:
                    self.bus.publish(NEW_ALERT, alert)
                except Exception:
                    logger.exception("failed to publish alert on bus")
        return alerts

    def _process_complete(self, lines):
        """Dispatch to the subclass method, binding self correctly.

        Subclasses override `process_lines(self, lines)` as a regular method.
        Look it up via the class (not the instance attribute) so descriptor
        binding produces a bound method — this lets subclasses be passed in
        by reference (`ClassName.process_lines`) without losing `self`.
        """
        method = getattr(type(self), "process_lines", None)
        if method is None:
            # Fallback to the instance attribute (e.g. callable passed in)
            fn = self.process_lines
            return fn(lines)
        return method(self, lines)

    def run(self) -> None:
        """Main loop: stat, read, split, process, emit."""
        while not self._stop_event.is_set():
            try:
                # 1. Stat the file to detect size changes (incl. rotations).
                try:
                    size = self.path.stat().st_size
                except FileNotFoundError:
                    logger.debug("file not found yet: %s", self.path)
                    self._sleep()
                    continue
                except OSError:
                    logger.exception("stat failed for %s", self.path)
                    self._sleep()
                    continue

                # First iteration: if start_from_eof, seek to current EOF so we
                # never replay historical content. This makes the service safe
                # to (re)start without flooding the bus with old alerts.
                if not self._initialised:
                    self._initialised = True
                    if self.start_from_eof:
                        self.offset = size
                        logger.info(
                            "%s: starting at EOF (offset=%d) for %s",
                            self.name, self.offset, self.path,
                        )

                # 2. Rotation detection: file shrank beneath our last offset.
                if size < self.offset:
                    logger.info("rotation detected for %s (size=%d, offset=%d)",
                                self.path, size, self.offset)
                    self.offset = 0
                    self._buffer = ""

                # 3. Read new bytes from the last offset to EOF.
                if size > self.offset:
                    try:
                        with self.path.open("r", encoding="utf-8") as f:
                            f.seek(self.offset)
                            chunk = f.read(size - self.offset)
                    except OSError:
                        logger.exception("read failed for %s", self.path)
                        self._sleep()
                        continue

                    if chunk:
                        self._buffer += chunk

                    # 4. Split on newline; emit only fully-terminated lines.
                    if "\n" in self._buffer:
                        lines = self._buffer.split("\n")
                        # Last element is whatever follows the final newline
                        # (possibly '' at true EOF, or a partial line).
                        self._buffer = lines[-1]
                        complete = [ln for ln in lines[:-1] if ln != ""]
                        if complete:
                            try:
                                alerts = self._process_complete(complete)
                            except Exception:
                                logger.exception(
                                    "process_lines raised on %s", self.path
                                )
                                alerts = []
                            if alerts:
                                self._emit_alerts(alerts)
                            # Advance offset by the bytes consumed for these lines.
                            consumed = sum(
                                len(ln.encode("utf-8")) + 1 for ln in complete
                            )
                            self.offset += consumed

                self._sleep()
            except Exception:
                # Robust to unexpected errors: log and continue the loop.
                logger.exception("unexpected error in watcher loop for %s",
                                 self.path)
                self._sleep()

    def _sleep(self) -> None:
        """Interruptible sleep honoring the stop event."""
        self._stop_event.wait(self.poll_interval)


if __name__ == "__main__":
    import os
    import tempfile

    # Minimal stand-in for Alert so we don't require the full app imports.
    class Alert:
        def __init__(self, line: str):
            self.line = line

        def __repr__(self):
            return f"Alert({self.line!r})"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    def process_lines(lines):
        return [Alert(ln) for ln in lines]

    # Create a temp file with 3 lines.
    fd, tmp_name = tempfile.mkstemp(prefix="socshield_tail_", suffix=".log")
    os.close(fd)
    tmp_path = Path(tmp_name)

    initial = "first\nsecond\nthird\n"
    tmp_path.write_text(initial, encoding="utf-8")

    seen = []
    seen_lock = threading.Lock()

    def collect(lines):
        with seen_lock:
            seen.extend(lines)
        return [Alert(ln) for ln in lines]

    watcher = TailWatcher(
        name="selftest",
        path=tmp_path,
        process_lines=collect,
        poll_interval=0.1,
        bus=None,
    )

    watcher.start()
    # Give the watcher a few polls to consume the 3 lines.
    deadline = time.time() + 3.0
    while time.time() < deadline:
        with seen_lock:
            if len(seen) >= 3:
                break
        time.sleep(0.05)

    watcher.stop()
    watcher.join(timeout=2.0)

    print(f"lines_processed={len(seen)}")
    print(f"lines={seen}")
    assert len(seen) >= 3, f"expected >=3 lines, got {len(seen)}"

    # Test rotation: append a 4th line, then truncate/recreate smaller.
    with tmp_path.open("a", encoding="utf-8") as f:
        f.write("fourth\n")

    seen.clear()
    watcher2 = TailWatcher(
        name="selftest2",
        path=tmp_path,
        process_lines=collect,
        poll_interval=0.1,
        bus=None,
    )
    watcher2.start()
    deadline = time.time() + 2.0
    while time.time() < deadline:
        with seen_lock:
            if "fourth" in seen:
                break
        time.sleep(0.05)
    watcher2.stop()
    watcher2.join(timeout=2.0)

    print(f"after_append_lines={seen}")
    assert "fourth" in seen, "expected 'fourth' line after append"

    # Cleanup.
    try:
        tmp_path.unlink()
    except OSError:
        pass

    print("SELFTEST_OK")
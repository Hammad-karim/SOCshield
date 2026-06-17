"""Synchronous pub/sub event bus with per-subscriber dispatcher threads."""

import os
import sys
import queue
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Tuple

# Ensure repo root on sys.path so `from app.event_bus import ...` works
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

logger = logging.getLogger(__name__)

# Topic constants
NEW_ALERT = "NEW_ALERT"
INCIDENT_CREATED = "INCIDENT_CREATED"
INCIDENT_UPDATED = "INCIDENT_UPDATED"


@dataclass
class Event:
    topic: str
    payload: Any
    timestamp: str  # ISO 8601


class _Subscriber:
    __slots__ = ("topic", "handler", "queue", "thread", "stop_event")

    def __init__(self, topic: str, handler: Callable[[Event], None]):
        self.topic = topic
        self.handler = handler
        self.queue: "queue.Queue[Event]" = queue.Queue(maxsize=10000)
        self.stop_event = threading.Event()
        self.thread: threading.Thread = None  # type: ignore[assignment]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: List[_Subscriber] = []
        self._lock = threading.Lock()
        self._started = False

    def subscribe(self, topic: str, handler: Callable[[Event], None]) -> None:
        sub = _Subscriber(topic, handler)
        with self._lock:
            if self._started:
                self._start_subscriber(sub)
            self._subscribers.append(sub)

    def publish(self, topic: str, payload: Any) -> None:
        event = Event(topic=topic, payload=payload, timestamp=datetime.now(timezone.utc).isoformat())
        with self._lock:
            subs = [s for s in self._subscribers if s.topic == topic]
        for sub in subs:
            # Non-blocking; drop on full queue
            try:
                sub.queue.put_nowait(event)
            except queue.Full:
                logger.error("Event queue full for subscriber on topic %s; dropping event", topic)

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            for sub in self._subscribers:
                self._start_subscriber(sub)
            self._started = True

    def _start_subscriber(self, sub: _Subscriber) -> None:
        t = threading.Thread(
            target=self._dispatch,
            args=(sub,),
            name=f"event-bus-{sub.topic}",
            daemon=True,
        )
        sub.thread = t
        t.start()

    @staticmethod
    def _dispatch(sub: _Subscriber) -> None:
        while not sub.stop_event.is_set():
            try:
                event = sub.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                sub.handler(event)
            except Exception:
                logger.exception("Handler raised for topic %s", sub.topic)
            finally:
                sub.queue.task_done()

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for sub in subs:
            sub.stop_event.set()
        for sub in subs:
            t = sub.thread
            if t is not None:
                t.join(timeout=timeout)
        with self._lock:
            self._started = False

"""Small in-memory caches shared by the poller and the Telegram menus."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable


class EventTTLCache:
    CLEANUP_INTERVAL_SECONDS = 30

    def __init__(self, max_size: int, ttl_seconds: int):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.data: OrderedDict[str, float] = OrderedDict()
        self.lock = threading.Lock()
        self._next_cleanup = 0.0

    def contains(self, key: str) -> bool:
        with self.lock:
            ts = self.data.get(key)
            if ts is None:
                return False
            if time.time() - ts > self.ttl_seconds:
                self.data.pop(key, None)
                return False
            return True

    def add(self, key: str) -> None:
        with self.lock:
            now = time.time()
            self.data.pop(key, None)
            self.data[key] = now
            if now >= self._next_cleanup:
                self._cleanup_locked(now)
                self._next_cleanup = now + self.CLEANUP_INTERVAL_SECONDS
            while len(self.data) > self.max_size:
                self.data.popitem(last=False)

    def _cleanup_locked(self, now: float) -> None:
        # Insertion order equals insertion time, so expired keys are always at the front.
        while self.data:
            _key, ts = next(iter(self.data.items()))
            if now - ts <= self.ttl_seconds:
                return
            self.data.popitem(last=False)


class TTLCache:
    def __init__(self, ttl_seconds: float):
        self.ttl_seconds = ttl_seconds
        self._data: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get_or_call(self, key: str, factory: Callable[[], Any]) -> Any:
        with self._lock:
            item = self._data.get(key)
            if item is not None and time.time() - item[0] <= self.ttl_seconds:
                return item[1]
        value = factory()
        with self._lock:
            self._data[key] = (time.time(), value)
        return value

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

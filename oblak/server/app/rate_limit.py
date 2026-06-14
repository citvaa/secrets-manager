"""Very small in-memory rate limiter for login attempts (req. ZR-A5 / threat T8).

This is deliberately minimal and process-local. For a multi-process / multi-host
deployment it should be backed by a shared store such as Redis (open item).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from .config import settings


class SlidingWindowLimiter:
    """Tracks failed attempts per key within a sliding time window."""

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> None:
        bucket = self._hits[key]
        while bucket and now - bucket[0] > self._window:
            bucket.popleft()

    def is_blocked(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            return len(self._hits[key]) >= self._max

    def register_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            self._hits[key].append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


login_limiter = SlidingWindowLimiter(
    max_attempts=settings.login_max_attempts,
    window_seconds=settings.login_window_seconds,
)

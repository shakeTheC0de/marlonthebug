"""Simple per-host token scheduler that prevents accidental hammering."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from urllib.parse import urlparse


class HostRateLimiter:
    def __init__(self, requests_per_second: float = 8.0) -> None:
        self.requests_per_second = max(0.1, float(requests_per_second))
        self._interval = 1.0 / self.requests_per_second
        self._next_slot: dict[str, float] = defaultdict(float)
        self._lock = asyncio.Lock()

    async def acquire(self, url: str) -> None:
        host = urlparse(url).netloc.lower()
        async with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot[host])
            self._next_slot[host] = slot + self._interval
        delay = slot - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)

"""
Token-bucket rate limiter with adaptive backoff for InjeXion.
Safeguards targets from denial of service and handles HTTP 429/503 with jitter.
"""

import asyncio
import random
import time
from typing import Optional


class AsyncRateLimiter:
    """Token-bucket rate limiter ensuring requests stay within specified rate."""

    def __init__(self, rate_limit: float = 40.0):
        self.rate_limit = max(0.1, rate_limit)
        self.capacity = max(1.0, rate_limit)
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_limit)
            if self.tokens < 1.0:
                wait_time = (1.0 - self.tokens) / self.rate_limit
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0

    async def backoff(self, attempt: int = 1, base_seconds: float = 1.0) -> None:
        """Exponential backoff with full jitter on receiving 429 Too Many Requests."""
        max_sleep = base_seconds * (2 ** min(attempt, 5))
        sleep_duration = random.uniform(base_seconds, max_sleep)
        await asyncio.sleep(sleep_duration)


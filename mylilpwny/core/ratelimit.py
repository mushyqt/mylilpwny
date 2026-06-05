from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """Async token bucket rate limiter.

    Tokens are added at `rate` per second up to `capacity`.
    Each `acquire()` call consumes one token, waiting if necessary.
    """

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = rate
        self.capacity = capacity if capacity is not None else rate
        self._tokens: float = self.capacity
        self._last: float = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self.rate
                await asyncio.sleep(wait)

    @property
    def available(self) -> float:
        self._refill()
        return self._tokens


class RateLimiter:
    """Global + per-target token bucket rate limiter.

    Acquiring a slot consumes one token from both the global bucket
    and the target-specific bucket — both must have capacity.
    """

    def __init__(self, global_rps: float, per_target_rps: float | None = None) -> None:
        self._global = TokenBucket(rate=global_rps)
        self._per_target_rps = per_target_rps if per_target_rps is not None else global_rps
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def _get_bucket(self, target: str) -> TokenBucket:
        async with self._lock:
            if target not in self._buckets:
                self._buckets[target] = TokenBucket(rate=self._per_target_rps)
            return self._buckets[target]

    async def acquire(self, target: str = "") -> None:
        """Block until a slot is available for the given target."""
        bucket = await self._get_bucket(target)
        # Acquire global then per-target (order consistent to avoid deadlock)
        await self._global.acquire()
        await bucket.acquire()

    @property
    def global_available(self) -> float:
        return self._global.available

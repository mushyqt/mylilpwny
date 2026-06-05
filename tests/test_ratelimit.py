import asyncio
import time

import pytest

from mylilpwny.core.ratelimit import RateLimiter, TokenBucket


# --- TokenBucket ---

@pytest.mark.asyncio
async def test_token_bucket_immediate_when_full():
    bucket = TokenBucket(rate=10.0)
    t0 = time.monotonic()
    await bucket.acquire()
    assert time.monotonic() - t0 < 0.1  # should be instant


@pytest.mark.asyncio
async def test_token_bucket_throttles_at_rate():
    rate = 10.0  # 10 tokens/s → 0.1s per token
    bucket = TokenBucket(rate=rate, capacity=1.0)
    await bucket.acquire()  # consume the one token

    t0 = time.monotonic()
    await bucket.acquire()  # must wait ~0.1s for refill
    elapsed = time.monotonic() - t0

    assert 0.08 <= elapsed <= 0.3  # generous window for CI


@pytest.mark.asyncio
async def test_token_bucket_capacity_cap():
    bucket = TokenBucket(rate=100.0, capacity=3.0)
    await asyncio.sleep(0.5)   # would add 50 tokens at rate=100, but capped at 3
    assert bucket.available <= 3.0 + 0.1  # small float tolerance


@pytest.mark.asyncio
async def test_token_bucket_concurrent_acquires_serialised():
    bucket = TokenBucket(rate=5.0, capacity=2.0)
    results: list[float] = []

    async def grab() -> None:
        await bucket.acquire()
        results.append(time.monotonic())

    await asyncio.gather(grab(), grab(), grab())
    # Three acquires at 5 rps: first two instant (capacity=2), third waits ~0.2s
    assert len(results) == 3
    assert results[2] - results[0] >= 0.15


# --- RateLimiter ---

@pytest.mark.asyncio
async def test_rate_limiter_acquire_first_time():
    rl = RateLimiter(global_rps=100.0)
    t0 = time.monotonic()
    await rl.acquire("10.0.0.1")
    assert time.monotonic() - t0 < 0.05


@pytest.mark.asyncio
async def test_rate_limiter_separate_buckets_per_target():
    rl = RateLimiter(global_rps=100.0, per_target_rps=100.0)
    await rl.acquire("10.0.0.1")
    await rl.acquire("10.0.0.2")
    # Different targets have independent buckets — both should be fast
    t0 = time.monotonic()
    await rl.acquire("10.0.0.1")
    await rl.acquire("10.0.0.2")
    assert time.monotonic() - t0 < 0.1


@pytest.mark.asyncio
async def test_rate_limiter_global_limits_all_targets():
    rl = RateLimiter(global_rps=5.0)
    # Consume global capacity (default capacity = rate = 5)
    for _ in range(5):
        await rl.acquire("10.0.0.1")
    t0 = time.monotonic()
    await rl.acquire("10.0.0.2")   # hits global bucket limit
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.1  # had to wait for global refill


@pytest.mark.asyncio
async def test_rate_limiter_measured_throughput():
    """At 20 rps with capacity=1, 10 acquires should take ~0.45s (9 waits of 0.05s each)."""
    rps = 20.0
    bucket = TokenBucket(rate=rps, capacity=1.0)
    n = 10
    t0 = time.monotonic()
    for _ in range(n):
        await bucket.acquire()
    elapsed = time.monotonic() - t0
    # First is instant, remaining n-1 each wait 1/rps = 0.05s
    expected = (n - 1) / rps
    assert expected * 0.7 <= elapsed <= expected * 2.5

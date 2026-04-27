"""Unit tests for services/memory/rate_limiter.py.

Uses unittest.mock to freeze time.monotonic() and asyncio.sleep() so tests run
instantly without real delays.

Covers:
- Sliding-window allow and block semantics (SYNC, SUMMARY, EXPORT)
- Fixed-window KEYS_ROTATE capacity + midnight reset
- record_429 ratchet backoff
- block=False raises RateLimitWouldBlockError
- max_wait_seconds raises RateLimitTimeoutError
- quota_status() reporting
- Concurrent acquire serialises via asyncio.Lock
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.memory.rate_limiter import (
    RateLimitKey,
    RateLimiter,
    RateLimitTimeoutError,
    RateLimitWouldBlockError,
    _LIMITS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_limiter(**kwargs) -> RateLimiter:
    return RateLimiter(**kwargs)


async def _acquire_n(limiter: RateLimiter, key: RateLimitKey, n: int) -> None:
    """Acquire *n* slots sequentially."""
    for _ in range(n):
        await limiter.acquire(key)


# ---------------------------------------------------------------------------
# Sliding window — SYNC (100 req/min)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sync_100_acquires_succeed_without_sleep() -> None:
    """The first 100 acquisitions of SYNC fit in a 60s window and must not sleep."""
    limiter = _make_limiter()
    sleep_calls: List[float] = []

    start_time = 1_000_000.0

    with patch("servonaut.services.memory.rate_limiter.monotonic", side_effect=lambda: start_time):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            # All 100 have the same timestamp — within the window
            for _ in range(100):
                await limiter.acquire(RateLimitKey.SYNC)

    mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_sync_101st_call_triggers_sleep() -> None:
    """The 101st SYNC acquire must sleep until the oldest entry expires."""
    limiter = _make_limiter()

    # Simulate monotonic advancing slowly so all 100 slots land at t=0
    call_count = 0

    def fake_monotonic() -> float:
        return 0.0  # all timestamps the same

    with patch("servonaut.services.memory.rate_limiter.monotonic", side_effect=fake_monotonic):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            for _ in range(100):
                await limiter.acquire(RateLimitKey.SYNC)
            # 101st call should compute wait and sleep
            await limiter.acquire(RateLimitKey.SYNC)

    # Sleep must have been called at least once for the overflow
    assert mock_sleep.call_count >= 1
    sleep_arg = mock_sleep.call_args_list[0][0][0]
    # Wait should be around 60s (period) plus small jitter
    assert 55.0 <= sleep_arg <= 70.0


# ---------------------------------------------------------------------------
# record_429 ratchet — SYNC (floor 30s)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_record_429_causes_ratchet_sleep_at_least_30s() -> None:
    """After record_429(SYNC), the next acquire must sleep >= 30s."""
    limiter = _make_limiter(jitter_fraction=0.0)  # no jitter for determinism

    base_time = 1_000_000.0
    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=base_time):
        limiter.record_429(RateLimitKey.SYNC)

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=base_time):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await limiter.acquire(RateLimitKey.SYNC)

    assert mock_sleep.called
    sleep_arg = mock_sleep.call_args_list[0][0][0]
    # Floor is 30s; with jitter_fraction=0 the ratchet wait = remaining + 0
    assert sleep_arg >= 30.0


# ---------------------------------------------------------------------------
# SUMMARY — 5th-call overflow (capacity=5, period=60s)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_summary_6th_call_sleeps_at_least_60s() -> None:
    """The 6th SUMMARY acquire (after 5 at t=0) must sleep for ~60s."""
    limiter = _make_limiter()

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=0.0):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            for _ in range(5):
                await limiter.acquire(RateLimitKey.SUMMARY)
            await limiter.acquire(RateLimitKey.SUMMARY)  # 6th

    assert mock_sleep.call_count >= 1
    sleep_arg = mock_sleep.call_args_list[0][0][0]
    assert sleep_arg >= 55.0  # ~60s with small jitter tolerance


# ---------------------------------------------------------------------------
# EXPORT — 3rd call overflow (capacity=2, period=3600s)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_export_3rd_call_sleeps_at_least_3600s() -> None:
    """The 3rd EXPORT acquire (after 2 at t=0) must sleep for ~3600s."""
    limiter = _make_limiter()

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=0.0):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await limiter.acquire(RateLimitKey.EXPORT)
            await limiter.acquire(RateLimitKey.EXPORT)
            await limiter.acquire(RateLimitKey.EXPORT)  # 3rd

    assert mock_sleep.call_count >= 1
    sleep_arg = mock_sleep.call_args_list[0][0][0]
    assert sleep_arg >= 3500.0


# ---------------------------------------------------------------------------
# KEYS_ROTATE — fixed window
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_keys_rotate_6th_call_same_day_raises_timeout_when_max_wait_small() -> None:
    """The 6th KEYS_ROTATE call on the same calendar day with a tight max_wait raises."""
    limiter = _make_limiter()

    # Freeze the calendar day so all 6 calls land on the same UTC day
    fixed_day = datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
    with patch(
        "servonaut.services.memory.rate_limiter.RateLimiter._current_epoch_day",
        return_value=fixed_day.toordinal(),
    ):
        with patch(
            "servonaut.services.memory.rate_limiter.RateLimiter._seconds_until_midnight_utc",
            return_value=43200.0,  # 12 hours until midnight
        ):
            for _ in range(5):
                await limiter.acquire(RateLimitKey.KEYS_ROTATE)
            with pytest.raises(RateLimitTimeoutError):
                await limiter.acquire(
                    RateLimitKey.KEYS_ROTATE,
                    max_wait_seconds=10,
                )


@pytest.mark.asyncio
async def test_keys_rotate_resets_at_calendar_day_boundary() -> None:
    """After the window rolls over to a new UTC day, KEYS_ROTATE allows fresh slots."""
    limiter = _make_limiter()

    day_a = datetime(2026, 4, 25, 23, 59, 0, tzinfo=timezone.utc).toordinal()
    day_b = datetime(2026, 4, 26, 0, 0, 1, tzinfo=timezone.utc).toordinal()

    # Fill up day A
    with patch(
        "servonaut.services.memory.rate_limiter.RateLimiter._current_epoch_day",
        return_value=day_a,
    ):
        for _ in range(5):
            await limiter.acquire(RateLimitKey.KEYS_ROTATE)

    # Day B should have fresh capacity
    with patch(
        "servonaut.services.memory.rate_limiter.RateLimiter._current_epoch_day",
        return_value=day_b,
    ):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await limiter.acquire(RateLimitKey.KEYS_ROTATE)
    # Should not have slept (fresh window)
    mock_sleep.assert_not_called()


# ---------------------------------------------------------------------------
# block=False raises immediately
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_acquire_block_false_raises_would_block_error() -> None:
    """block=False must raise RateLimitWouldBlockError instead of sleeping."""
    limiter = _make_limiter()

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=0.0):
        # Fill SUMMARY window (capacity=5)
        for _ in range(5):
            await limiter.acquire(RateLimitKey.SUMMARY)
        with pytest.raises(RateLimitWouldBlockError):
            await limiter.acquire(RateLimitKey.SUMMARY, block=False)


# ---------------------------------------------------------------------------
# quota_status
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_quota_status_reports_correct_used_and_capacity() -> None:
    """quota_status() must reflect the number of slots consumed per key."""
    limiter = _make_limiter()

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=1_000_000.0):
        for _ in range(3):
            await limiter.acquire(RateLimitKey.SYNC)
        await limiter.acquire(RateLimitKey.SUMMARY)
        await limiter.acquire(RateLimitKey.SUMMARY)

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=1_000_000.0):
        status = limiter.quota_status()

    assert status["sync"]["used"] == 3
    assert status["sync"]["capacity"] == 100
    assert status["summary"]["used"] == 2
    assert status["summary"]["capacity"] == 5


@pytest.mark.asyncio
async def test_quota_status_contains_all_keys() -> None:
    limiter = _make_limiter()
    status = limiter.quota_status()
    for key in RateLimitKey:
        assert key.value in status


# ---------------------------------------------------------------------------
# Concurrent acquire serialises via asyncio.Lock
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_acquire_serialises() -> None:
    """Two coroutines acquiring the same key must not race — both must succeed."""
    limiter = _make_limiter()

    # SUMMARY has capacity=5; two concurrent acquires both fit — no race crash
    results: List[str] = []

    async def worker(label: str) -> None:
        await limiter.acquire(RateLimitKey.SUMMARY)
        results.append(label)

    await asyncio.gather(worker("a"), worker("b"))
    assert sorted(results) == ["a", "b"]


@pytest.mark.asyncio
async def test_concurrent_acquire_beyond_capacity_both_eventually_succeed() -> None:
    """6 concurrent SUMMARY acquires: first 5 fit immediately, 6th must block."""
    limiter = _make_limiter()
    completed: List[int] = []

    async def worker(idx: int) -> None:
        await limiter.acquire(RateLimitKey.SUMMARY)
        completed.append(idx)

    # We patch sleep so the overflow resolves instantly in test
    with patch("asyncio.sleep", new_callable=AsyncMock):
        await asyncio.gather(*[worker(i) for i in range(6)])

    assert len(completed) == 6


# ---------------------------------------------------------------------------
# reset helper
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reset_clears_state_for_specific_key() -> None:
    limiter = _make_limiter()

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=0.0):
        for _ in range(5):
            await limiter.acquire(RateLimitKey.SUMMARY)

    limiter.reset(RateLimitKey.SUMMARY)

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=0.0):
        status = limiter.quota_status()
    assert status["summary"]["used"] == 0


@pytest.mark.asyncio
async def test_reset_none_clears_all_keys() -> None:
    limiter = _make_limiter()

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=0.0):
        await limiter.acquire(RateLimitKey.SYNC)
        await limiter.acquire(RateLimitKey.SUMMARY)

    limiter.reset()

    with patch("servonaut.services.memory.rate_limiter.monotonic", return_value=0.0):
        status = limiter.quota_status()
    assert status["sync"]["used"] == 0
    assert status["summary"]["used"] == 0

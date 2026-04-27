"""Client-side rate limiter for memory sync API endpoints.

Mirrors the server-side limits from spec §6 so the client avoids burning quota
with guaranteed-rejected requests. A sliding-window deque tracks timestamps for
most keys; KEYS_ROTATE uses a fixed-window (calendar day UTC) because the
server enforces per-day absolute caps.

Usage::

    limiter = RateLimiter()
    await limiter.acquire(RateLimitKey.SYNC)  # blocks until capacity available
    # ... make API call ...
    # On 429 response:
    limiter.record_429(RateLimitKey.SYNC)
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from random import uniform
from time import monotonic
from typing import Any, Deque, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class RateLimitWouldBlockError(RuntimeError):
    """Raised by ``acquire(block=False)`` when the window is full."""


class RateLimitTimeoutError(RuntimeError):
    """Raised by ``acquire(max_wait_seconds=N)`` when the required wait exceeds N."""


# ---------------------------------------------------------------------------
# Internal config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Window:
    capacity: int
    period_seconds: float
    # True for keys whose server cap is a calendar-day absolute (e.g. KEYS_ROTATE).
    fixed_window: bool = False


# Spec §6 limits
_LIMITS: Dict["RateLimitKey", _Window] = {}  # populated after class definition

# Minimum backoff applied after receiving a 429 — spec §6 floors.
_BACKOFF_FLOORS_SEC: Dict["RateLimitKey", float] = {}  # populated after class definition


# ---------------------------------------------------------------------------
# Rate limit keys
# ---------------------------------------------------------------------------

class RateLimitKey(str, Enum):
    SYNC = "sync"                    # 100 req/min sliding
    SUMMARY = "summary"              # 5 req/min sliding
    EXPORT = "export"                # 2 req/hour sliding
    KEYS_ME = "keys_me"             # 3 req/hour sliding
    KEYS_ROTATE = "keys_rotate"      # 5 req/day FIXED window
    GENERAL = "general"             # fallback — 60 req/min sliding


# Populate after RateLimitKey is defined so we can use the enum as dict key.
_LIMITS = {
    RateLimitKey.SYNC: _Window(capacity=100, period_seconds=60.0),
    RateLimitKey.SUMMARY: _Window(capacity=5, period_seconds=60.0),
    RateLimitKey.EXPORT: _Window(capacity=2, period_seconds=3600.0),
    RateLimitKey.KEYS_ME: _Window(capacity=3, period_seconds=3600.0),
    RateLimitKey.KEYS_ROTATE: _Window(capacity=5, period_seconds=86400.0, fixed_window=True),
    RateLimitKey.GENERAL: _Window(capacity=60, period_seconds=60.0),
}

_BACKOFF_FLOORS_SEC = {
    RateLimitKey.SYNC: 30.0,
    RateLimitKey.SUMMARY: 120.0,
    RateLimitKey.EXPORT: 3600.0,
    RateLimitKey.KEYS_ME: 1200.0,
    RateLimitKey.KEYS_ROTATE: 86400.0,
    RateLimitKey.GENERAL: 30.0,
}


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Async client-side rate limiter for memory sync API endpoints.

    One instance should be created per app session (constructed in
    ``app.py::_init_services``) and shared across all memory services.

    Args:
        jitter_fraction: Fraction of the backoff floor added as random jitter
            to prevent thundering-herd when multiple clients back off together.
            Default is 0.25 (25 %).
    """

    def __init__(self, *, jitter_fraction: float = 0.25) -> None:
        self._jitter_fraction = jitter_fraction
        # Sliding-window: deque of monotonic timestamps per key.
        self._timestamps: Dict[RateLimitKey, Deque[float]] = {
            key: deque() for key in RateLimitKey
        }
        # Fixed-window: (epoch_day, count) — epoch_day = days since Unix epoch (UTC).
        self._fixed_window: Dict[RateLimitKey, Tuple[int, int]] = {}
        # Per-key asyncio locks — created lazily to avoid issues with event-loop
        # resolution at module import time.
        self._locks: Dict[RateLimitKey, asyncio.Lock] = {}
        # Monotonic "ratchet" deadline — any acquire before this time waits extra.
        self._ratchet_until: Dict[RateLimitKey, float] = {
            key: 0.0 for key in RateLimitKey
        }

    def _get_lock(self, key: RateLimitKey) -> asyncio.Lock:
        """Return (creating if necessary) the per-key lock."""
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    def _jitter(self) -> float:
        return uniform(0.0, self._jitter_fraction)

    @staticmethod
    def _current_epoch_day() -> int:
        """Return the current UTC calendar day as an integer (days since Unix epoch)."""
        return datetime.now(timezone.utc).toordinal()

    @staticmethod
    def _seconds_until_midnight_utc() -> float:
        """Return seconds until the next UTC midnight."""
        now = datetime.now(timezone.utc)
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        # timedelta to next midnight
        from datetime import timedelta
        next_midnight = midnight + timedelta(days=1)
        return (next_midnight - now).total_seconds()

    async def acquire(
        self,
        key: RateLimitKey,
        *,
        block: bool = True,
        max_wait_seconds: Optional[float] = None,
    ) -> None:
        """Acquire a slot for the given rate-limit key.

        Blocks (with ``asyncio.sleep``) until a slot is available, or raises
        if ``block=False`` or if the wait would exceed *max_wait_seconds*.

        Args:
            key: The endpoint key to acquire.
            block: If ``False``, raise ``RateLimitWouldBlockError`` immediately
                instead of sleeping.
            max_wait_seconds: If set, raise ``RateLimitTimeoutError`` when the
                required wait exceeds this value.

        Raises:
            RateLimitWouldBlockError: When ``block=False`` and a wait is needed.
            RateLimitTimeoutError: When the required wait exceeds *max_wait_seconds*.
        """
        async with self._get_lock(key):
            window = _LIMITS[key]

            # --- Ratchet check (enforced after a 429) ---
            ratchet_remaining = self._ratchet_until[key] - monotonic()
            if ratchet_remaining > 0:
                wait = ratchet_remaining + self._jitter() * _BACKOFF_FLOORS_SEC[key]
                if not block:
                    raise RateLimitWouldBlockError(
                        f"{key.value}: ratchet active for {wait:.1f}s more"
                    )
                if max_wait_seconds is not None and wait > max_wait_seconds:
                    raise RateLimitTimeoutError(
                        f"{key.value}: ratchet wait {wait:.1f}s exceeds max_wait_seconds={max_wait_seconds}"
                    )
                await asyncio.sleep(wait)

            if window.fixed_window:
                await self._acquire_fixed(key, window, block=block, max_wait_seconds=max_wait_seconds)
            else:
                await self._acquire_sliding(key, window, block=block, max_wait_seconds=max_wait_seconds)

    async def _acquire_sliding(
        self,
        key: RateLimitKey,
        window: _Window,
        *,
        block: bool,
        max_wait_seconds: Optional[float],
    ) -> None:
        """Acquire with sliding-window semantics (lock already held by caller)."""
        now = monotonic()
        cutoff = now - window.period_seconds
        ts = self._timestamps[key]

        # Evict expired entries from the front.
        while ts and ts[0] <= cutoff:
            ts.popleft()

        if len(ts) < window.capacity:
            ts.append(now)
            return

        # Window full — compute wait until oldest expires.
        oldest = ts[0]
        wait = (oldest + window.period_seconds) - now + self._jitter() * window.period_seconds * 0.1

        if not block:
            raise RateLimitWouldBlockError(
                f"{key.value}: sliding window full; retry in {wait:.1f}s"
            )
        if max_wait_seconds is not None and wait > max_wait_seconds:
            raise RateLimitTimeoutError(
                f"{key.value}: wait {wait:.1f}s exceeds max_wait_seconds={max_wait_seconds}"
            )
        await asyncio.sleep(wait)
        # After sleeping, record the new timestamp.
        now2 = monotonic()
        cutoff2 = now2 - window.period_seconds
        while ts and ts[0] <= cutoff2:
            ts.popleft()
        ts.append(now2)

    async def _acquire_fixed(
        self,
        key: RateLimitKey,
        window: _Window,
        *,
        block: bool,
        max_wait_seconds: Optional[float],
    ) -> None:
        """Acquire with fixed-window (calendar day UTC) semantics (lock already held)."""
        today = self._current_epoch_day()
        epoch_day, count = self._fixed_window.get(key, (today, 0))

        if epoch_day != today:
            # New calendar day — reset counter.
            epoch_day = today
            count = 0

        if count < window.capacity:
            self._fixed_window[key] = (epoch_day, count + 1)
            return

        # Capacity exhausted for today.
        wait = self._seconds_until_midnight_utc() + self._jitter() * 60.0

        if not block:
            raise RateLimitWouldBlockError(
                f"{key.value}: daily fixed window exhausted; resets in {wait:.0f}s"
            )
        if max_wait_seconds is not None and wait > max_wait_seconds:
            raise RateLimitTimeoutError(
                f"{key.value}: wait until midnight ({wait:.0f}s) exceeds max_wait_seconds={max_wait_seconds}"
            )
        await asyncio.sleep(wait)
        # After sleeping, record for the new day.
        new_today = self._current_epoch_day()
        self._fixed_window[key] = (new_today, 1)

    def record_429(self, key: RateLimitKey) -> None:
        """Record a server 429 response, activating the ratchet backoff floor.

        The ratchet prevents immediate retry after a 429 by enforcing a minimum
        wait of ``_BACKOFF_FLOORS_SEC[key] * (1 + uniform(0, jitter_fraction))``.

        Args:
            key: The key that was rate-limited by the server.
        """
        floor = _BACKOFF_FLOORS_SEC[key]
        candidate = monotonic() + floor * (1 + uniform(0, self._jitter_fraction))
        # Ratchet semantics: only ever extends, never shortens an existing deadline.
        self._ratchet_until[key] = max(self._ratchet_until.get(key, 0.0), candidate)

    def reset(self, key: Optional[RateLimitKey] = None) -> None:
        """Clear rate-limit state for one or all keys (test helper).

        Args:
            key: Key to reset, or ``None`` to reset all keys.
        """
        keys = [key] if key is not None else list(RateLimitKey)
        for k in keys:
            self._timestamps[k].clear()
            self._fixed_window.pop(k, None)
            self._ratchet_until[k] = 0.0

    def quota_status(self) -> Dict[str, Dict[str, Any]]:
        """Return current usage snapshot for all rate-limit keys.

        Returns a dict of ``{key.value: {used, capacity, period_seconds, ratchet_until_epoch}}``.
        """
        result: Dict[str, Dict[str, Any]] = {}
        now = monotonic()
        for key, window in _LIMITS.items():
            if window.fixed_window:
                today = self._current_epoch_day()
                epoch_day, count = self._fixed_window.get(key, (today, 0))
                used = count if epoch_day == today else 0
            else:
                cutoff = now - window.period_seconds
                ts = self._timestamps[key]
                used = sum(1 for t in ts if t > cutoff)
            result[key.value] = {
                "used": used,
                "capacity": window.capacity,
                "period_seconds": window.period_seconds,
                "ratchet_until_epoch": self._ratchet_until[key],
            }
        return result

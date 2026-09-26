"""Condition waits for journeys that drive child processes.

The TUI driver has its own waits (``TuiDriver.wait_until``); these are for
everything else. They poll a predicate and never sleep for a fixed time.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable, Optional, TypeVar

T = TypeVar("T")

DEFAULT_TIMEOUT = 10.0
_POLL_SECONDS = 0.02


def wait_for(
    predicate: Callable[[], T],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    desc: str = "condition",
    alive: Optional[Callable[[], bool]] = None,
) -> T:
    """Poll *predicate* until it is truthy and return its value.

    *alive*, when given, must stay true: a child that exits early fails the
    wait at once instead of at the timeout.
    """
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if alive is not None and not alive():
            raise AssertionError(f"the process exited while waiting for {desc}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {desc}")
        time.sleep(_POLL_SECONDS)


def holds_for(predicate: Callable[[], object], seconds: float) -> bool:
    """True when *predicate* stays falsy for *seconds* (for "never happens" checks)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return False
        time.sleep(_POLL_SECONDS)
    return not predicate()


async def wait_for_async(
    predicate: Callable[[], T], *, timeout: float = DEFAULT_TIMEOUT, desc: str = "condition"
) -> T:
    """:func:`wait_for` for async journeys: yields to the event loop between polls."""
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {desc}")
        await asyncio.sleep(_POLL_SECONDS)

"""Bounded waits for asyncio lifecycle tests.

Scenario steps wait for an event ("the bind has started", "the state has
settled") with a generous liveness bound instead of a tight latency budget:
a passing run never waits it out, and only a genuine hang does. A loaded CI
runner can take far longer than a developer machine to reach a step, so a
bound tuned to a fast machine turns scheduling delay into a false failure.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

import pytest

T = TypeVar("T")

# Upper bound for reaching one scenario step. Passing runs take milliseconds.
STEP_TIMEOUT_SECONDS = 10.0


async def wait_until(
    predicate: Callable[[], bool],
    timeout: float = STEP_TIMEOUT_SECONDS,
) -> None:
    """Yield to the loop until ``predicate()`` holds, failing after ``timeout``."""

    async def poll() -> None:
        while not predicate():
            await asyncio.sleep(0.005)

    await asyncio.wait_for(poll(), timeout=timeout)


def run_within(coroutine: Coroutine[Any, Any, T], seconds: float) -> T:
    """Run ``coroutine`` with ``asyncio.run`` and fail if it has not finished,
    including the event loop's own teardown, within ``seconds``.

    The loop runs in a daemon thread so that a hang fails this test with a
    clear message instead of stalling until the suite-wide timeout.
    """
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["result"] = asyncio.run(coroutine)
        except BaseException as error:  # noqa: BLE001 - re-raised on the test thread
            outcome["error"] = error

    runner = threading.Thread(target=target, name="bounded-event-loop", daemon=True)
    runner.start()
    runner.join(seconds)
    if runner.is_alive():
        pytest.fail(f"event loop did not finish within {seconds} s, including teardown")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["result"]

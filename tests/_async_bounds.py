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
    # Poll inline rather than in a child task: a child's completion resumes
    # the caller one loop turn later, and work queued in that turn (a widget
    # recompose, for instance) can undo the condition before it is read.
    # ``asyncio.TimeoutError`` is raised because on Python 3.10 it is not the
    # builtin ``TimeoutError``.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() >= deadline:
            raise asyncio.TimeoutError
        await asyncio.sleep(0.005)


async def wait_for_screen_ready(
    app: Any, expected: type[T] | T, *, required: tuple[str, ...] = (),
) -> T:
    """Wait for the current screen and its required children to be mounted."""
    found: list[T] = []

    def ready() -> bool:
        if (error := getattr(app, "_exception", None)) is not None:
            raise error
        screen = app.screen
        is_expected = isinstance(screen, expected) if isinstance(expected, type) else screen is expected
        if not (is_expected and screen.is_attached and screen.is_mounted):
            return False
        for selector in required:
            children = list(screen.query(selector))
            if len(children) != 1 or not all(child.is_attached and child.is_mounted for child in children):
                return False
        found[:] = [screen]
        return True

    await wait_until(ready)
    return found[0]


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

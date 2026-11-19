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


def _click_target(app: Any, scope: Any, target_or_selector: Any, center: bool) -> Any:
    from textual.css.query import NoMatches
    from textual.errors import NoWidget
    from textual.widget import Widget

    if (error := getattr(app, "_exception", None)) is not None:
        raise error
    if app.screen is not scope or not (scope.is_attached and scope.is_mounted):
        return None
    try:
        target = target_or_selector if isinstance(target_or_selector, Widget) else scope.query_one(target_or_selector)
    except NoMatches:
        return None
    if not (target.is_attached and target.is_mounted and target.screen is scope):
        return None
    region = target.region
    if region.width <= 0 or region.height <= 0:
        return None
    points = (region.offset, region.center) if center else (region.offset,)
    try:
        if not all(point in scope.size.region and app.get_widget_at(*point)[0] is target for point in points):
            return None
    except NoWidget:
        return None
    return target


async def wait_for_click_target(
    app: Any, target_or_selector: Any, *, screen: Any = None, center: bool = False,
) -> Any:
    """Wait for a mounted target's click origin and optional centre to be hittable."""
    if (error := getattr(app, "_exception", None)) is not None:
        raise error
    scope = app.screen if screen is None else screen
    found: list[Any] = []

    def ready() -> bool:
        target = _click_target(app, scope, target_or_selector, center)
        if target is None:
            return False
        found[:] = [target]
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

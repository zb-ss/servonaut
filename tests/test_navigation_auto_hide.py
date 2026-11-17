"""The real narrow default: below 110 columns the navigation is hidden and keys still reach it."""

from __future__ import annotations

import pytest

from servonaut.widgets.sidebar import Sidebar

from tests._async_bounds import wait_until
from tests.test_workspace_pilot import _Host

pytestmark = pytest.mark.asyncio


def _sidebar(app) -> Sidebar:
    return app.screen.query_one(Sidebar)


def _focus_in_sidebar(app) -> bool:
    focused = app.focused
    return focused is not None and _sidebar(app) in focused.ancestors_with_self


async def _ready(app, pilot) -> None:
    await wait_until(lambda: bool(app.screen.query(Sidebar)))
    await pilot.pause()


async def test_a_narrow_terminal_opens_with_the_navigation_hidden() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await _ready(app, pilot)
        assert not _sidebar(app).display
        content = app.screen.query_one("#main-layout").content_region.width
        assert content == 100  # the rail's 25 cells belong to the content


async def test_a_wide_terminal_opens_with_the_navigation_shown() -> None:
    app = _Host()
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        assert _sidebar(app).display


async def test_the_rail_opens_with_shift_f6_and_hides_again_with_escape_at_100_columns() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await _ready(app, pilot)
        await pilot.press("shift+f6")
        await wait_until(lambda: _sidebar(app).display and _focus_in_sidebar(app))
        await pilot.press("escape")
        await wait_until(lambda: not _sidebar(app).display)
        assert not _focus_in_sidebar(app)


async def test_leaving_keyboard_navigation_applies_the_width_it_ended_in() -> None:
    app = _Host()
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        await pilot.press("shift+f6")
        await wait_until(lambda: _focus_in_sidebar(app))
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await pilot.press("escape")
        await wait_until(lambda: not _sidebar(app).display)
        assert not _focus_in_sidebar(app)


async def test_an_explicit_choice_expires_when_the_width_class_changes() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await _ready(app, pilot)
        app.action_toggle_navigation()
        await wait_until(lambda: _sidebar(app).display)
        assert app.workspace_state.navigation_choice_class == "narrow"
        await pilot.resize_terminal(160, 50)
        await wait_until(lambda: app.workspace_state.navigation_choice_class is None)
        await pilot.resize_terminal(100, 30)
        await wait_until(lambda: not _sidebar(app).display)

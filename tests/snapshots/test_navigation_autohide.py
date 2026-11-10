"""Below 110 columns the navigation collapses by itself; explicit choices stand."""

from __future__ import annotations

import pytest
from textual.widgets import Button

from servonaut.widgets.sidebar import Sidebar

from . import _harness

pytestmark = pytest.mark.asyncio


def _sidebar(app) -> Sidebar:
    return app.screen.query_one(Sidebar)


async def _settle(pilot) -> None:
    await pilot.pause()
    await pilot.pause()


async def test_narrow_terminal_starts_with_navigation_hidden() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await _harness.wait_for_fleet(pilot)
        assert not _sidebar(app).display


async def test_wide_terminal_starts_with_navigation_shown() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        await _harness.wait_for_fleet(pilot)
        assert _sidebar(app).display


async def test_resizing_across_the_threshold_toggles_navigation() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        await _harness.wait_for_fleet(pilot)
        await pilot.resize_terminal(100, 30)
        await _settle(pilot)
        assert not _sidebar(app).display
        await pilot.resize_terminal(140, 40)
        await _settle(pilot)
        assert _sidebar(app).display


async def test_showing_navigation_at_100_columns_stays_until_the_class_changes() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await _harness.wait_for_fleet(pilot)
        app.screen.query_one("#workspace_navigation", Button).press()
        await _settle(pilot)
        assert _sidebar(app).display
        await pilot.resize_terminal(90, 30)
        await _settle(pilot)
        assert _sidebar(app).display  # same width class: the choice stands
        await pilot.resize_terminal(160, 50)
        await _settle(pilot)
        assert _sidebar(app).display
        await pilot.resize_terminal(100, 30)
        await _settle(pilot)
        assert not _sidebar(app).display  # the automatic rule is back


async def test_hiding_navigation_on_a_wide_terminal_stands_until_narrow() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        await _harness.wait_for_fleet(pilot)
        app.screen.query_one("#workspace_navigation", Button).press()
        await _settle(pilot)
        assert not _sidebar(app).display
        await pilot.resize_terminal(130, 40)
        await _settle(pilot)
        assert not _sidebar(app).display


async def test_the_toggle_key_shows_and_hides_navigation() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await _harness.wait_for_fleet(pilot)
        assert not _sidebar(app).display
        app.action_toggle_navigation()
        await _settle(pilot)
        assert _sidebar(app).display
        app.action_toggle_navigation()
        await _settle(pilot)
        assert not _sidebar(app).display


async def test_focus_never_stays_in_a_hidden_navigation() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        await _harness.wait_for_fleet(pilot)
        sidebar = _sidebar(app)
        sidebar.enter_navigation_mode()
        await _settle(pilot)
        sidebar.exit_navigation_mode()
        await pilot.resize_terminal(100, 30)
        await _settle(pilot)
        assert not sidebar.display
        focused = app.focused
        assert focused is None or sidebar not in focused.ancestors_with_self

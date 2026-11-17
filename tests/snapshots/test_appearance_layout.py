"""Settings > Appearance lays itself out for the room it has, however fast it is opened."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from textual.widgets import Button

from . import _harness


async def _open_appearance_at_once(pilot: Any) -> Any:
    """Open Settings and choose Appearance with no pause in between."""
    pilot.app.open_settings_screen("general")
    screen = await _harness.wait_for_screen(pilot, "SettingsScreen")
    screen.query_one("#navbtn_appearance", Button).press()
    await _harness.wait_until(
        pilot,
        lambda: screen._current_panel() is not None
        and screen._current_panel().PANEL_ID == "appearance"
        and screen._current_panel()._loaded
        and not screen._current_panel()._settling,
        "the appearance panel",
    )
    await pilot.pause()
    return screen


@pytest.mark.timeout(300)
@pytest.mark.parametrize("size,expected", [((160, 50), "-side"), ((100, 30), "-stacked")])
def test_appearance_chosen_at_once_takes_the_layout_its_width_calls_for(size: tuple, expected: str) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp()
        async with app.run_test(size=size) as pilot:
            await _harness.wait_for_fleet(pilot)
            pilot.app.workspace_state.navigation_visible = False
            for attempt in range(20):
                screen = await _open_appearance_at_once(pilot)
                layout = screen.query_one("#appearance_layout")
                assert layout.has_class(expected), (attempt, sorted(layout.classes))
                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(main())

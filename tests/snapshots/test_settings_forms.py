"""Compact scalar settings with the application navigation rail hidden."""

from __future__ import annotations

from typing import Any

import pytest

from . import _harness


@pytest.mark.parametrize("panel_id,size", [
    ("general", "160x50"),
    ("general", "100x30"),
    ("history_paths", "160x50"),
    ("cloudtrail", "160x50"),
    ("cloudwatch", "160x50"),
])
def test_contextual_settings_form(screen_snapshot: Any, panel_id: str, size: str) -> None:
    async def before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        pilot.app.workspace_state.navigation_visible = False
        pilot.app.open_settings_screen(panel_id)
        screen = await _harness.wait_for_screen(pilot, "SettingsScreen")
        await _harness.wait_until(
            pilot,
            lambda: screen._current_panel() is not None
            and screen._current_panel()._loaded
            and not screen._current_panel()._settling,
            f"the {panel_id} form to settle",
        )
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], before)

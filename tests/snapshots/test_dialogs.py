"""Shared dialogs drawn over the real app with the seeded screenshot state."""

from __future__ import annotations

from typing import Any

import pytest

from servonaut.screens.settings.shell import DiscardChangesModal

from . import _harness


@pytest.mark.parametrize("size", list(_harness.SIZES))
def test_discard_unsaved_settings(screen_snapshot: Any, size: str) -> None:
    """The unsaved-changes prompt keeps its safe action visible at both sizes."""

    async def scenario(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        pilot.app.open_settings_screen("general")
        await _harness.wait_for_screen(pilot, "SettingsScreen")
        pilot.app.push_screen(DiscardChangesModal("General"))
        await _harness.wait_for_screen(pilot, "DiscardChangesModal")
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], scenario)

"""A panel left before or while it loads never asks to discard.

After ``load()`` a panel re-takes its "saved" snapshot over the next few
frames, so values that arrive late (editor rows mounting, a select settling)
are not taken for edits. Switching panels or leaving Settings inside that
window must finish the re-baseline first instead of asking "discard
changes?" about edits nobody made. Edits after the panel has settled still
ask.
"""
from __future__ import annotations

from typing import Any, Callable, List

import pytest
from textual.widgets import Input

from servonaut.screens.settings import SettingsScreen
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.shell import DiscardChangesModal
from tests.test_open_settings_screen import _Host


def _hold_rebaseline(monkeypatch: pytest.MonkeyPatch) -> List[Any]:
    """Keep every deferred re-baseline from running, as a busy machine would."""
    held: List[Any] = []

    def hold(panel: SettingsPanel, frames_left: int) -> None:
        if frames_left > 0:
            held.append(panel)

    monkeypatch.setattr(SettingsPanel, "_schedule_rebaseline", hold)
    return held


async def _wait_until(pilot: Any, condition: Callable[[], bool], what: str) -> None:
    """Wait for *condition*; a busy runner can take several frames to mount."""
    for _ in range(50):
        if condition():
            return
        await pilot.pause()
    assert condition(), what


async def _open_general(app: _Host, pilot: Any) -> Any:
    await pilot.pause()
    app.open_settings_screen()
    await _wait_until(
        pilot,
        lambda: isinstance(app.screen, SettingsScreen)
        and app.screen._current_panel() is not None,
        "Settings never opened a panel",
    )
    settings = app.screen
    assert settings._active_id == "general"
    return settings


async def _late_value(pilot: Any, panel: SettingsPanel) -> None:
    """A value that reaches the panel after its load, before any re-baseline."""
    panel.query_one("#general_terminal", Input).value = "arrived-after-load"
    await pilot.pause()


@pytest.mark.asyncio
async def test_switching_panels_while_one_settles_does_not_ask(monkeypatch):
    held = _hold_rebaseline(monkeypatch)
    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        settings = await _open_general(app, pilot)
        panel = settings._current_panel()
        await _wait_until(
            pilot, lambda: panel in held, "the load should have queued a re-baseline"
        )
        await _late_value(pilot, panel)

        settings._request_switch("ai_provider")
        await _wait_until(
            pilot,
            lambda: settings._active_id == "ai_provider"
            or isinstance(app.screen, DiscardChangesModal),
            "the switch never happened",
        )

        assert not isinstance(app.screen, DiscardChangesModal)
        assert settings._active_id == "ai_provider"


@pytest.mark.asyncio
async def test_leaving_settings_while_a_panel_settles_does_not_ask(monkeypatch):
    held = _hold_rebaseline(monkeypatch)
    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        settings = await _open_general(app, pilot)
        panel = settings._current_panel()
        await _wait_until(
            pilot, lambda: panel in held, "the load should have queued a re-baseline"
        )
        await _late_value(pilot, panel)

        settings.action_back()
        await _wait_until(
            pilot,
            lambda: app.screen is not settings,
            "Settings was never left",
        )

        assert not isinstance(app.screen, DiscardChangesModal)
        assert app.screen is not settings


@pytest.mark.asyncio
async def test_switching_before_the_panel_has_loaded_does_not_ask(monkeypatch):
    """A switch that reaches the panel before its first load, as on a busy machine."""
    from servonaut.screens.settings.panels.general import GeneralPanel

    loads: List[Any] = []
    monkeypatch.setattr(GeneralPanel, "load", lambda self: loads.append(self))
    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        settings = await _open_general(app, pilot)
        panel = settings._current_panel()
        await _wait_until(
            pilot, lambda: panel in loads, "the panel should have been asked to load"
        )

        settings._request_switch("ai_provider")
        await _wait_until(
            pilot,
            lambda: settings._active_id == "ai_provider"
            or isinstance(app.screen, DiscardChangesModal),
            "the switch never happened",
        )

        assert not isinstance(app.screen, DiscardChangesModal)
        assert settings._active_id == "ai_provider"


@pytest.mark.asyncio
async def test_an_edit_after_the_panel_settled_still_asks():
    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        settings = await _open_general(app, pilot)
        panel = settings._current_panel()
        # Not settling is also true before the first load, and that load
        # would overwrite the edit below: wait for loaded AND settled.
        await _wait_until(
            pilot,
            lambda: panel._loaded and not panel._settling,
            "the panel never settled",
        )

        panel.query_one("#general_terminal", Input).value = "edited-by-the-user"
        await pilot.pause()
        settings._request_switch("ai_provider")
        await _wait_until(
            pilot,
            lambda: isinstance(app.screen, DiscardChangesModal),
            "an edit made after the load should ask before it is discarded",
        )

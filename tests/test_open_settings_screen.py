"""Chat "add a provider" actions open Settings on the AI Provider panel.

The chat panel's pinned-error banner and its empty-state modal both send the
user to provider settings. They call ``app.open_settings_screen``, which must
exist on the real app and open the right category.
"""
from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from textual.app import App
from textual.screen import Screen

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.settings import SettingsScreen
from servonaut.styles import CSS_FILES
from servonaut.widgets.chat_panel import ChatPanel
from tests.test_chat_panel_pinned_error import _build_panel


def _panel_with_app():
    panel = _build_panel()
    app = MagicMock(spec=ServonautApp)
    return panel, app, patch.object(
        ChatPanel, "app", new_callable=PropertyMock, return_value=app
    )


def test_pinned_add_provider_button_opens_ai_provider_settings():
    panel, app, bound = _panel_with_app()
    with bound:
        event = MagicMock()
        event.button.id = "btn-pinned-add-provider"
        panel.on_button_pressed(event)
    app.open_settings_screen.assert_called_once_with("ai_provider")
    app.notify.assert_not_called()


@pytest.mark.parametrize("choice", ["add_api_key", "ollama"])
def test_empty_state_choices_open_ai_provider_settings(choice):
    panel, app, bound = _panel_with_app()
    with bound:
        panel._push_empty_state_modal()
        _modal, on_choice = app.push_screen.call_args.args
        on_choice(choice)
    app.open_settings_screen.assert_called_once_with("ai_provider")


class _Host(App):
    """Minimal host with the real ``open_settings_screen``, on a plain screen."""

    CSS_PATH = CSS_FILES
    open_settings_screen = ServonautApp.open_settings_screen

    def __init__(self) -> None:
        super().__init__()
        config = AppConfig()
        self.config_manager = MagicMock()
        self.config_manager.get = MagicMock(return_value=config)
        self.auth_service = MagicMock()
        self.auth_service.is_authenticated = False
        self.auth_service.has_feature = MagicMock(return_value=False)

    def on_mount(self) -> None:
        self.push_screen(Screen())


@pytest.mark.asyncio
async def test_open_settings_screen_shows_the_requested_panel():
    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        app.open_settings_screen("ai_provider")
        await pilot.pause()

        screen = app.screen
        assert isinstance(screen, SettingsScreen)
        assert screen._active_id == "ai_provider"
        assert list(screen._panels) == ["ai_provider"]  # still lazy
        assert screen._sections["AI"].collapsed is False
        assert screen._sections["General"].collapsed is True
        assert "--active" in screen.query_one("#navbtn_ai_provider").classes


@pytest.mark.asyncio
async def test_open_settings_screen_switches_in_place_when_already_open():
    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        app.open_settings_screen()
        await pilot.pause()
        settings = app.screen
        assert settings._active_id == "general"

        app.open_settings_screen("ai_provider")
        await pilot.pause()

        assert app.screen is settings
        assert settings._active_id == "ai_provider"


@pytest.mark.asyncio
async def test_unknown_panel_falls_back_to_the_first_category():
    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        app.open_settings_screen("no_such_panel")
        await pilot.pause()
        assert app.screen._active_id == "general"


@pytest.mark.asyncio
async def test_open_settings_screen_reuses_settings_under_another_screen():
    """Help over Settings: close Help and reuse Settings, keeping its edits."""
    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        app.open_settings_screen()
        await pilot.pause()
        settings = app.screen
        app.push_screen(Screen())  # e.g. Help opened on top of Settings
        await pilot.pause()

        app.open_settings_screen("ai_provider")
        await pilot.pause()

        assert app.screen is settings
        assert sum(isinstance(s, SettingsScreen) for s in app.screen_stack) == 1
        assert settings._active_id == "ai_provider"


@pytest.mark.asyncio
async def test_nav_expands_the_group_of_the_panel_that_actually_opened():
    """A requested panel that fails to build falls back; so does the nav."""
    import dataclasses

    def broken_factory():
        raise RuntimeError("panel unavailable")

    app = _Host()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        screen = SettingsScreen(initial_panel="ai_provider")
        spec = screen._spec_of["ai_provider"]
        screen._spec_of["ai_provider"] = dataclasses.replace(spec, factory=broken_factory)
        app.switch_screen(screen)
        await pilot.pause()

        assert screen._active_id == "general"
        assert screen._sections["General"].collapsed is False
        assert screen._sections["AI"].collapsed is True

"""Tests for KeyManagementScreen instance override removal confirmation."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.key_management import KeyManagementScreen
from servonaut.styles import CSS_FILES
from tests._async_bounds import wait_until
from tests._native_actions import click_action


class _KeyHostApp(App):
    CSS_PATH = CSS_FILES

    def __init__(self, instance_keys: dict[str, str]) -> None:
        super().__init__()
        self.demo_mode = False
        self.redaction_service = None
        self.config = SimpleNamespace(default_key="", instance_keys=dict(instance_keys))
        self.saved_configs: list[object] = []
        self.config_manager = MagicMock()
        self.config_manager.get.side_effect = lambda: self.config
        self.config_manager.save.side_effect = self.saved_configs.append
        self.ssh_service = MagicMock()
        self.ssh_service.check_ssh_agent.return_value = True
        self.ssh_service.list_available_keys.return_value = []
        self.notifications: list[tuple[str, str | None]] = []
        self.screen_under_test = KeyManagementScreen()

    def on_mount(self) -> None:
        self.push_screen(self.screen_under_test)

    def notify(self, message: str, *, severity: str | None = None, **kwargs: object) -> None:
        self.notifications.append((str(message), severity))


async def _open_remove_dialog(app: _KeyHostApp, pilot) -> KeyManagementScreen:
    await wait_until(lambda: isinstance(app.screen, KeyManagementScreen))
    screen = app.screen_under_test
    await wait_until(
        lambda: bool(screen.query("#btn_remove_mapping"))
        and not screen.query_one("#btn_remove_mapping", Button).disabled
    )
    await click_action(pilot, "#btn_remove_mapping")
    await wait_until(
        lambda: isinstance(app.screen, ConfirmActionScreen)
        and bool(app.screen.query("#confirm_input"))
        and bool(app.screen.query("#btn_confirm"))
    )
    return screen


async def _confirm_dialog(app: _KeyHostApp, pilot) -> None:
    await wait_until(
        lambda: isinstance(app.screen, ConfirmActionScreen)
        and bool(app.screen.query("#confirm_input"))
        and bool(app.screen.query("#btn_confirm"))
    )
    modal = app.screen
    assert isinstance(modal, ConfirmActionScreen)
    confirm_input = modal.query_one("#confirm_input", Input)
    confirm_input.value = "remove"
    await wait_until(lambda: not modal.query_one("#btn_confirm", Button).disabled)
    await click_action(pilot, "#btn_confirm")
    await wait_until(lambda: isinstance(app.screen, KeyManagementScreen))


@pytest.mark.asyncio
async def test_remove_mapping_still_removes_after_table_reload_while_confirm_open() -> None:
    app = _KeyHostApp({"i-0123456789abcdef0": "~/.ssh/web_key.pem"})
    async with app.run_test(size=(140, 44)) as pilot:
        screen = await _open_remove_dialog(app, pilot)
        # Reloading the overrides table replaces every DataTable RowKey.
        screen.refresh_after_demo_toggle()
        await _confirm_dialog(app, pilot)

        assert "i-0123456789abcdef0" not in app.config.instance_keys
        assert len(app.saved_configs) == 1
        assert screen.query_one("#btn_remove_mapping", Button).disabled is True
        assert any(
            severity == "information" and "Removed key mapping" in msg
            for msg, severity in app.notifications
        )


@pytest.mark.asyncio
async def test_remove_mapping_notifies_when_override_disappeared_before_confirm() -> None:
    app = _KeyHostApp({"i-0123456789abcdef0": "~/.ssh/web_key.pem"})
    async with app.run_test(size=(140, 44)) as pilot:
        screen = await _open_remove_dialog(app, pilot)
        app.config.instance_keys.clear()
        screen._load_instance_mappings()
        await _confirm_dialog(app, pilot)

        assert app.saved_configs == []
        assert screen.query_one("#instance_keys_table", DataTable).row_count == 1
        assert any(
            severity == "warning" and "i-0123456789abcdef0" in msg
            for msg, severity in app.notifications
        )

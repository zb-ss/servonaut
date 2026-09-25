"""OVH VPS action screens run inside a real Textual app.

Covers the reverse-DNS line on the server actions screen and the reinstall
confirmation, both of which used Textual APIs that Textual 8 changed.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input, Static

from servonaut.config.schema import AppConfig
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.ovh_reinstall import OVHReinstallScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services.connection_service import ConnectionService

VPS = {
    "id": "vps-web-1",
    "name": "web-1",
    "provider_type": "vps",
    "is_ovh": True,
    "public_ip": "192.0.2.1",
}


class VpsHostApp(App):
    demo_mode = False
    memory_service = None
    redaction_service = None
    ovh_audit = None

    def __init__(self, vps_service) -> None:
        super().__init__()
        self.config = AppConfig()
        self.config_manager = Mock()
        self.config_manager.get.return_value = self.config
        self.connection_service = ConnectionService(self.config_manager)
        self.ovh_vps_service = vps_service

    def connection_instance(self, instance: dict) -> dict:
        return instance

    def real_instance_id(self, instance_id: str) -> str:
        return instance_id


async def _wait_for(pilot, predicate, what: str) -> None:
    for _ in range(1500):
        if predicate():
            return
        await pilot.pause(0.01)
    raise AssertionError(f"timed out waiting for {what}")


@pytest.mark.asyncio
async def test_vps_actions_show_the_reverse_dns() -> None:
    service = SimpleNamespace(get_reverse_dns=AsyncMock(return_value="mail-[b]1[/b].example.test"))
    app = VpsHostApp(service)
    async with app.run_test(size=(155, 47)) as pilot:
        screen = ServerActionsScreen(dict(VPS))
        await app.push_screen(screen)

        def info() -> str:
            return str(screen.query_one("#server_info", Static).content)

        await _wait_for(pilot, lambda: "Reverse DNS" in info(), "the reverse DNS line")
        # The name comes from the provider: shown literally, never as markup.
        assert "[dim]Reverse DNS:[/dim] mail-\\[b]1\\[/b].example.test" in info()
        assert "[dim]Public IP:[/dim] 192.0.2.1\n[dim]Reverse DNS:[/dim]" in info()
        service.get_reverse_dns.assert_awaited_once_with("vps-web-1", "192.0.2.1")
        assert app.screen is screen


def _reinstall_service() -> MagicMock:
    service = MagicMock()
    service.list_images = AsyncMock(return_value=[
        {"id": "img-1", "name": "Debian 12", "os_type": "linux"},
    ])
    service.reinstall = AsyncMock(return_value=True)
    return service


async def _open_confirmation(app: VpsHostApp, pilot) -> OVHReinstallScreen:
    screen = OVHReinstallScreen(dict(VPS))
    await app.push_screen(screen)
    await _wait_for(
        pilot, lambda: screen.query_one("#images_table", DataTable).row_count == 1, "images",
    )
    screen.query_one("#btn_reinstall", Button).press()
    await _wait_for(pilot, lambda: isinstance(app.screen, ConfirmActionScreen), "the confirmation")
    return screen


@pytest.mark.asyncio
async def test_reinstall_asks_for_the_server_name_then_reinstalls() -> None:
    service = _reinstall_service()
    app = VpsHostApp(service)
    async with app.run_test(size=(155, 47)) as pilot:
        screen = await _open_confirmation(app, pilot)
        modal = app.screen
        modal.query_one("#confirm_input", Input).value = "web-1"
        button = modal.query_one("#btn_confirm", Button)
        await _wait_for(pilot, lambda: not button.disabled, "the confirm button")
        button.press()
        await _wait_for(pilot, lambda: service.reinstall.await_count == 1, "the reinstall")
        service.reinstall.assert_awaited_once_with("vps-web-1", "img-1")
        assert app.screen is screen


@pytest.mark.asyncio
async def test_backing_out_of_the_reinstall_sends_nothing() -> None:
    service = _reinstall_service()
    app = VpsHostApp(service)
    async with app.run_test(size=(155, 47)) as pilot:
        screen = await _open_confirmation(app, pilot)
        await pilot.press("escape")
        await _wait_for(pilot, lambda: app.screen is screen, "the reinstall screen")
        await pilot.pause(0.05)
        service.reinstall.assert_not_awaited()

"""OVH VPS action screens run inside a real Textual app.

Covers the reverse-DNS line on the server actions screen and the reinstall
confirmation, both of which used Textual APIs that Textual 8 changed.
"""

from __future__ import annotations

import asyncio
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


async def _open_confirmation(app: VpsHostApp, pilot, vps: dict = VPS) -> OVHReinstallScreen:
    screen = OVHReinstallScreen(dict(vps))
    await app.push_screen(screen)
    await _wait_for(
        pilot, lambda: screen.query_one("#images_table", DataTable).row_count == 1, "images",
    )
    screen.query_one("#btn_reinstall", Button).press()
    await _wait_for(pilot, lambda: isinstance(app.screen, ConfirmActionScreen), "the confirmation")
    # The modal joins the stack before it is composed; it is ready once it
    # holds the focus.
    await _wait_for(pilot, lambda: app.screen.focused is not None, "the confirmation's focus")
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
        button = screen.query_one("#btn_reinstall", Button)
        await _wait_for(pilot, lambda: not button.disabled, "Reinstall offered again")


async def _confirm(app: VpsHostApp, pilot, name: str) -> None:
    modal = app.screen
    modal.query_one("#confirm_input", Input).value = name
    button = modal.query_one("#btn_confirm", Button)
    await _wait_for(pilot, lambda: not button.disabled, "the confirm button")
    button.press()


@pytest.mark.asyncio
async def test_a_second_press_cannot_cancel_a_running_reinstall() -> None:
    service = _reinstall_service()
    release = asyncio.Event()

    async def slow_reinstall(*_args):
        await release.wait()
        return True

    service.reinstall = AsyncMock(side_effect=slow_reinstall)
    app = VpsHostApp(service)
    async with app.run_test(size=(155, 47)) as pilot:
        screen = await _open_confirmation(app, pilot)
        await _confirm(app, pilot, "web-1")
        await _wait_for(pilot, lambda: service.reinstall.await_count == 1, "the reinstall")

        button = screen.query_one("#btn_reinstall", Button)
        assert button.disabled
        button.press()  # a second press while the first is running
        await pilot.pause(0.05)
        assert app.screen is screen  # no second confirmation

        release.set()
        await _wait_for(
            pilot,
            lambda: any("has been queued" in n.message for n in app._notifications),
            "the queued notice",
        )
        service.reinstall.assert_awaited_once_with("vps-web-1", "img-1")
        assert button.disabled  # queued: the same reinstall is not offered again


@pytest.mark.asyncio
async def test_a_failed_reinstall_offers_the_button_again() -> None:
    service = _reinstall_service()
    service.reinstall = AsyncMock(side_effect=RuntimeError("VPS is busy"))
    app = VpsHostApp(service)
    async with app.run_test(size=(155, 47)) as pilot:
        screen = await _open_confirmation(app, pilot)
        await _confirm(app, pilot, "web-1")
        await _wait_for(pilot, lambda: service.reinstall.await_count == 1, "the reinstall")
        button = screen.query_one("#btn_reinstall", Button)
        await _wait_for(pilot, lambda: not button.disabled, "Reinstall offered again")
        await _wait_for(
            pilot,
            lambda: any(n.message == "Reinstall failed: VPS is busy" for n in app._notifications),
            "the failure notice",
        )


@pytest.mark.asyncio
async def test_reinstall_shows_provider_names_literally() -> None:
    service = _reinstall_service()
    service.list_images = AsyncMock(return_value=[
        {"id": "img-1", "name": "Debian [red]12[/red]", "os_type": "linux"},
    ])
    app = VpsHostApp(service)
    async with app.run_test(size=(155, 47)) as pilot:
        await _open_confirmation(app, pilot, dict(VPS, name="web-[b]1[/b]"))
        description = app.screen._description
        assert "Reinstall [bold]web-\\[b]1\\[/b][/bold] with" in description
        assert "[bold]Debian \\[red]12\\[/red][/bold]." in description


@pytest.mark.parametrize(
    "instance, heading",
    [
        (dict(VPS, name="web-[b]1[/b]", os="Debian [red]12"), "OVH Server: web-\\[b]1\\[/b]"),
        ({"id": "custom-1", "name": "web-[b]1[/b]", "is_custom": True,
          "public_ip": "10.0.0.5", "group": "[i]edge"}, "Server: web-\\[b]1\\[/b]"),
        ({"id": "i-0abc", "name": "web-[b]1[/b]", "public_ip": "9.9.9.9",
          "region": "eu-west-1", "state": "running"}, "Server: web-\\[b]1\\[/b]"),
    ],
    ids=["ovh", "custom", "aws"],
)
def test_server_info_shows_names_literally(instance, heading) -> None:
    from unittest.mock import PropertyMock, patch

    from rich.text import Text

    app = VpsHostApp(SimpleNamespace())
    screen = ServerActionsScreen(instance)
    with patch.object(ServerActionsScreen, "app", new_callable=PropertyMock, return_value=app):
        info = screen._build_server_info()

    assert f"[bold cyan]{heading}[/bold cyan]" in info
    plain = Text.from_markup(info).plain
    assert "web-[b]1[/b]" in plain
    if "os" in instance:
        assert "OS: Debian [red]12" in plain
    if "group" in instance:
        assert "Group: [i]edge" in plain

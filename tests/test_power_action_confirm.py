"""Power actions that interrupt a server ask yes/no first, in every manager.

Runs the AWS, OVH and Hetzner manager screens inside a real Textual app so
the confirmation goes through ``push_screen_wait`` in a worker, exactly as
the user sees it.
"""

from __future__ import annotations

from typing import Callable
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Static

from servonaut.screens.aws_manager import AWSManagerScreen
from servonaut.screens.hetzner_manager import HetznerManagerScreen
from servonaut.screens.ovh_manager import OVHManagerScreen
from servonaut.screens.power_confirm import (
    PowerActionConfirmModal,
    confirm_and_run_power_action,
)


class ManagerHost(App):
    demo_mode = False
    redaction_service = None
    aws_audit = None
    ovh_audit = None
    ovh_service = None
    hetzner_service = None
    aws_service = None


async def _wait_for(pilot, predicate: Callable[[], bool], what: str) -> None:
    for _ in range(1500):
        if predicate():
            return
        await pilot.pause(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def _hetzner_service(state: str = "running") -> MagicMock:
    svc = MagicMock()
    svc.fetch_instances_cached = AsyncMock(return_value=[{
        "id": "42", "name": "web-[b]1[/b]", "type": "cx22", "state": state,
        "public_ip": "9.9.9.9", "region": "fsn1", "is_hetzner": True,
    }])
    for method in ("power_on", "power_off", "shutdown", "reboot"):
        setattr(svc, method, AsyncMock(return_value=True))
    return svc


def _aws_service() -> MagicMock:
    svc = MagicMock()
    svc.fetch_instances_cached = AsyncMock(return_value=[{
        "id": "i-0abc", "name": "app-1", "type": "t3.micro", "state": "running",
        "public_ip": "9.9.9.9", "region": "eu-west-1",
    }])
    svc.stop_instance = AsyncMock(return_value=True)
    svc.reboot_instance = AsyncMock(return_value=True)
    return svc


def _ovh_service() -> MagicMock:
    svc = MagicMock()
    svc.fetch_instances_cached = AsyncMock(return_value=[{
        "id": "vps-1.example", "name": "mail-1", "type": "vps", "state": "running",
        "provider_type": "vps", "public_ip": "9.9.9.9", "region": "GRA", "is_ovh": True,
    }])
    svc.stop_instance = AsyncMock(return_value=True)
    svc.reboot_instance = AsyncMock(return_value=True)
    return svc


async def _open(app: ManagerHost, pilot, screen, table_id: str) -> None:
    await app.push_screen(screen)
    await _wait_for(
        pilot, lambda: screen.query_one(f"#{table_id}", DataTable).row_count == 1, "the row",
    )
    screen.query_one(f"#{table_id}", DataTable).focus()
    await pilot.pause()


async def _press_and_get_modal(app, pilot, screen, button_id: str) -> PowerActionConfirmModal:
    button = screen.query_one(f"#{button_id}", Button)
    await _wait_for(pilot, lambda: not button.disabled, f"{button_id} enabled")
    button.press()
    await _wait_for(pilot, lambda: isinstance(app.screen, PowerActionConfirmModal), "the question")
    modal = app.screen
    # The modal joins the screen stack before it is composed; it is ready for
    # keys and queries once it holds the focus.
    await _wait_for(pilot, lambda: modal.focused is not None, "the question's focus")
    return modal


@pytest.mark.asyncio
async def test_hetzner_power_off_asks_and_enter_means_no() -> None:
    app = ManagerHost()
    app.hetzner_service = _hetzner_service()
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerManagerScreen()
        await _open(app, pilot, screen, "hetzner_mgr_table")
        modal = await _press_and_get_modal(app, pilot, screen, "btn_hetzner_mgr_power_off")

        assert app.focused.id == "btn_power_confirm_no"
        # The server name is provider data: shown literally, never as markup.
        assert "Power off [bold]web-\\[b]1\\[/b][/bold] (Hetzner Cloud)?" in modal.message
        message = str(modal.query_one("#power_confirm_message", Static).content)
        assert "unsaved data can be lost" in message

        await pilot.press("enter")
        await _wait_for(pilot, lambda: app.screen is screen, "the manager")
        await pilot.pause(0.05)
        app.hetzner_service.power_off.assert_not_awaited()


@pytest.mark.parametrize(
    "button_id, method",
    [
        ("btn_hetzner_mgr_power_off", "power_off"),
        ("btn_hetzner_mgr_shutdown", "shutdown"),
        ("btn_hetzner_mgr_reboot", "reboot"),
    ],
)
@pytest.mark.asyncio
async def test_hetzner_disruptive_actions_run_after_yes(button_id: str, method: str) -> None:
    app = ManagerHost()
    app.hetzner_service = _hetzner_service()
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerManagerScreen()
        await _open(app, pilot, screen, "hetzner_mgr_table")
        modal = await _press_and_get_modal(app, pilot, screen, button_id)
        getattr(app.hetzner_service, method).assert_not_awaited()

        modal.query_one("#btn_power_confirm_yes", Button).press()
        await _wait_for(
            pilot, lambda: getattr(app.hetzner_service, method).await_count == 1, method,
        )
        getattr(app.hetzner_service, method).assert_awaited_once_with("42")


@pytest.mark.asyncio
async def test_hetzner_start_does_not_ask() -> None:
    app = ManagerHost()
    app.hetzner_service = _hetzner_service(state="off")
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerManagerScreen()
        await _open(app, pilot, screen, "hetzner_mgr_table")
        button = screen.query_one("#btn_hetzner_mgr_power_on", Button)
        await _wait_for(pilot, lambda: not button.disabled, "start enabled")
        button.press()
        await _wait_for(pilot, lambda: app.hetzner_service.power_on.await_count == 1, "start")
        assert not isinstance(app.screen, PowerActionConfirmModal)


@pytest.mark.parametrize(
    "button_id, method",
    [("btn_aws_mgr_stop", "stop_instance"), ("btn_aws_mgr_reboot", "reboot_instance")],
)
@pytest.mark.asyncio
async def test_aws_stop_and_reboot_ask_first(button_id: str, method: str) -> None:
    app = ManagerHost()
    app.aws_service = _aws_service()
    async with app.run_test(size=(160, 48)) as pilot:
        screen = AWSManagerScreen()
        await _open(app, pilot, screen, "aws_mgr_table")
        modal = await _press_and_get_modal(app, pilot, screen, button_id)
        assert "app-1" in modal.message and "AWS EC2, eu-west-1" in modal.message

        await pilot.press("escape")
        await _wait_for(pilot, lambda: app.screen is screen, "the manager")
        getattr(app.aws_service, method).assert_not_awaited()

        modal = await _press_and_get_modal(app, pilot, screen, button_id)
        modal.query_one("#btn_power_confirm_yes", Button).press()
        await _wait_for(pilot, lambda: getattr(app.aws_service, method).await_count == 1, method)
        getattr(app.aws_service, method).assert_awaited_once_with("i-0abc", "eu-west-1")


@pytest.mark.parametrize(
    "button_id, method",
    [("btn_ovh_mgr_stop", "stop_instance"), ("btn_ovh_mgr_reboot", "reboot_instance")],
)
@pytest.mark.asyncio
async def test_ovh_stop_and_reboot_ask_first(button_id: str, method: str) -> None:
    app = ManagerHost()
    app.ovh_service = _ovh_service()
    async with app.run_test(size=(160, 48)) as pilot:
        screen = OVHManagerScreen()
        await _open(app, pilot, screen, "ovh_mgr_table")
        modal = await _press_and_get_modal(app, pilot, screen, button_id)
        assert "mail-1" in modal.message and "OVHcloud VPS" in modal.message

        modal.query_one("#btn_power_confirm_yes", Button).press()
        await _wait_for(pilot, lambda: getattr(app.ovh_service, method).await_count == 1, method)
        getattr(app.ovh_service, method).assert_awaited_once_with("vps-1.example", "vps")


@pytest.mark.asyncio
async def test_hetzner_manager_lists_a_server_created_from_it() -> None:
    from textual.widgets import Input

    from servonaut.config.schema import AppConfig
    from servonaut.screens.confirm_action import ConfirmActionScreen
    from servonaut.screens.hetzner_create import HetznerCreateScreen

    app = ManagerHost()
    app.config_manager = MagicMock()
    app.config_manager.get.return_value = AppConfig()
    app.instances = []
    svc = _hetzner_service()
    before = list(svc.fetch_instances_cached.return_value)
    after = before + [{
        "id": "43", "name": "web-2", "type": "cx22", "state": "running",
        "public_ip": "9.9.9.8", "region": "fsn1", "is_hetzner": True,
    }]
    svc.list_server_types = AsyncMock(return_value=[
        {"name": "cx22", "cores": 2, "memory_gb": 4, "disk_gb": 40,
         "architecture": "x86", "monthly_price_gross": "4.00"},
    ])
    svc.list_images = AsyncMock(return_value=[{"name": "debian-12", "architecture": "x86"}])
    svc.list_locations = AsyncMock(return_value=[{"name": "fsn1"}])
    svc.list_ssh_keys = AsyncMock(return_value=[{"id": 1, "name": "deploy", "fingerprint": "f"}])

    async def create_server(**_kwargs):
        svc.fetch_instances_cached.return_value = after
        return after[-1]

    svc.create_server = AsyncMock(side_effect=create_server)
    app.hetzner_service = svc

    def names(screen) -> list[str]:
        table = screen.query_one("#hetzner_mgr_table", DataTable)
        return [str(table.get_row_at(i)[1]) for i in range(table.row_count)]

    async with app.run_test(size=(160, 48)) as pilot:
        manager = HetznerManagerScreen()
        await _open(app, pilot, manager, "hetzner_mgr_table")
        manager.query_one("#btn_hetzner_mgr_new", Button).press()
        await _wait_for(pilot, lambda: isinstance(app.screen, HetznerCreateScreen), "the wizard")
        wizard = app.screen
        await _wait_for(
            pilot,
            lambda: wizard.query_one("#hetzner_keys_table", DataTable).row_count == 1,
            "the wizard's tables",
        )
        wizard.query_one("#hetzner_input_name", Input).value = "web-2"
        wizard.query_one("#btn_hetzner_create_submit", Button).press()
        await _wait_for(pilot, lambda: isinstance(app.screen, ConfirmActionScreen), "confirm")
        confirm = app.screen
        confirm.query_one("#confirm_input", Input).value = "create"
        button = confirm.query_one("#btn_confirm", Button)
        await _wait_for(pilot, lambda: not button.disabled, "the confirm button")
        button.press()

        await _wait_for(pilot, lambda: app.screen is manager, "back on the manager")
        await _wait_for(pilot, lambda: "web-2" in names(manager), "the new server listed")
        svc.create_server.assert_awaited_once()


async def _run_shared_flow(*, answer: bool, prompt) -> tuple[MagicMock, AsyncMock, list, MagicMock]:
    app = MagicMock()
    app.push_screen_wait = AsyncMock(return_value=answer)
    run = AsyncMock()
    statuses: list = []
    declined = MagicMock()
    await confirm_and_run_power_action(
        app, prompt=prompt, server_name="web-[b]1[/b]", provider="Hetzner Cloud",
        in_progress_verb="Rebooting", set_status=statuses.append, run=run,
        on_declined=declined,
    )
    return app, run, statuses, declined


@pytest.mark.asyncio
async def test_shared_flow_runs_after_yes_and_escapes_the_status() -> None:
    app, run, statuses, declined = await _run_shared_flow(
        answer=True, prompt=("Reboot", "It restarts."),
    )
    app.push_screen_wait.assert_awaited_once()
    run.assert_awaited_once_with()
    assert statuses == ["[dim]Rebooting web-\\[b]1\\[/b]…[/dim]"]
    declined.assert_not_called()


@pytest.mark.asyncio
async def test_shared_flow_reports_a_no_and_runs_nothing() -> None:
    _, run, statuses, declined = await _run_shared_flow(
        answer=False, prompt=("Reboot", "It restarts."),
    )
    run.assert_not_awaited()
    assert statuses == []
    declined.assert_called_once_with()


@pytest.mark.asyncio
async def test_shared_flow_without_a_prompt_does_not_ask() -> None:
    app, run, _, _ = await _run_shared_flow(answer=False, prompt=None)
    app.push_screen_wait.assert_not_awaited()
    run.assert_awaited_once_with()

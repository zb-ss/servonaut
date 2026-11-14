"""Server tools retain workspace preferences through nested navigation."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual import events
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.file_browser import FileBrowserScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.ovh_reinstall import OVHReinstallScreen
from servonaut.screens.ovh_resize import OVHResizeScreen
from servonaut.screens.scan_results import ScanResultsScreen
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services.connection_service import ConnectionService
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until

pytestmark = pytest.mark.usefixtures("navigation_open")


def _server(name: str) -> dict:
    return {
        "id": f"id-{name}", "name": name, "is_custom": True,
        "public_ip": "192.0.2.10", "state": "running", "type": "small",
        "private_ip": "10.0.0.1", "region": "local", "key_name": "",
    }


class _ServerWorkspaceApp(ServonautApp):
    """Use real screen routing and CSS without starting services or SSH."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__()
        self.workspace_state.navigation_visible = navigation_visible
        self.instances = [_server("web-1"), _server("db-1")]
        self.config_manager = Mock()
        self.config_manager.get.return_value = AppConfig()
        self.connection_service = ConnectionService(self.config_manager)
        self.ssh_service = Mock()
        self.ssh_service.get_key_path.return_value = None
        self.cache_service = SimpleNamespace(
            is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [],
        )
        self.keyword_store = Mock()
        self.keyword_store.get_results.return_value = [
            {"source": "example.log", "content": "ready", "timestamp": ""},
        ]
        self.scan_service = SimpleNamespace(scan_server=AsyncMock(return_value=[]))
        self.ovh_vps_service = SimpleNamespace(
            list_upgrade_models=AsyncMock(return_value=[{"name": "larger", "vcpus": 2}]),
            list_images=AsyncMock(return_value=[{"id": "img-1", "name": "Linux", "os_type": "linux"}]),
            upgrade=AsyncMock(), reinstall=AsyncMock(),
        )
        self.ovh_audit = Mock()

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(InstanceListScreen())

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


SCREEN_CASES = [
    (FileBrowserScreen, "Files", "#remote_tree", ("#remote_tree",)),
    (SCPTransferScreen, "Transfer · web-1", "#local_path_input",
     ("#local_path_input", "#remote_path_input", "#transfer_button", "#cancel_button")),
    (ScanResultsScreen, "Keyword scan", "#scan_button", ("#scan_button", "#results_table")),
    (OVHResizeScreen, "Resize", "#resize_container", ("#models_table", "#btn_upgrade", "#btn_back")),
    (OVHReinstallScreen, "Reinstall", "#reinstall_container", ("#images_table", "#btn_reinstall", "#btn_back")),
]


async def _click_navigation(app: _ServerWorkspaceApp, pilot: Pilot) -> None:
    button = app.screen.query_one("#workspace_navigation", Button)
    await wait_until(lambda: not button.has_class("-active"))
    assert await pilot.click(button)
    await pilot.pause()


async def _assert_reachable(
    app: _ServerWorkspaceApp, pilot: Pilot, selector: str,
) -> None:
    widget = app.screen.query_one(selector)
    widget.focus()
    widget.scroll_visible(animate=False)
    await pilot.pause()
    assert app.focused is widget
    assert widget.region.width > 0 and widget.region.height > 0
    assert app.screen.region.contains(*widget.region.center)
    assert app.get_widget_at(*widget.region.center)[0] is widget


async def _tab_to(app: _ServerWorkspaceApp, pilot: Pilot, selector: str) -> None:
    target = app.screen.query_one(selector)
    assert target in app.screen.focus_chain
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is target:
            return
        await pilot.press("tab")
    raise AssertionError(f"Tab did not reach {selector}")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("screen_type,context,focus,targets", SCREEN_CASES)
async def test_server_tools_keep_initial_focus_and_reachable_controls(
    size: tuple[int, int], visible: bool, screen_type: type[WorkspaceScreen],
    context: str, focus: str, targets: tuple[str, ...],
) -> None:
    app = _ServerWorkspaceApp(visible)
    async with app.run_test(size=size) as pilot:
        screen = screen_type(_server("web-1"))
        await app.push_screen(screen)
        await pilot.pause()
        assert isinstance(screen, WorkspaceScreen)
        assert screen.query_one(Sidebar).display is visible
        assert app.focused is screen.query_one(focus)
        assert screen.query_one("#workspace_context", Static).render().plain == context
        for selector in ("#workspace_navigation", "#workspace_chat"):
            button = screen.query_one(selector, Button)
            assert app.get_widget_at(*button.region.center)[0] is button
        for selector in targets:
            await _assert_reachable(app, pilot, selector)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("shortcut,screen_type", [("4", SCPTransferScreen), ("5", ScanResultsScreen)])
async def test_deep_return_applies_navigation_preference_and_retains_selected_server(
    size: tuple[int, int], visible: bool, shortcut: str,
    screen_type: type[WorkspaceScreen],
) -> None:
    app = _ServerWorkspaceApp(visible)
    async with app.run_test(size=size) as pilot:
        fleet = app.screen
        table = fleet.query_one(InstanceTable)
        table.move_cursor(row=1)
        await pilot.press("o")
        actions = app.screen
        assert isinstance(actions, ServerActionsScreen)
        await pilot.press(shortcut)
        tool = app.screen
        assert isinstance(tool, screen_type)
        assert tool._instance["id"] == app.instances[1]["id"]
        assert tool.query_one(Sidebar).display is visible
        await _click_navigation(app, pilot)
        for expected in (actions, fleet):
            await pilot.press("escape")
            await wait_until(lambda: app.screen is expected)
            await pilot.pause()
            assert expected.query_one(Sidebar).display is not visible
        assert table.cursor_row == 1
        assert app.focused is table


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,key", [(FileBrowserScreen, "r"), (ScanResultsScreen, "s")])
async def test_navigation_letters_are_muted_and_escape_returns_without_popping(
    screen_type: type[WorkspaceScreen], key: str,
) -> None:
    app = _ServerWorkspaceApp(False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = screen_type(_server("web-1"))
        await app.push_screen(screen)
        origin = screen.query_one(screen.AUTO_FOCUS)
        await pilot.press("shift+f6", key)
        assert app.screen is screen and screen.query_one(Sidebar).navigation_mode
        app.scan_service.scan_server.assert_not_awaited()
        if screen_type is FileBrowserScreen:
            screen._remote_tree._cache["sentinel"] = []
            await pilot.press("r")
            assert "sentinel" in screen._remote_tree._cache
        await pilot.press("escape")
        assert app.screen is screen
        assert app.focused is origin
        assert not screen.query_one(Sidebar).display
        await pilot.press(key)
        if screen_type is FileBrowserScreen:
            assert screen._remote_tree._cache == {}
        else:
            await wait_until(lambda: app.scan_service.scan_server.await_count == 1)
            app.scan_service.scan_server.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,table_id,action_id,method", [
    (OVHResizeScreen, "models_table", "btn_upgrade", "upgrade"),
    (OVHReinstallScreen, "images_table", "btn_reinstall", "reinstall"),
])
async def test_worker_confirmation_keeps_modal_focus_and_restores_hidden_workspace(
    screen_type: type[WorkspaceScreen], table_id: str, action_id: str, method: str,
) -> None:
    app = _ServerWorkspaceApp(False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = screen_type({"id": "vps-1", "name": "web-1", "is_ovh": True})
        await app.push_screen(screen)
        table = screen.query_one(f"#{table_id}", DataTable)
        await wait_until(lambda: table.row_count == 1)
        table.focus()
        await pilot.press("shift+f6")
        screen.query_one(f"#{action_id}", Button).press()
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        modal = app.screen
        await wait_until(lambda: modal.focused is not None)
        origin = modal.query_one("#confirm_input", Input)
        assert app.focused is origin
        assert not screen.query_one(Sidebar).navigation_mode
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is origin
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        await pilot.pause()
        assert not screen.query_one(Sidebar).display
        assert app.focused is table
        getattr(app.ovh_vps_service, method).assert_not_awaited()
        await wait_until(lambda: app.ovh_audit.log_action.called)
        assert app.ovh_audit.log_action.call_args.kwargs["confirmed"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("screen_type,table_id,action_id", [
    (OVHResizeScreen, "models_table", "btn_upgrade"),
    (OVHReinstallScreen, "images_table", "btn_reinstall"),
])
async def test_compact_provider_tools_allow_tab_navigation_without_row_confirmation(
    visible: bool, screen_type: type[WorkspaceScreen], table_id: str, action_id: str,
) -> None:
    app = _ServerWorkspaceApp(visible)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = screen_type({"id": "vps-1", "name": "web-1", "is_ovh": True})
        await app.push_screen(screen)
        table = screen.query_one(f"#{table_id}", DataTable)
        await wait_until(lambda: table.row_count == 1)
        await _tab_to(app, pilot, f"#{table_id}")
        await pilot.press("enter")
        assert app.screen is screen
        app.ovh_vps_service.upgrade.assert_not_awaited()
        app.ovh_vps_service.reinstall.assert_not_awaited()
        await _tab_to(app, pilot, f"#{action_id}")
        action = screen.query_one(f"#{action_id}", Button)
        await pilot.pause()
        assert screen.region.contains(*action.region.center)
        assert app.get_widget_at(*action.region.center)[0] is action
        assert screen.query_one(Sidebar).display is visible


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["web-[red]1[/red]", "web-[/red]1"])
async def test_resize_title_renders_provider_name_literally(name: str) -> None:
    app = _ServerWorkspaceApp(False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = OVHResizeScreen({"id": "vps-1", "name": name, "is_ovh": True})
        await app.push_screen(screen)
        await pilot.pause()
        assert screen.query_one("#resize_title", Static).render().plain == f"Resize VPS: {name}"

"""OVH resource screens preserve account and server context in the workspace."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual import events
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, OVHAccount
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.ovh_billing import OVHBillingScreen
from servonaut.screens.ovh_firewall import OVHFirewallScreen
from servonaut.screens.ovh_ip_management import OVHIPManagementScreen
from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen
from servonaut.screens.ovh_storage import OVHStorageScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services.accounts import AccountRegistry, OVHAccountServices
from servonaut.services.connection_service import ConnectionService
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until

pytestmark = pytest.mark.usefixtures("navigation_open")


def _server(name: str) -> dict:
    return {
        "id": f"vps-{name}", "name": name, "is_ovh": True,
        "provider_type": "vps", "public_ip": "192.0.2.10",
        "private_ip": "10.0.0.1", "state": "running", "type": "small",
        "region": "local", "key_name": "", "account": "ovh",
    }


def _services(label: str) -> OVHAccountServices:
    return OVHAccountServices(
        ovh=SimpleNamespace(check_credentials=AsyncMock(return_value=None)),
        billing=SimpleNamespace(
            get_current_usage=AsyncMock(return_value={}),
            get_monthly_spend_history=AsyncMock(return_value=[]),
            get_invoices=AsyncMock(return_value=[
                {"billId": f"{label}-bill", "date": "2026-01-01"},
            ]),
            get_service_list=AsyncMock(return_value=[]),
        ),
        storage=SimpleNamespace(list_volumes=AsyncMock(return_value=[
            {"id": f"{label}-vol", "name": f"{label}-volume", "size": 10},
        ])),
        cloud=SimpleNamespace(list_ssh_keys=AsyncMock(return_value=[
            {"id": f"{label}-key", "name": f"{label}-key", "publicKey": "ssh-ed25519 example"},
        ])),
        ip=SimpleNamespace(
            list_ips=AsyncMock(return_value=[{"ip": "10.0.0.1/32", "type": "failover"}]),
            get_firewall=AsyncMock(return_value={"enabled": False}),
            list_firewall_rules=AsyncMock(return_value=[{"sequence": 0, "action": "permit"}]),
            toggle_firewall=AsyncMock(),
        ),
        snapshot=SimpleNamespace(
            list_vps_snapshots=AsyncMock(return_value=[{"id": "snap-1", "name": "daily"}]),
            get_vps_backup_options=AsyncMock(return_value={}),
            restore_vps_snapshot=AsyncMock(),
        ),
        vps=SimpleNamespace(get_reverse_dns=AsyncMock(return_value="web.example.test")),
    )


class _ResourceApp(ServonautApp):
    """Real navigation and registered CSS, with every provider behind a fake."""

    def __init__(self, visible: bool = True, *, multi: bool = False) -> None:
        super().__init__()
        config = AppConfig()
        config.aws.enabled = False
        config.ovh.enabled = True
        config.ovh.application_key = "example-key"
        config.ovh.cloud_project_ids = ["project-primary"]
        if multi:
            config.ovh.accounts = [OVHAccount(
                label="backup", client_id="example-client", client_secret="example-secret",
                cloud_project_ids=["project-backup"],
            )]
        self.config_manager = Mock()
        self.config_manager.get.return_value = config
        self.connection_service = ConnectionService(self.config_manager)
        self.accounts = AccountRegistry(config)
        self.bundles: dict[str, OVHAccountServices] = {}
        for ref in self.accounts.accounts("ovh"):
            bundle = _services(ref.label)
            self.bundles[ref.label] = bundle
            self.accounts._state.providers["ovh"].services[ref.key] = bundle.ovh
            self.accounts._state.ovh_bundles[ref.key] = bundle
        self.instances = [_server("web-1"), _server("db-1")]
        self.workspace_state.navigation_visible = visible
        self.cache_service = SimpleNamespace(
            is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [],
        )
        self.ovh_audit = Mock()

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(InstanceListScreen())

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()

    def provider_inventory(self, provider: str) -> None:
        # The fleet is seeded above; these journeys exercise resource loaders,
        # not the independent all-provider fleet refresh workers.
        return None


SCREEN_CASES = [
    (OVHBillingScreen, "Billing", "invoices_table", "btn_back"),
    (OVHStorageScreen, "Block storage", "volumes_table", "btn_create"),
    (OVHIPManagementScreen, "IP management", "ip_table", "btn_move"),
    (OVHSSHKeysScreen, "SSH keys", "ssh_keys_table", "btn_add_key"),
    (OVHSnapshotsScreen, "Snapshots", "snapshots_table", "btn_restore"),
    (OVHFirewallScreen, "Firewall", "rules_table", "btn_toggle"),
]

# Measured on the unchanged screen sources with the accepted dependency base
# at both supported sizes; workspace chrome must preserve these initial targets.
INITIAL_FOCUS = {
    OVHBillingScreen: "billing_container",
    OVHStorageScreen: "storage_container",
    OVHIPManagementScreen: "ip_mgmt_container",
    OVHSSHKeysScreen: "ovh_ssh_keys_container",
    OVHSnapshotsScreen: "snapshots_container",
    OVHFirewallScreen: "firewall_container",
}


def _screen(screen_type: type[WorkspaceScreen], name: str = "web-1") -> WorkspaceScreen:
    if screen_type in {OVHSnapshotsScreen, OVHFirewallScreen}:
        return screen_type(_server(name))
    return screen_type()


async def _toggle_navigation(app: _ResourceApp, pilot: Pilot) -> None:
    button = app.screen.query_one("#workspace_navigation", Button)
    await wait_until(lambda: not button.has_class("-active"))
    assert await pilot.click(button)
    await pilot.pause()


async def _tab_to(app: _ResourceApp, pilot: Pilot, selector: str) -> None:
    target = app.screen.query_one(selector)
    assert target in app.screen.focus_chain
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is target:
            return
        await pilot.press("tab")
    raise AssertionError(f"Tab did not reach {selector}")


def _assert_exposed(app: _ResourceApp, selector: str) -> None:
    target = app.screen.query_one(selector)
    assert target.region.width > 0 and target.region.height > 0
    assert app.screen.region.contains(*target.region.center)
    assert app.get_widget_at(*target.region.center)[0] is target, {
        "target": (target.id, tuple(target.region)),
        "ancestors": [
            (node.id, tuple(node.region)) for node in target.ancestors
            if hasattr(node, "region")
        ],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("screen_type,label,table_id,action_id", SCREEN_CASES)
async def test_resource_controls_and_content_remain_reachable(
    size: tuple[int, int], visible: bool, screen_type: type[WorkspaceScreen],
    label: str, table_id: str, action_id: str,
) -> None:
    app = _ResourceApp(visible)
    async with app.run_test(size=size) as pilot:
        screen = _screen(screen_type)
        await app.push_screen(screen)
        table = screen.query_one(f"#{table_id}", DataTable)
        await wait_until(lambda: table.row_count == 1)
        origin = app.focused
        assert origin is screen.query_one(f"#{INITIAL_FOCUS[screen_type]}")
        assert screen.query_one(Sidebar).display is visible
        assert screen.query_one("#workspace_context", Static).render().plain == label
        for selector in ("#workspace_navigation", "#workspace_chat"):
            _assert_exposed(app, selector)
        await pilot.press("shift+f6", "escape")
        assert app.screen is screen and app.focused is origin
        assert screen.query_one(Sidebar).display is visible
        for selector in (f"#{table_id}", f"#{action_id}"):
            await _tab_to(app, pilot, selector)
            await pilot.pause()
            _assert_exposed(app, selector)


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,key,method", [
    (OVHStorageScreen, "r", "action_refresh"),
    (OVHSSHKeysScreen, "r", "action_refresh"),
    (OVHSSHKeysScreen, "n", "action_add_key"),
    (OVHSSHKeysScreen, "d", "action_delete_key"),
])
async def test_resource_letters_are_inert_in_navigation_and_work_in_content(
    screen_type: type[WorkspaceScreen], key: str, method: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _ResourceApp(False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = _screen(screen_type)
        await app.push_screen(screen)
        called = Mock()

        def record_action() -> None:
            called()

        monkeypatch.setattr(screen, method, record_action)
        origin = app.focused
        await pilot.press("shift+f6", key)
        called.assert_not_called()
        await pilot.press("escape")
        assert app.screen is screen and app.focused is origin
        assert not screen.query_one(Sidebar).display
        await pilot.press(key)
        called.assert_called_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("screen_type,open_id,input_id,save_id,cancel_id", [
    (OVHStorageScreen, "btn_create", "input_vol_name", "btn_save_vol", "btn_cancel_form"),
    (OVHSSHKeysScreen, "btn_add_key", "input_key_name", "btn_save_key", "btn_cancel_form"),
])
async def test_inline_resource_draft_survives_pane_toggle_at_compact_width(
    visible: bool, screen_type: type[WorkspaceScreen], open_id: str,
    input_id: str, save_id: str, cancel_id: str,
) -> None:
    app = _ResourceApp(visible)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = _screen(screen_type)
        await app.push_screen(screen)
        screen.query_one(f"#{open_id}", Button).press()
        field = screen.query_one(f"#{input_id}", Input)
        await wait_until(lambda: app.focused is field)
        await pilot.press(*"draft-nrd")
        assert field.value == "draft-nrd"
        await _toggle_navigation(app, pilot)
        assert field.value == "draft-nrd" and app.focused is field
        for selector in (f"#{save_id}", f"#{cancel_id}"):
            await _tab_to(app, pilot, selector)
            await pilot.pause()
            _assert_exposed(app, selector)


@pytest.mark.asyncio
async def test_storage_create_save_and_cancel_are_painted_after_keyboard_scroll() -> None:
    app = _ResourceApp()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = OVHStorageScreen()
        await app.push_screen(screen)
        screen.query_one("#btn_create", Button).press()
        await wait_until(lambda: screen.query_one("#create_vol_form").display)
        for selector in ("#btn_save_vol", "#btn_cancel_form"):
            await _tab_to(app, pilot, selector)
            await pilot.pause()
            _assert_exposed(app, selector)


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,table_id,picker_id", [
    (OVHBillingScreen, "invoices_table", "billing_account"),
    (OVHStorageScreen, "volumes_table", "storage_account"),
    (OVHIPManagementScreen, "ip_table", "ip_mgmt_account"),
    (OVHSSHKeysScreen, "ssh_keys_table", "ovh_ssh_keys_account"),
])
async def test_chosen_account_survives_navigation_toggle(
    screen_type: type[WorkspaceScreen], table_id: str, picker_id: str,
) -> None:
    app = _ResourceApp(False, multi=True)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = _screen(screen_type)
        await app.push_screen(screen)
        table = screen.query_one(f"#{table_id}", DataTable)
        await wait_until(lambda: table.row_count == 1)
        picker = screen.query_one(f"#{picker_id}", AccountPicker)
        picker.query_one(Select).value = "backup"
        await wait_until(lambda: screen._account == "backup" and table.row_count == 1)
        selected = list(table.get_row_at(0))
        await _toggle_navigation(app, pilot)
        assert picker.account == "backup" and screen._account == "backup"
        assert list(table.get_row_at(0)) == selected


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,open_id,action_id,service_field,mutation", [
    (OVHSnapshotsScreen, "btn_ovh_snapshots", "btn_restore", "snapshot", "restore_vps_snapshot"),
    (OVHFirewallScreen, "btn_ovh_firewall", "btn_toggle", "ip", "toggle_firewall"),
])
async def test_server_resource_confirmation_returns_to_same_workspace(
    screen_type: type[WorkspaceScreen], open_id: str, action_id: str,
    service_field: str, mutation: str,
) -> None:
    app = _ResourceApp(False)
    async with app.run_test(size=(100, 30)) as pilot:
        fleet = app.screen
        table = fleet.query_one(InstanceTable)
        table.move_cursor(row=1)
        await pilot.press("o")
        actions = app.screen
        assert isinstance(actions, ServerActionsScreen)
        await wait_until(lambda: bool(actions.query(f"#{open_id}")))
        actions.query_one(f"#{open_id}", Button).press()
        await wait_until(lambda: (
            isinstance(app.screen, screen_type) and bool(app.screen.query(DataTable))
        ))
        screen = app.screen
        resource_table = screen.query_one(DataTable)
        await wait_until(lambda: resource_table.row_count == 1)
        resource_table.focus()
        await pilot.press("shift+f6")
        screen.query_one(f"#{action_id}", Button).press()
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        modal = app.screen
        await wait_until(lambda: modal.focused is not None)
        focused = app.focused
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is focused
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert not screen.query_one(Sidebar).display
        assert app.focused is resource_table
        provider = getattr(app.bundles["ovh"], service_field)
        getattr(provider, mutation).assert_not_awaited()
        await pilot.press("escape", "escape")
        assert app.screen is fleet and table.cursor_row == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,title_id,prefix", [
    (OVHSnapshotsScreen, "snapshots_title", "Snapshots"),
    (OVHFirewallScreen, "firewall_title", "Firewall"),
])
@pytest.mark.parametrize("name", ["web-[red]1[/red]", "web-[/red]1"])
async def test_resource_title_renders_shown_name_literally(
    screen_type: type[WorkspaceScreen], title_id: str, prefix: str, name: str,
) -> None:
    app = _ResourceApp(False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = _screen(screen_type, name)
        await app.push_screen(screen)
        await pilot.pause()
        assert screen.query_one(f"#{title_id}", Static).render().plain == f"{prefix}: {name}"

"""Resource reflow retains fake provider state and native form/modal ownership."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Select, TextArea

from servonaut.app import ServonautApp
from servonaut.screens.backup_restore import BackupConfirmModal, BackupRestoreScreen
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.ovh_billing import OVHBillingScreen
from servonaut.screens.ovh_firewall import OVHFirewallScreen
from servonaut.screens.ovh_ip_management import OVHIPManagementScreen
from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen
from servonaut.screens.ovh_storage import OVHStorageScreen
from servonaut.screens.snapshot_manager import ConfirmModal, SnapshotManagerScreen
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase,
    assert_button_label_painted,
    assert_essential_targets,
    assert_layout,
    collapse_chat,
    content,
    one_layout_transition,
    open_case,
    open_chat,
    preserve_native_state,
    tab_to,
)
from tests.test_selection_copy import _Clipboard, _drag
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_ovh_resources import _ResourceApp, _screen
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


MUTATIONS = {
    "storage": ("create_volume", "delete_volume", "attach_volume", "detach_volume",
                "create_volume_snapshot"),
    "cloud": ("add_ssh_key", "delete_ssh_key"),
    "ip": ("toggle_firewall", "add_firewall_rule", "delete_firewall_rule",
           "move_failover_ip", "set_reverse_dns", "delete_reverse_dns"),
    "snapshot": (
        "create_vps_snapshot", "create_cloud_snapshot", "restore_vps_snapshot",
        "delete_vps_snapshot", "delete_cloud_snapshot", "configure_vps_backup",
    ),
}
READ_SERVICES = ("ovh", "billing", "storage", "cloud", "ip", "snapshot", "vps")
PRIMARY_TABLES = {
    OVHBillingScreen: "#invoices_table", OVHFirewallScreen: "#rules_table",
    OVHIPManagementScreen: "#ip_table", OVHSnapshotsScreen: "#snapshots_table",
    OVHSSHKeysScreen: "#ssh_keys_table", OVHStorageScreen: "#volumes_table",
    SnapshotManagerScreen: "#snapshots_table", BackupRestoreScreen: "#backups_table",
}
TOOLBARS = {
    OVHBillingScreen: "#invoice_pagination", OVHFirewallScreen: "#firewall_actions",
    OVHIPManagementScreen: "#ip_actions", OVHSnapshotsScreen: "#snapshots_actions",
    OVHSSHKeysScreen: "#ovh_ssh_keys_actions", OVHStorageScreen: "#storage_actions",
    SnapshotManagerScreen: "#snapshots_actions",
    BackupRestoreScreen: "#backups_actions",
}


@pytest.fixture(autouse=True)
def _isolated_resources(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    monkeypatch.setattr(BackupRestoreScreen, "_summarize", staticmethod(
        lambda path: {"custom_servers_count": 0, "ovh_enabled": True},
    ))
    guards: list[Mock] = []
    original_init = _ResourceApp.__init__

    def initialize(
        self: _ResourceApp, visible: bool = True, *, multi: bool = False,
    ) -> None:
        original_init(self, visible, multi=multi)
        for bundle in self.bundles.values():
            for field, methods in MUTATIONS.items():
                for method in methods:
                    guard = AsyncMock(
                        side_effect=AssertionError("Unexpected provider write"),
                    )
                    setattr(getattr(bundle, field), method, guard)
                    guards.append(guard)
        sync = SimpleNamespace(list_snapshots=AsyncMock(return_value=[{
            "id": "snapshot-one", "label": "daily", "version": 1,
            "created_at": "2026-01-01T00:00:00Z", "hash": "fixture-hash",
        }]))
        for method in ("restore_by_id", "rename_snapshot", "delete_snapshot", "push"):
            guard = AsyncMock(
                side_effect=AssertionError("Unexpected config-sync write"),
            )
            setattr(sync, method, guard)
            guards.append(guard)
        for method in ("apply_remote_config", "has_probe"):
            guard = Mock(side_effect=AssertionError("Unexpected config-sync operation"))
            setattr(sync, method, guard)
            guards.append(guard)
        self.config_sync_service = sync
        self.config_manager.list_backups.return_value = [{
            "path": Path("fixture-backup.json"), "timestamp": datetime(2026, 1, 1),
            "size_bytes": 24,
        }]
        restore = Mock(side_effect=AssertionError("Unexpected local config restore"))
        self.config_manager.restore_backup = restore
        guards.append(restore)

    monkeypatch.setattr(_ResourceApp, "__init__", initialize)
    yield
    for guard in guards:
        guard.assert_not_called()


def _app(visible: bool, *, multi: bool = False) -> _ResourceApp:
    app = _ResourceApp(visible, multi=multi)
    app.theme = "servonaut"
    return app


def _opener(
    screen_type: type[WorkspaceScreen],
) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        screen = _screen(screen_type)
        await app.push_screen(screen)
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    table = screen.query_one(PRIMARY_TABLES[type(screen)], DataTable)
    await wait_until(lambda: table.row_count == 1)
    await screen.workers.wait_for_complete()
    await wait_until(lambda: not getattr(screen, "_loading", False))


def _seed(screen: WorkspaceScreen) -> None:
    screen.query_one(PRIMARY_TABLES[type(screen)], DataTable).move_cursor(row=0)


def _state(screen: WorkspaceScreen) -> object:
    tables = tuple((table, table.cursor_row,
                    tuple(tuple(table.get_row_at(i)) for i in range(table.row_count)))
                   for table in screen.query(DataTable))
    fields = tuple((field, field.value) for field in screen.query("Input, Select"))
    accounts = tuple((picker, picker.account) for picker in screen.query(AccountPicker))
    buttons = tuple(
        (button, button.disabled) for button in content(screen).query(Button)
    )
    data = tuple((name, repr(getattr(screen, name))) for name in (
        "_instance", "_ip", "_firewall_enabled", "_rules", "_snapshots",
        "_all_invoices", "_invoice_page", "_volumes", "_account", "_project_id",
        "_keys", "_backups",
    ) if hasattr(screen, name))
    reads = tuple(
        (label, field, name, value.await_count)
        for label, bundle in screen.app.bundles.items()
        for field in READ_SERVICES
        for name, value in vars(getattr(bundle, field)).items()
        if isinstance(value, AsyncMock) and name not in MUTATIONS.get(field, ())
    )
    config_reads = (
        screen.app.config_sync_service.list_snapshots.await_count,
        screen.app.config_manager.list_backups.call_count,
    )
    return tables, fields, accounts, buttons, data, reads, config_reads


# Initial native focus is checked without forcing AUTO_FOCUS for test setup.
# All boundary maps stay absent until actual native terminal/column measurement.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'billing': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((158, 50), 95, False, True),
            BoundarySample((160, 50), 96, False, False),
            BoundarySample((161, 50), 97, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((184, 50), 95, False, True),
            BoundarySample((185, 50), 96, False, False),
            BoundarySample((186, 50), 97, False, False),
        ),
    },
    'firewall': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((158, 50), 95, False, True),
            BoundarySample((160, 50), 96, False, False),
            BoundarySample((161, 50), 97, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((184, 50), 95, False, True),
            BoundarySample((185, 50), 96, False, False),
            BoundarySample((186, 50), 97, False, False),
        ),
    },
    'ip': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((167, 50), 103, False, True),
            BoundarySample((168, 50), 104, False, False),
            BoundarySample((169, 50), 105, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((192, 50), 103, False, True),
            BoundarySample((193, 50), 104, False, False),
            BoundarySample((194, 50), 105, False, False),
        ),
    },
    'snapshots': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((158, 50), 95, False, True),
            BoundarySample((160, 50), 96, False, False),
            BoundarySample((161, 50), 97, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((184, 50), 95, False, True),
            BoundarySample((185, 50), 96, False, False),
            BoundarySample((186, 50), 97, False, False),
        ),
    },
    'keys': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((158, 50), 95, False, True),
            BoundarySample((160, 50), 96, False, False),
            BoundarySample((161, 50), 97, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((184, 50), 95, False, True),
            BoundarySample((185, 50), 96, False, False),
            BoundarySample((186, 50), 97, False, False),
        ),
    },
    'storage': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((175, 50), 111, False, True),
            BoundarySample((176, 50), 112, False, False),
            BoundarySample((177, 50), 113, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((200, 50), 111, False, True),
            BoundarySample((201, 50), 112, False, False),
            BoundarySample((202, 50), 113, False, False),
        ),
    },
    'config-snapshots': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((175, 50), 111, False, True),
            BoundarySample((176, 50), 112, False, False),
            BoundarySample((177, 50), 113, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((200, 50), 111, False, True),
            BoundarySample((201, 50), 112, False, False),
            BoundarySample((202, 50), 113, False, False),
        ),
    },
    'backups': {
        ('chat-min', False): (
            BoundarySample((100, 50), 55, True, True),
            BoundarySample((101, 50), 56, False, True),
            BoundarySample((102, 50), 57, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((133, 50), 55, True, True),
            BoundarySample((135, 50), 56, False, True),
            BoundarySample((136, 50), 57, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((145, 50), 87, False, True),
            BoundarySample((146, 50), 88, False, True),
            BoundarySample((147, 50), 89, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((176, 50), 87, False, True),
            BoundarySample((177, 50), 88, False, False),
            BoundarySample((178, 50), 89, False, False),
        ),
    },
}


CASES = (
    ReflowCase("billing", _app, _opener(OVHBillingScreen), _ready,
               "#billing_container", ("#invoices_table", "#btn_back"),
               _seed, _state, (("#invoices_table", "ovh-bill"),), boundaries=_MEASURED_BOUNDARIES['billing']),
    ReflowCase("firewall", _app, _opener(OVHFirewallScreen), _ready,
               "#firewall_container", ("#rules_table", "#btn_toggle", "#btn_add_rule"),
               _seed, _state, (("#rules_table", "permit"),), boundaries=_MEASURED_BOUNDARIES['firewall']),
    ReflowCase("ip", _app, _opener(OVHIPManagementScreen), _ready,
               "#ip_mgmt_container",
               ("#ip_table", "#btn_move", "#btn_rdns", "#btn_back"),
               _seed, _state, (("#ip_table", "10.0.0.1"),), boundaries=_MEASURED_BOUNDARIES['ip']),
    ReflowCase("snapshots", _app, _opener(OVHSnapshotsScreen), _ready,
               "#snapshots_container",
               ("#snapshots_table", "#btn_restore", "#btn_back"),
               _seed, _state, (("#snapshots_table", "daily"),), boundaries=_MEASURED_BOUNDARIES['snapshots']),
    ReflowCase("keys", _app, _opener(OVHSSHKeysScreen), _ready,
               "#ovh_ssh_keys_container",
               ("#ssh_keys_table", "#btn_add_key", "#btn_back"),
               _seed, _state, (("#ssh_keys_table", "ovh-key"),), boundaries=_MEASURED_BOUNDARIES['keys']),
    ReflowCase("storage", _app, _opener(OVHStorageScreen), _ready,
               "#storage_container", ("#volumes_table", "#btn_create", "#btn_back"),
               _seed, _state, (("#volumes_table", "ovh-volume"),), boundaries=_MEASURED_BOUNDARIES['storage']),
    ReflowCase("config-snapshots", _app, _opener(SnapshotManagerScreen), _ready,
               "#snapshots_container",
               ("#snapshots_table", "#btn_restore", "#btn_refresh"),
               _seed, _state, (("#snapshots_table", "daily"),), boundaries=_MEASURED_BOUNDARIES['config-snapshots']),
    ReflowCase("backups", _app, _opener(BackupRestoreScreen), _ready,
               "#backups_container",
               ("#backups_table", "#btn_bkp_restore", "#btn_bkp_refresh"),
               _seed, _state, (("#backups_table", "2026-01-01"),), boundaries=_MEASURED_BOUNDARIES['backups']),
)
CASE_IDS = [case.name for case in CASES]


async def _assert_all_toolbar_buttons(
    app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen,
) -> None:
    # Disabled actions still require readable labels and visible geometry;
    # they are intentionally not part of native Tab expectations.
    for button in screen.query_one(TOOLBARS[type(screen)]).query(Button):
        button.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert content(screen).region.contains_region(button.region)
        assert screen.region.contains_region(button.region)
        assert app.get_widget_at(*button.region.center)[0] is button
        assert_button_label_painted(app, button)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation,chat", [(False, False), (False, True),
                                         (True, False), (True, True)])
async def test_resource_reflow_retains_four_visibility_states(
    case: ReflowCase, size: tuple[int, int], navigation: bool, chat: bool,
) -> None:
    app = case.app_factory(navigation)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        if chat:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation
        assert case.state(screen) == baseline
        if chat and size == (160, 50):
            assert content(screen).display
        if content(screen).display:
            await assert_essential_targets(case, app, pilot, screen)
            await _assert_all_toolbar_buttons(app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
async def test_resource_state_focus_native_tab_and_chat_draft_survive_reflow(
    case: ReflowCase,
) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        await _assert_all_toolbar_buttons(app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize("navigation", [False, True])
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
async def test_resource_qualified_native_boundary_and_all_action_fit(
    case: ReflowCase, navigation: bool, kind: str,
) -> None:
    samples = case.boundary_samples(kind, navigation)
    app = case.app_factory(navigation)
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        threshold = (screen.CHAT_MIN_CONTENT_WIDTH if kind == "chat-min"
                     else screen.CONTENT_NARROW_WIDTH)
        assert [sample.native_content_width for sample in samples] == [
            threshold - 1, threshold, threshold + 1,
        ]
        for sample in samples:
            with one_layout_transition(screen):
                await pilot.resize_terminal(*sample.size)
                await pilot.pause()
            assert screen.has_class("-chat-replace") is sample.expected_replace
            assert screen.has_class("-content-narrow") is sample.expected_content_narrow
            assert_layout(app, screen)
            with patch.object(screen, "CHAT_MIN_CONTENT_WIDTH", 1):
                screen.apply_workspace_state()
                await pilot.pause()
                assert content(screen).region.width == sample.native_content_width
                # Hidden-policy columns are measured counterfactually, not
                # required to fit controls that users cannot see there.
                if not sample.expected_replace:
                    await assert_essential_targets(case, app, pilot, screen)
                    await _assert_all_toolbar_buttons(app, pilot, screen)
            screen.apply_workspace_state()
            await pilot.pause()
            assert screen.has_class("-chat-replace") is sample.expected_replace
            assert screen.has_class("-content-narrow") is sample.expected_content_narrow
            assert content(screen).display is not sample.expected_replace
            assert case.state(screen) == baseline
            assert_layout(app, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
async def test_resource_navigation_crossing_modal_restores_visible_origin(
    case: ReflowCase,
) -> None:
    sample = case.boundary_samples("chat-min", True)[0]
    assert sample.expected_replace
    app = case.app_factory(False)
    async with app.run_test(size=sample.size) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        origin = screen.query_one(case.primary_focus_selector)
        assert content(screen).display
        await tab_to(pilot, origin)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        assert not content(screen).display
        modal = ConfirmActionScreen(
            "Review", "No write is connected.", [], "YES", "Confirm",
        )
        await app.push_screen(modal)
        await wait_until(lambda: app.focused is modal.query_one("#confirm_input"))
        assert not sidebar.navigation_mode and not sidebar.display
        assert content(screen).display and screen.focused is origin
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is modal.query_one("#confirm_input")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen and app.focused is origin)


@pytest.mark.asyncio
@pytest.mark.parametrize("case,selector,literal", [
    (CASES[1], "#firewall_title", "Firewall"),
    (CASES[3], "#snapshots_title", "Snapshots"),
    (CASES[6], "#snapshots_header", "Config"),
])
async def test_relevant_literal_copy_after_replacement(
    case: ReflowCase, selector: str, literal: str, clipboard: _Clipboard,
) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        title = screen.query_one(selector)
        title.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        rows = _painted(app, title).splitlines()
        row = next(i for i, text in enumerate(rows) if literal in text)
        x = title.region.x - title.content_region.x + rows[row].index(literal)
        y = title.region.y - title.content_region.y + row
        # Static drag endpoints include the final hovered character cell.
        await _drag(pilot, title, (x, y), (x + len(literal) - 1, y))
        assert clipboard.calls == [literal]


@pytest.mark.asyncio
@pytest.mark.parametrize("case,picker_id", [
    (CASES[0], "#billing_account"), (CASES[2], "#ip_mgmt_account"),
    (CASES[4], "#ovh_ssh_keys_account"), (CASES[5], "#storage_account"),
])
async def test_native_chosen_account_and_its_rows_survive_chat_reflow(
    case: ReflowCase, picker_id: str,
) -> None:
    app = _app(False, multi=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        picker = screen.query_one(picker_id, AccountPicker)
        select = picker.query_one(Select)
        await tab_to(pilot, select)
        await pilot.press("enter", "end", "enter")
        await wait_until(lambda: picker.account == "backup")
        await case.ready(screen)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        assert picker.account == "backup" and case.state(screen) == baseline


INLINE = (
    (CASES[1], "#btn_add_rule", "#input_action", ("#btn_save_rule",)),
    (CASES[2], "#btn_move", "#input_move_target", ("#btn_move_confirm",)),
    (CASES[2], "#btn_rdns", "#input_rdns", ("#btn_rdns_set", "#btn_rdns_delete")),
    (CASES[4], "#btn_add_key", "#input_key_name",
     ("#btn_save_key", "#btn_cancel_form")),
    (CASES[5], "#btn_create", "#input_vol_name", ("#btn_save_vol", "#btn_cancel_form")),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("case,open_id,field_id,actions", INLINE)
async def test_native_inline_form_and_draft_remain_owned_after_reflow(
    case: ReflowCase, open_id: str, field_id: str, actions: tuple[str, ...],
) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        button = screen.query_one(open_id)
        await tab_to(pilot, button)
        await _click(pilot, open_id)
        await screen.workers.wait_for_complete()
        field = screen.query_one(field_id, Input)
        await tab_to(pilot, field)
        await pilot.press("ctrl+a", *"draft-example")
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert not content(screen).display
        await collapse_chat(app, pilot, screen)
        await wait_until(lambda: app.focused is field)
        assert field.value == "draft-example" and case.state(screen) == baseline
        for selector in actions:
            target = screen.query_one(selector, Button)
            await tab_to(pilot, target)
            await pilot.pause()
            assert screen.region.contains_region(target.region)
            assert app.get_widget_at(*target.region.center)[0] is target
            assert target.label.plain in _painted(app, target)


@pytest.mark.asyncio
@pytest.mark.parametrize("case,modal_type", [
    (CASES[6], ConfirmModal), (CASES[7], BackupConfirmModal),
])
async def test_mixed_screen_native_confirmation_resume_applies_preference_once(
    case: ReflowCase, modal_type: type,
) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        origin = screen.query_one(PRIMARY_TABLES[type(screen)])
        await tab_to(pilot, origin)
        await pilot.press("r")
        await wait_until(lambda: isinstance(app.screen, modal_type))
        modal = app.screen
        focused = app.focused
        app.workspace_state.navigation_visible = True
        with patch.object(screen, "apply_workspace_state",
                          wraps=screen.apply_workspace_state) as apply_state:
            await pilot.press("shift+f6", "f2", "ctrl+g")
            assert app.screen is modal and app.focused is focused
            await pilot.press("escape")
            await wait_until(lambda: app.screen is screen)
            await pilot.pause()
        apply_state.assert_called_once_with()
        assert screen.query_one(Sidebar).display and content(screen).display
        assert app.focused is origin and case.state(screen) == baseline
        assert_layout(app, screen)


@pytest.mark.asyncio
async def test_config_snapshot_loading_finishes_while_chat_replaces_content() -> None:
    case = CASES[6]
    app = case.app_factory(False)
    original = app.config_sync_service.list_snapshots
    started, release = asyncio.Event(), asyncio.Event()

    async def gated(**kwargs: object) -> list[dict]:
        started.set()
        await release.wait()
        return await original(**kwargs)

    app.config_sync_service.list_snapshots = AsyncMock(side_effect=gated)
    async with app.run_test(size=(100, 30)) as pilot:
        try:
            screen = await case.open_screen(app, pilot)
            await wait_until(started.is_set)
            await pilot.pause()
            assert app.focused is screen.query_one(case.primary_focus_selector)
            panel = await open_chat(app, pilot, screen)
            editor = panel.query_one("#chat-input", TextArea)
            editor.load_text("Keep the loading draft")
            assert not content(screen).display
            release.set()
            await case.ready(screen)
            await pilot.pause()
            assert app.focused is editor and editor.text == "Keep the loading draft"
            await collapse_chat(app, pilot, screen)
            await wait_until(
                lambda: app.focused is screen.query_one(case.primary_focus_selector),
            )
        finally:
            release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("case,theme", [
    (CASES[0], "servonaut-light"), (CASES[4], "ansi-dark"), (CASES[7], "ansi-light"),
])
async def test_resource_representative_palettes_keep_all_toolbar_targets(
    case: ReflowCase, theme: str,
) -> None:
    app = case.app_factory(True)
    app.theme = theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        assert content(screen).display
        await assert_essential_targets(case, app, pilot, screen)
        await _assert_all_toolbar_buttons(app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [c for c in CASES if c.name in {"keys", "config-snapshots", "backups"}],
                         ids=lambda c: c.name)
async def test_action_hints_are_bindings_and_the_key_matches_the_click(case: ReflowCase) -> None:
    from tests._hint_conformance import assert_hints_match_bindings, record_actions

    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        calls: list[str] = []
        record_actions(screen, calls)
        table = screen.query_one(PRIMARY_TABLES[type(screen)], DataTable)
        table.focus()
        assert await assert_hints_match_bindings(pilot, screen, calls) >= 1

"""Provider workspace controls preserve table, wizard and keyboard context."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual import events
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.aws_create import AWSCreateScreen
from servonaut.screens.aws_manager import AWSManagerScreen
from servonaut.screens.hetzner_create import HetznerCreateScreen
from servonaut.screens.hetzner_manager import HetznerManagerScreen
from servonaut.screens.hetzner_ssh_keys import HetznerSSHKeysScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.ovh_manager import OVHManagerScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import assert_button_label_painted
from tests.test_workspace_ovh_lifecycle import ROWS as OVH_ROWS, _OvhHost
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


def _rows(*, hetzner: bool = False) -> list[dict]:
    return [
        {"id": str(index) if hetzner else f"i-example-{index}", "name": name,
         "is_hetzner": hetzner, "type": "small", "state": "stopped",
         "public_ip": "192.0.2.10", "region": "us-east-1", "key_name": ""}
        for index, name in enumerate(("web-1", "db-1"), start=1)
    ]


def _aws() -> SimpleNamespace:
    return SimpleNamespace(
        fetch_instances_cached=AsyncMock(return_value=_rows()),
        list_regions=AsyncMock(return_value=["us-east-1"]),
        list_amis=AsyncMock(return_value=[
            {"image_id": "ami-example", "name": "Linux", "architecture": "x86_64"},
        ]),
        list_instance_types=AsyncMock(return_value=[
            {"instance_type": "small", "vcpus": 2, "memory_mib": 1024},
        ]),
        list_key_pairs=AsyncMock(return_value=[{"key_name": "example-key"}]),
        list_subnets=AsyncMock(return_value=[
            {"subnet_id": "subnet-example", "vpc_id": "vpc-example", "cidr_block": "10.0.0.0/24"},
        ]),
        list_security_groups=AsyncMock(return_value=[
            {"group_id": "sg-example", "group_name": "example", "vpc_id": "vpc-example"},
        ]),
        run_instances=AsyncMock(), last_fetch_error=None,
    )


def _hetzner() -> SimpleNamespace:
    return SimpleNamespace(
        fetch_instances_cached=AsyncMock(return_value=_rows(hetzner=True)),
        list_server_types=AsyncMock(return_value=[
            {"name": "small", "cores": 2, "memory_gb": 4, "disk_gb": 40, "architecture": "x86"},
        ]),
        list_images=AsyncMock(return_value=[{"id": 1, "name": "Linux", "architecture": "x86"}]),
        list_locations=AsyncMock(return_value=[{"name": "local", "city": "Example", "country": "DE"}]),
        list_ssh_keys=AsyncMock(return_value=[{"id": 1, "name": "example-key", "fingerprint": "aa:bb"}]),
        create_server=AsyncMock(), last_fetch_error=None,
    )


class _CloudApp(ServonautApp):
    """Actual app dispatch and styles without cloud or startup workers."""

    def __init__(self, screen_type: type[WorkspaceScreen], visible: bool = True) -> None:
        super().__init__()
        config = AppConfig()
        config.hetzner.enabled = True
        self.config_manager = Mock()
        self.config_manager.get.return_value = config
        self.aws_service = _aws()
        self.hetzner_service = _hetzner()
        self.instances = _rows() + _rows(hetzner=True)
        self.cache_service = SimpleNamespace(
            is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [],
        )
        self.workspace_state.navigation_visible = visible
        self.screen_type = screen_type

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(self.screen_type())

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()

    def provider_inventory(self, provider: str) -> None:
        # The underlying fleet is seeded; cloud-screen loaders use the fake
        # service attributes through their normal single-account fallback.
        return None


SCREEN_CASES = [
    (AWSManagerScreen, "AWS servers", "aws_mgr_table", "btn_aws_mgr_new"),
    (AWSCreateScreen, "Create AWS server", "aws_regions_table", "btn_aws_create_back"),
    (HetznerManagerScreen, "Hetzner servers", "hetzner_mgr_table", "btn_hetzner_mgr_new"),
    (HetznerCreateScreen, "Create Hetzner server", "hetzner_types_table", "btn_hetzner_create_back"),
    (HetznerSSHKeysScreen, "Hetzner SSH keys", "hetzner_ssh_keys_table", "btn_hetzner_ssh_add"),
]

# Original mounted focus and first-Tab targets, measured at both sizes.
FOCUS_TARGETS = {
    AWSManagerScreen: ("aws_mgr_container", "aws_mgr_table"),
    AWSCreateScreen: ("aws_create_container", "aws_input_name"),
    HetznerManagerScreen: ("hetzner_mgr_container", "hetzner_mgr_table"),
    HetznerCreateScreen: ("hetzner_create_container", "hetzner_input_name"),
    HetznerSSHKeysScreen: ("hetzner_ssh_keys_container", "hetzner_ssh_keys_table"),
}


async def _ready(app: _CloudApp, table_id: str) -> WorkspaceScreen:
    await wait_until(lambda: isinstance(app.screen, app.screen_type))
    screen = app.screen
    await wait_until(lambda: bool(screen.query(f"#{table_id}")))
    table = screen.query_one(f"#{table_id}", DataTable)
    await wait_until(lambda: table.row_count > 0)
    return screen


async def _toggle(app: _CloudApp, pilot: Pilot) -> None:
    button = app.screen.query_one("#workspace_navigation", Button)
    await wait_until(lambda: not button.has_class("-active"))
    assert await pilot.click(button)
    await pilot.pause()


async def _tab_to(app: _CloudApp, pilot: Pilot, selector: str) -> None:
    target = app.screen.query_one(selector)
    assert target in app.screen.focus_chain
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is target:
            return
        await pilot.press("tab")
    raise AssertionError(f"Tab did not reach {selector}")


def _assert_exposed(app: _CloudApp, selector: str) -> None:
    target = app.screen.query_one(selector)
    assert target.region.width > 0 and target.region.height > 0
    assert app.screen.region.contains(*target.region.center)
    assert app.get_widget_at(*target.region.center)[0] is target


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("screen_type,label,table_id,action_id", SCREEN_CASES)
async def test_provider_workspace_controls_preserve_content_and_keyboard_reachability(
    size: tuple[int, int], visible: bool, screen_type: type[WorkspaceScreen],
    label: str, table_id: str, action_id: str,
) -> None:
    app = _CloudApp(screen_type, visible)
    async with app.run_test(size=size) as pilot:
        screen = await _ready(app, table_id)
        await pilot.pause()
        origin = app.focused
        initial_id, next_id = FOCUS_TARGETS[screen_type]
        assert origin is screen.query_one(f"#{initial_id}")
        await pilot.press("tab")
        if screen.has_class("-content-narrow") and screen.query(".provider-manager-rail"):
            # Narrow: the actions come before the table, so Tab reaches them first.
            assert app.focused is screen.query(".provider-manager-rail ActionButton").first()
        else:
            assert app.focused is screen.query_one(f"#{next_id}")
        origin.focus()
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
        await pilot.press("escape")
        assert app.screen is not screen


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,key,method,table_id", [
    (AWSManagerScreen, "n", "action_new", "aws_mgr_table"),
    (AWSManagerScreen, "s", "action_start", "aws_mgr_table"),
    (AWSManagerScreen, "d", "action_terminate", "aws_mgr_table"),
    (HetznerManagerScreen, "n", "action_new", "hetzner_mgr_table"),
    (HetznerManagerScreen, "s", "action_power_on", "hetzner_mgr_table"),
    (HetznerManagerScreen, "d", "action_delete", "hetzner_mgr_table"),
    (HetznerSSHKeysScreen, "n", "action_add_key", "hetzner_ssh_keys_table"),
    (HetznerSSHKeysScreen, "d", "action_delete_key", "hetzner_ssh_keys_table"),
    (HetznerSSHKeysScreen, "r", "action_refresh", "hetzner_ssh_keys_table"),
])
async def test_navigation_disabled_none_is_final_and_content_shortcuts_still_work(
    screen_type: type[WorkspaceScreen], key: str, method: str, table_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _CloudApp(screen_type, False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _ready(app, table_id)
        action = Mock()

        def record_action() -> None:
            action()

        monkeypatch.setattr(screen, method, record_action)
        await pilot.press("shift+f6")
        assert screen.check_action(method.removeprefix("action_"), ()) is None
        await pilot.press(key)
        action.assert_not_called()
        await pilot.press("escape", key)
        assert app.screen is screen
        action.assert_called_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("manager_type,create_type,table_id,input_id", [
    (AWSManagerScreen, AWSCreateScreen, "aws_mgr_table", "aws_input_name"),
    (HetznerManagerScreen, HetznerCreateScreen, "hetzner_mgr_table", "hetzner_input_name"),
])
async def test_create_return_retains_selected_server_and_applies_pane_preference(
    visible: bool, manager_type: type[WorkspaceScreen],
    create_type: type[WorkspaceScreen], table_id: str, input_id: str,
) -> None:
    app = _CloudApp(manager_type, visible)
    async with app.run_test(size=(100, 30)) as pilot:
        manager = await _ready(app, table_id)
        table = manager.query_one(f"#{table_id}", DataTable)
        table.move_cursor(row=1)
        await pilot.press("n")
        await wait_until(lambda: isinstance(app.screen, create_type))
        wizard = app.screen
        name = wizard.query_one(f"#{input_id}", Input)
        name.focus()
        await pilot.press(*"draft-nsd")
        await _toggle(app, pilot)
        assert name.value == "draft-nsd" and app.focused is name
        await pilot.press("escape")
        await wait_until(lambda: app.screen is manager)
        assert manager.query_one(Sidebar).display is not visible
        assert table.cursor_row == 1
        app.aws_service.run_instances.assert_not_awaited()
        app.hetzner_service.create_server.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,input_id,table_id,back_id", [
    (AWSCreateScreen, "aws_input_name", "aws_regions_table", "btn_aws_create_back"),
    (HetznerCreateScreen, "hetzner_input_name", "hetzner_types_table", "btn_hetzner_create_back"),
])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_wizard_input_editing_and_bottom_action_survive_navigation(
    screen_type: type[WorkspaceScreen], input_id: str, table_id: str,
    back_id: str, size: tuple[int, int],
) -> None:
    app = _CloudApp(screen_type, False)
    async with app.run_test(size=size) as pilot:
        screen = await _ready(app, table_id)
        field = screen.query_one(f"#{input_id}", Input)
        field.focus()
        await pilot.press(*"web-nsdr")
        await pilot.press("shift+f6", "escape")
        assert field.value == "web-nsdr" and app.focused is field
        await _tab_to(app, pilot, f"#{back_id}")
        await pilot.pause()
        _assert_exposed(app, f"#{back_id}")


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_type,table_id", [
    (AWSManagerScreen, "aws_mgr_table"),
    (HetznerManagerScreen, "hetzner_mgr_table"),
])
async def test_manager_demo_redraw_retains_raw_rows_with_workspace_controls(
    screen_type: type[WorkspaceScreen], table_id: str,
) -> None:
    app = _CloudApp(screen_type, False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _ready(app, table_id)
        table = screen.query_one(f"#{table_id}", DataTable)
        table.move_cursor(row=1)
        raw = [(row["id"], row["name"]) for row in screen._raw_instances]
        await pilot.press("ctrl+shift+d")
        await pilot.pause()
        assert app.demo_mode
        assert [(row["id"], row["name"]) for row in screen._raw_instances] == raw
        assert screen._instances[1]["name"] != raw[1][1]
        assert not screen.query_one(Sidebar).display
        for selector in ("#workspace_navigation", "#workspace_chat"):
            _assert_exposed(app, selector)
        await pilot.press("ctrl+shift+d")
        await pilot.pause()
        assert [(row["id"], row["name"]) for row in screen._instances] == raw


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["aws", "hetzner", "ovh"])
async def test_narrow_manager_primary_actions_are_painted_on_arrival(
    monkeypatch: pytest.MonkeyPatch, provider: str,
) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    if provider == "ovh":
        app = _OvhHost(True)
        service = app.ovh_service
        rows = [dict(row) for row in OVH_ROWS]
        third_id = "proj-1/inst-3"
    else:
        screen_type = AWSManagerScreen if provider == "aws" else HetznerManagerScreen
        app = _CloudApp(screen_type, True)
        service = app.aws_service if provider == "aws" else app.hetzner_service
        rows = _rows(hetzner=provider == "hetzner")
        third_id = "i-example-3" if provider == "aws" else "3"
    rows.append(dict(rows[-1], id=third_id, name="worker-1"))
    service.fetch_instances_cached.side_effect = None
    service.fetch_instances_cached.return_value = rows

    async with app.run_test(size=(100, 30)) as pilot:
        if provider == "ovh":
            await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
            screen = OVHManagerScreen()
            await app.push_screen(screen)
        else:
            screen = await _ready(app, f"{provider}_mgr_table")
        table = screen.query_one(f"#{provider}_mgr_table", DataTable)
        await wait_until(lambda: table.row_count == 3)
        await pilot.pause()

        container = screen.query_one(f"#{provider}_mgr_container")
        assert app.focused is container and container.scroll_y == 0
        assert screen.query_one(Sidebar).display
        assert table.region.height >= 6
        assert rows[0]["name"] in _painted(app, table)
        identity = screen.query_one(f"#{provider}_mgr_identity", Static)
        assert rows[0]["id"] in str(identity.content)
        assert rows[0]["public_ip"] in str(identity.content)
        # Arrival is checked before any Tab, scroll or focus reveal.
        for suffix in ("refresh", "new"):
            button = screen.query_one(f"#btn_{provider}_mgr_{suffix}", Button)
            assert_button_label_painted(app, button)
            assert app.get_widget_at(*button.region.center)[0] is button

        # The action rail precedes the table at this width.
        await pilot.pause()
        await pilot.press("tab")
        assert app.focused is screen.query_one(f"#btn_{provider}_mgr_refresh")
        await pilot.press("tab")
        assert app.focused is screen.query_one(f"#btn_{provider}_mgr_new")

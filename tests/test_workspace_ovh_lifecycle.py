"""OVH lifecycle workspaces keep rows, targets and wizard results beside chat."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, create_autospec, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Select

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.ovh_cloud_create import OVHCloudCreateScreen
from servonaut.screens.ovh_manager import OVHManagerScreen
from servonaut.services.ovh_audit import OVHAuditLogger
from servonaut.services.ovh_cloud_service import OVHCloudService
from servonaut.services.ovh_service import OVHService
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_essential_targets, assert_layout, collapse_chat, content,
    one_layout_transition, open_case, open_chat, preserve_native_state,
)
from tests.test_workspace_pilot import _Host, _click
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


PROJECT = "proj-1"
# A stopped VPS (start applies) and a running Public Cloud instance (stop,
# reboot and delete apply), in the order the table draws them.
ROWS = (
    {"id": "vps-1.example", "name": "mail-1", "type": "vps-starter", "state": "stopped",
     "provider_type": "vps", "public_ip": "9.9.9.9", "region": "GRA", "is_ovh": True},
    {"id": f"{PROJECT}/inst-1", "name": "web-1", "type": "d2-2", "state": "running",
     "provider_type": "cloud", "public_ip": "1.1.1.1", "region": "GRA7", "is_ovh": True},
)
FLAVOR = {"id": "flv-1", "name": "d2-2", "region": "GRA7", "available": True,
          "vcpus": 1, "ram": 2, "disk": 25}
IMAGE = {"id": "img-1", "name": "Debian 12", "os_type": "linux", "min_disk": 10,
         "region": "GRA7"}
KEY = {"id": "key-1", "name": "ops"}


class _OvhHost(_Host):
    """The accepted native workspace host with exact OVH service fakes."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        config = AppConfig()
        config.ovh.enabled = True
        config.ovh.cloud_project_ids = [PROJECT]
        self.config = config
        self.config_manager = SimpleNamespace(
            get=lambda: self.config, save=Mock(), update=Mock(),
        )
        self.fetch_release = asyncio.Event()
        self.fetch_release.set()
        # No account registry: the screens use the default-account services.
        self.ovh_service = create_autospec(OVHService, instance=True)
        self.ovh_service.fetch_instances_cached.side_effect = self._fetch
        self.ovh_service.check_credentials.return_value = None
        for method in ("start_instance", "stop_instance", "reboot_instance"):
            getattr(self.ovh_service, method).return_value = True
        cloud = create_autospec(OVHCloudService, instance=True)
        cloud.list_regions.return_value = ["GRA7"]
        cloud.list_flavors.side_effect = self._flavors
        cloud.list_images.side_effect = self._images
        cloud.list_ssh_keys.return_value = [dict(KEY)]
        cloud.create_instance.return_value = {"id": "inst-2"}
        cloud.delete_instance.return_value = True
        self.ovh_cloud_service = cloud
        self.ovh_audit = create_autospec(OVHAuditLogger, instance=True)

    async def _fetch(self, force_refresh: bool = False) -> list:
        await self.fetch_release.wait()
        return [dict(row) for row in ROWS]

    async def _flavors(self, project_id: str, region: str = "") -> list:
        return [dict(FLAVOR)]

    async def _images(self, project_id: str, region: str = "") -> list:
        return [dict(IMAGE)]


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    trips = {
        "browser": Mock(side_effect=AssertionError("Unexpected browser")),
        "process": Mock(side_effect=AssertionError("Unexpected subprocess")),
        "async_process": AsyncMock(side_effect=AssertionError("Unexpected subprocess")),
        "socket": Mock(side_effect=AssertionError("Unexpected network")),
        "connection": AsyncMock(side_effect=AssertionError("Unexpected network")),
        "keyring": Mock(side_effect=AssertionError("Unexpected keyring operation")),
    }
    monkeypatch.setattr("webbrowser.open", trips["browser"])
    monkeypatch.setattr("subprocess.Popen", trips["process"])
    monkeypatch.setattr("subprocess.run", trips["process"])
    monkeypatch.setattr("asyncio.create_subprocess_exec", trips["async_process"])
    monkeypatch.setattr("socket.create_connection", trips["socket"])
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", trips["connection"])
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, trips["keyring"])
    yield trips
    trips["browser"].assert_not_called()
    trips["process"].assert_not_called()
    trips["async_process"].assert_not_awaited()
    trips["socket"].assert_not_called()
    trips["connection"].assert_not_awaited()
    trips["keyring"].assert_not_called()


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = OVHManagerScreen() if kind == "manager" else OVHCloudCreateScreen()
        app.root_results = []
        await app.push_screen(screen, app.root_results.append)
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, OVHManagerScreen):
        await wait_until(lambda: screen.query_one("#ovh_mgr_table", DataTable).row_count == 2)
        await wait_until(lambda: not screen._loading)
        return
    await wait_until(lambda: screen.query_one("#input_region", Select).value == "GRA7")
    for selector in ("#flavors_table", "#images_table", "#keys_table"):
        await wait_until(lambda selector=selector: screen.query_one(
            selector, DataTable).row_count == 1)


def _seed(screen: WorkspaceScreen) -> None:
    # Non-default state that must survive every reflow.
    if isinstance(screen, OVHManagerScreen):
        screen.query_one("#ovh_mgr_table", DataTable).move_cursor(row=1)
    else:
        screen.query_one("#input_name", Input).value = "web-2"


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, OVHManagerScreen):
        table = screen.query_one("#ovh_mgr_table", DataTable)
        return (table, table.row_count, table.cursor_row,
                tuple(row["id"] for row in screen._instances))
    return (
        screen.query_one("#input_name", Input).value,
        screen.query_one("#input_region", Select).value,
        tuple(screen.query_one(selector, DataTable).cursor_row
              for selector in ("#flavors_table", "#images_table", "#keys_table")),
        screen._project_id,
    )


# Derived native first focus: the content container is the first focusable
# widget in DOM order. open_case characterises it.
PRIMARY = {"manager": "#ovh_mgr_container", "create": "#cloud_create_container"}
# Every control that is active on the seeded row (the running cloud
# instance); Start is disabled there and is covered by TOOLBAR below.
TARGETS = {
    "manager": ("#ovh_mgr_table", "#btn_ovh_mgr_refresh", "#btn_ovh_mgr_new",
                "#btn_ovh_mgr_stop", "#btn_ovh_mgr_reboot", "#btn_ovh_mgr_delete"),
    "create": ("#input_name", "#input_region", "#flavors_table", "#btn_create", "#btn_back"),
}
# The whole manager toolbar, enabled or not. It must fit the content width
# wherever the content is shown; if the current layout clips it, these cells
# stay red until a scoped responsive toolbar change is approved.
TOOLBAR = ("#btn_ovh_mgr_refresh", "#btn_ovh_mgr_new", "#btn_ovh_mgr_start",
           "#btn_ovh_mgr_stop", "#btn_ovh_mgr_reboot", "#btn_ovh_mgr_delete")
PAINTED = {
    "manager": (("#ovh_mgr_table", "mail-1"),),
    "create": (("#flavors_table", "d2-2"),),
}
KINDS = ("manager", "create")
# Native boundary samples are deliberately absent until qualified measurements.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'manager': {
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
            BoundarySample((168, 50), 104, False, True),
            BoundarySample((169, 50), 105, False, False),
            BoundarySample((170, 50), 106, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((193, 50), 104, False, True),
            BoundarySample((194, 50), 105, False, False),
            BoundarySample((195, 50), 106, False, False),
        ),
    },
    'create': {
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


CASES = tuple(
    ReflowCase(kind, _OvhHost, _opener(kind), _ready, PRIMARY[kind], TARGETS[kind],
               _seed, _state, PAINTED[kind], boundaries=_MEASURED_BOUNDARIES[kind])
    for kind in KINDS
)


def _case(kind: str) -> ReflowCase:
    return next(case for case in CASES if case.name == kind)


def _effects(app: _OvhHost) -> tuple:
    ovh, cloud = app.ovh_service, app.ovh_cloud_service
    return (
        ovh.fetch_instances_cached.await_count, ovh.start_instance.await_count,
        ovh.stop_instance.await_count, ovh.reboot_instance.await_count,
        cloud.create_instance.await_count, cloud.delete_instance.await_count,
        app.ovh_audit.log_action.call_count, app.config_manager.save.call_count,
        tuple(app.root_results),
    )


def _ledgered(ledger: list, callback: Callable[[object], object]) -> Callable[[object], object]:
    def record(result: object) -> object:
        ledger.append(result)
        return callback(result)
    return record


async def _focus_row(pilot: Pilot, screen: OVHManagerScreen, row: int) -> DataTable:
    table = screen.query_one("#ovh_mgr_table", DataTable)
    table.focus()
    await wait_until(lambda: screen.app.focused is table)
    table.move_cursor(row=row)
    await pilot.pause()
    return table


async def _type_and_confirm(pilot: Pilot, confirm: ConfirmActionScreen, word: str) -> None:
    box = confirm.query_one("#confirm_input", Input)
    box.focus()
    await wait_until(lambda: confirm.app.focused is box)
    await pilot.press(*word)
    await wait_until(lambda: not confirm.query_one("#btn_confirm", Button).disabled)
    await _click(pilot, "#btn_confirm")


async def _assert_whole_toolbar(app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen) -> None:
    if not isinstance(screen, OVHManagerScreen):
        return
    body = content(screen)
    row = screen.query_one("#ovh_mgr_actions")
    focused = app.focused
    # Reveal the row once; every button is then checked at that one scroll
    # offset, so no per-button scroll can manufacture a fit.
    row.scroll_visible(animate=False, immediate=True)
    await pilot.pause()
    offset = (body.scroll_x, body.scroll_y, row.scroll_x)
    visible = body.scrollable_content_region
    for selector in TOOLBAR:
        button = screen.query_one(selector, Button)
        assert button.region.width > 0 and button.region.height > 0, selector
        # Horizontally inside the toolbar row and the visible content.
        assert row.content_region.x <= button.region.x, selector
        assert button.region.right <= row.content_region.right, selector
        assert visible.x <= button.region.x and button.region.right <= visible.right, selector
        assert visible.contains_region(button.region), selector
        # Disabled buttons stay disabled; only geometry, hit and paint matter.
        hit = app.get_widget_at(*button.region.center)[0]
        assert hit is button or button in hit.ancestors, selector
        assert button.label.plain in _painted(app, button), selector
    assert (body.scroll_x, body.scroll_y, row.scroll_x) == offset
    assert app.focused is focused


async def _workers_done(app: ServonautApp, *names: str) -> None:
    await wait_until(lambda: not [
        worker for worker in app.workers
        if worker.name in names and not worker.is_finished
    ])


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("chat_open", [False, True])
async def test_ovh_workspace_pane_combinations(
    case: ReflowCase, size: tuple[int, int], navigation_visible: bool, chat_open: bool,
) -> None:
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        if chat_open:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert case.state(screen) == baseline
        if content(screen).display:
            await assert_essential_targets(case, app, pilot, screen)
            await _assert_whole_toolbar(app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
async def test_ovh_workspace_native_state_survives_reflow(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        await _assert_whole_toolbar(app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_ovh_workspace_uses_qualified_native_boundaries(
    case: ReflowCase, kind: str, navigation_visible: bool,
) -> None:
    # Fails closed until qualified native samples exist (boundaries=None).
    samples = case.boundary_samples(kind, navigation_visible)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        threshold = (
            screen.CHAT_MIN_CONTENT_WIDTH if kind == "chat-min"
            else screen.CONTENT_NARROW_WIDTH
        )
        # Samples straddle the declared threshold by exactly one native cell.
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
            if sample.expected_replace:
                # Counterfactual: force the columns the policy hides, measure
                # the native width, then restore and re-check the real flags.
                with patch.object(screen, "CHAT_MIN_CONTENT_WIDTH", 1):
                    screen.apply_workspace_state()
                    await pilot.pause()
                    assert content(screen).region.width == sample.native_content_width
                screen.apply_workspace_state()
                await pilot.pause()
                assert screen.has_class("-chat-replace") is sample.expected_replace
                assert screen.has_class("-content-narrow") is sample.expected_content_narrow
                assert not content(screen).display
            else:
                assert content(screen).region.width == sample.native_content_width
                await assert_essential_targets(case, app, pilot, screen)
                await _assert_whole_toolbar(app, pilot, screen)
            assert case.state(screen) == baseline


async def _enter_rail(pilot: Pilot, screen: WorkspaceScreen) -> Sidebar:
    await pilot.press("shift+f6")
    sidebar = screen.query_one(Sidebar)
    await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
    return sidebar


@pytest.mark.asyncio
# Each key on the row where it would act from the content.
@pytest.mark.parametrize("key,row", [("n", 0), ("s", 0), ("t", 1), ("b", 1), ("d", 1)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_rail_focused_ovh_manager_keys_have_no_side_effects(
    key: str, row: int, navigation_visible: bool,
) -> None:
    case = _case("manager")
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await _focus_row(pilot, screen, row)
        before = (case.state(screen), _effects(app), tuple(app.screen_stack))
        sidebar = await _enter_rail(pilot, screen)
        await pilot.press(key)
        await pilot.pause()
        # A wizard, a power confirm, a delete confirm or a service call would show here.
        assert app.screen is screen
        assert (case.state(screen), _effects(app), tuple(app.screen_stack)) == before
        assert sidebar.navigation_mode and sidebar.has_focus_within
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
async def test_check_action_composes_rail_guard_before_passthrough() -> None:
    manager_case = _case("manager")
    app = manager_case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(manager_case, app, pilot)
        await _focus_row(pilot, screen, 0)
        assert screen.check_action("new", ()) is True
        await _enter_rail(pilot, screen)
        # Only printable single-key bindings are muted from the rail.
        assert screen.check_action("new", ()) is None
        assert screen.check_action("refresh", ()) is True
    create_case = _case("create")
    app = create_case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(create_case, app, pilot)
        field = screen.query_one("#input_name", Input)
        field.focus()
        await wait_until(lambda: app.focused is field)
        # The wizard binds only Escape: the existing passthrough keeps it.
        assert screen.check_action("back", ()) is True
        await _enter_rail(pilot, screen)
        assert screen.check_action("back", ()) is True


@pytest.mark.asyncio
async def test_manager_start_from_content_sends_one_exact_power_call() -> None:
    case = _case("manager")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        ovh = app.ovh_service
        assert ovh.fetch_instances_cached.await_args_list == [call(force_refresh=True)]
        await _focus_row(pilot, screen, 0)
        # Starting a stopped server does not ask first.
        await pilot.press("s")
        await wait_until(lambda: ovh.start_instance.await_count == 1)
        await _workers_done(app, "ovh_mgr_start_instance")
        assert app.screen is screen
        ovh.start_instance.assert_awaited_once_with("vps-1.example", "vps")
        app.ovh_audit.log_action.assert_called_once_with(
            action="start_instance", target="vps-1.example",
            details={"provider_type": "vps", "success": True}, confirmed=True,
        )
        assert ovh.fetch_instances_cached.await_args_list == [call(force_refresh=True)] * 2
        assert (ovh.stop_instance.await_count, ovh.reboot_instance.await_count) == (0, 0)


@pytest.mark.asyncio
async def test_manager_delete_beside_chat_targets_the_captured_row() -> None:
    case = _case("manager")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        assert content(screen).display
        await _focus_row(pilot, screen, 1)
        captured = screen._selected_instance()
        assert captured["id"] == f"{PROJECT}/inst-1"
        await pilot.press("d")
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        await _type_and_confirm(pilot, app.screen, "delete")
        cloud = app.ovh_cloud_service
        await wait_until(lambda: cloud.delete_instance.await_count == 1)
        await _workers_done(app, "ovh_mgr_delete")
        assert app.screen is screen
        cloud.delete_instance.assert_awaited_once_with(PROJECT, "inst-1")
        assert app.ovh_audit.log_action.call_args_list == [
            call(action="cloud_delete", target=f"{PROJECT}/inst-1",
                 details={"provider_type": "cloud", "success": success}, confirmed=True)
            for success in (False, True)
        ]
        # The fleet is refreshed with every fetched OVH row.
        assert {row["id"] for row in ROWS} <= {row.get("id") for row in app.instances}
        assert app.ovh_service.fetch_instances_cached.await_count == 2
        assert app.ovh_service.stop_instance.await_count == 0


@pytest.mark.asyncio
async def test_manager_held_load_survives_chat_reflow() -> None:
    app = _OvhHost(True)
    app.fetch_release.clear()
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = OVHManagerScreen()
        await app.push_screen(screen)
        fetch = app.ovh_service.fetch_instances_cached
        await wait_until(lambda: fetch.await_count == 1)
        worker = next(w for w in app.workers if w.name == "ovh_mgr_load")
        panel = await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert screen.has_class("-chat-replace") and not content(screen).display
        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        assert not worker.is_finished and panel.is_attached and screen._loading
        app.fetch_release.set()
        table = screen.query_one("#ovh_mgr_table", DataTable)
        await wait_until(lambda: table.row_count == 2)
        await wait_until(lambda: worker.is_finished)
        assert fetch.await_args_list == [call(force_refresh=True)]
        assert not screen._loading
        assert [row["id"] for row in screen._instances] == [row["id"] for row in ROWS]
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["escape", "rail-switch", "created"])
async def test_manager_create_wizard_result_contract(route: str) -> None:
    # Escape pops the wizard and drops the manager's callback uncalled (no
    # reload); a rail switch replaces the wizard without calling it; a
    # completed create dismisses with True and the manager reloads.
    case = _case("manager")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        manager = await open_case(case, app, pilot)
        fetch = app.ovh_service.fetch_instances_cached
        cloud = app.ovh_cloud_service
        ledger: list = []
        push_screen = app.push_screen

        def _recording_push(screen, callback=None, *args, **kwargs):
            if isinstance(screen, OVHCloudCreateScreen) and callback is not None:
                callback = _ledgered(ledger, callback)
            return push_screen(screen, callback, *args, **kwargs)

        await _focus_row(pilot, manager, 0)
        with patch.object(app, "push_screen", _recording_push):
            await pilot.press("n")
            await wait_until(lambda: isinstance(app.screen, OVHCloudCreateScreen))
        wizard = app.screen
        await _ready(wizard)
        if route == "escape":
            await pilot.press("escape")
            await wait_until(lambda: app.screen is manager)
            await pilot.pause()
            assert ledger == []
            assert fetch.await_args_list == [call(force_refresh=True)]
        elif route == "rail-switch":
            sidebar = await _enter_rail(pilot, wizard)
            sidebar.query_one("#nav_list").focus()
            await pilot.press("enter")
            await wait_until(lambda: wizard not in app.screen_stack)
            await pilot.pause()
            stack = tuple(type(screen).__name__ for screen in app.screen_stack)
            assert manager in app.screen_stack, stack
            # switch_screen drops the wizard's callback without calling it.
            assert ledger == [], stack
            assert fetch.await_args_list == [call(force_refresh=True)], stack
        else:
            field = wizard.query_one("#input_name", Input)
            field.focus()
            await wait_until(lambda: app.focused is field)
            await pilot.press(*"web-2")
            await wait_until(lambda: field.value == "web-2")
            await _click(pilot, "#btn_create")
            await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
            await _type_and_confirm(pilot, app.screen, "create")
            await wait_until(lambda: app.screen is manager)
            # The wizard refreshes the fleet, then the manager reloads its list.
            await wait_until(lambda: fetch.await_count == 3)
            await wait_until(lambda: not manager._loading)
            assert ledger == [True]
            cloud.create_instance.assert_awaited_once_with(
                project_id=PROJECT, name="web-2", flavor_id="flv-1",
                image_id="img-1", region="GRA7", ssh_key_id="key-1",
            )
            app.ovh_audit.log_action.assert_called_once_with(
                action="cloud_create", target=PROJECT,
                details={"name": "web-2", "flavor_id": "flv-1", "image_id": "img-1",
                         "region": "GRA7", "ssh_key_id": "key-1"},
                confirmed=True,
            )
            assert fetch.await_args_list == [call(force_refresh=True)] * 3
        if route != "created":
            assert cloud.create_instance.await_count == 0
            assert app.ovh_audit.log_action.call_count == 0
        assert cloud.delete_instance.await_count == 0
        assert app.config_manager.save.call_count == 0
        assert app._exception is None

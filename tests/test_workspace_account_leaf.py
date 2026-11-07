"""Account-area workspaces keep their content, hotkeys and service boundaries."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Static, TextArea

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, CustomServer
from servonaut.screens.bug_report import BugReportScreen
from servonaut.screens.bug_report_consent_modal import BugReportConsentModal
from servonaut.screens.custom_servers import CustomServersScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.key_management import KeyManagementScreen
from servonaut.services.bug_report_service import BugReportService
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.relay_indicator import RelayStatusScreen
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_essential_targets, assert_layout, content, one_layout_transition,
    open_case, open_chat, preserve_native_state,
)
from tests.test_consent_dialogs import fake_payload
from tests.test_workspace_pilot import _Host, _click


SERVERS = ("web-1", "db-1", "cache-1")


class _CustomServers:
    """In-memory custom server store with the service's read/remove surface."""

    def __init__(self) -> None:
        self.servers = [
            CustomServer(name=name, host=f"10.0.0.{index + 1}", username="admin")
            for index, name in enumerate(SERVERS)
        ]
        self.remove_server = Mock(side_effect=self._remove)

    def _remove(self, name: str) -> bool:
        before = len(self.servers)
        self.servers = [server for server in self.servers if server.name != name]
        return len(self.servers) < before

    def list_servers(self) -> list[CustomServer]:
        return list(self.servers)

    def list_as_instances(self) -> list[dict]:
        return [
            {"id": server.name, "name": server.name, "is_custom": True}
            for server in self.servers
        ]


class _AccountHost(_Host):
    """The accepted native workspace host with inert account-area services."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        config = AppConfig(
            default_key="~/.ssh/example_key",
            instance_keys={"id-web-1": "~/.ssh/web_key"},
        )
        self.config_manager = SimpleNamespace(
            get=Mock(return_value=config), save=Mock(), update=Mock(),
        )
        self.ssh_service = SimpleNamespace(
            check_ssh_agent=Mock(return_value=True),
            start_ssh_agent=Mock(return_value=True),
            list_available_keys=Mock(return_value=["~/.ssh/example_key", "~/.ssh/web_key"]),
            add_key_to_agent=Mock(return_value=True),
        )
        self.custom_server_service = _CustomServers()
        self.reconcile_team_memory = Mock(return_value=False)
        self.bug_report_service = MagicMock(spec=BugReportService)
        self.bug_report_service.collect_diagnostics.return_value = fake_payload()
        self.bug_report_service.render_preview.return_value = "Example diagnostic preview"
        self.relay_restart_entered = asyncio.Event()
        self.relay_restart_release = asyncio.Event()
        self.relay_manager = SimpleNamespace(
            restart=AsyncMock(side_effect=self._restart),
            stop=AsyncMock(return_value=None),
            last_error=None,
        )

    async def _restart(self) -> SimpleNamespace:
        self.relay_restart_entered.set()
        await self.relay_restart_release.wait()
        return SimpleNamespace(state=None, message="")


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    status = AsyncMock(return_value='{"connected": true, "client_ids": []}')
    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=status),
    )
    process = Mock(side_effect=AssertionError("Unexpected subprocess"))
    connection = AsyncMock(side_effect=AssertionError("Unexpected network"))
    keyring = Mock(side_effect=AssertionError("Unexpected keyring operation"))
    monkeypatch.setattr("subprocess.Popen", process)
    monkeypatch.setattr("subprocess.run", process)
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", connection)
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, keyring)
    yield
    process.assert_not_called()
    connection.assert_not_awaited()
    keyring.assert_not_called()


def _plain(widget: Static) -> str:
    return widget.render().plain


async def _push(app: ServonautApp, screen: WorkspaceScreen) -> None:
    await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
    await app.push_screen(screen)


async def _consent(app: ServonautApp, pilot: Pilot, report: BugReportScreen) -> None:
    await wait_until(lambda: isinstance(app.screen, BugReportConsentModal))
    await pilot.pause()
    await _click(pilot, "#continue")
    await wait_until(lambda: app.screen is report)
    await wait_until(lambda: "collected" in _plain(report.query_one("#diagnostics-status", Static)))


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        screen = {
            "keys": KeyManagementScreen, "custom": CustomServersScreen,
            "relay": RelayStatusScreen, "bug": BugReportScreen,
        }[kind]()
        await _push(app, screen)
        if kind == "bug":
            await _consent(app, pilot, screen)
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, KeyManagementScreen):
        await wait_until(lambda: screen.query_one("#available_keys_table", DataTable).row_count == 2)
    elif isinstance(screen, CustomServersScreen):
        await wait_until(lambda: screen.query_one("#custom_servers_table", DataTable).row_count == 3)
    elif isinstance(screen, RelayStatusScreen):
        await wait_until(lambda: "connected" in _plain(screen.query_one("#backend_status", Static)))
    else:
        await wait_until(lambda: not screen.query_one("#submit", Button).disabled)


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, KeyManagementScreen):
        screen.query_one("#input_mapping_instance", Input).value = "id-db-1"
        screen.query_one("#input_mapping_key", Input).value = "~/.ssh/db_key"
    elif isinstance(screen, CustomServersScreen):
        screen.query_one("#custom_servers_table", DataTable).move_cursor(row=1)
    elif isinstance(screen, BugReportScreen):
        screen.query_one("#title", Input).value = "Example café Ω summary"
        screen.query_one("#description", TextArea).load_text("Steps\nExpected Ω")


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, KeyManagementScreen):
        tables = tuple(screen.query(DataTable))
        return (
            _plain(screen.query_one("#current_default_key", Static)),
            tuple((table, table.row_count, table.cursor_coordinate) for table in tables),
            tuple((field.id, field.value) for field in screen.query(Input)),
        )
    if isinstance(screen, CustomServersScreen):
        table = screen.query_one("#custom_servers_table", DataTable)
        return (
            table, table.row_count, table.cursor_row,
            screen.query_one("#add_form").display,
            screen.query_one("#add_form_actions").display,
        )
    if isinstance(screen, RelayStatusScreen):
        return (
            _plain(screen.query_one("#local_status", Static)),
            _plain(screen.query_one("#backend_status", Static)),
        )
    return (
        screen.query_one("#title", Input).value,
        screen.query_one("#description", TextArea).text,
        screen._consent, screen._payload,
        screen.query_one("#submit", Button).disabled,
    )


# The scroll containers are the derived native first focus (no AUTO_FOCUS;
# workspace and rail buttons are not focusable outside navigation mode).
# Bug report focus after the consent modal closes is the expected title
# Input. Both are characterised by open_case on the first native run.
PRIMARY = {
    "keys": "#keys_container", "custom": "#custom_servers_container",
    "relay": "#relay_container", "bug": "#title",
}
TARGETS = {
    "keys": ("#input_default_key", "#btn_set_default", "#input_mapping_instance",
             "#input_mapping_key", "#btn_add_mapping", "#instance_keys_table",
             "#input_agent_key", "#btn_add_agent", "#btn_list_agent", "#available_keys_table"),
    "custom": ("#custom_servers_table", "#btn_add_server", "#btn_remove_server", "#btn_back"),
    "relay": ("#btn_relay_restart", "#btn_relay_stop", "#btn_relay_close"),
    "bug": ("#title", "#description", "#edit-consent", "#refresh-preview", "#submit"),
}
KINDS = ("keys", "custom", "relay", "bug")
# Native boundary samples are deliberately absent until qualified measurements.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'keys': {
        ('chat-min', False): (
            BoundarySample((92, 50), 47, True, True),
            BoundarySample((93, 50), 48, False, True),
            BoundarySample((94, 50), 49, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((120, 50), 47, True, True),
            BoundarySample((121, 50), 48, True, True),
            BoundarySample((122, 50), 49, False, True),
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
    'custom': {
        ('chat-min', False): (
            BoundarySample((102, 50), 57, True, True),
            BoundarySample((103, 50), 58, False, True),
            BoundarySample((104, 50), 59, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((136, 50), 57, True, True),
            BoundarySample((138, 50), 58, True, True),
            BoundarySample((139, 50), 59, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((131, 50), 79, False, True),
            BoundarySample((133, 50), 80, False, True),
            BoundarySample((134, 50), 81, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((168, 50), 79, False, True),
            BoundarySample((169, 50), 80, False, False),
            BoundarySample((170, 50), 81, False, False),
        ),
    },
    'relay': {
        ('chat-min', False): (
            BoundarySample((138, 50), 83, True, True),
            BoundarySample((140, 50), 84, False, False),
            BoundarySample((141, 50), 85, False, False),
        ),
        ('chat-min', True): (
            BoundarySample((172, 50), 83, True, True),
            BoundarySample((173, 50), 84, False, False),
            BoundarySample((174, 50), 85, False, False),
        ),
        ('content-narrow', False): (
            BoundarySample((138, 50), 83, True, True),
            BoundarySample((140, 50), 84, False, False),
            BoundarySample((141, 50), 85, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((172, 50), 83, True, True),
            BoundarySample((173, 50), 84, False, False),
            BoundarySample((174, 50), 85, False, False),
        ),
    },
    'bug': {
        ('chat-min', False): (
            BoundarySample((102, 50), 57, True, True),
            BoundarySample((103, 50), 58, False, True),
            BoundarySample((104, 50), 59, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((136, 50), 57, True, True),
            BoundarySample((138, 50), 58, True, True),
            BoundarySample((139, 50), 59, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((163, 50), 99, False, True),
            BoundarySample((164, 50), 100, False, False),
            BoundarySample((165, 50), 101, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((188, 50), 99, False, True),
            BoundarySample((189, 50), 100, False, False),
            BoundarySample((190, 50), 101, False, False),
        ),
    },
}


CASES = tuple(
    ReflowCase(kind, _AccountHost, _opener(kind), _ready, PRIMARY[kind],
               TARGETS[kind], _seed, _state, (), boundaries=_MEASURED_BOUNDARIES[kind])
    for kind in KINDS
)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("chat_open", [False, True])
async def test_account_workspace_pane_combinations(
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
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
async def test_account_workspace_native_state_survives_reflow(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_account_workspace_uses_qualified_native_boundaries(
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
            assert case.state(screen) == baseline


async def _enter_rail(pilot: Pilot, screen: WorkspaceScreen) -> Sidebar:
    await pilot.press("shift+f6")
    sidebar = screen.query_one(Sidebar)
    await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
    return sidebar


def _observe(app: _AccountHost, screen: WorkspaceScreen) -> object:
    ssh = app.ssh_service
    workers = tuple(sorted(
        worker.name for worker in app.workers
        if worker.name in {"relay_restart", "relay_stop"} and not worker.is_finished
    ))
    return (
        app.screen is screen, ssh.check_ssh_agent.call_count,
        ssh.start_ssh_agent.call_count, ssh.list_available_keys.call_count,
        app.custom_server_service.remove_server.call_count,
        app.relay_manager.restart.call_count, app.relay_manager.stop.call_count,
        workers, _state(screen),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,key", [
    ("keys", "r"), ("custom", "n"), ("custom", "d"), ("relay", "r"), ("relay", "s"),
    ("bug", "x"),
])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_rail_focused_hotkeys_have_no_side_effects(
    kind: str, key: str, navigation_visible: bool,
) -> None:
    case = next(case for case in CASES if case.name == kind)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        before = _observe(app, screen)
        sidebar = await _enter_rail(pilot, screen)
        await pilot.press(key)
        await pilot.pause()
        assert _observe(app, screen) == before
        assert sidebar.navigation_mode and sidebar.has_focus_within
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert app.screen is screen and _observe(app, screen) == before
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["keys", "custom", "relay"])
async def test_check_action_composes_rail_guard_before_passthrough(kind: str) -> None:
    case = next(case for case in CASES if case.name == kind)
    action = {"keys": "refresh", "custom": "remove_server", "relay": "stop"}[kind]
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        assert screen.check_action(action, ()) is True
        await _enter_rail(pilot, screen)
        assert screen.check_action(action, ()) is None
        await pilot.press("escape")
        await wait_until(lambda: not screen.query_one(Sidebar).navigation_mode)
        if kind != "relay":
            field = screen.query_one("#input_default_key" if kind == "keys" else "#input_name", Input)
            if kind == "custom":
                await pilot.press("n")
                await wait_until(lambda: app.focused is field)
            else:
                field.focus()
                await wait_until(lambda: app.focused is field)
            assert screen.check_action(action, ()) is None


@pytest.mark.asyncio
async def test_key_refresh_still_runs_from_content() -> None:
    case = next(case for case in CASES if case.name == "keys")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        await open_case(case, app, pilot)
        calls = app.ssh_service.check_ssh_agent.call_count
        await pilot.press("r")
        await wait_until(lambda: app.ssh_service.check_ssh_agent.call_count == calls + 1)
        assert app.ssh_service.start_ssh_agent.call_count == 0


@pytest.mark.asyncio
async def test_custom_server_add_and_remove_still_run_from_content() -> None:
    case = next(case for case in CASES if case.name == "custom")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        table = screen.query_one("#custom_servers_table", DataTable)
        table.focus()
        await wait_until(lambda: app.focused is table and table.cursor_row == 1)
        await pilot.press("d")
        await wait_until(lambda: table.row_count == 2)
        app.custom_server_service.remove_server.assert_called_once_with("db-1")
        app.reconcile_team_memory.assert_called_once_with()
        await pilot.press("n")
        await wait_until(lambda: app.focused is screen.query_one("#input_name", Input))
        assert screen.query_one("#add_form").display
        assert screen.query_one("#add_form_actions").display


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["key", "button"])
async def test_relay_restart_worker_is_app_owned_and_outlives_the_screen(route: str) -> None:
    case = next(case for case in CASES if case.name == "relay")
    app = case.app_factory(True)
    # Finished workers leave app.workers, so record the App-level launches.
    app.run_worker = Mock(wraps=app.run_worker)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        launched = [call.kwargs.get("name") for call in app.run_worker.call_args_list]
        # Diagnostic reads belong to the view; only mutations outlive it.
        assert "relay_modal_backend" not in launched
        if route == "key":
            await pilot.press("r")
        else:
            await _click(pilot, "#btn_relay_restart")
        await wait_until(app.relay_restart_entered.is_set)
        await wait_until(lambda: screen not in app.screen_stack)
        worker = next(worker for worker in app.workers if worker.name == "relay_restart")
        assert worker.node is app and not worker.is_finished
        restart_call = next(
            call for call in app.run_worker.call_args_list
            if call.kwargs.get("name") == "relay_restart"
        )
        assert restart_call.kwargs["exclusive"] is True
        assert restart_call.kwargs["exit_on_error"] is False
        app.relay_restart_release.set()
        await wait_until(lambda: worker.is_finished)
        app.relay_manager.restart.assert_awaited_once_with()
        assert isinstance(app.screen, InstanceListScreen) and app._exception is None


@pytest.mark.asyncio
async def test_relay_stop_from_content_is_app_owned_and_pops_once() -> None:
    case = next(case for case in CASES if case.name == "relay")
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await pilot.press("s")
        await wait_until(lambda: screen not in app.screen_stack)
        await wait_until(lambda: app.relay_manager.stop.await_count == 1)
        assert isinstance(app.screen, InstanceListScreen) and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_bug_report_first_consent_cancel_still_leaves_without_collecting(
    navigation_visible: bool,
) -> None:
    app = _AccountHost(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        report = BugReportScreen()
        await _push(app, report)
        await wait_until(lambda: isinstance(app.screen, BugReportConsentModal))
        await pilot.press("escape")
        await wait_until(lambda: report not in app.screen_stack)
        assert isinstance(app.screen, InstanceListScreen)
        app.bug_report_service.collect_diagnostics.assert_not_called()
        assert app.screen.query_one(Sidebar).display is navigation_visible
        assert app._exception is None

"""DB-credential workspaces keep scans, targets and stores safe beside chat."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from pathlib import PurePosixPath
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, call, create_autospec, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Checkbox, DataTable, Input, OptionList

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, DBProfile
from servonaut.mcp.db_staging import DBCredentialStaging
from servonaut.screens.db_coverage_view import ConfirmDbRemoveModal, DbCoverageScreen
from servonaut.screens.db_credential_scan import DbCredentialScanScreen
from servonaut.screens.db_fleet_scan import DbFleetScanScreen
from servonaut.screens.db_scan_roots import DbScanRootsScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.services.secret_provider import LocalProvider
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_essential_targets, assert_layout, collapse_chat, content,
    one_layout_transition, open_case, open_chat, preserve_native_state,
)
from tests.test_workspace_pilot import _Host, _click


INSTANCE = {"id": "id-web-1", "name": "web-1", "is_custom": True, "username": "admin"}
STORE = "the local secret store"


def _candidate(token: str = "dbstg_example") -> dict:
    return {
        "token": token, "engine": "mysql", "user": "app", "host": "127.0.0.1",
        "port": 3306, "database": "appdb", "password_preview": "****xyz",
        "source": "/var/www/app/.env",
    }


class _DbHost(_Host):
    """The accepted native workspace host with explicit DB-tool fakes."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        config = AppConfig()
        config.db_profiles = [DBProfile(
            instance="id-web-1", label="shop.example.com", password_secret="db/shop",
        )]
        config.db_scan_roots = {"id-web-1": ["/srv/app"]}
        self.config = config
        self.config_manager = SimpleNamespace(
            get=lambda: self.config, save=Mock(), update=Mock(),
        )
        self.scan_release = asyncio.Event()
        self.scan_release.set()
        self.staging_batch = create_autospec(DBCredentialStaging, instance=True)
        # Only the DB tool surface these screens call; anything else raises.
        self.servonaut_tools = MagicMock(spec=[
            "db_scan_stage", "db_setup_save", "db_setup_remove", "describe_secret_store",
            "open_db_staging_batch",
        ])
        # The fleet scan opens one batch store synchronously before probing.
        self.servonaut_tools.open_db_staging_batch = Mock(return_value=self.staging_batch)
        self.servonaut_tools.db_scan_stage = AsyncMock(side_effect=self._stage)
        self.servonaut_tools.db_setup_save = AsyncMock(return_value="Saved db_profile")
        self.servonaut_tools.db_setup_remove = AsyncMock(return_value="Removed db_profile")
        self.servonaut_tools.describe_secret_store = Mock(return_value=STORE)
        self.auth_service = MagicMock()
        self.entitlement_guard = MagicMock()
        self.connection_service = SimpleNamespace(
            resolve_profile=Mock(return_value=None),
            get_target_host=Mock(return_value="192.0.2.10"),
            get_proxy_args=Mock(return_value=[]),
            get_extra_options=Mock(return_value=[]),
            get_target_port=Mock(return_value=22),
        )
        self.ssh_service = MagicMock()

    async def _stage(
        self, instance_id: str, search_path: str = "", source: str = "auto",
        *, staging: object = None,
    ) -> dict:
        # Mirrors ServonautTools.db_scan_stage, so a wrong keyword fails here.
        await self.scan_release.wait()
        # One token per instance, so every commit proves which row it stored.
        return {"error": None, "instance": instance_id,
                "candidates": [_candidate(f"dbstg-{instance_id}")]}


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    provider = create_autospec(LocalProvider, instance=True)
    provider.provider_name = "local"
    provider.path = PurePosixPath("example-secrets.json")
    provider.list_secrets.return_value = ["db/shop"]
    monkeypatch.setattr(
        "servonaut.services.secret_provider_resolver.resolve_secret_provider",
        lambda *args, **kwargs: provider,
    )
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
    yield {"provider": provider, **trips}
    trips["browser"].assert_not_called()
    trips["process"].assert_not_called()
    trips["async_process"].assert_not_awaited()
    trips["socket"].assert_not_called()
    trips["connection"].assert_not_awaited()
    trips["keyring"].assert_not_called()


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = {
            "fleet": lambda: DbFleetScanScreen(list(app.instances)),
            "roots": lambda: DbScanRootsScreen(dict(INSTANCE), roots=["/srv/app"]),
            "coverage": DbCoverageScreen,
            "scan": lambda: DbCredentialScanScreen(dict(INSTANCE)),
        }[kind]()
        app.root_results = []
        await app.push_screen(screen, app.root_results.append)
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, DbFleetScanScreen):
        await wait_until(lambda: screen.query_one("#fleet_db_table", DataTable).row_count == 2)
    elif isinstance(screen, DbScanRootsScreen):
        await wait_until(lambda: screen.query_one("#db_roots_list", OptionList).option_count >= 1)
    elif isinstance(screen, DbCoverageScreen):
        await wait_until(lambda: screen.query_one("#db_cov_table", DataTable).row_count == 2)
    else:
        await wait_until(lambda: screen.query_one("#db_scan_candidates", OptionList).option_count >= 1)


def _seed(screen: WorkspaceScreen) -> None:
    return None


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, DbFleetScanScreen):
        table = screen.query_one("#fleet_db_table", DataTable)
        return (table, table.row_count, table.cursor_row)
    if isinstance(screen, DbScanRootsScreen):
        return (tuple(screen._roots),
                screen.query_one("#db_roots_list", OptionList).option_count)
    if isinstance(screen, DbCoverageScreen):
        table = screen.query_one("#db_cov_table", DataTable)
        return (table, table.row_count, table.cursor_row, tuple(screen._rows))
    options = screen.query_one("#db_scan_candidates", OptionList)
    return (options, options.option_count, screen._selected_token)


# Native first focus: roots and coverage preserve their task controls explicitly;
# fleet uses its scroll owner, and scan focuses its candidate list.
PRIMARY = {"fleet": "#fleet_db_container", "roots": "#db_roots_list",
           "coverage": "#db_cov_filter", "scan": "#db_scan_candidates"}
TARGETS = {
    "fleet": ("#fleet_db_table", "#fleet_commit_all", "#fleet_commit_selected", "#fleet_rescan"),
    "roots": ("#db_roots_list", "#db_roots_input", "#db_roots_add_typed", "#db_roots_add_browsed",
              "#db_roots_remove", "#db_roots_save", "#db_roots_cancel"),
    "coverage": ("#db_cov_filter", "#db_cov_table"),
    "scan": ("#db_scan_candidates", "#db_scan_store", "#db_scan_rescan", "#db_scan_roots_btn"),
}
KINDS = ("fleet", "roots", "coverage", "scan")
# Native boundary samples are deliberately absent until qualified measurements.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'fleet': {
        ('chat-min', False): (
            BoundarySample((110, 50), 65, True, True),
            BoundarySample((111, 50), 66, False, True),
            BoundarySample((112, 50), 67, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((150, 50), 65, True, True),
            BoundarySample((151, 50), 66, True, True),
            BoundarySample((152, 50), 67, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((138, 50), 83, False, True),
            BoundarySample((140, 50), 84, False, False),
            BoundarySample((141, 50), 85, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((172, 50), 83, False, True),
            BoundarySample((173, 50), 84, False, False),
            BoundarySample((174, 50), 85, False, False),
        ),
    },
    'roots': {
        ('chat-min', False): (
            BoundarySample((118, 50), 71, True, True),
            BoundarySample((120, 50), 72, False, True),
            BoundarySample((121, 50), 73, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((160, 50), 71, True, True),
            BoundarySample((161, 50), 72, False, True),
            BoundarySample((162, 50), 73, False, True),
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
    'coverage': {
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
    'scan': {
        ('chat-min', False): (
            BoundarySample((104, 50), 59, True, True),
            BoundarySample((105, 50), 60, False, True),
            BoundarySample((106, 50), 61, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((140, 50), 59, True, True),
            BoundarySample((141, 50), 60, True, True),
            BoundarySample((142, 50), 61, False, True),
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
}


CASES = tuple(
    ReflowCase(kind, _DbHost, _opener(kind), _ready, PRIMARY[kind], TARGETS[kind],
               _seed, _state, (), boundaries=_MEASURED_BOUNDARIES[kind])
    for kind in KINDS
)


def _case(kind: str) -> ReflowCase:
    return next(case for case in CASES if case.name == kind)


def _effects(app: _DbHost) -> tuple:
    tools = app.servonaut_tools
    return (tools.db_scan_stage.await_count, tools.db_setup_save.await_count,
            tools.db_setup_remove.await_count, app.config_manager.save.call_count,
            tuple(app.root_results))


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("chat_open", [False, True])
async def test_db_workspace_pane_combinations(
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
async def test_db_workspace_native_state_survives_reflow(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_db_workspace_uses_qualified_native_boundaries(
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


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,key", [
    ("fleet", "s"), ("fleet", "a"), ("roots", "a"), ("roots", "b"), ("roots", "d"),
    ("coverage", "r"), ("coverage", "d"), ("scan", "s"), ("scan", "p"),
])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_rail_focused_db_keys_have_no_side_effects(
    kind: str, key: str, navigation_visible: bool,
) -> None:
    case = _case(kind)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        before = (case.state(screen), _effects(app))
        sidebar = await _enter_rail(pilot, screen)
        await pilot.press(key)
        await pilot.pause()
        # Commit, remove, rescan, root edits or a pushed dialog would show here.
        assert app.screen is screen
        assert (case.state(screen), _effects(app)) == before
        assert sidebar.navigation_mode and sidebar.has_focus_within
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
async def test_fleet_commit_all_still_commits_once_from_content() -> None:
    case = _case("fleet")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        tools = app.servonaut_tools
        # web-1 already has a vaulted profile: only db-1 is probed, in one batch.
        tools.open_db_staging_batch.assert_called_once_with()
        assert tools.db_scan_stage.await_args_list == [
            call("id-db-1", staging=app.staging_batch),
        ]
        screen.query_one("#fleet_db_table", DataTable).focus()
        await pilot.pause()
        await pilot.press("a")
        await wait_until(lambda: tools.db_setup_save.await_count == 1)
        await pilot.pause()
        assert tools.db_setup_save.await_args_list == [
            call("dbstg-id-db-1", instance_id="id-db-1"),
        ]
        assert tools.db_setup_remove.await_count == 0


@pytest.mark.asyncio
async def test_coverage_check_action_and_remove_confirmation_from_content() -> None:
    case = _case("coverage")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        # The filter Input keeps the original passthrough for printable keys.
        assert app.focused is screen.query_one("#db_cov_filter")
        assert screen.check_action("remove", ()) is None
        await _enter_rail(pilot, screen)
        assert screen.check_action("remove", ()) is None
        await pilot.press("escape")
        table = screen.query_one("#db_cov_table", DataTable)
        table.focus()
        await wait_until(lambda: app.focused is table)
        assert screen.check_action("remove", ()) is True
        row = next(index for index, item in enumerate(screen._rows) if item.secret_present)
        captured = screen._rows[row]
        assert (captured.instance_id, captured.label) == ("id-web-1", "shop.example.com")
        table.move_cursor(row=row)
        await pilot.press("d")
        await wait_until(lambda: isinstance(app.screen, ConfirmDbRemoveModal))
        await _click(pilot, "#btn_db_remove_cancel")
        await wait_until(lambda: app.screen is screen)
        assert app.servonaut_tools.db_setup_remove.await_count == 0
        # Beside chat, Confirm removes exactly the captured row: first with the
        # default "also delete the secret" choice, then with it unticked.
        await open_chat(app, pilot, screen)
        assert content(screen).display
        for removals, (toggle, delete_secret) in enumerate(((False, True), (True, False)), 1):
            table.focus()
            await wait_until(lambda: app.focused is table)
            table.move_cursor(row=row)
            await pilot.press("d")
            await wait_until(lambda: isinstance(app.screen, ConfirmDbRemoveModal))
            checkbox = app.screen.query_one("#db_remove_delete_secret", Checkbox)
            assert checkbox.value is True and not checkbox.disabled
            if toggle:
                assert await pilot.click("#db_remove_delete_secret")
                await wait_until(lambda: checkbox.value is False)
            await _click(pilot, "#btn_db_remove_confirm")
            await wait_until(lambda: app.screen is screen)
            await wait_until(
                lambda: app.servonaut_tools.db_setup_remove.await_count == removals,
            )
            await wait_until(lambda: not [
                worker for worker in app.workers
                if worker.group == "db_coverage" and not worker.is_finished
            ])
            assert app.servonaut_tools.db_setup_remove.await_args_list[-1] == call(
                captured.instance_id, app=captured.label, delete_secret=delete_secret,
            )
        assert app.servonaut_tools.db_setup_remove.await_count == 2
        assert app.servonaut_tools.db_setup_save.await_count == 0


@pytest.mark.asyncio
async def test_scan_keeps_a_held_scan_running_through_chat_reflow() -> None:
    case = _case("scan")
    app = case.app_factory(True)
    app.scan_release.clear()
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = DbCredentialScanScreen(dict(INSTANCE))
        await app.push_screen(screen)
        await wait_until(lambda: app.servonaut_tools.db_scan_stage.await_count == 1)
        tools = app.servonaut_tools
        # The configured root is passed through; no fleet batch is opened.
        assert tools.db_scan_stage.await_args_list == [
            call("id-web-1", search_path="/srv/app"),
        ]
        worker = next(w for w in app.workers if w.name == "db_scan")
        panel = await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert screen.has_class("-chat-replace") and not content(screen).display
        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        assert not worker.is_finished and panel.is_attached
        app.scan_release.set()
        options = screen.query_one("#db_scan_candidates", OptionList)
        await wait_until(lambda: options.option_count == 1)
        await wait_until(lambda: worker.is_finished)
        assert options.get_option_at_index(0).id == "dbstg-id-web-1"
        assert screen._selected_token == "dbstg-id-web-1"
        assert tools.db_scan_stage.await_args_list == [
            call("id-web-1", search_path="/srv/app"),
        ]
        assert tools.open_db_staging_batch.call_count == 0
        assert tools.db_setup_save.await_count == 0
        assert app._exception is None


def _ledgered(ledger: list, callback: Callable[[object], object]) -> Callable[[object], object]:
    def record(result: object) -> object:
        ledger.append(result)
        return callback(result)
    return record


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["save", "cancel", "rail-switch"])
async def test_nested_scan_roots_characterises_caller_result(route: str) -> None:
    # Option (a): the roots picker adopts the rail. Save and Cancel keep their
    # results; a rail switch away is recorded, not prevented.
    case = _case("scan")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        scan = await open_case(case, app, pilot)
        tools = app.servonaut_tools
        stages = list(tools.db_scan_stage.await_args_list)
        assert stages == [call("id-web-1", search_path="/srv/app")]
        # Record every invocation of the caller's result callback, so a
        # discarded callback ([]) is distinct from a callback(None).
        ledger: list = []
        push_screen = app.push_screen

        def _recording_push(screen, callback=None, *args, **kwargs):
            if isinstance(screen, DbScanRootsScreen) and callback is not None:
                callback = _ledgered(ledger, callback)
            return push_screen(screen, callback, *args, **kwargs)

        with patch.object(app, "push_screen", _recording_push):
            await pilot.press("p")
            await wait_until(lambda: isinstance(app.screen, DbScanRootsScreen))
        roots = app.screen
        # Every route starts from an unsaved draft edit, typed natively.
        field = roots.query_one("#db_roots_input", Input)
        field.focus()
        await wait_until(lambda: app.focused is field)
        await pilot.press(*"/srv/extra")
        await wait_until(lambda: field.value == "/srv/extra")
        await _click(pilot, "#db_roots_add_typed")
        await wait_until(lambda: roots._roots == ["/srv/app", "/srv/extra"])
        assert roots.query_one("#db_roots_list", OptionList).option_count == 2
        assert app.config.db_scan_roots == {"id-web-1": ["/srv/app"]}
        if route == "save":
            await _click(pilot, "#db_roots_save")
            await wait_until(lambda: app.screen is scan)
            await wait_until(lambda: tools.db_scan_stage.await_count == len(stages) + 1)
            assert ledger == [["/srv/app", "/srv/extra"]]
            app.config_manager.save.assert_called_once_with(app.config)
            assert app.config.db_scan_roots == {"id-web-1": ["/srv/app", "/srv/extra"]}
            assert tools.db_scan_stage.await_args_list == stages + [
                call("id-web-1", search_path="/srv/app /srv/extra"),
            ]
        elif route == "cancel":
            await _click(pilot, "#db_roots_cancel")
            await wait_until(lambda: app.screen is scan)
            await pilot.pause()
            assert ledger == [None]
            assert app.config_manager.save.call_count == 0
            assert app.config.db_scan_roots == {"id-web-1": ["/srv/app"]}
            assert tools.db_scan_stage.await_args_list == stages
        else:
            sidebar = await _enter_rail(pilot, roots)
            sidebar.query_one("#nav_list").focus()
            await pilot.press("enter")
            await wait_until(lambda: roots not in app.screen_stack)
            await pilot.pause()
            stack = tuple(type(screen).__name__ for screen in app.screen_stack)
            assert scan in app.screen_stack, stack
            # switch_screen drops the pushed screen's callback without calling it.
            assert ledger == [], stack
            assert app.config_manager.save.call_count == 0, stack
            assert app.config.db_scan_roots == {"id-web-1": ["/srv/app"]}, stack
            assert tools.db_scan_stage.await_args_list == stages, stack
        assert tools.db_setup_save.await_count == 0

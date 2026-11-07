"""Server tool adapters exercise native workspace reflow without infrastructure."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import DataTable, Input, Static, TextArea

from servonaut.app import ServonautApp
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.file_browser import FileBrowserScreen
from servonaut.screens.ovh_reinstall import OVHReinstallScreen
from servonaut.screens.ovh_resize import OVHResizeScreen
from servonaut.screens.scan_results import ScanResultsScreen
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.remote_tree import RemoteTree
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample,
    ReflowCase,
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
from tests.test_workspace_reflow import _painted
from tests.test_workspace_server_screens import _ServerWorkspaceApp, _server


@pytest.fixture(autouse=True)
def _isolated_services(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # Native widget events remain real; external work must never start here.
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    ssh = Mock(side_effect=AssertionError("Unexpected SSH operation"))
    monkeypatch.setattr("servonaut.widgets.remote_tree.run_ssh", ssh)
    hosts: list[_ServerWorkspaceApp] = []
    original_init = _ServerWorkspaceApp.__init__

    def tracked_init(
        self: _ServerWorkspaceApp, navigation_visible: bool = True,
    ) -> None:
        original_init(self, navigation_visible)
        hosts.append(self)

    monkeypatch.setattr(_ServerWorkspaceApp, "__init__", tracked_init)
    yield
    ssh.assert_not_called()
    for app in hosts:
        app.scan_service.scan_server.assert_not_awaited()
        app.ovh_vps_service.upgrade.assert_not_awaited()
        app.ovh_vps_service.reinstall.assert_not_awaited()
        for name in ("build_upload_command", "build_download_command", "execute_transfer"):
            getattr(app.scp_service, name).assert_not_called()


def _app(navigation_visible: bool) -> _ServerWorkspaceApp:
    app = _ServerWorkspaceApp(navigation_visible)
    app.theme = "servonaut"
    # Read-only provider lists are the existing host's fixed AsyncMock data.
    app.scan_service.scan_server = AsyncMock(
        side_effect=AssertionError("Unexpected scan operation"),
    )
    app.ovh_vps_service.upgrade = AsyncMock(
        side_effect=AssertionError("Unexpected resize operation"),
    )
    app.ovh_vps_service.reinstall = AsyncMock(
        side_effect=AssertionError("Unexpected reinstall operation"),
    )
    app.scp_service = Mock()
    for name in ("build_upload_command", "build_download_command", "execute_transfer"):
        getattr(app.scp_service, name).side_effect = AssertionError(
            "Unexpected transfer operation",
        )
    return app


def _opener(
    screen_type: type[WorkspaceScreen],
) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        screen = screen_type(_server("web-1"))
        await app.push_screen(screen)
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    tables = list(screen.query(DataTable))
    if tables:
        await wait_until(lambda: tables[0].row_count == 1)


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, FileBrowserScreen):
        tree = screen.query_one(RemoteTree)
        leaf = tree.root.add_leaf("report café Ω.txt")
        leaf.data = {"path": "/tmp/report.txt", "type": "file"}
        tree.select_node(leaf)
        tree._cache["/tmp"] = [{"name": "report café Ω.txt", "type": "file"}]
    elif isinstance(screen, SCPTransferScreen):
        screen.query_one("#local_path_input", Input).value = "/tmp/report-Ω.txt"
        screen.query_one("#remote_path_input", Input).value = "/srv/report-Ω.txt"
    else:
        screen.query_one(DataTable).move_cursor(row=0)


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, FileBrowserScreen):
        tree = screen.query_one(RemoteTree)
        return tree, tree.cursor_node, repr(tree._cache)
    if isinstance(screen, SCPTransferScreen):
        local = screen.query_one("#local_path_input", Input)
        remote = screen.query_one("#remote_path_input", Input)
        return local, remote, local.value, remote.value, screen._transfer_direction
    table = screen.query_one(DataTable)
    rows = tuple(tuple(table.get_row_at(i)) for i in range(table.row_count))
    data = getattr(screen, "_models", getattr(screen, "_images", None))
    return table, table.cursor_row, rows, repr(data)


# Native integer widths and exact CSS policy flags are independently measured.
BOUNDARIES = {
    'files': {
        ('chat-min', False): (
            BoundarySample((92, 40), 47, True, True),
            BoundarySample((93, 40), 48, False, True),
            BoundarySample((94, 40), 49, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((120, 40), 47, True, True),
            BoundarySample((121, 40), 48, True, True),
            BoundarySample((122, 40), 49, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((131, 40), 79, False, True),
            BoundarySample((133, 40), 80, False, True),
            BoundarySample((134, 40), 81, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((168, 40), 79, False, True),
            BoundarySample((169, 40), 80, False, False),
            BoundarySample((170, 40), 81, False, False),
        ),
    },
    'transfer': {
        ('chat-min', False): (
            BoundarySample((96, 40), 51, True, True),
            BoundarySample((97, 40), 52, False, True),
            BoundarySample((98, 40), 53, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((126, 40), 51, True, True),
            BoundarySample((128, 40), 52, True, True),
            BoundarySample((129, 40), 53, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((145, 40), 87, False, True),
            BoundarySample((146, 40), 88, False, True),
            BoundarySample((147, 40), 89, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((176, 40), 87, False, True),
            BoundarySample((177, 40), 88, False, False),
            BoundarySample((178, 40), 89, False, False),
        ),
    },
    'scan': {
        ('chat-min', False): (
            BoundarySample((92, 40), 47, True, True),
            BoundarySample((93, 40), 48, False, True),
            BoundarySample((94, 40), 49, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((120, 40), 47, True, True),
            BoundarySample((121, 40), 48, True, True),
            BoundarySample((122, 40), 49, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((131, 40), 79, False, True),
            BoundarySample((133, 40), 80, False, True),
            BoundarySample((134, 40), 81, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((168, 40), 79, False, True),
            BoundarySample((169, 40), 80, False, False),
            BoundarySample((170, 40), 81, False, False),
        ),
    },
    'resize': {
        ('chat-min', False): (
            BoundarySample((96, 40), 51, True, True),
            BoundarySample((97, 40), 52, False, True),
            BoundarySample((98, 40), 53, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((126, 40), 51, True, True),
            BoundarySample((128, 40), 52, True, True),
            BoundarySample((129, 40), 53, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((138, 40), 83, False, True),
            BoundarySample((140, 40), 84, False, False),
            BoundarySample((141, 40), 85, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((172, 40), 83, False, True),
            BoundarySample((173, 40), 84, False, False),
            BoundarySample((174, 40), 85, False, False),
        ),
    },
    'reinstall': {
        ('chat-min', False): (
            BoundarySample((100, 40), 55, True, True),
            BoundarySample((101, 40), 56, False, True),
            BoundarySample((102, 40), 57, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((133, 40), 55, True, True),
            BoundarySample((135, 40), 56, False, True),
            BoundarySample((136, 40), 57, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((138, 40), 83, False, True),
            BoundarySample((140, 40), 84, False, False),
            BoundarySample((141, 40), 85, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((172, 40), 83, False, True),
            BoundarySample((173, 40), 84, False, False),
            BoundarySample((174, 40), 85, False, False),
        ),
    },
}

CASES = (
    ReflowCase(
        "files", _app, _opener(FileBrowserScreen), _ready, "#remote_tree",
        ("#remote_tree",), _seed, _state,
        (("#remote_tree", "report café Ω.txt"),),
        boundaries=BOUNDARIES["files"],
    ),
    ReflowCase(
        "transfer", _app, _opener(SCPTransferScreen), _ready, "#local_path_input",
        ("#local_path_input", "#remote_path_input", "#transfer_button", "#cancel_button"),
        _seed, _state, (("#local_path_input", "report-Ω.txt"),),
        boundaries=BOUNDARIES["transfer"],
    ),
    ReflowCase(
        "scan", _app, _opener(ScanResultsScreen), _ready, "#scan_button",
        ("#scan_button", "#results_table"), _seed, _state,
        (("#results_table", "example.log"),),
        boundaries=BOUNDARIES["scan"],
    ),
    ReflowCase(
        "resize", _app, _opener(OVHResizeScreen), _ready, "#resize_container",
        ("#models_table", "#btn_upgrade", "#btn_back"), _seed, _state,
        (("#models_table", "larger"),),
        boundaries=BOUNDARIES["resize"],
    ),
    ReflowCase(
        "reinstall", _app, _opener(OVHReinstallScreen), _ready, "#reinstall_container",
        ("#images_table", "#btn_reinstall", "#btn_back"), _seed, _state,
        (("#images_table", "Linux"),),
        boundaries=BOUNDARIES["reinstall"],
    ),
)
CASE_IDS = [case.name for case in CASES]
COPY_TARGETS = {
    "files": "#browser_header", "transfer": "#transfer_banner",
    "scan": "#scan_banner", "resize": "#resize_title",
    "reinstall": "#reinstall_title",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible,chat_open", [
    (False, False), (False, True), (True, False), (True, True),
])
async def test_server_workspace_visibility_combinations(
    case: ReflowCase, size: tuple[int, int],
    navigation_visible: bool, chat_open: bool,
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


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
async def test_server_reflow_preserves_draft_domain_state_and_native_tab_targets(
    case: ReflowCase,
) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
async def test_server_native_static_copy_survives_replacement_and_restore(
    case: ReflowCase, clipboard: _Clipboard,
) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        label = screen.query_one(COPY_TARGETS[case.name], Static)
        label.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        rows = _painted(app, label).splitlines()
        row = next(i for i, text in enumerate(rows) if "web-1" in text)
        column = rows[row].index("web-1")
        origin_x = label.region.x - label.content_region.x + column
        origin_y = label.region.y - label.content_region.y + row
        await _drag(pilot, label, (origin_x, origin_y), (origin_x + 5, origin_y))
        assert clipboard.calls == ["web-1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
async def test_server_qualified_native_boundary_and_painted_fit(
    case: ReflowCase, navigation_visible: bool, kind: str,
) -> None:
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
                # Probe native width only; real policy replaces this content.
                with patch.object(screen, "CHAT_MIN_CONTENT_WIDTH", 1):
                    screen.apply_workspace_state()
                    await pilot.pause()
                    assert content(screen).region.width == sample.native_content_width
                screen.apply_workspace_state()
                await pilot.pause()
                assert screen.has_class("-chat-replace") is sample.expected_replace
                assert screen.has_class("-content-narrow") is (
                    sample.expected_content_narrow
                )
                assert not content(screen).display
            else:
                assert content(screen).region.width == sample.native_content_width
                await assert_essential_targets(case, app, pilot, screen)
            assert case.state(screen) == baseline


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
async def test_server_navigation_reveal_modal_keeps_visible_origin_and_draft(
    case: ReflowCase,
) -> None:
    # Qualification must find a real crossing, rather than derive a terminal
    # width by adding the nominal sidebar width to a rounded content region.
    sample = case.boundary_samples("chat-min", True)[0]
    assert sample.expected_replace
    app = case.app_factory(False)
    async with app.run_test(size=sample.size) as pilot:
        screen = await open_case(case, app, pilot)
        panel = await open_chat(app, pilot, screen)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Retain the tool draft")
        document = editor.document
        assert content(screen).display
        origin = screen.query_one(case.primary_focus_selector)
        await tab_to(pilot, origin)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        assert not content(screen).display
        modal = ConfirmActionScreen(
            "Review action", "No external operation is connected.",
            ["Keep this workspace intact"], "CONFIRM", "Confirm",
        )
        await app.push_screen(modal)
        await wait_until(lambda: app.focused is modal.query_one("#confirm_input"))
        assert not sidebar.navigation_mode and not sidebar.display
        assert content(screen).display and screen.focused is origin
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is modal.query_one("#confirm_input")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen and app.focused is origin)
        assert editor.document is document and editor.text == "Retain the tool draft"


@pytest.mark.asyncio
@pytest.mark.parametrize("case,theme", [
    (CASES[0], "ansi-dark"), (CASES[1], "servonaut-light"),
    (CASES[4], "ansi-light"),
], ids=["files-ansi-dark", "transfer-light", "reinstall-ansi-light"])
async def test_server_representative_named_palettes_keep_native_targets(
    case: ReflowCase, theme: str,
) -> None:
    app = case.app_factory(True)
    app.theme = theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        await assert_essential_targets(case, app, pilot, screen)


@pytest.mark.asyncio
async def test_nested_fleet_actions_transfer_retains_separate_chat_owners() -> None:
    app = _app(False)
    async with app.run_test(size=(160, 50)) as pilot:
        fleet = app.screen
        table = fleet.query_one(InstanceTable)
        table.move_cursor(row=1)
        fleet_panel = await open_chat(app, pilot, fleet)
        fleet_panel.query_one("#chat-input", TextArea).load_text("Fleet draft")
        await tab_to(pilot, table)
        await pilot.press("o")
        await wait_until(lambda: isinstance(app.screen, ServerActionsScreen))
        actions = app.screen
        actions_panel = await open_chat(app, pilot, actions)
        actions_panel.query_one("#chat-input", TextArea).load_text("Actions draft")
        await tab_to(pilot, actions.query_one("#btn_scp"))
        await pilot.press("4")
        await wait_until(lambda: isinstance(app.screen, SCPTransferScreen))
        tool = app.screen
        assert tool._instance["id"] == app.instances[1]["id"]
        tool_panel = await open_chat(app, pilot, tool)
        tool_panel.query_one("#chat-input", TextArea).load_text("Transfer draft")
        assert len({id(fleet_panel), id(actions_panel), id(tool_panel)}) == 3
        for expected, panel, draft in (
            (actions, actions_panel, "Actions draft"), (fleet, fleet_panel, "Fleet draft"),
        ):
            app.pop_screen()
            await wait_until(lambda: app.screen is expected)
            await pilot.pause()
            assert expected.query_one(ChatPanel) is panel
            assert panel.query_one("#chat-input", TextArea).text == draft
        assert table.cursor_row == 1

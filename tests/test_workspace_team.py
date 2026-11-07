"""The Teams screen keeps its team state, holds and hotkeys inside the workspace."""

from __future__ import annotations

import asyncio
import socket
import subprocess
import webbrowser
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, SelectionList, Static, TextArea

from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.team_management import TeamManagementScreen
from servonaut.screens.team_share_confirm import ShareServersConfirmModal
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample,
    ReflowCase,
    assert_essential_targets,
    assert_layout,
    content,
    one_layout_transition,
    open_case,
    open_chat,
    preserve_native_state,
    tab_to,
)
from tests.test_fleet_workspace_layout import _open_chat
from tests.test_team_management_screen import _SAMPLE_TEAMS, _make_team_service
from tests.test_workspace_pilot import _click, _Host
from tests.test_workspace_reflow import _painted

_SHARED_CSS = (
    Path(__file__).resolve().parents[1] / "src/servonaut/styles/providers/_shared.tcss"
)
_MUTATIONS = (
    "create_team", "invite_member", "resend_invite", "remove_member", "update_role",
    "push_server", "push_team_config", "get_latest_team_config", "remove_shared_server",
)
_MEMBER_BUTTONS = ("#btn_invite", "#btn_change_role", "#btn_resend", "#btn_copy_url", "#btn_remove")
_PENDING_ACCEPT_URL = "https://staging.example.com/invite/abc123"
_HOLD_REASON = "Wait for the server changes to finish before leaving."
_HOSTS: list[_TeamApp] = []


def _team_service() -> Mock:
    service = _make_team_service(list(_SAMPLE_TEAMS))
    for name in _MUTATIONS:
        setattr(service, name, AsyncMock(side_effect=AssertionError(f"Unexpected {name}")))
    return service


class _TeamApp(_Host):
    """Actual app dispatch, styles and rail; team, auth and policy are fakes."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        self.theme = "servonaut"
        self.auth_service = SimpleNamespace(
            is_authenticated=True, has_feature=lambda feature: feature == "team_workspaces",
        )
        self.team_service = _team_service()
        # No refresher: the agent-rules card reads only the isolated local store.
        self.team_policy = None
        self.redaction_service = None
        self.allowed_mutations: set[str] = set()
        _HOSTS.append(self)


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # Native widget events remain real; external work must never start here.
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    process = Mock(side_effect=AssertionError("Unexpected process start"))
    connect = Mock(side_effect=AssertionError("Unexpected network connection"))
    loop_connect = AsyncMock(side_effect=AssertionError("Unexpected network connection"))
    browser = Mock(side_effect=AssertionError("Unexpected browser launch"))
    monkeypatch.setattr(subprocess, "run", process)
    monkeypatch.setattr(subprocess, "Popen", process)
    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", loop_connect)
    monkeypatch.setattr(webbrowser, "open", browser)
    _HOSTS.clear()
    yield
    for tripwire in (process, connect, loop_connect, browser):
        tripwire.assert_not_called()
    for app in _HOSTS:
        for name in _MUTATIONS:
            if name not in app.allowed_mutations:
                getattr(app.team_service, name).assert_not_awaited()


async def _open_teams(app: _TeamApp, pilot: Pilot) -> WorkspaceScreen:
    app.on_sidebar_navigation_requested(Sidebar.NavigationRequested("nav_teams"))
    await wait_until(lambda: isinstance(app.screen, TeamManagementScreen)
                     and bool(app.screen.query("#teams_table")))
    return app.screen


async def _ready(screen: WorkspaceScreen) -> None:
    teams = screen.query_one("#teams_table", DataTable)
    await wait_until(lambda: teams.row_count == len(_SAMPLE_TEAMS))
    screen.query_one("#btn_view_team", Button).press()
    members = screen.query_one("#members_table", DataTable)
    await wait_until(lambda: screen._loaded_team_slug == "eng" and members.row_count == 2)


def _seed(screen: WorkspaceScreen) -> None:
    # Row 1 is the pending invite, the only member with an accept URL.
    screen.query_one("#members_table", DataTable).move_cursor(row=1)
    screen.query_one("#teams_table", DataTable).move_cursor(row=1)


def _state(screen: WorkspaceScreen) -> object:
    service = screen.app.team_service
    tables = tuple(
        (table.id, table.cursor_row,
         tuple(tuple(table.get_row_at(i)) for i in range(table.row_count)))
        for table in content(screen).query(DataTable)
    )
    return (
        tables, screen._current_team_slug, screen._loaded_team_slug,
        screen._current_team_role, tuple(member.get("id") for member in screen._members),
        screen._server_busy, service.list_teams.await_count, service.get_team.await_count,
    )


def _team_controls(screen: WorkspaceScreen) -> list:
    return list(content(screen).query("Button, DataTable, Select, Input"))


# These native integer widths retain the separately measured fractional
# policy flags: a rounded width can still be below its declared threshold.
BOUNDARIES: dict[
    tuple[str, bool], tuple[BoundarySample, BoundarySample, BoundarySample]
] = {
    ("chat-min", False): (
        BoundarySample((108, 40), 63, True, True),
        BoundarySample((109, 40), 64, False, True),
        BoundarySample((110, 40), 65, False, True),
    ),
    ("chat-min", True): (
        BoundarySample((146, 40), 63, True, True),
        BoundarySample((148, 40), 64, True, True),
        BoundarySample((149, 40), 65, False, True),
    ),
    ("content-narrow", False): (
        BoundarySample((156, 40), 94, False, True),
        BoundarySample((158, 40), 95, False, True),
        BoundarySample((159, 40), 96, False, False),
    ),
    ("content-narrow", True): (
        BoundarySample((183, 40), 94, False, True),
        BoundarySample((184, 40), 95, False, False),
        BoundarySample((185, 40), 96, False, False),
    ),
}

CASE = ReflowCase(
    "teams", _TeamApp, _open_teams, _ready, "#team_management_container",
    ("#members_table", *_MEMBER_BUTTONS, "#btn_back"), _seed, _state,
    (("#members_table", "bob@example.com"),),
    boundaries=BOUNDARIES,
)


def test_team_reflow_replaces_the_terminal_breakpoint() -> None:
    assert issubclass(TeamManagementScreen, WorkspaceScreen)
    assert TeamManagementScreen.CHAT_REFLOW is True
    assert TeamManagementScreen.CHAT_MIN_CONTENT_WIDTH > 0
    assert TeamManagementScreen.CONTENT_NARROW_WIDTH > 0
    assert "HORIZONTAL_BREAKPOINTS" not in vars(TeamManagementScreen)
    css = _SHARED_CSS.read_text(encoding="utf-8")
    assert "TeamManagementScreen.-narrow" not in css
    assert css.count("TeamManagementScreen.-content-narrow #member_actions_row") == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible,chat_open", [
    (False, False), (False, True), (True, False), (True, True),
])
async def test_team_workspace_visibility_combinations(
    size: tuple[int, int], navigation_visible: bool, chat_open: bool,
) -> None:
    app = CASE.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(CASE, app, pilot)
        baseline = CASE.state(screen)
        assert "Teams" in _painted(app, screen.query_one("#workspace_context", Static))
        if chat_open:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert CASE.state(screen) == baseline
        if content(screen).display:
            await assert_essential_targets(CASE, app, pilot, screen)


@pytest.mark.asyncio
async def test_team_reflow_preserves_draft_team_state_and_native_tab_targets() -> None:
    app = CASE.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASE, app, pilot)
        await preserve_native_state(CASE, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("size,navigation_visible,chat_open", [
    ((160, 50), True, True), ((160, 50), False, True), ((160, 50), True, False),
    ((100, 30), True, False), ((100, 30), False, False),
])
async def test_member_buttons_follow_content_width_not_terminal_width(
    size: tuple[int, int], navigation_visible: bool, chat_open: bool,
) -> None:
    app = CASE.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(CASE, app, pilot)
        if chat_open:
            await open_chat(app, pilot, screen)
        assert content(screen).display, "these sizes keep chat beside the content"
        if (size, navigation_visible, chat_open) == ((160, 50), True, True):
            # A wide terminal with narrow content: the old 120-column breakpoint
            # kept one row here and cut off the last member buttons.
            assert content(screen).outer_size.width < screen.CONTENT_NARROW_WIDTH
        assert not screen.has_class("-narrow") and not screen.has_class("-wide")
        narrow = content(screen).outer_size.width < screen.CONTENT_NARROW_WIDTH
        assert screen.has_class("-content-narrow") is narrow
        records = screen.query_one("#team_records")
        assert records.styles.layout.name == ("vertical" if narrow else "horizontal")
        row = screen.query_one("#member_actions_row")
        assert row.styles.layout.name == "grid"
        assert row.styles.grid_size_columns == 2
        row.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        for selector in _MEMBER_BUTTONS:
            button = screen.query_one(selector, Button)
            assert button.region.width > 0
            assert row.region.x <= button.region.x and button.region.right <= row.region.right
            assert button.label.plain in _painted(app, button)


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
async def test_team_qualified_native_boundary_and_painted_fit(
    navigation_visible: bool, kind: str,
) -> None:
    samples = CASE.boundary_samples(kind, navigation_visible)
    app = CASE.app_factory(navigation_visible)
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(CASE, app, pilot)
        baseline = CASE.state(screen)
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
            if not sample.expected_replace:
                assert content(screen).region.width == sample.native_content_width
                await assert_essential_targets(CASE, app, pilot, screen)
                await tab_to(pilot, screen.query_one("#btn_remove", Button))
                await pilot.pause()
                row = screen.query_one("#member_actions_row")
                for selector in _MEMBER_BUTTONS:
                    button = screen.query_one(selector, Button)
                    assert row.content_region.contains_region(button.region)
                    assert content(screen).scrollable_content_region.contains_region(button.region)
                    assert all(
                        app.get_widget_at(x, y)[0] is button
                        for y in range(button.region.y, button.region.bottom)
                        for x in range(button.region.x, button.region.right)
                    )
                    assert button.label.plain in _painted(app, button)
            assert CASE.state(screen) == baseline


@pytest.mark.asyncio
async def test_escape_on_the_rail_leaves_the_rail_and_escape_from_content_leaves_teams() -> None:
    app = CASE.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASE, app, pilot)
        # The route replaced the fleet, so Teams sits directly on this entry.
        underlying, depth = app.screen_stack[-2], len(app.screen_stack)
        assert depth == 2 and not isinstance(underlying, InstanceListScreen)
        origin = app.focused
        baseline = CASE.state(screen)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        assert screen.navigation_focused
        await pilot.press("escape")
        await wait_until(lambda: app.focused is origin)
        assert app.screen is screen and not sidebar.navigation_mode
        assert CASE.state(screen) == baseline
        assert len(app.screen_stack) == depth and app.screen_stack[-2] is underlying
        # Positive control: Escape from the content leaves Teams exactly once.
        # At the root the app's back opens a fresh fleet over the same entry.
        await pilot.press("escape")
        await wait_until(lambda: screen not in app.screen_stack)
        assert len(app.screen_stack) == depth and app.screen_stack[-2] is underlying
        assert isinstance(app.screen, InstanceListScreen)


@pytest.mark.asyncio
async def test_busy_hold_outranks_the_rail_guard_and_the_input_passthrough() -> None:
    app = CASE.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASE, app, pilot)
        sidebar = screen.query_one(Sidebar)
        sidebar.enter_navigation_mode()
        await wait_until(lambda: screen.navigation_focused)
        assert screen.check_action("back", ()) is True
        screen._server_busy = True
        try:
            assert screen.check_action("back", ()) is False
            assert app.check_action("focus_navigation", ()) is False
            assert app.check_action("toggle_navigation", ()) is False
        finally:
            screen._server_busy = False
        sidebar.exit_navigation_mode()
        await pilot.pause()
        screen._show_create_form()
        await wait_until(lambda: isinstance(app.focused, Input))
        assert not screen.navigation_focused
        assert screen.check_action("back", ()) is True
        screen._server_busy = True
        try:
            assert screen.check_action("back", ()) is False
        finally:
            screen._server_busy = False


@pytest.mark.asyncio
async def test_held_server_operation_disables_only_team_controls() -> None:
    app = CASE.app_factory(True)
    entered, release = asyncio.Event(), asyncio.Event()

    async def push(slug: str, payload: dict) -> dict:
        entered.set()
        await release.wait()
        return {"id": f"shared-{payload.get('name')}"}

    app.team_service.push_server = AsyncMock(side_effect=push)
    app.allowed_mutations.add("push_server")
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASE, app, pilot)
        share_all = screen.query_one("#btn_share_all", Button)
        await tab_to(pilot, share_all)
        controls = _team_controls(screen)
        before = {widget: widget.disabled for widget in controls}
        outside = [
            widget for widget in screen.query("Button, DataTable, Select, Input")
            if widget not in controls
        ]
        outside_before = {widget: widget.disabled for widget in outside}
        assert screen.query_one("#nav_list", Button) in outside
        assert screen.query_one("#workspace_chat", Button) in outside
        await pilot.press("enter")
        await wait_until(lambda: isinstance(app.screen, ShareServersConfirmModal) and bool(
            app.screen.query("#share_confirm_list")
            and app.screen.query_one("#share_confirm_list", SelectionList).option_count
        ))
        offered = app.screen.query_one("#share_confirm_list", SelectionList).option_count
        app.screen.query_one("#share_confirm_share", Button).press()
        try:
            await wait_until(entered.is_set)
            await wait_until(lambda: app.screen is screen and screen._server_busy)
            assert all(widget.disabled for widget in controls)
            assert {widget: widget.disabled for widget in outside} == outside_before
            reads = ("list_teams", "get_team", "list_shared_servers", "list_team_configs")
            before_reads = {
                name: (list(getattr(app.team_service, name).call_args_list),
                       list(getattr(app.team_service, name).await_args_list))
                for name in reads
            }
            with patch.object(app, "notify", Mock(wraps=app.notify)) as notify:
                # The active Account section leaves Core collapsed initially.
                await _click(pilot, "#section_core .section-header")
                await wait_until(lambda: bool(screen.query_one("#nav_list", Button).region))
                nav = screen.query_one("#nav_list", Button)
                assert app.get_widget_at(*nav.region.center)[0] is nav
                await _click(pilot, "#nav_list")
                await pilot.pause()
            assert app.screen is screen
            assert any(call.args[:1] == (_HOLD_REASON,) for call in notify.call_args_list)
            assert {
                name: (list(getattr(app.team_service, name).call_args_list),
                       list(getattr(app.team_service, name).await_args_list))
                for name in reads
            } == before_reads
            panel = await _open_chat(app, pilot)
            editor = panel.query_one("#chat-input", TextArea)
            await pilot.press(*"draft")
            assert editor.text == "draft"
            assert screen._server_busy
            await wait_until(
                lambda: not screen.query_one("#workspace_chat_end", Button).disabled,
            )
            # Live controls, held actions: the hold still refuses End and the rail toggle.
            sidebar = screen.query_one(Sidebar)
            await _click(pilot, "#workspace_chat_end")
            await _click(pilot, "#workspace_navigation")
            await pilot.pause()
            assert panel.is_attached and not panel._collapsed
            assert sidebar.display
            assert editor.text == "draft"
        finally:
            release.set()
        await wait_until(lambda: not screen._server_busy)
        await pilot.pause()
        assert {widget: widget.disabled for widget in controls} == before
        # The End control follows the open chat, not a value saved at the start.
        assert not screen.query_one("#workspace_chat_end", Button).disabled
        # Existing contract: focus returns to the control that started the work.
        await wait_until(lambda: app.focused is share_all)
        assert editor.text == "draft" and panel.is_attached
        push_server = app.team_service.push_server
        assert push_server.await_count == offered
        assert all(call.args[0] == "eng" for call in push_server.await_args_list)


@pytest.mark.asyncio
async def test_copy_accept_url_beside_chat_keeps_the_draft_and_member_cursor() -> None:
    app = CASE.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASE, app, pilot)
        panel = await open_chat(app, pilot, screen)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep this draft")
        document = editor.document
        assert content(screen).display
        button = screen.query_one("#btn_copy_url", Button)
        button.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        with patch.object(app, "copy_to_clipboard", Mock()) as copy:
            await _click(pilot, "#btn_copy_url")
            await wait_until(lambda: copy.call_count == 1)
        copy.assert_called_once_with(_PENDING_ACCEPT_URL)
        assert screen.query_one("#members_table", DataTable).cursor_row == 1
        assert editor.document is document and editor.text == "Keep this draft"
        assert not panel._collapsed


@pytest.mark.asyncio
@pytest.mark.parametrize("email", [
    "a[/b]c@example.com", "a[red]b[/red]c@example.com", "a[", "a[X", "a\\",
])
async def test_remove_member_confirmation_keeps_literal_email_and_cancels(email: str) -> None:
    from copy import deepcopy

    from servonaut.screens.confirm_action import ConfirmActionScreen

    app = _TeamApp(False)
    team = deepcopy(app.team_service.get_team.return_value)
    team["members"][1]["invitation_email"] = email
    app.team_service.get_team.return_value = team
    try:
        async with app.run_test(size=(100, 30)) as pilot:
            screen = await _open_teams(app, pilot)
            await _ready(screen)
            members = screen.query_one("#members_table", DataTable)
            await tab_to(pilot, members)
            await pilot.press("up", "up", "up", "down")
            await wait_until(lambda: members.cursor_row == 1)
            await tab_to(pilot, screen.query_one("#btn_remove", Button))
            await pilot.press("enter")
            await wait_until(lambda: app._exception is not None or (
                isinstance(app.screen, ConfirmActionScreen)
                and bool(app.screen.query("#modal_description"))
                and bool(app.screen.query_one("#modal_description").region)
            ))
            assert app._exception is None
            modal = app.screen
            await pilot.pause()
            description = _painted(app, modal.query_one("#modal_description"))
            prompt_widget = modal.query_one("#confirm_prompt")
            prompt = _painted(app, prompt_widget)
            region = prompt_widget.content_region
            strips = app.screen._compositor.render_strips()
            glyphs = [(char, bool(segment.style and segment.style.bold))
                      for y in range(region.y, region.bottom)
                      for segment in strips[y].crop(region.x, region.right)
                      for char in segment.text]
            painted_text = "".join(char for char, _ in glyphs)
            target_start = painted_text.index('Type "') + len('Type "')
            target_bold = [bold for _, bold in glyphs[target_start:target_start + len(email)]]
            assert modal._confirm_text == email
            editor = modal.query_one("#confirm_input", Input)
            confirm = modal.query_one("#btn_confirm", Button)
            await tab_to(pilot, editor)
            await pilot.press(*email.upper())
            await wait_until(lambda: editor.value == email.upper())
            assert confirm.disabled
            await pilot.press("ctrl+shift+a", *email)
            await wait_until(lambda: editor.value == email and not confirm.disabled)
            await pilot.press("escape")
            await wait_until(lambda: app.screen is screen)
            # Trusted emphasis must not consume the literal confirmation target.
            assert email in description
            assert f'Type "{email}" to confirm:' in prompt
            assert len(target_bold) == len(email) and all(target_bold)
            assert app._exception is None
    finally:
        app.team_service.remove_member.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["ansi-dark", "servonaut-light", "ansi-light"])
async def test_team_named_palettes_keep_native_targets(theme: str) -> None:
    app = CASE.app_factory(True)
    app.theme = theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASE, app, pilot)
        await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        await assert_essential_targets(CASE, app, pilot, screen)

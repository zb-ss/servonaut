"""Native chat columns preserve fleet values, state and content focus."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from textual.geometry import Region
from textual.pilot import Pilot
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Input, TabbedContent, Tabs, TextArea,
)
from textual.widgets.text_area import Selection

from servonaut.screens.ai_conversations_screen import AIConversationsScreen
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.help import HelpScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.scan_results import ScanResultsScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services.chat_service import ChatMessage, ChatSession
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.status_bar import StatusBar
from tests._async_bounds import wait_until
from tests.test_selection_copy import _Clipboard, _drag
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_pilot import _Host, _click, _row

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.fixture(autouse=True)
def _no_chat_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    # Layout and native input routing use real widgets, with no provider/audio.
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)


class _LayoutHost(_Host):
    def __init__(self, *, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        self.keyword_store = SimpleNamespace(
            search=lambda query: [], get_results=lambda instance_id: [],
        )


def _control_regions(screen: Screen) -> tuple[Region, ...]:
    return tuple(screen.query_one(f"#{name}", Button).region for name in (
        "workspace_navigation", "workspace_chat",
    ))


async def _open_chat(app: _LayoutHost, pilot: Pilot) -> ChatPanel:
    await pilot.press("f2")
    await pilot.pause()
    panel = app.screen.query_one(ChatPanel)

    def input_mounted() -> bool:
        if app._exception is not None:
            raise app._exception
        return any(editor.is_mounted for editor in panel.query("#chat-input"))

    await wait_until(input_mounted)
    editor = panel.query_one("#chat-input", TextArea)
    await wait_until(lambda: app.focused is editor)
    return panel


def _assert_strip_painted(app: _LayoutHost, detail: TextArea) -> str:
    assert detail.region.x == 0 and detail.region.width == app.size.width
    assert detail.region.height == 4
    for x in (1, app.size.width // 2, app.size.width - 2):
        widget = app.get_widget_at(x, detail.region.y + 1)[0]
        assert widget is detail or detail in widget.ancestors
    rows = app.screen._compositor.render_strips()
    return "".join(
        rows[y].crop(detail.region.x, detail.region.right).text
        for y in range(detail.region.y, detail.region.bottom)
    )


async def _choose_history(
    history: AIConversationsScreen, kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    await wait_until(lambda: history.is_mounted)
    assert history.app._exception is None
    table_id = "#local_table" if kind == "local" else "#convs_table"
    selectors = ("#convs_tabs", "#tab_cloud", "#tab_local", table_id)
    await wait_until(lambda: all(bool(history.query(selector)) for selector in selectors))
    tabbed = history.query_one("#convs_tabs", TabbedContent)
    await wait_until(lambda: bool(tabbed.query(Tabs)))
    native_tabs = tabbed.query_one(Tabs)
    selected_table = history.query_one(table_id, DataTable)
    pane_ids = ("tab_cloud", "tab_local")
    await wait_until(lambda: (
        tabbed.is_mounted and native_tabs.is_mounted and selected_table.is_mounted
        and native_tabs.tab_count == 2
        and all(tabbed.get_tab(pane_id).is_mounted
                and tabbed.get_pane(pane_id).is_mounted for pane_id in pane_ids)
        and tabbed.active in pane_ids and native_tabs.active_tab is not None
    ))
    assert tabbed.tab_count == 2
    assert native_tabs.active == tabbed.get_tab(tabbed.active).id
    assert history.app._exception is None
    if kind == "local":
        history._active_tab = "tab_local"
        monkeypatch.setattr(history, "_selected_local", lambda: {"id": "saved-session"})
        history.action_open_local()
    else:
        history._active_tab = "tab_cloud"
        monkeypatch.setattr(history, "_selected", lambda: SimpleNamespace(
            id="saved-cloud", title="Saved cloud",
        ))
        history.action_open_selected()


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [True, False])
@pytest.mark.parametrize("pilot_screen", ["fleet", "actions"])
async def test_wide_chat_has_its_own_nonoverlapping_column(
    navigation_visible: bool, pilot_screen: str,
) -> None:
    app = _LayoutHost(navigation_visible=navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        if pilot_screen == "actions":
            await pilot.press("o")
        screen = app.screen
        controls = _control_regions(screen)
        content = screen.query_one(
            "#instance_list_container" if pilot_screen == "fleet" else "#sa-body",
        )
        closed_width = content.region.width
        panel = await _open_chat(app, pilot)
        assert content.region.right <= panel.region.x
        assert content.region.width < closed_width and content.region.width > 0
        assert 45 <= panel.region.width <= 64
        assert panel.parent is screen.query_one("#main-layout")
        assert _control_regions(screen) == controls
        assert screen.query_one(Sidebar).display is navigation_visible
        if pilot_screen == "fleet":
            detail = screen.query_one("#instance_detail", TextArea)
            assert "Public IP" in _assert_strip_painted(app, detail)
            status, footer = screen.query_one(StatusBar), screen.query_one(Footer)
            assert panel.region.bottom <= detail.region.y
            assert detail.region.bottom <= status.region.y
            assert status.region.bottom <= footer.region.y
        await pilot.press("f2")
        await pilot.pause()
        assert content.region.width == closed_width and not panel.display


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [True, False])
@pytest.mark.parametrize("pilot_screen", ["fleet", "actions"])
async def test_narrow_chat_replaces_mounted_content_and_keeps_requested_navigation(
    navigation_visible: bool, pilot_screen: str,
) -> None:
    app = _LayoutHost(navigation_visible=navigation_visible)
    async with app.run_test(size=(100, 30)) as pilot:
        if pilot_screen == "actions":
            await pilot.press("o")
        screen = app.screen
        controls = _control_regions(screen)
        content = screen.query_one(
            "#instance_list_container" if pilot_screen == "fleet" else "#sa-body",
        )
        panel = await _open_chat(app, pilot)
        assert not content.display and content.is_attached
        assert panel.region.width == screen.query_one("#main-layout").region.width - (
            screen.query_one(Sidebar).region.width if navigation_visible else 0
        )
        assert screen.query_one(Sidebar).display is navigation_visible
        assert app.workspace_state.navigation_visible is navigation_visible
        assert _control_regions(screen) == controls
        for name in ("workspace_chat", "workspace_chat_end"):
            button = screen.query_one(f"#{name}", Button)
            assert app.get_widget_at(*button.region.center)[0] is button
        if pilot_screen == "fleet":
            _assert_strip_painted(app, screen.query_one("#instance_detail", TextArea))


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_pointer_copy_reaches_complete_wrapped_unicode_value_with_chat_open(
    size: tuple, clipboard: _Clipboard,
) -> None:
    app = _LayoutHost()
    # Exceed both supported strip widths so the ID genuinely soft-wraps.
    identifier = "id-" + "a" * 172 + "-Ω"
    app.instances = [_row("edge-café-東京-[literal]-" + "n" * 30)]
    app.instances[0]["id"] = identifier
    async with app.run_test(size=size) as pilot:
        panel = await _open_chat(app, pilot)
        detail = app.screen.query_one("#instance_detail", TextArea)
        _assert_strip_painted(app, detail)
        # Reveal the wrapped ID through native input before the actual drag.
        offset = detail.content_region.offset - detail.region.offset
        assert await pilot.click(detail, offset=(offset.x, offset.y))
        await pilot.press("pagedown")
        await wait_until(lambda: detail.wrapped_document._width == detail.wrap_width)
        painted = _assert_strip_painted(app, detail)
        assert identifier in "".join(painted.split())
        composer = panel.query_one("#chat-input", TextArea)
        composer.load_text("An unrelated old selection")
        stale = Selection((0, 0), (0, 9))
        composer.selection = stale
        start = detail.text.index(identifier)
        start_location = detail.document.get_location_from_index(start)
        end_location = detail.document.get_location_from_index(start + len(identifier))
        a = detail.wrapped_document.location_to_offset(start_location)
        b = detail.wrapped_document.location_to_offset(end_location)
        assert start_location[0] == end_location[0] and b.y > a.y
        a, b = a - detail.scroll_offset, b - detail.scroll_offset
        for point in (a, b):
            assert 0 <= point.x < detail.content_size.width
            assert 0 <= point.y < detail.content_size.height
            hit = app.get_widget_at(
                detail.content_region.x + point.x, detail.content_region.y + point.y,
            )[0]
            assert hit is detail or detail in hit.ancestors
        assert composer.selection == stale
        assert composer.selected_text == composer.text[:9]
        assert composer.selected_text and composer.selected_text != identifier
        assert app.focused is detail
        clipboard.calls.clear()
        await _drag(pilot, detail, (a.x, a.y), (b.x, b.y))
        assert detail.selected_text == identifier
        assert clipboard.calls == [identifier]
        assert app.screen.query_one(ChatPanel) is panel and app.focused is detail


@pytest.mark.asyncio
@pytest.mark.parametrize("empty", ["fleet", "filter"])
async def test_empty_selection_has_fixed_strip_height_and_no_stale_value(
    empty: str, clipboard: _Clipboard,
) -> None:
    app = _LayoutHost()
    if empty == "fleet":
        app.instances = []
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot)
        detail = app.screen.query_one("#instance_detail", TextArea)
        region = detail.region
        if empty == "filter":
            app.screen.query_one("#search_input", Input).value = "no-such-server"
            await wait_until(lambda: app.screen.query_one(InstanceTable).row_count == 0)
        await pilot.pause()
        assert detail.text == "No server selected"
        assert "No server selected" in _assert_strip_painted(app, detail)
        assert detail.region == region and panel.is_attached
        clipboard.calls.clear()
        assert await pilot.click(detail, offset=(2, 1))
        await pilot.pause()
        assert clipboard.calls == [] and detail.selected_text == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["collapse", "end"])
@pytest.mark.parametrize("pilot_screen", ["fleet", "actions"])
async def test_narrow_hide_restores_visible_content_focus(stop: str, pilot_screen: str) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        if pilot_screen == "actions":
            await pilot.press("o")
        screen = app.screen
        origin = (
            screen.query_one(InstanceTable) if pilot_screen == "fleet"
            else screen.query_one("#btn_browse", Button)
        )
        origin.focus()
        panel = await _open_chat(app, pilot)
        await pilot.press("f2" if stop == "collapse" else "f3")
        await wait_until(lambda: app.focused is origin and bool(origin.region))
        assert app.screen is screen
        if stop == "end":
            await wait_until(lambda: not panel.is_attached)
        else:
            assert panel.is_attached and panel._collapsed


@pytest.mark.asyncio
@pytest.mark.parametrize("hidden", ["widget", "ancestor"])
async def test_narrow_collapse_skips_a_remembered_target_that_remains_hidden(hidden: str) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        origin = screen.query_one(InstanceTable)
        await wait_until(lambda: app.focused is origin)
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep café [literal] Ω draft")
        editor.selection = Selection((0, 5), (0, 9))
        document, selection = editor.document, editor.selection
        # Keep this explicit hiding after the workspace reveals its content.
        target = origin if hidden == "widget" else origin.parent
        assert target is not None
        target.display = False
        assert origin.focusable  # Native focusability alone ignores display:none.
        await pilot.press("f2")
        await wait_until(lambda: panel._collapsed and not screen.has_class("-chat-replace"))
        await wait_until(lambda: app.focused is not None and app.focused is not origin
                         and bool(app.focused.region))
        focused = app.focused
        assert focused is not None and focused.screen is screen
        assert focused.display and focused.visible
        assert all(widget.display for widget in focused.ancestors)
        assert focused is not panel and panel not in focused.ancestors
        hit = app.get_widget_at(*focused.region.center)[0]
        assert hit is focused or focused in hit.ancestors
        assert app.screen is screen and not target.display
        assert panel.is_attached and panel._collapsed
        assert editor.document is document and editor.text == "Keep café [literal] Ω draft"
        assert editor.selection == selection


@pytest.mark.asyncio
@pytest.mark.parametrize("cover", ["modal", "screen"])
@pytest.mark.parametrize("stop", ["collapse", "end"])
async def test_narrow_focus_hook_does_not_redirect_modal_or_background_focus(
    cover: str, stop: str,
) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot)
        if cover == "modal":
            await app.push_screen(ConfirmActionScreen(
                title="Confirm", description="Continue this operation", consequences=[],
                confirm_text="web-1", action_label="Continue",
            ))
        else:
            await app.push_screen(HelpScreen())
        await pilot.pause()
        foreground, focused = app.screen, app.focused
        # Simulate a late lifecycle cleanup while a different screen owns input.
        if stop == "collapse":
            panel.collapse_panel()
        else:
            panel.close_panel()
        await pilot.pause()
        assert app.screen is foreground and app.focused is focused


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_rapid_collapse_restore_keeps_focus_in_reopened_composer(size: tuple) -> None:
    app = _LayoutHost()
    async with app.run_test(size=size) as pilot:
        panel = await _open_chat(app, pilot)
        composer = panel.query_one("#chat-input", TextArea)
        app.action_toggle_chat()
        app.action_toggle_chat()
        await pilot.pause()
        assert not panel._collapsed and app.focused is composer


@pytest.mark.asyncio
@pytest.mark.parametrize("pilot_screen", ["fleet", "actions"])
async def test_resize_moves_focus_out_of_content_that_becomes_hidden(pilot_screen: str) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        if pilot_screen == "actions":
            await pilot.press("o")
        screen = app.screen
        content_focus = (
            screen.query_one(InstanceTable) if pilot_screen == "fleet"
            else screen.query_one("#btn_browse", Button)
        )
        panel = await _open_chat(app, pilot)
        content_focus.focus()
        await wait_until(lambda: app.focused is content_focus)
        await pilot.resize_terminal(100, 30)
        composer = panel.query_one("#chat-input", TextArea)
        await wait_until(lambda: app.focused is composer)


@pytest.mark.asyncio
async def test_resize_and_push_pop_keep_documents_cursor_filters_and_owned_worker() -> None:
    app = _LayoutHost(navigation_visible=False)
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with app.run_test(size=(160, 50)) as pilot:
        fleet = app.screen
        table = fleet.query_one(InstanceTable)
        search = fleet.query_one("#search_input", Input)
        search.value = "web"
        await wait_until(lambda: table.row_count == 1)
        table.focus()
        detail = fleet.query_one("#instance_detail", TextArea)
        panel = await _open_chat(app, pilot)
        composer = panel.query_one("#chat-input", TextArea)
        composer.load_text("Keep this unsent draft")
        composer.selection = Selection((0, 5), (0, 9))
        composer_selection = composer.selection
        composer_document, detail_document = composer.document, detail.document
        row = table.cursor_row
        panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        await _click(pilot, "#workspace_navigation")
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert composer.document is composer_document and composer.selection == composer_selection
        await pilot.press("f2", "f2")
        await pilot.resize_terminal(160, 50)
        await pilot.press("f2")
        await pilot.press("o")
        await pilot.pause()
        assert app.screen is not fleet and not cancelled.is_set()
        app.pop_screen()
        await wait_until(lambda: app.screen is fleet)
        await pilot.press("f2")
        await pilot.pause()
        assert fleet.query_one(ChatPanel) is panel and not cancelled.is_set()
        assert composer.document is composer_document and composer.text == "Keep this unsent draft"
        assert composer.selection == composer_selection
        assert detail.document is detail_document
        assert table.cursor_row == row and search.value == "web"
        app.action_end_chat()
        await wait_until(lambda: cancelled.is_set() and not panel.is_attached)
        await wait_until(lambda: fleet.query_one("#workspace_chat", Button).label.plain == "Open chat")


@pytest.mark.asyncio
async def test_non_reflow_workspace_keeps_existing_overlay_mount() -> None:
    class OverlayWorkspace(ScanResultsScreen):
        # Keep the opt-out contract explicit after the real screen adopts reflow.
        CHAT_REFLOW = False

    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(OverlayWorkspace(_row("web-1")))
        screen = app.screen
        panel = await _open_chat(app, pilot)
        assert panel.parent is screen and panel.styles.dock == "right"
        assert panel.styles.layer == "overlay"
        assert screen.query_one("#scan_container").display


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_nested_end_removes_painted_editor_without_component_style_error(size: tuple) -> None:
    app = _LayoutHost(navigation_visible=False)
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with app.run_test(size=size) as pilot:
        panel = await _open_chat(app, pilot)
        composer = panel.query_one("#chat-input", TextArea)
        composer.load_text("An unsent draft")
        composer.selection = Selection((0, 3), (0, 9))
        panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        await _click(pilot, "#workspace_navigation")
        # Reuse the same editor after native screen suspension/resumption.
        await pilot.press("f2")
        await app.push_screen(HelpScreen())
        app.pop_screen()
        await pilot.press("f2")
        await pilot.pause()
        app.action_end_chat()
        await wait_until(lambda: cancelled.is_set() and not panel.is_attached)
        await wait_until(lambda: app.screen.query_one("#workspace_chat", Button).label.plain == "Open chat")
        await pilot.pause()
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("history_kind", ["local", "cloud"])
@pytest.mark.parametrize("pilot_screen", ["fleet", "actions"])
async def test_history_load_finds_existing_nested_chat_without_mounting_another(
    monkeypatch: pytest.MonkeyPatch, history_kind: str, pilot_screen: str,
) -> None:
    monkeypatch.setattr(AIConversationsScreen, "on_mount", lambda self: None)
    app = _LayoutHost()
    saved = ChatSession(
        id="saved-session", messages=[ChatMessage(role="assistant", content="Saved reply")],
    )
    app.chat_service = SimpleNamespace(
        load_session=lambda session_id: saved, list_sessions=lambda **kwargs: [],
    )
    app.ai_conversations_client = SimpleNamespace(get=AsyncMock(return_value={
        "id": "saved-cloud", "title": "Saved cloud", "messages": [
            {"role": "assistant", "content": "Saved reply"},
        ],
    }))
    async with app.run_test(size=(100, 30)) as pilot:
        if pilot_screen == "actions":
            await pilot.press("o")
        fleet = app.screen
        panel = await _open_chat(app, pilot)
        history = AIConversationsScreen()
        await app.push_screen(history)
        await _choose_history(history, history_kind, monkeypatch)
        await wait_until(lambda: app.screen is fleet)
        await wait_until(lambda: panel._session is not None and bool(panel._session.messages))
        assert len(fleet.query(ChatPanel)) == 1
        assert fleet.query_one(ChatPanel) is panel
        assert panel.parent is fleet.query_one("#main-layout")
        assert panel._session.messages[-1].content == "Saved reply"


@pytest.mark.asyncio
@pytest.mark.parametrize("history_kind", ["local", "cloud"])
@pytest.mark.parametrize("source", ["fleet", "actions"])
@pytest.mark.parametrize("history_chat", [False, True])
async def test_history_load_targets_topmost_origin_when_two_chats_exist(
    monkeypatch: pytest.MonkeyPatch, history_kind: str, source: str, history_chat: bool,
) -> None:
    monkeypatch.setattr(AIConversationsScreen, "on_mount", lambda self: None)
    app = _LayoutHost()
    saved = ChatSession(
        id="saved-session", messages=[ChatMessage(role="assistant", content="Selected reply")],
    )
    app.chat_service = SimpleNamespace(
        load_session=lambda session_id: saved, list_sessions=lambda **kwargs: [],
    )
    app.ai_conversations_client = SimpleNamespace(get=AsyncMock(return_value={
        "id": "saved-cloud", "messages": [{"role": "assistant", "content": "Selected reply"}],
    }))
    async with app.run_test(size=(160, 50)) as pilot:
        if source == "fleet":
            await app.push_screen(ServerActionsScreen(_row("web-1")))
        peer = await _open_chat(app, pilot)
        peer_session = peer._session = ChatSession(id="background-conversation")
        peer.query_one("#chat-input", TextArea).load_text("Background draft")
        destination = (
            ServerActionsScreen(_row("web-1")) if source == "actions"
            else InstanceListScreen()
        )
        await app.push_screen(destination)
        origin = await _open_chat(app, pilot)
        origin._session = ChatSession(id="origin-conversation")
        origin.query_one("#chat-input", TextArea).load_text("Origin draft")
        # Exercise the real History button's production screen-opening path.
        await _click(pilot, "#btn-chat-history")
        await wait_until(lambda: isinstance(app.screen, AIConversationsScreen))
        history = app.screen
        transient = await _open_chat(app, pilot) if history_chat else None
        await _choose_history(history, history_kind, monkeypatch)
        await wait_until(lambda: app.screen is destination)
        selected_id = "saved-session" if history_kind == "local" else "saved-cloud"
        await wait_until(lambda: any(
            panel._session is not None and panel._session.id == selected_id
            for panel in (origin, peer, *([transient] if transient is not None else []))
        ))
        assert origin._session.id == selected_id
        assert peer._session is peer_session
        assert peer.query_one("#chat-input", TextArea).text == "Background draft"
        assert destination.query_one(ChatPanel) is origin
        assert origin.parent is destination.query_one("#main-layout")

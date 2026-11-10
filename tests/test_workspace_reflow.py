"""Reflow follows the available content width while preserving native state."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.widgets.chat_panel import (
    ChatPanel, _CONVO_IDLE, _CONVO_STATE_GLYPHS, _MIC_IDLE, _MIC_RECORDING,
    _SPINNER_FRAMES,
)
from servonaut.widgets.fleet_values import ValueRow
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import _LayoutHost, _open_chat
from tests.test_selection_copy import _Clipboard
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_pilot import _click

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.fixture(autouse=True)
def _no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)


def _painted(app: _LayoutHost, widget: Widget) -> str:
    rows = app.screen._compositor.render_strips()
    return "\n".join(
        rows[y].crop(widget.region.x, widget.region.right).text
        for y in range(widget.region.y, widget.region.bottom)
    )


async def _screen(app: _LayoutHost, pilot: Pilot, family: str) -> WorkspaceScreen:
    if family == "actions":
        await app.push_screen(ServerActionsScreen(app.instances[0]))
    await pilot.pause()
    return app.screen


def _content(screen: WorkspaceScreen) -> Widget:
    return screen.query_one(".workspace-content")


@pytest.mark.parametrize("minimum,narrow", [
    (None, None), (64, None), (None, 105), (0, 105), (64, 0),
])
def test_opted_in_screen_requires_explicit_positive_thresholds(
    minimum: int | None, narrow: int | None,
) -> None:
    class UnconfiguredScreen(WorkspaceScreen):
        CHAT_REFLOW = True
        CHAT_MIN_CONTENT_WIDTH = minimum
        CONTENT_NARROW_WIDTH = narrow

    with pytest.raises(ValueError, match="CHAT_MIN_CONTENT_WIDTH.*CONTENT_NARROW_WIDTH"):
        UnconfiguredScreen()


@pytest.mark.parametrize("screen_type", [InstanceListScreen, ServerActionsScreen])
def test_pilots_declare_both_content_thresholds_locally(
    screen_type: type[WorkspaceScreen],
) -> None:
    assert WorkspaceScreen.CHAT_MIN_CONTENT_WIDTH is None
    assert WorkspaceScreen.CONTENT_NARROW_WIDTH is None
    for name in ("CHAT_MIN_CONTENT_WIDTH", "CONTENT_NARROW_WIDTH"):
        assert vars(screen_type)[name] > 0


@pytest.mark.asyncio
async def test_server_actions_chat_keeps_a_readable_detail_column() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _screen(app, pilot, "actions")
        await _open_chat(app, pilot)
        toolbar = screen.query_one("#action_buttons")
        detail = screen.query_one("#sa-detail")
        body = _content(screen)
        assert toolbar.region.x == detail.region.x == body.region.x
        assert toolbar.region.width == detail.region.width == body.region.width
        assert toolbar.region.bottom <= detail.region.y
        assert screen.query_one("#sa-detail").region.width >= 47
        assert "192.0.2.10" in _painted(app, screen.query_one("#server_info"))


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["fleet", "actions"])
async def test_hidden_navigation_medium_terminal_retains_two_content_columns(
    family: str,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    async with app.run_test(size=(120, 40)) as pilot:
        screen = await _screen(app, pilot, family)
        panel = await _open_chat(app, pilot)
        content = screen.query_one(
            "#instance_list_container" if family == "fleet" else "#sa-body",
        )
        assert content.display and content.region.width > 0
        assert content.region.right <= panel.region.x


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["fleet", "actions"])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("size", [(160, 50), (120, 40), (100, 30)])
@pytest.mark.parametrize("chat_state", ["closed", "open", "collapsed"])
async def test_pilot_reflow_preserves_independent_pane_combinations(
    family: str, navigation_visible: bool, size: tuple[int, int], chat_state: str,
) -> None:
    app = _LayoutHost(navigation_visible=navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await _screen(app, pilot, family)
        content, sidebar = _content(screen), screen.query_one(Sidebar)
        row = screen.query_one("#main-layout")
        panel = None
        if chat_state != "closed":
            panel = await _open_chat(app, pilot)
            editor = panel.query_one("#chat-input", TextArea)
            editor.load_text("Keep the same draft")
            document = editor.document
            if chat_state == "collapsed":
                await pilot.press("f2")
                await pilot.pause()
                assert panel._collapsed and panel.is_attached
                assert editor.document is document
        assert sidebar.display is navigation_visible
        nav_width = sidebar.region.width if navigation_visible else 0
        if chat_state != "open":
            assert content.display and not screen.has_class("-chat-replace")
            assert content.region.width == row.content_region.width - nav_width
        elif screen.has_class("-chat-replace"):
            assert not content.display and content.is_attached
            assert panel.region.width == row.content_region.width - nav_width
        else:
            assert content.display and content.region.right <= panel.region.x
            assert content.region.width > 0
        for name in ("workspace_navigation", "workspace_chat"):
            button = screen.query_one(f"#{name}", Button)
            assert app.get_widget_at(*button.region.center)[0] is button
        if panel is not None:
            end = screen.query_one("#workspace_chat_end", Button)
            assert app.get_widget_at(*end.region.center)[0] is end


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["fleet", "actions"])
@pytest.mark.parametrize("scenario", ["crossing", "always-replaced", "closed"])
async def test_navigation_reveal_uses_width_predicate_and_restores_visible_origin(
    monkeypatch: pytest.MonkeyPatch, family: str, scenario: str,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    size = (130, 40) if scenario == "crossing" else (100, 30) if scenario == "always-replaced" else (160, 50)
    async with app.run_test(size=size) as pilot:
        screen = await _screen(app, pilot, family)
        content = _content(screen)
        if scenario != "closed":
            panel = await _open_chat(app, pilot)
            editor = panel.query_one("#chat-input", TextArea)
            editor.load_text("Retain this draft")
            document = editor.document
        origin = (
            screen.query_one(InstanceTable) if family == "fleet"
            else screen.query_one("#btn_browse", Button)
        ) if scenario != "always-replaced" else editor
        origin.focus()
        await wait_until(lambda: app.focused is origin)
        initial_replace = screen.has_class("-chat-replace")
        changes = Mock(wraps=screen.set_class)
        monkeypatch.setattr(screen, "set_class", changes)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        await pilot.pause()
        expected_replaced = scenario != "closed"
        assert content.display is not expected_replaced
        assert screen.has_class("-chat-replace") is expected_replaced
        assert sidebar.has_focus_within
        enter_changes = [call for call in changes.call_args_list if "-chat-replace" in call.args]
        assert len(enter_changes) == int(initial_replace != expected_replaced)
        changes.reset_mock()
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode and app.focused is origin)
        assert screen.has_class("-chat-replace") is initial_replace
        leave_changes = [call for call in changes.call_args_list if "-chat-replace" in call.args]
        assert len(leave_changes) == int(initial_replace != expected_replaced)
        assert content.is_attached
        if scenario != "closed":
            assert editor.document is document and editor.text == "Retain this draft"


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["fleet", "actions"])
async def test_replacement_returns_to_native_columns_and_reopened_panel(
    family: str,
) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _screen(app, pilot, family)
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Preserved while resizing")
        editor.selection = Selection((0, 0), (0, 9))
        selection, document = editor.selection, editor.document
        column_width = panel.region.width
        for size in ((100, 30), (160, 50), (200, 50), (100, 30), (160, 50)):
            await pilot.resize_terminal(*size)
            await pilot.pause()
            assert screen.has_class("-chat-replace") is (size[0] == 100)
            if size[0] >= 160:
                assert panel.region.width == column_width
                assert _content(screen).region.right <= panel.region.x
                assert screen.has_class("-content-narrow") is (size[0] == 160)
            assert editor.document is document and editor.selection == selection
        await pilot.press("f3")
        await wait_until(lambda: not panel.is_attached)
        await wait_until(lambda: screen.query_one("#workspace_chat", Button).label.plain == "Open chat")
        await pilot.resize_terminal(100, 30)
        replacement = await _open_chat(app, pilot)
        assert replacement is not panel and screen.has_class("-chat-replace")
        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        assert not screen.has_class("-chat-replace")
        assert replacement.region.width == column_width
        assert app._exception is None


# Boundary fixtures exercise the cells immediately around each transition.
_BOUNDARIES = [
    ("fleet", False, 109), ("fleet", True, 149),
    ("actions", False, 101), ("actions", True, 135),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("delta", [-1, 0, 1])
@pytest.mark.parametrize("family,navigation_visible,boundary", _BOUNDARIES)
async def test_native_painted_boundary_keeps_essential_content_usable(
    theme: str, delta: int, family: str, navigation_visible: bool, boundary: int,
) -> None:
    app = _LayoutHost(navigation_visible=navigation_visible)
    app.theme = theme
    async with app.run_test(size=(boundary + delta, 40)) as pilot:
        screen = await _screen(app, pilot, family)
        panel = await _open_chat(app, pilot)
        await pilot.pause()
        content = _content(screen)
        assert screen.has_class("-chat-replace") is (delta < 0)
        if delta >= 0:
            assert content.region.right <= panel.region.x
            for name in ("btn-chat-new", "btn-chat-history", "btn-chat-provider", "btn-chat-close"):
                button = panel.query_one(f"#{name}", Button)
                assert panel.region.contains(*button.region.center)
                assert button.label.plain in _painted(app, button)
                assert app.get_widget_at(*button.region.center)[0] is button
            if family == "fleet":
                painted = _painted(app, screen.query_one(InstanceTable))
                for label in ("Name", "State", "Provider", "Public IP", "Type"):
                    assert label in painted
            else:
                assert screen.has_class("-content-narrow")
                toolbar = screen.query_one("#action_buttons")
                detail = screen.query_one("#sa-detail")
                assert toolbar.region.x == detail.region.x == content.region.x
                assert toolbar.region.width == detail.region.width == content.region.width
                assert toolbar.region.bottom <= detail.region.y
                assert "192.0.2.10" in _painted(app, screen.query_one("#server_info"))
        else:
            assert not content.display and content.is_attached
        for name in ("workspace_chat", "workspace_chat_end"):
            button = screen.query_one(f"#{name}", Button)
            assert app.get_widget_at(*button.region.center)[0] is button


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_fleet_full_value_copy_affordance_stays_visible_with_chat(
    theme: str, size: tuple[int, int], clipboard: _Clipboard,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    app.theme = theme
    async with app.run_test(size=size) as pilot:
        await _open_chat(app, pilot)
        bar = app.screen.query_one("#fleet_value_bar")
        painted = _painted(app, bar)
        assert "Copy row" in painted and "192.0.2.10" in painted
        clipboard.calls.clear()
        await _click(pilot, "#fleet_copy_row_line")
        await wait_until(lambda: bool(clipboard.calls))
        assert "web-1" in clipboard.calls[-1]
        assert "192.0.2.10" in clipboard.calls[-1]
        app.screen.query_one("#search_input", Input).value = "missing-fixture"
        await wait_until(lambda: app.screen.query_one(InstanceTable).row_count == 0)
        assert app.screen.query_one("#fleet_copy_row_line", Button).disabled


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_copy_row_and_values_stay_out_of_the_tab_route(
    size: tuple[int, int], clipboard: _Clipboard,
) -> None:
    app = _LayoutHost()
    async with app.run_test(size=size) as pilot:
        table = app.screen.query_one(InstanceTable)
        for button in ("#fleet_copy_row", "#fleet_copy_row_line"):
            assert app.screen.query_one(button, Button) not in app.screen.focus_chain
        table.focus()
        await wait_until(lambda: app.focused is table)
        await pilot.press("tab")
        await pilot.pause()
        assert not isinstance(app.focused, ValueRow)
        table.focus()
        clipboard.calls.clear()
        await pilot.press("y")
        await wait_until(lambda: bool(clipboard.calls))
        assert "web-1" in clipboard.calls[-1]


@pytest.mark.asyncio
@pytest.mark.parametrize("shown_id,expected", [("id[/b]Ω", "id[/b]Ω"), ("", "server")])
async def test_unnamed_server_context_falls_back_to_literal_shown_identity(
    shown_id: str, expected: str,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    app.instances[0].update(name="", id=shown_id)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _screen(app, pilot, "actions")
        await _open_chat(app, pilot)
        context = screen.query_one("#workspace_context", Static)
        assert f"Server actions · {expected}" in _painted(app, context)
        assert app._exception is None


@pytest.mark.asyncio
async def test_server_identity_is_literal_and_refreshes_on_real_demo_toggle() -> None:
    app = _LayoutHost(navigation_visible=False)
    app.instances[0]["name"] = "web[/b]Ω"
    original_id = app.instances[0]["id"]
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _screen(app, pilot, "actions")
        await _open_chat(app, pilot)
        context = screen.query_one("#workspace_context", Static)
        assert "web[/b]Ω" in _painted(app, context)
        app.action_toggle_demo()
        await pilot.pause()
        assert "web[/b]Ω" not in _painted(app, context)
        assert screen._instance["name"] in _painted(app, context)
        assert app.connection_instance(screen._instance)["id"] == original_id
        app.action_toggle_demo()
        await pilot.pause()
        assert "web[/b]Ω" in _painted(app, context)
        assert app.connection_instance(screen._instance)["id"] == original_id
        assert app._exception is None


@pytest.mark.asyncio
async def test_chat_header_uses_explicit_end_and_keeps_teardown_action() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _open_chat(app, pilot)
        end = panel.query_one("#btn-chat-close", Button)
        assert end.label.plain == "End chat" and "End chat" in _painted(app, end)
        await _click(pilot, "#btn-chat-close")
        await wait_until(lambda: not panel.is_attached)
        await wait_until(lambda: app.screen.query_one("#workspace_chat", Button).label.plain == "Open chat")
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["fleet", "actions"])
@pytest.mark.parametrize("modal_kind", ["confirmation", "palette"])
async def test_suspending_threshold_crossing_navigation_preserves_origin(
    family: str, modal_kind: str,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    async with app.run_test(size=(130, 40)) as pilot:
        screen = await _screen(app, pilot, family)
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Retain this draft while confirming")
        content = _content(screen)
        origin = (screen.query_one(InstanceTable) if family == "fleet"
                  else screen.query_one("#btn_browse", Button))
        assert content.display
        origin.focus()
        await wait_until(lambda: app.focused is origin)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.has_focus_within and not content.display)
        if modal_kind == "confirmation":
            await app.push_screen(ConfirmActionScreen(
                title="Confirm", description="Continue this operation", consequences=[],
                confirm_text="web-1", action_label="Continue",
            ))
        else:
            await pilot.press("ctrl+p")
        await pilot.pause()
        modal = app.screen
        modal_focus = modal.focused
        assert modal is not screen and modal_focus is not None
        assert app.focused is modal_focus and modal_focus.screen is modal
        assert not sidebar.navigation_mode and not sidebar.display
        assert content.display and screen.focused is origin
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen and app.focused is origin)
        assert origin.region and content.display
        assert screen.query_one(ChatPanel) is panel
        assert editor.text == "Retain this draft while confirming"
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("family,width", [("fleet", 109), ("actions", 101)])
async def test_header_keyboard_focus_stays_visible_while_pointer_hovers(
    theme: str, family: str, width: int,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    app.theme = theme
    async with app.run_test(size=(width, 40)) as pilot:
        screen = await _screen(app, pilot, family)
        panel = await _open_chat(app, pilot)
        end = panel.query_one("#btn-chat-close", Button)
        provider = panel.query_one("#btn-chat-provider", Button)
        region = end.region
        await pilot.hover(end)
        await pilot.pause()
        provider.focus()
        await wait_until(lambda: app.focused is provider)
        await pilot.press("tab")
        await wait_until(lambda: app.focused is end)
        await pilot.pause()
        label_segments = [
            segment for y in range(end.size.height) for segment in end.render_line(y)
            if "End chat" in segment.text
        ]
        assert label_segments and all(
            segment.style and segment.style.underline for segment in label_segments
        )
        assert end.region == region
        assert app.get_widget_at(*region.center)[0] is end


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("family,width", [("fleet", 109), ("actions", 101)])
async def test_minimum_chat_column_keeps_draft_and_native_glyph_controls_usable(
    theme: str, family: str, width: int,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    app.theme = theme
    async with app.run_test(size=(width, 40)) as pilot:
        screen = await _screen(app, pilot, family)
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Retain this unsent draft")
        document = editor.document
        selection = editor.selection = Selection((0, 7), (0, 11))
        controls = [panel.query_one(f"#btn-chat-{name}", Button)
                    for name in ("mic", "convo", "send")]
        tooltips = [button.tooltip for button in controls]
        assert panel.region.width == 45
        row = panel.query_one("#chat-input-row")
        assert editor.region.width == row.content_region.width
        assert editor.region.width >= 36
        assert editor.region.bottom <= controls[0].region.y
        assert len({button.region.y for button in controls}) == 1
        assert [button.region.width for button in controls] == [6, 6, 6]
        labels = [(_MIC_IDLE, _MIC_RECORDING, *_SPINNER_FRAMES),
                  (_CONVO_IDLE, *_CONVO_STATE_GLYPHS.values()), ("➤",)]
        for button, variants in zip(controls, labels):
            region = button.region
            for glyph in variants:
                button.label = glyph
                await pilot.pause()
                assert glyph in _painted(app, button)
                strips = app.screen._compositor.render_strips()
                inner = button.content_region
                assert glyph in "\n".join(
                    strips[y].crop(inner.x, inner.right).text
                    for y in range(inner.y, inner.bottom)
                )
                assert button.region == region and button.region.height == 3
                assert panel.region.contains_region(button.region)
                assert app.get_widget_at(*button.region.center)[0] is button
        assert [button.tooltip for button in controls] == tooltips
        assert editor.document is document and editor.selection == selection
        assert editor.text == "Retain this unsent draft"
        editor.focus()
        await wait_until(lambda: app.focused is editor)
        for button in controls:
            await pilot.press("tab")
            await wait_until(lambda: app.focused is button)
        await pilot.resize_terminal(width, 30)
        await pilot.pause()
        assert not screen.has_class("-chat-replace")
        assert panel.query_one("#chat-messages").scrollable_content_region.height > 0
        for widget in (editor, *controls):
            assert panel.region.contains_region(widget.region)
            assert app.get_widget_at(*widget.region.center)[0] is widget
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert screen.has_class("-chat-replace")
        assert editor.region.right <= controls[0].region.x
        assert panel.region.contains_region(editor.region)
        assert app.get_widget_at(*editor.region.center)[0] is editor
        for button in controls:
            assert button.region.height == 3 and button.region.width == 6
            assert panel.region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
        assert editor.document is document and editor.selection == selection

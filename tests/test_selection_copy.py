"""Mouse selection copies the current gesture through the existing transports."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from textual import events
from textual.app import ComposeResult
from textual.pilot import Pilot
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.ai_analysis import AIAnalysisScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.utils import platform_utils
from servonaut.widgets.fleet_values import ValueRow
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.instance_table import InstanceTable
from tests._async_bounds import wait_until


@dataclass
class _Clipboard:
    calls: list[str] = field(default_factory=list)
    succeeds: bool = True

    def __call__(self, text: str) -> bool:
        self.calls.append(text)
        return self.succeeds


@pytest.fixture
def clipboard() -> Iterator[_Clipboard]:
    previous = platform_utils.clipboard_writer()
    recorder = _Clipboard()
    platform_utils.set_clipboard_writer(recorder)
    try:
        yield recorder
    finally:
        platform_utils.set_clipboard_writer(previous)


class _SelectionScreen(Screen):
    CSS = """
    _SelectionScreen > Static { height: 3; width: 76; }
    _SelectionScreen > TextArea {
        width: 76; height: 4; border: none; padding: 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("  café [literal]\nline two Ω  ", markup=False, id="plain")
        yield TextArea("first café\nfirst second line", id="first")
        yield TextArea("second Ω\nsecond second line", id="second")


class _CopyApp(ServonautApp):
    """Keep production event routing without starting external services."""

    CSS_PATH = []
    CSS = "ToastRack { display: none; }"

    def __init__(self, screen: Screen) -> None:
        super().__init__()
        self.test_screen = screen

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(self.test_screen)

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


def _offset(widget: Widget, column: int, row: int = 0) -> tuple[int, int]:
    content = widget.content_region
    return (content.x - widget.region.x + column, content.y - widget.region.y + row)


async def _drag(
    pilot: Pilot,
    widget: Widget,
    start: tuple[int, int],
    end: tuple[int, int],
) -> None:
    assert await pilot.mouse_down(widget, offset=_offset(widget, *start))
    await pilot.hover(widget, offset=_offset(widget, *end))
    assert await pilot.mouse_up(widget, offset=_offset(widget, *end))
    await pilot.pause()


@pytest.mark.asyncio
async def test_static_drag_copies_complete_literal_unicode_only_on_release(
    clipboard: _Clipboard,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        plain = app.screen.query_one("#plain", Static)
        assert await pilot.mouse_down(plain, offset=_offset(plain, 0))
        await pilot.hover(plain, offset=_offset(plain, len("line two Ω "), 1))
        assert clipboard.calls == []
        await pilot.mouse_up(plain, offset=_offset(plain, len("line two Ω "), 1))
        await wait_until(lambda: bool(clipboard.calls))
        assert clipboard.calls == ["café [literal]\nline two Ω"]


@pytest.mark.asyncio
async def test_textarea_drag_copies_multiline_selection_not_entire_document(
    clipboard: _Clipboard,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        first = app.screen.query_one("#first", TextArea)
        await _drag(pilot, first, (6, 0), (5, 1))
        assert first.selected_text == "café\nfirst"
        assert clipboard.calls == ["café\nfirst"]


@pytest.mark.asyncio
async def test_empty_mouse_selection_leaves_clipboard_untouched(
    clipboard: _Clipboard,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        app.copy_to_clipboard("previous value")
        await pilot.click("#first", offset=(2, 1))
        assert app.screen.query_one("#first", TextArea).selected_text == ""
        assert clipboard.calls == []
        assert app.clipboard == "previous value"


@pytest.mark.asyncio
async def test_failed_native_writer_delivers_same_selection_to_terminal(
    clipboard: _Clipboard,
) -> None:
    clipboard.succeeds = False
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        first = app.screen.query_one("#first", TextArea)
        await _drag(pilot, first, (6, 0), (10, 0))
        assert clipboard.calls == ["café"]
        assert app.clipboard == "café"


@pytest.mark.asyncio
async def test_fresh_textarea_selection_wins_over_an_older_editor_selection(
    clipboard: _Clipboard,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        first = app.screen.query_one("#first", TextArea)
        second = app.screen.query_one("#second", TextArea)
        await _drag(pilot, first, (0, 0), (5, 0))
        assert clipboard.calls == ["first"]
        clipboard.calls.clear()
        await _drag(pilot, second, (0, 0), (6, 0))
        assert second.selected_text == "second"
        assert first.selected_text == "first"
        assert clipboard.calls == ["second"]


@pytest.mark.asyncio
async def test_fresh_static_selection_wins_over_an_older_textarea_selection(
    clipboard: _Clipboard,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        first = app.screen.query_one("#first", TextArea)
        await _drag(pilot, first, (0, 0), (5, 0))
        clipboard.calls.clear()
        plain = app.screen.query_one("#plain", Static)
        await _drag(pilot, plain, (2, 0), (5, 0))
        assert app.screen.get_selected_text().strip() == "café"
        assert clipboard.calls == ["café"]


@pytest.mark.asyncio
async def test_fresh_textarea_selection_replaces_an_older_static_selection(
    clipboard: _Clipboard,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        plain = app.screen.query_one("#plain", Static)
        await _drag(pilot, plain, (2, 0), (5, 0))
        assert clipboard.calls == ["café"]
        clipboard.calls.clear()
        second = app.screen.query_one("#second", TextArea)
        await _drag(pilot, second, (0, 0), (6, 0))
        assert second.selected_text == "second"
        assert clipboard.calls == ["second"]


@pytest.mark.asyncio
async def test_whitespace_static_selection_does_not_copy_an_older_editor_selection(
    clipboard: _Clipboard,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        first = app.screen.query_one("#first", TextArea)
        await _drag(pilot, first, (0, 0), (5, 0))
        clipboard.calls.clear()
        plain = app.screen.query_one("#plain", Static)
        await _drag(pilot, plain, (0, 0), (1, 0))
        assert app.screen.get_selected_text() is not None
        assert app.screen.get_selected_text().strip() == ""
        assert clipboard.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_drag", [False, True])
async def test_empty_or_cancelled_editor_gesture_does_not_copy_an_older_selection(
    clipboard: _Clipboard, cancel_drag: bool,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        first = app.screen.query_one("#first", TextArea)
        second = app.screen.query_one("#second", TextArea)
        await _drag(pilot, first, (0, 0), (5, 0))
        clipboard.calls.clear()
        app.copy_to_clipboard("keep this value")
        assert await pilot.mouse_down(second, offset=_offset(second, 0))
        if cancel_drag:
            await pilot.hover(second, offset=_offset(second, 6))
            assert second.selected_text == "second"
            assert clipboard.calls == []
        await pilot.mouse_up(second, offset=_offset(second, 0))
        assert second.selected_text == ""
        assert clipboard.calls == []
        assert app.clipboard == "keep this value"


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["  café\nΩ  ", "\x1b[31m  café\nΩ  \x1b[0m"])
async def test_keyboard_selection_waits_for_mouse_release_and_normalizes_payload(
    clipboard: _Clipboard, text: str,
) -> None:
    app = _CopyApp(_SelectionScreen())
    async with app.run_test(size=(100, 30)) as pilot:
        first = app.screen.query_one("#first", TextArea)
        first.load_text(text)
        first.focus()
        await pilot.press("f7")
        assert first.selected_text == text
        assert clipboard.calls == []
        # A native mouse release emits TextSelected even outside the editor.
        await pilot.mouse_up(offset=(95, 20))
        await wait_until(lambda: bool(clipboard.calls))
        assert clipboard.calls == ["café\nΩ"]


class _FleetCopyApp(_CopyApp):
    CSS_PATH = ServonautApp.CSS_PATH

    def __init__(self) -> None:
        super().__init__(InstanceListScreen())
        self.instances = [{
            "id": "server-1",
            "name": "café-[literal]-service-with-a-complete-name",
            "type": "small", "state": "running", "public_ip": "",
            "private_ip": "10.0.0.1", "region": "region-1",
            "key_name": "/keys/a-long-complete-key-name.pem",
        }]
        self.cache_service = SimpleNamespace(get_age=lambda: None)
        self.config_manager = SimpleNamespace(get=AppConfig)

    def provider_inventory(self, provider: str) -> None:
        return None


def _name_value(app: ServonautApp, size: tuple[int, int], *, chat_open: bool = False) -> ValueRow:
    """The selected server's name value, in the form this size (and the chat) shows."""
    narrow = size[0] < 130 or chat_open
    host = "#fleet_value_line" if narrow else "#fleet_values"
    return app.screen.query_one(host).query_one(
        f"#fleet_value_{'line' if narrow else 'list'}_name", ValueRow,
    )


# Few enough characters to stay on the first painted line of any value cell.
_HIGHLIGHTED = 8


async def _drag_value(pilot: Pilot, row: ValueRow) -> str:
    """Highlight the start of a value with the mouse; returns the highlighted text."""
    await _drag(pilot, row.value_widget, (0, 0), (_HIGHLIGHTED - 1, 0))
    return row.value[:_HIGHLIGHTED]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_fleet_value_drag_copies_only_the_highlighted_part(
    clipboard: _Clipboard, size: tuple[int, int],
) -> None:
    app = _FleetCopyApp()
    async with app.run_test(size=size) as pilot:
        row = _name_value(app, size)
        await wait_until(lambda: bool(row.value))
        assert isinstance(app.focused, InstanceTable)
        assert row.value == str(app.instances[0]["name"])
        expected = await _drag_value(pilot, row)
        assert app.screen.get_selected_text() == expected
        assert clipboard.calls == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("first_source", ["detail", "chat"])
async def test_fleet_and_chat_copy_the_fresh_selection_in_either_direction(
    clipboard: _Clipboard, size: tuple[int, int], first_source: str,
) -> None:
    app = _FleetCopyApp()
    async with app.run_test(size=size) as pilot:
        await wait_until(lambda: bool(_name_value(app, size).value))
        await pilot.press("f2")
        await wait_until(lambda: bool(app.screen.query(ChatPanel)))
        detail = _name_value(app, size, chat_open=True)
        await wait_until(lambda: detail.display and detail.region.width > 0)
        chat = app.screen.query_one("#chat-input", TextArea)
        await wait_until(lambda: app.focused is chat)
        chat.load_text("fresh chat Ω")
        sources = {"detail": (detail, detail.value[:_HIGHLIGHTED]), "chat": (chat, "fresh chat Ω")}
        second_source = "chat" if first_source == "detail" else "detail"
        for source in (first_source, second_source):
            editor, expected = sources[source]
            clipboard.calls.clear()
            if source == "detail":
                await _drag_value(pilot, editor)
                assert app.screen.get_selected_text() == expected
            else:
                await _drag(pilot, editor, (0, 0), (len(expected), 0))
                assert editor.selected_text == expected
            assert clipboard.calls == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("selection_source", ["chat", "outside"])
async def test_collapsing_chat_retires_only_its_native_screen_copy_target(
    clipboard: _Clipboard, size: tuple[int, int], selection_source: str,
) -> None:
    app = _FleetCopyApp()
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        table = screen.query_one(InstanceTable)
        await wait_until(lambda: isinstance(app.focused, InstanceTable))
        await pilot.press("f2")
        await wait_until(lambda: bool(screen.query(ChatPanel)))
        panel = screen.query_one(ChatPanel)
        editor = panel.query_one("#chat-input", TextArea)
        await wait_until(lambda: app.focused is editor)
        draft = "draft café [literal] Ω\nlast"
        editor.load_text(draft)
        editor.selection = Selection((0, 6), (1, 2))
        document, selection = editor.document, editor.selection
        if selection_source == "chat":
            expected = "chat café [literal] Ω"
            target = Static(expected, markup=False, classes="chat-message-assistant")
            await panel.query_one("#chat-messages").mount(target)
        else:
            target = _name_value(app, size, chat_open=True)
            expected = target.value[:_HIGHLIGHTED]
        await pilot.pause()
        target.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        # Native Static selection includes the glyph at the release coordinate.
        await _drag(
            pilot, target.value_widget if isinstance(target, ValueRow) else target,
            (0, 0), (len(expected) - 1, 0),
        )
        assert screen.get_selected_text() == expected
        assert clipboard.calls[-1] == expected
        assert editor.document is document and editor.text == draft
        assert editor.selection == selection

        # Only keys after the real drag: another mouse gesture or editor
        # selection change would clear native screen selection independently.
        clipboard.calls.clear()
        app.copy_to_clipboard("keep the clipboard")
        await pilot.press("f2")
        await wait_until(lambda: panel._collapsed and app.focused is table)
        assert panel.is_attached and not panel.display
        with patch.object(app, "copy_to_clipboard", wraps=app.copy_to_clipboard) as copy:
            await pilot.press("ctrl+c")
            await pilot.pause()
            if selection_source == "chat":
                copy.assert_not_called()
                assert app.clipboard == "keep the clipboard"
            else:
                copy.assert_called_once_with(expected)
                assert app.clipboard == expected
        assert clipboard.calls == []
        assert editor.document is document and editor.text == draft
        assert editor.selection == selection
        await pilot.press("f2")
        await wait_until(lambda: app.focused is editor)
        assert screen.query_one(ChatPanel) is panel and not panel._collapsed
        assert editor.document is document and editor.text == draft
        assert editor.selection == selection


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("drag_phase", ["mouse-down", "auto-scroll"])
async def test_collapsing_chat_retires_native_drag_before_release(
    clipboard: _Clipboard, size: tuple[int, int], drag_phase: str,
) -> None:
    app = _FleetCopyApp()
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        table = screen.query_one(InstanceTable)
        await wait_until(lambda: app.focused is table)
        await pilot.press("f2")
        await wait_until(lambda: bool(screen.query(ChatPanel)))
        panel = screen.query_one(ChatPanel)
        editor = panel.query_one("#chat-input", TextArea)
        await wait_until(lambda: app.focused is editor)
        draft = "active draft café [literal] Ω\nkeep"
        editor.load_text(draft)
        editor.selection = Selection((0, 7), (1, 2))
        document, selection = editor.document, editor.selection
        messages = panel.query_one("#chat-messages")
        await messages.remove_children()
        target = Static(
            "\n".join(f"chat café [literal] Ω row {index}" for index in range(80)),
            markup=False, classes="chat-message-assistant",
        )
        await messages.mount(target)
        await pilot.pause()
        messages.scroll_home(animate=False)
        await pilot.pause()
        assert messages.max_scroll_y > 0 and messages.scroll_y == 0
        assert await pilot.mouse_down(target, offset=_offset(target, 0))
        pointer = (target.content_region.x + 4, messages.content_region.bottom - 1)
        if drag_phase == "auto-scroll":
            # Pilot.hover sends zero deltas, which cannot start native auto-scroll.
            previous = app.mouse_position
            assert pointer[1] > previous.y
            hit = app.get_widget_at(*pointer)[0]
            assert hit is target or target in hit.ancestors
            assert app.post_message(events.MouseMove(
                widget=None, x=pointer[0], y=pointer[1],
                delta_x=pointer[0] - previous.x, delta_y=pointer[1] - previous.y,
                button=1, shift=False, meta=False, ctrl=False,
                screen_x=pointer[0], screen_y=pointer[1],
            ))
            await wait_until(lambda: messages.scroll_y > 0)
            assert "chat café" in (screen.get_selected_text() or "")
        else:
            assert screen.get_selected_text() is None
        assert clipboard.calls == []  # The mouse button is still held.
        app.copy_to_clipboard("keep the clipboard")
        await pilot.press("f2")
        await wait_until(lambda: panel._collapsed and app.focused is table)
        if drag_phase == "auto-scroll":
            # Let the already-started native auto-scroll timer tick after hiding.
            await pilot.pause(0.1)
        # A held pointer moving after collapse must not revive the old start.
        await pilot.hover(offset=pointer)
        await pilot.pause()
        assert screen.get_selected_text() is None
        await pilot.mouse_up(offset=pointer)
        await pilot.pause()
        assert clipboard.calls == [] and app.clipboard == "keep the clipboard"
        with patch.object(app, "copy_to_clipboard", wraps=app.copy_to_clipboard) as copy:
            await pilot.press("ctrl+c")
            await pilot.pause()
            copy.assert_not_called()
        assert panel.is_attached and not panel.display
        assert editor.document is document and editor.text == draft
        assert editor.selection == selection
        await pilot.press("f2")
        await wait_until(lambda: app.focused is editor)
        assert screen.query_one(ChatPanel) is panel and not panel._collapsed
        assert editor.document is document and editor.text == draft
        assert editor.selection == selection


class _AnalysisCopyApp(_FleetCopyApp):
    def __init__(self) -> None:
        super().__init__()
        self.test_screen = AIAnalysisScreen()
        self.ai_analysis_service = SimpleNamespace(
            estimate_tokens=lambda text: 0,
            chunk_text=lambda text: [text],
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("native_succeeds", [True, False])
async def test_ai_output_copies_once_and_preserves_whitespace_and_multiline_payload(
    clipboard: _Clipboard, native_succeeds: bool,
) -> None:
    clipboard.succeeds = native_succeeds
    app = _AnalysisCopyApp()
    async with app.run_test(size=(160, 50)) as pilot:
        output = app.screen.query_one("#ai_output", TextArea)
        text = "  café [literal]\nline two Ω  "
        output.load_text(text)
        await pilot.pause()
        await _drag(pilot, output, (0, 0), (len("line two Ω  "), 1))
        assert output.selected_text == text
        assert clipboard.calls == [text]
        if not native_succeeds:
            assert app.clipboard == text


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh_source", ["input", "output", "empty-input"])
async def test_ai_output_local_copy_does_not_duplicate_or_steal_another_gesture(
    clipboard: _Clipboard, fresh_source: str,
) -> None:
    app = _AnalysisCopyApp()
    async with app.run_test(size=(160, 50)) as pilot:
        source = app.screen.query_one("#ai_text_input", TextArea)
        output = app.screen.query_one("#ai_output", TextArea)
        source.load_text("fresh input")
        output.load_text("old output")
        await pilot.pause()
        old_editor = source if fresh_source == "output" else output
        await _drag(pilot, old_editor, (0, 0), (3, 0))
        clipboard.calls.clear()
        if fresh_source == "empty-input":
            await pilot.click(source, offset=_offset(source, 0))
            assert clipboard.calls == []
        else:
            editor = output if fresh_source == "output" else source
            expected = "old" if fresh_source == "output" else "fresh"
            await _drag(pilot, editor, (0, 0), (len(expected), 0))
            assert clipboard.calls == [expected]


async def _analysis_copy_tab_to(pilot: Pilot, target: Widget) -> None:
    for _ in range(len(pilot.app.screen.focus_chain) + 1):
        if pilot.app.focused is target:
            return
        await pilot.press("tab")
    raise AssertionError(f"Native Tab must reach {target!r}")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("copy_phase", ["pending", "error"])
async def test_ai_full_copy_does_not_reuse_output_from_a_previous_request(
    clipboard: _Clipboard, size: tuple[int, int], copy_phase: str,
) -> None:
    import asyncio

    from textual.widgets import Button, Input

    from tests._async_bounds import STEP_TIMEOUT_SECONDS

    first = "  first café [literal]\nprevious answer Ω  "
    recovered = "  new café [literal]\nrecovered answer Ω  "
    input_text = "current log café [literal] Ω"
    prompt_text = "Explain the current log"
    requests: list[tuple[str, str]] = []
    second_started = asyncio.Event()
    release_second = asyncio.Event()

    # Exact analyze_text interface; only the second request is held and fails.
    async def analyze_text(text: str, system_prompt: str = "") -> dict:
        requests.append((text, system_prompt))
        if len(requests) == 2:
            second_started.set()
            await release_second.wait()
            raise RuntimeError("fixture analysis failure")
        assert len(requests) in (1, 3), "Unexpected additional analysis request"
        return {
            "content": first if len(requests) == 1 else recovered,
            "tokens_used": 0, "model": "fixture-model", "estimated_cost": None,
        }

    app = _AnalysisCopyApp()
    app.ai_analysis_service.analyze_text = analyze_text
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        source = screen.query_one("#ai_text_input", TextArea)
        output = screen.query_one("#ai_output", TextArea)
        prompt = screen.query_one("#ai_user_prompt", Input)
        analyze = screen.query_one("#btn_analyze", Button)
        back = screen.query_one("#btn_back", Button)
        status = screen.query_one("#ai_status", Static)
        source.load_text(input_text)
        prompt.value = prompt_text
        await _analysis_copy_tab_to(pilot, back)
        await pilot.pause()
        try:
            # F5 exercises the normal Analyze binding and real worker lifecycle.
            await pilot.press("f5")
            await wait_until(lambda: output.text == first and not analyze.disabled)
            assert output.selected_text == "" and app.focused is back
            with patch.object(app, "copy_to_clipboard", wraps=app.copy_to_clipboard) as copy:
                await pilot.press("y")
                copy.assert_called_once_with(first)
            assert app.clipboard == first

            app.copy_to_clipboard("keep the clipboard")
            await pilot.press("f5")
            await wait_until(lambda: second_started.is_set())
            assert analyze.disabled and output.text == "" and output.selected_text == ""
            assert requests == [(input_text, prompt_text)] * 2
            if copy_phase == "pending":
                assert app.focused is back and not release_second.is_set()
                with patch.object(app, "copy_to_clipboard", wraps=app.copy_to_clipboard) as copy:
                    await pilot.press("y")
                    copy.assert_not_called()
                assert app.clipboard == "keep the clipboard"
                assert analyze.disabled and output.text == ""

            release_second.set()
            await wait_until(lambda: not analyze.disabled)
            assert "Error: fixture analysis failure" in status.render().plain
            assert output.text == "" and output.selected_text == ""
            assert app.focused is back
            with patch.object(app, "copy_to_clipboard", wraps=app.copy_to_clipboard) as copy:
                await pilot.press("y")
                copy.assert_not_called()
            assert app.clipboard == "keep the clipboard"

            await pilot.press("f5")
            await wait_until(lambda: output.text == recovered and not analyze.disabled)
            assert "Analysis complete." in status.render().plain
            assert output.selected_text == "" and app.focused is back
            with patch.object(app, "copy_to_clipboard", wraps=app.copy_to_clipboard) as copy:
                await pilot.press("y")
                copy.assert_called_once_with(recovered)
            assert app.clipboard == recovered
            assert source.text == input_text and prompt.value == prompt_text
            assert requests == [(input_text, prompt_text)] * 3
            # The y binding uses Textual's terminal clipboard, not a native process.
            assert clipboard.calls == []
        finally:
            release_second.set()
            for worker in tuple(screen.workers):
                if worker.name == "analyze" and not worker.is_finished:
                    await asyncio.wait_for(worker.wait(), timeout=STEP_TIMEOUT_SECONDS)

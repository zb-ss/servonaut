"""Utility editors retain native selection, pinned actions and exact results."""

from __future__ import annotations

import io
import queue
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.text import Text
from textual import events
from textual.app import App
from textual.color import Color
from textual.screen import ModalScreen
from textual.widgets import Button, RichLog, Static, TextArea

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.copy_mode import CopyModeScreen
from servonaut.screens.log_viewer import LogViewerScreen
from servonaut.screens.text_editor_modal import TextEditorModal
from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.utils import platform_utils
from servonaut.widgets.dialogs import DialogContent, DialogFrame, DialogNotificationSpace
from tests._async_bounds import wait_until

pytestmark = pytest.mark.usefixtures("navigation_open")


SIZES = [(100, 30), (160, 50)]
DOCUMENT = "\n".join(f"row {index}: café Ω [literal] " + "text " * 30 for index in range(100))
PAYLOAD = "  \x1b[31mcafé\x1b[0m  \ntail Ω  \n"


@pytest.fixture(autouse=True)
def terminal_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME", "BW_SESSION"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def clipboard():
    previous = platform_utils.clipboard_writer()
    calls: list[str] = []
    state = SimpleNamespace(succeeds=True, calls=calls)

    def write(text: str) -> bool:
        calls.append(text)
        return state.succeeds

    platform_utils.set_clipboard_writer(write)
    try:
        yield state
    finally:
        platform_utils.set_clipboard_writer(previous)


class _DialogHost(App):
    CSS_PATH = CSS_FILES

    def __init__(self, modal: ModalScreen, theme: str = "servonaut") -> None:
        super().__init__()
        for registered in SERVONAUT_THEMES:
            self.register_theme(registered)
        self.theme = theme
        self.modal = modal
        self.results: list[str | None] = []
        self.terminal_payloads: list[str] = []

    def on_mount(self) -> None:
        self.push_screen(self.modal, self.results.append)

    def copy_to_clipboard(self, text: str) -> None:
        self.terminal_payloads.append(text)
        super().copy_to_clipboard(text)


def _area(modal: ModalScreen) -> TextArea:
    return modal.query_one(TextArea)


async def _click(pilot, button: Button) -> None:
    await wait_until(lambda: not button.has_class("-active"))
    assert pilot.app.get_widget_at(*button.region.center)[0] is button
    assert await pilot.click(button)
    await pilot.pause()


async def _drag_first_line(pilot, area: TextArea) -> None:
    content = area.content_region
    offset = (content.x - area.region.x, content.y - area.region.y)
    assert await pilot.mouse_down(area, offset=offset)
    await pilot.hover(area, offset=(offset[0], offset[1] + 1))
    assert await pilot.mouse_up(area, offset=(offset[0], offset[1] + 1))
    await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
@pytest.mark.parametrize("kind", ["copy", "edit"])
async def test_native_editor_scroll_and_selection_leave_controls_pinned(
    size, theme, kind, clipboard,
) -> None:
    modal = CopyModeScreen(DOCUMENT) if kind == "copy" else TextEditorModal(DOCUMENT)
    app = _DialogHost(modal, theme)
    async with app.run_test(size=size, notifications=True) as pilot:
        await pilot.pause()
        area = _area(modal)
        frame = modal.query_one(DialogFrame)
        body = modal.query_one(DialogContent)
        assert app.focused is area
        assert area.text == DOCUMENT and area.soft_wrap
        assert area.read_only is (kind == "copy")
        assert area.show_line_numbers is (kind == "edit")
        hint = modal.query_one(
            "#copy-mode-hint" if kind == "copy" else "#text-editor-hint", Static,
        )
        painted_hint = "\n".join(
            strip.text for strip in hint.render_lines(hint.region.size.region)
        )
        assert ("Copy selection" if kind == "copy" else "Ctrl+S") in painted_hint
        assert area.region.height >= 3
        assert body.region.contains_region(area.region)
        assert not body.allow_vertical_scroll and not body.allow_horizontal_scroll
        buttons = list(modal.query(Button))
        targets = {button.id: button.region for button in buttons}
        original_frame = frame.region
        document = area.document
        await wait_until(lambda: area.max_scroll_y > 0)
        initial_scroll = area.scroll_y
        # TextArea binds PageDown and F7; Ctrl+End/Home are not its bindings.
        await pilot.press("pagedown")
        await wait_until(lambda: area.scroll_y > initial_scroll)
        assert body.scroll_y == 0
        await pilot.press("f7")
        await wait_until(lambda: area.selected_text == DOCUMENT)
        assert area.document is document and area.text == DOCUMENT
        assert not frame.border_subtitle
        for button in buttons:
            await pilot.press("tab")
            assert app.focused is button
            assert modal.region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
        for index in range(3):
            app.notify(f"Notice {index}\nsecond row\nthird row", title="Editor notice", timeout=60)
        await wait_until(lambda: len(modal.query("Toast")) == 3)
        await pilot.pause()
        rack = modal.query_one("ToastRack")
        lane = modal.query_one(DialogNotificationSpace)
        # A hidden spacer reserves layout but has no compositor-mapped region.
        arrangement = modal.arrange(modal.scrollable_content_region.size)
        placement = next(p for p in arrangement.placements if p.widget is lane)
        reserved = placement.region + placement.offset + modal.scrollable_content_region.offset
        assert reserved.contains_region(rack.region)
        assert not frame.region.overlaps(rack.region)
        toasts = list(rack.query("Toast"))
        assert all(toast.is_mounted for toast in toasts)
        newest = toasts[-1]
        # Native ToastRack scroll_end is deferred until after layout refresh.
        await wait_until(lambda: rack.max_scroll_y > 0 and rack.scroll_y == rack.max_scroll_y)
        await pilot.pause()
        assert rack.scrollable_content_region.contains_region(newest.region)
        assert app.get_widget_at(*newest.content_region.center)[0] is newest
        painted = "\n".join(strip.text for strip in modal._compositor.render_strips())
        assert "Editor notice" in painted and "Notice 2" in painted
        assert "third row" in painted
        assert frame.region == original_frame
        assert {button.id: button.region for button in buttons} == targets
        assert all(app.get_widget_at(*button.region.center)[0] is button for button in buttons)
        app.clear_notifications()
        await wait_until(lambda: not modal.query("Toast"))
        await pilot.pause()
        assert frame.region == original_frame
        assert {button.id: button.region for button in buttons} == targets


@pytest.mark.asyncio
@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("native_succeeds", [False, True])
@pytest.mark.parametrize("trigger", ["keyboard", "mouse"])
async def test_copy_preserves_pointer_selection_after_button_focus_and_fallback(
    selected, native_succeeds, trigger, clipboard,
) -> None:
    clipboard.succeeds = native_succeeds
    modal = CopyModeScreen(PAYLOAD)
    app = _DialogHost(modal)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        area = _area(modal)
        expected = PAYLOAD
        if selected:
            await _drag_first_line(pilot, area)
            expected = PAYLOAD.splitlines(keepends=True)[0]
            assert area.selected_text == expected
        else:
            assert not area.selected_text
        assert clipboard.calls == []
        if trigger == "mouse":
            await _click(pilot, modal.query_one("#copy-mode-copy", Button))
            assert app.focused is not area
        else:
            await pilot.press("y")
            await pilot.pause()
        assert clipboard.calls == [expected]
        assert app.terminal_payloads == ([] if native_succeeds else [expected])
        assert area.text == PAYLOAD and app.screen is modal


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["keyboard", "mouse"])
async def test_copy_empty_document_and_read_only_input(trigger, clipboard) -> None:
    modal = CopyModeScreen("")
    app = _DialogHost(modal)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("x")
        assert _area(modal).text == ""
        if trigger == "keyboard":
            await pilot.press("y")
        else:
            await _click(pilot, modal.query_one("#copy-mode-copy", Button))
        await pilot.pause()
        assert clipboard.calls == [""]


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["escape", "button"])
async def test_copy_close_returns_to_the_existing_screen(trigger) -> None:
    modal = CopyModeScreen("text")
    app = _DialogHost(modal)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        if trigger == "escape":
            await pilot.press("escape")
        else:
            await _click(pilot, modal.query_one("#copy-mode-close", Button))
        await wait_until(lambda: app.screen is not modal)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("trigger", ["keyboard", "mouse"])
async def test_warning_save_requires_confirmation_of_the_actual_edited_text(size, trigger) -> None:
    checked: list[str] = []

    def check(text: str) -> str:
        checked.append(text)
        return "Review [literal] content before keeping it."

    modal = TextEditorModal("original", check=check)
    app = _DialogHost(modal)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        area = _area(modal)

        async def save() -> None:
            if trigger == "mouse":
                await _click(pilot, modal.query_one("#text-editor-save", Button))
            else:
                await pilot.press("ctrl+s")
                await pilot.pause()

        area.load_text("first draft")
        await pilot.pause()
        await save()
        warning = modal.query_one("#text-editor-warning", Static)
        assert warning.display and "[literal]" in warning.render().plain
        assert not app.results and app.screen is modal
        assert modal.region.contains_region(warning.region)
        area.load_text("second draft\n  ")
        await pilot.pause()
        await save()
        assert not app.results and app.screen is modal
        await save()
        await wait_until(lambda: app.results == ["second draft\n  "])
        assert checked == ["first draft", "second draft\n  ", "second draft\n  "]


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
async def test_warning_is_painted_in_the_existing_warning_role_with_literal_text(theme) -> None:
    message = "Review [literal] draft."
    modal = TextEditorModal("draft", check=lambda text: message)
    app = _DialogHost(modal, theme)
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await pilot.pause()
        await pilot.press("ctrl+s")
        await pilot.pause()
        warning = modal.query_one("#text-editor-warning", Static)
        assert warning.display and modal.region.contains_region(warning.region)
        assert not app.results and app.screen is modal
        painted = modal._compositor.render_strips()[warning.content_region.y]
        assert message in painted.text
        expected = Color.parse(app.get_css_variables()["warning"]).rich_color
        for column in range(warning.content_region.x, warning.content_region.x + len(message)):
            style = modal._compositor.get_style_at(column, warning.content_region.y)
            assert style.color == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("trigger", ["escape", "mouse"])
async def test_edit_disarms_pending_discard_and_cancel_requires_second_press(size, trigger) -> None:
    modal = TextEditorModal("original")
    app = _DialogHost(modal)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()

        async def cancel() -> None:
            if trigger == "mouse":
                await _click(pilot, modal.query_one("#text-editor-cancel", Button))
            else:
                await pilot.press("escape")
                await pilot.pause()

        _area(modal).load_text("draft")
        await pilot.pause()
        await cancel()
        assert not app.results and app.screen is modal
        _area(modal).load_text("new draft")
        await pilot.pause()
        await cancel()
        assert not app.results and app.screen is modal
        assert "Cancel again" in modal.query_one("#text-editor-warning", Static).render().plain
        await cancel()
        await wait_until(lambda: app.results == [None])


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["keyboard", "mouse"])
@pytest.mark.parametrize("text", ["", "  café [literal]\nΩ  \n"])
async def test_unchecked_save_returns_exact_text_once(trigger, text) -> None:
    modal = TextEditorModal(text)
    app = _DialogHost(modal)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        if trigger == "keyboard":
            await pilot.press("ctrl+s")
        else:
            await _click(pilot, modal.query_one("#text-editor-save", Button))
        await wait_until(lambda: app.results == [text])


class _WaitHost(_DialogHost):
    def on_mount(self) -> None:
        self.run_worker(self._wait_for_editor())

    async def _wait_for_editor(self) -> None:
        self.results.append(await self.push_screen_wait(self.modal))


@pytest.mark.asyncio
@pytest.mark.parametrize("save", [False, True])
async def test_editor_waiting_caller_receives_exact_save_or_none(save) -> None:
    text = "  café\nΩ  \n"
    modal = TextEditorModal(text)
    app = _WaitHost(modal)
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: app.screen is modal and modal.is_mounted)
        await pilot.pause()
        assert app.focused is _area(modal)
        await pilot.press("ctrl+s" if save else "escape")
        await wait_until(lambda: app.results == ([text] if save else [None]))


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("title", ["api [/]", "[bold]literal[/bold]"])
async def test_editor_title_and_hint_preserve_literal_markup(size, title) -> None:
    hint = "Editing [red]notes[/red]"
    modal = TextEditorModal("document", title=title, hint=hint)
    app = _DialogHost(modal)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        frame = modal.query_one("#text-editor-container")
        assert Text.from_markup(str(frame.border_title)).plain == title
        assert hint in modal.query_one("#text-editor-hint", Static).render().plain
        assert app.focused is _area(modal)


class _Stream:
    """Blocking in-memory stdout used by the real log reader thread."""

    def __init__(self) -> None:
        self.lines: queue.Queue[bytes | None] = queue.Queue()

    def __iter__(self):
        while (line := self.lines.get()) is not None:
            yield line


class _Process:
    def __init__(self) -> None:
        self.stdout = _Stream()
        self.stderr = io.BytesIO()

    def send(self, text: str) -> None:
        self.stdout.lines.put((text + "\n").encode())

    def terminate(self) -> None:
        self.stdout.lines.put(None)

    def kill(self) -> None:
        self.terminate()

    def wait(self, timeout=None) -> int:
        return 0


class _Logs:
    last_probe_source = None

    async def probe_log_paths(self, *args, **kwargs):
        return ["/var/log/app.log"]

    async def scan_log_directories(self, *args, **kwargs):
        return []

    async def resolve_connection(self, *args, **kwargs):
        return {"host": "10.0.0.1", "username": "tester", "key_path": None,
                "proxy_args": [], "port": 22}

    def classify_log_file(self, path):
        return "live"

    def get_read_command(self, *args):
        return "tail -f /var/log/app.log"


class _LogHost(ServonautApp):
    def __init__(self, manager: ConfigManager) -> None:
        super().__init__()
        self.config_manager = manager
        self.log_viewer_service = _Logs()
        self.ssh_service = SimpleNamespace(build_ssh_command=lambda **kwargs: ["ssh", "fake"])
        self.connection_service = SimpleNamespace()
        self.viewer = LogViewerScreen({"id": "custom-web-1", "name": "web-1", "provider": "custom"})

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(self.viewer)

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_log_stream_resumes_and_flushes_new_lines_after_copy_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size,
) -> None:
    import servonaut.screens.log_viewer as log_module

    process = _Process()
    monkeypatch.setattr(log_module, "subprocess", SimpleNamespace(
        Popen=lambda *args, **kwargs: process, PIPE=-1, DEVNULL=-3,
    ))
    monkeypatch.setattr(log_module, "track_background_process", lambda child: None)
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(AppConfig())
    manager.load()
    app = _LogHost(manager)
    try:
        async with app.run_test(size=size) as pilot:
            viewer = app.viewer
            await wait_until(lambda: viewer._reader_thread is not None)
            process.send("before overlay")
            await wait_until(lambda: "before overlay" in viewer._content_buffer)
            await pilot.press("v")
            await wait_until(lambda: isinstance(app.screen, CopyModeScreen))
            assert _area(app.screen).text == "before overlay"
            process.send("while overlay is open")
            await pilot.pause()
            assert "while overlay is open" not in viewer._content_buffer
            await pilot.press("escape")
            await wait_until(lambda: app.screen is viewer)
            process.send("after overlay")
            await wait_until(lambda: "after overlay" in viewer._content_buffer)
            assert viewer._content_buffer == [
                "before overlay", "while overlay is open", "after overlay",
            ]
            output = viewer.query_one("#log_output", RichLog)
            assert any("after overlay" in strip.text for strip in output.lines)
    finally:
        process.terminate()

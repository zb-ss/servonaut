"""Annotating from the memory screen works where the terminal cannot be suspended.

``App.suspend()`` raises ``SuspendNotSupported`` under the headless driver
and under web drivers. The annotate action used to let that escape and stop
the app; it now falls back to an in-app editor.
"""
from __future__ import annotations

import contextlib
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Button, Footer, Static, TextArea

from servonaut.config.schema import MemoryConfig
from servonaut.screens.memory import MemoryScreen
from servonaut.screens.text_editor_modal import TextEditorModal
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.widgets.safe_header import SafeHeader

_SECRET_NOTES = "db password=hunter2hunter2\n"

_INSTANCE: Dict[str, Any] = {
    "id": "custom-web-1",
    "name": "web-1",
    "provider": "custom",
    "public_ip": "10.0.0.5",
}


def _memory_service(tmp_path: Path) -> MemoryService:
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    return MemoryService(store=store, config=MemoryConfig(enabled=True), probers=[])


class _Host(App):
    """Minimal host; ``run_test`` uses the headless driver, which cannot suspend."""

    CSS = ""

    def __init__(self, memory_service: MemoryService, **instance: Any) -> None:
        super().__init__()
        self.memory_service = memory_service
        self.memory_sync_service = MagicMock()
        self.notes: List[tuple] = []
        self._instance = {**_INSTANCE, **instance}

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Footer()

    def on_mount(self) -> None:
        self.push_screen(MemoryScreen(dict(self._instance)))

    def notify(self, message, *, severity="information", **kwargs) -> None:
        self.notes.append((message, severity))


def _annotations(service: MemoryService) -> str:
    return service.read_annotations("custom-web-1", "custom")


async def _open_editor(app: _Host, pilot) -> TextEditorModal:
    await pilot.pause()
    await pilot.press("a")
    await pilot.pause()
    assert app.is_running, "annotate stopped the app"
    assert isinstance(app.screen, TextEditorModal)
    return app.screen


async def _settle(app: _Host, pilot) -> None:
    """Let the memory screen's save worker finish."""
    await pilot.pause()
    await app.screen.workers.wait_for_complete()
    await pilot.pause()


@pytest.mark.asyncio
async def test_annotate_without_suspend_opens_the_in_app_editor(tmp_path: Path) -> None:
    service = _memory_service(tmp_path)
    app = _Host(service)

    async with app.run_test(headless=True) as pilot:
        editor = await _open_editor(app, pilot)
        area = editor.query_one("#text-editor-area", TextArea)
        # First open is seeded with the notes template, as with $EDITOR.
        assert "## Runbook" in area.text

        area.load_text("## Purpose\n\nPrimary web node.\n")
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

        assert isinstance(app.screen, MemoryScreen)

    assert _annotations(service) == "## Purpose\n\nPrimary web node.\n"
    meta = service.get_annotations_meta("custom-web-1")
    assert meta.get("annotations_hash")
    app.memory_sync_service.enqueue_annotations.assert_called_once()
    assert ("Annotations saved.", "information") in app.notes


@pytest.mark.asyncio
async def test_escape_with_unsaved_changes_needs_a_second_press(tmp_path: Path) -> None:
    service = _memory_service(tmp_path)
    app = _Host(service)

    async with app.run_test(headless=True) as pilot:
        editor = await _open_editor(app, pilot)
        seeded = editor.text
        editor.query_one("#text-editor-area", TextArea).load_text("draft")
        await pilot.pause()

        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is editor, "one Escape must not discard edits"

        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MemoryScreen)

    assert _annotations(service) == seeded
    app.memory_sync_service.enqueue_annotations.assert_not_called()


@pytest.mark.asyncio
async def test_cancel_button_with_unsaved_changes_needs_a_second_press(
    tmp_path: Path,
) -> None:
    service = _memory_service(tmp_path)
    app = _Host(service)

    async with app.run_test(headless=True) as pilot:
        editor = await _open_editor(app, pilot)
        seeded = editor.text
        editor.query_one("#text-editor-area", TextArea).load_text("draft")
        cancel = editor.query_one("#text-editor-cancel", Button)

        cancel.press()
        await pilot.pause()
        assert app.screen is editor, "one Cancel must not discard edits"

        cancel.press()
        await pilot.pause()
        assert isinstance(app.screen, MemoryScreen)

    assert _annotations(service) == seeded


@pytest.mark.asyncio
async def test_secret_warning_comes_before_saving_so_the_text_can_be_fixed(
    tmp_path: Path,
) -> None:
    service = _memory_service(tmp_path)
    app = _Host(service)

    async with app.run_test(headless=True) as pilot:
        editor = await _open_editor(app, pilot)
        seeded = editor.text
        area = editor.query_one("#text-editor-area", TextArea)
        area.load_text(_SECRET_NOTES)
        editor.query_one("#text-editor-save", Button).press()
        await pilot.pause()

        # Warned, still editing, nothing written yet.
        assert app.screen is editor
        assert _annotations(service) == seeded
        warning = str(editor.query_one("#text-editor-warning", Static).render())
        assert "secrets" in warning and "password" in warning

        area.load_text("db password is in the vault\n")
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    assert _annotations(service) == "db password is in the vault\n"


@pytest.mark.asyncio
async def test_saving_again_keeps_notes_that_look_like_secrets(tmp_path: Path) -> None:
    service = _memory_service(tmp_path)
    app = _Host(service)

    async with app.run_test(headless=True) as pilot:
        editor = await _open_editor(app, pilot)
        editor.query_one("#text-editor-area", TextArea).load_text(_SECRET_NOTES)
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert app.screen is editor
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    assert _annotations(service) == _SECRET_NOTES
    assert any("secrets" in msg and sev == "warning" for msg, sev in app.notes)


@pytest.mark.asyncio
async def test_save_writes_off_the_ui_thread(tmp_path: Path) -> None:
    service = _memory_service(tmp_path)
    app = _Host(service)
    writers: List[threading.Thread] = []
    real_write = service.write_annotations

    def _write(*args: Any, **kwargs: Any) -> Path:
        writers.append(threading.current_thread())
        return real_write(*args, **kwargs)

    service.write_annotations = _write  # type: ignore[method-assign]

    async with app.run_test(headless=True) as pilot:
        editor = await _open_editor(app, pilot)
        editor.query_one("#text-editor-area", TextArea).load_text("notes\n")
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    assert len(writers) == 1
    assert writers[0] is not threading.main_thread()
    assert _annotations(service) == "notes\n"


@pytest.mark.asyncio
async def test_server_name_with_markup_characters_does_not_crash(tmp_path: Path) -> None:
    service = _memory_service(tmp_path)
    app = _Host(service, name="api [/]")

    async with app.run_test(headless=True) as pilot:
        editor = await _open_editor(app, pilot)
        container = editor.query_one("#text-editor-container")
        assert Text.from_markup(str(container.border_title)).plain == "Notes — api [/]"


@pytest.mark.asyncio
async def test_suspendable_terminal_still_uses_the_external_editor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a real terminal, $EDITOR runs on it: stdout must not be captured."""
    monkeypatch.setenv("VISUAL", "vi")
    service = _memory_service(tmp_path)
    app = _Host(service)
    done = subprocess.CompletedProcess(["vi"], 0, stdout=None, stderr="")

    @contextlib.contextmanager
    def _suspend():
        yield

    with patch("servonaut.screens.memory.subprocess.run", return_value=done) as run:
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            app.suspend = _suspend
            await pilot.press("a")
            await pilot.pause()
            assert isinstance(app.screen, MemoryScreen)

    argv = run.call_args.args[0]
    assert argv[0] == "vi" and argv[-1].endswith("annotations.md")
    kwargs = run.call_args.kwargs
    # A terminal editor draws its UI on stdout; capturing it hides the editor.
    assert "capture_output" not in kwargs
    assert kwargs.get("stdout") is None
    assert kwargs.get("stderr") is subprocess.PIPE


# ---------------------------------------------------------------------------
# TextEditorModal on its own
# ---------------------------------------------------------------------------

class _ModalHost(App):
    def __init__(self, text: str, title: str = "Notes") -> None:
        super().__init__()
        self._text = text
        self._title = title
        self.result: Optional[str] = "<unset>"

    def on_mount(self) -> None:
        def _done(value: Optional[str]) -> None:
            self.result = value

        self.push_screen(TextEditorModal(self._text, title=self._title), _done)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "new_text, button, expected",
    [
        ("edited", "#text-editor-save", "edited"),
        ("original", "#text-editor-cancel", None),
    ],
)
async def test_modal_buttons(new_text: str, button: str, expected: Optional[str]) -> None:
    app = _ModalHost("original")
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        app.screen.query_one("#text-editor-area", TextArea).load_text(new_text)
        app.screen.query_one(button, Button).press()
        await pilot.pause()
    assert app.result == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("title", ["api [/]", "[bold]x", "web [red]1[/red]"])
async def test_modal_title_is_shown_literally(title: str) -> None:
    """A border title is parsed as markup; a stray bracket used to crash."""
    app = _ModalHost("original", title=title)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        assert app.is_running
        container = app.screen.query_one("#text-editor-container")
        assert Text.from_markup(str(container.border_title)).plain == title


@pytest.mark.asyncio
async def test_modal_escape_without_changes_closes_at_once() -> None:
    app = _ModalHost("original")
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert app.result is None

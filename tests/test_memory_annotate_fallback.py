"""Annotating from the memory screen works where the terminal cannot be suspended.

``App.suspend()`` raises ``SuspendNotSupported`` under the headless driver
and under web drivers (the desktop shell). The annotate action used to let
that escape and stop the app; it now falls back to an in-app editor.
"""
from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button, Footer, Header, TextArea

from servonaut.config.schema import MemoryConfig
from servonaut.screens.memory import MemoryScreen
from servonaut.screens.text_editor_modal import TextEditorModal
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore

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

    def __init__(self, memory_service: MemoryService) -> None:
        super().__init__()
        self.memory_service = memory_service
        self.memory_sync_service = MagicMock()
        self.notes: List[tuple] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

    def on_mount(self) -> None:
        self.push_screen(MemoryScreen(dict(_INSTANCE)))

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
        await pilot.pause()

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
async def test_saving_notes_that_look_like_secrets_warns_but_keeps_them(
    tmp_path: Path,
) -> None:
    service = _memory_service(tmp_path)
    app = _Host(service)
    text = "db password=hunter2hunter2\n"

    async with app.run_test(headless=True) as pilot:
        editor = await _open_editor(app, pilot)
        editor.query_one("#text-editor-area", TextArea).load_text(text)
        editor.query_one("#text-editor-save", Button).press()
        await pilot.pause()

    assert _annotations(service) == text
    assert any("secrets" in msg and sev == "warning" for msg, sev in app.notes)


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
    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text
        self.result: Optional[str] = "<unset>"

    def on_mount(self) -> None:
        def _done(value: Optional[str]) -> None:
            self.result = value

        self.push_screen(TextEditorModal(self._text, title="Notes"), _done)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "button, expected",
    [("#text-editor-save", "edited"), ("#text-editor-cancel", None)],
)
async def test_modal_buttons(button: str, expected: Optional[str]) -> None:
    app = _ModalHost("original")
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        app.screen.query_one("#text-editor-area", TextArea).load_text("edited")
        app.screen.query_one(button, Button).press()
        await pilot.pause()
    assert app.result == expected


@pytest.mark.asyncio
async def test_modal_escape_without_changes_closes_at_once() -> None:
    app = _ModalHost("original")
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert app.result is None

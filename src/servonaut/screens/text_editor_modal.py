"""In-app multi-line text editor, for when an external ``$EDITOR`` cannot run.

Launching ``$EDITOR`` needs ``App.suspend()``, which raises
``SuspendNotSupported`` wherever Textual does not own a real terminal: the
headless driver and web drivers such as the desktop shell. Screens that edit
a text file fall back to this modal there.
"""

from __future__ import annotations

from typing import Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static, TextArea


class TextEditorModal(ModalScreen[Optional[str]]):
    """Edit *text* in a TextArea; dismisses with the new text, or ``None``.

    Escape with unsaved changes asks for a second Escape before discarding,
    so one stray key press cannot throw away a page of notes.
    """

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    TextEditorModal {
        align: center middle;
    }

    TextEditorModal #text-editor-container {
        width: 90%;
        height: 85%;
        background: $surface;
        border: round $accent;
        border-title-color: $accent;
    }

    TextEditorModal #text-editor-hint {
        height: auto;
        padding: 0 2;
        color: $text-muted;
        background: $panel;
    }

    TextEditorModal #text-editor-area {
        height: 1fr;
    }

    TextEditorModal #text-editor-buttons {
        height: auto;
        align: right middle;
        padding: 0 1;
    }

    TextEditorModal #text-editor-cancel {
        margin-right: 1;
    }

    TextEditorModal #text-editor-save {
        margin-right: 1;
    }
    """

    def __init__(self, text: str, title: str = "Edit", hint: str = "") -> None:
        super().__init__()
        self._original = text
        self._title = title
        self._hint = hint
        self._discard_armed = False

    def compose(self) -> ComposeResult:
        with Vertical(id="text-editor-container") as container:
            container.border_title = self._title
            hint = f"{escape(self._hint)} | " if self._hint else ""
            yield Static(
                f"{hint}[bold]Ctrl+S[/bold] Save | [bold]Esc[/bold] Cancel",
                id="text-editor-hint",
            )
            yield TextArea(
                self._original,
                id="text-editor-area",
                soft_wrap=True,
                show_line_numbers=True,
            )
            with Horizontal(id="text-editor-buttons"):
                yield Button("Cancel", id="text-editor-cancel")
                yield Button("Save", variant="primary", id="text-editor-save")

    def on_mount(self) -> None:
        self.query_one("#text-editor-area", TextArea).focus()

    @property
    def text(self) -> str:
        """The editor's current contents."""
        return self.query_one("#text-editor-area", TextArea).text

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        event.stop()
        self._discard_armed = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "text-editor-save":
            self.action_save()
        elif event.button.id == "text-editor-cancel":
            self.dismiss(None)

    def action_save(self) -> None:
        self.dismiss(self.text)

    def action_cancel(self) -> None:
        if self.text == self._original or self._discard_armed:
            self.dismiss(None)
            return
        self._discard_armed = True
        self.notify(
            "Unsaved changes. Press Esc again to discard, or Ctrl+S to save.",
            severity="warning",
        )

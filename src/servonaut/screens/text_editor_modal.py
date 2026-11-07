"""In-app multi-line text editor, for when an external ``$EDITOR`` cannot run.

Launching ``$EDITOR`` needs ``App.suspend()``, which raises
``SuspendNotSupported`` wherever Textual does not own a real terminal, such
as the headless driver and web drivers. Screens that edit a text file fall
back to this modal there.
"""

from __future__ import annotations

from typing import Callable, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Button, Static, TextArea

from servonaut.widgets.dialogs import (
    DialogActions, DialogContent, DialogFrame, DialogNotificationSpace,
)

# Returns a warning to show before saving the given text, or None when fine.
SaveCheck = Callable[[str], Optional[str]]


class TextEditorModal(ModalScreen[Optional[str]]):
    """Edit *text* in a TextArea; dismisses with the new text, or ``None``.

    Cancelling (Escape or the Cancel button) with unsaved changes asks for a
    second press before discarding, so one stray key cannot throw away a page
    of notes. When *check* returns a warning for the text being saved, the
    warning is shown and the editor stays open: the user can fix the text, or
    save again to keep it as written.
    """

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CLASSES = "dialog-screen"

    DEFAULT_CSS = """
    TextEditorModal #text-editor-hint {
        height: auto;
        padding: 0 2;
        background: $panel;
    }

    TextEditorModal #text-editor-area {
        height: 1fr;
    }

    TextEditorModal #text-editor-warning {
        height: auto;
        padding: 0 2;
        color: $warning;
        display: none;
    }

    TextEditorModal #text-editor-warning.visible {
        display: block;
    }

    """

    def __init__(
        self,
        text: str,
        title: str = "Edit",
        hint: str = "",
        check: Optional[SaveCheck] = None,
    ) -> None:
        super().__init__()
        self._original = text
        self._title = title
        self._hint = hint
        self._check = check
        self._discard_armed = False
        self._confirmed_text: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        hint = f"{escape(self._hint)} | " if self._hint else ""
        frame = DialogFrame(
            heading=Static(
                f"{hint}[bold]Ctrl+S[/bold] Save | [bold]Esc[/bold] Cancel",
                id="text-editor-hint",
                classes="dialog-muted",
            ),
            body=DialogContent(
                TextArea(
                    self._original,
                    id="text-editor-area",
                    soft_wrap=True,
                    show_line_numbers=True,
                ),
            ),
            status=Static("", id="text-editor-warning", markup=False),
            actions=DialogActions(
                Button("Cancel", id="text-editor-cancel"),
                Button("Save", variant="primary", id="text-editor-save"),
                id="text-editor-buttons",
            ),
            size="fill",
            id="text-editor-container",
        )
        # Border titles are parsed as markup: a server named "api [/]"
        # would otherwise raise MarkupError.
        frame.border_title = escape(self._title)
        yield frame

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
            self.action_cancel()

    def action_save(self) -> None:
        text = self.text
        warning = self._check(text) if self._check is not None else None
        if warning and text != self._confirmed_text:
            self._confirmed_text = text
            self._show_warning(f"{warning} Save again to keep it as written.")
            return
        self.dismiss(text)

    def action_cancel(self) -> None:
        if self.text == self._original or self._discard_armed:
            self.dismiss(None)
            return
        self._discard_armed = True
        self._show_warning(
            "Unsaved changes. Cancel again to discard them, or Ctrl+S to save."
        )

    def _show_warning(self, message: str) -> None:
        warning = self.query_one("#text-editor-warning", Static)
        warning.update(message)
        warning.add_class("visible")
        self.notify(message, severity="warning", markup=False)

"""Copy mode overlay — opens content in a selectable TextArea."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static, TextArea

from servonaut.utils.platform_utils import copy_to_clipboard


class CopyModeScreen(ModalScreen[None]):
    """Modal overlay that displays text in a selectable TextArea.

    Users can select text with the mouse, then press y to copy the
    selection (or the full content if nothing is selected).
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=True),
        Binding("y", "copy", "Copy", show=True),
    ]

    DEFAULT_CSS = """
    CopyModeScreen {
        align: center middle;
    }

    #copy-mode-container {
        width: 90%;
        height: 85%;
        background: $surface;
        border: round $accent;
        border-title-color: $accent;
    }

    #copy-mode-hint {
        height: 1;
        padding: 0 2;
        color: $text-muted;
        background: $panel;
    }

    #copy-mode-text {
        height: 1fr;
    }
    """

    def __init__(self, text: str, title: str = "Copy Mode") -> None:
        super().__init__()
        self._text = text
        self._title = title

    def compose(self) -> ComposeResult:
        with Vertical(id="copy-mode-container") as container:
            container.border_title = self._title
            yield Static(
                "Select text with mouse | [bold]y[/bold] Copy selection | [bold]Esc[/bold] Close",
                id="copy-mode-hint",
            )
            yield TextArea(self._text, id="copy-mode-text", read_only=True, soft_wrap=True)

    def on_mount(self) -> None:
        self.query_one("#copy-mode-text", TextArea).focus()

    def action_copy(self) -> None:
        """Copy selected text or full content."""
        text_area = self.query_one("#copy-mode-text", TextArea)
        selected = text_area.selected_text
        text = selected if selected else self._text

        if copy_to_clipboard(text):
            label = "selection" if selected else "all content"
            lines = len(text.splitlines())
            self.app.notify(f"Copied {label} ({lines} lines)")
        else:
            self.app.copy_to_clipboard(text)
            self.app.notify("Copied (via terminal)")

    def action_close(self) -> None:
        self.app.pop_screen()

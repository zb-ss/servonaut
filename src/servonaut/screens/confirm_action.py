"""Reusable confirmation modal for destructive operations."""

from __future__ import annotations

from typing import List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Static


class ConfirmActionScreen(Screen[bool]):
    """Reusable modal for confirming destructive operations.

    Returns True (confirmed) or False (cancelled) via self.dismiss().
    Usage: confirmed = await self.app.push_screen_wait(ConfirmActionScreen(...))
    """

    BINDINGS = [
        Binding("escape", "action_cancel", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    ConfirmActionScreen {
        align: center middle;
    }

    ConfirmActionScreen #modal_container {
        width: 70;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    ConfirmActionScreen #modal_title {
        text-style: bold;
        margin-bottom: 1;
    }

    ConfirmActionScreen #modal_description {
        margin-bottom: 1;
    }

    ConfirmActionScreen #consequences_label {
        margin-bottom: 0;
    }

    ConfirmActionScreen .consequence_item {
        padding-left: 2;
    }

    ConfirmActionScreen #severity_message {
        text-style: bold;
        margin-top: 1;
        margin-bottom: 1;
    }

    ConfirmActionScreen #confirm_prompt {
        margin-bottom: 0;
    }

    ConfirmActionScreen #confirm_input {
        margin-bottom: 1;
    }

    ConfirmActionScreen #btn_row {
        height: auto;
        align: right middle;
    }

    ConfirmActionScreen #btn_cancel {
        margin-right: 1;
    }
    """

    def __init__(
        self,
        title: str,
        description: str,
        consequences: List[str],
        confirm_text: str,
        action_label: str,
        severity: str = "danger",
    ) -> None:
        """Initialize the confirmation modal.

        Args:
            title: Dialog title, e.g. "Reinstall VPS".
            description: Rich markup string explaining the operation.
            consequences: List of consequences shown as bullet points.
            confirm_text: Exact text the user must type to enable confirm button.
            action_label: Label for the confirm button.
            severity: "danger" (red) or "warning" (amber).
        """
        super().__init__()
        self._title = title
        self._description = description
        self._consequences = consequences
        self._confirm_text = confirm_text
        self._action_label = action_label
        self._severity = severity

    def compose(self) -> ComposeResult:
        """Compose the confirmation modal UI."""
        title_color = "red" if self._severity == "danger" else "yellow"
        consequence_color = "red" if self._severity == "danger" else "yellow"
        button_variant = "error" if self._severity == "danger" else "warning"

        severity_text = (
            "This action CANNOT be undone."
            if self._severity == "danger"
            else "Please review carefully before proceeding."
        )

        consequence_widgets: List[Static] = [
            Static(
                f"[{consequence_color}]  • {c}[/{consequence_color}]",
                classes="consequence_item",
            )
            for c in self._consequences
        ]

        yield Header()
        yield Container(
            Static(
                f"[bold {title_color}]{self._title}[/bold {title_color}]",
                id="modal_title",
            ),
            Static(self._description, id="modal_description"),
            Static("This will:", id="consequences_label"),
            *consequence_widgets,
            Static(
                f"[bold {title_color}]{severity_text}[/bold {title_color}]",
                id="severity_message",
            ),
            Static(
                f'Type "[bold]{self._confirm_text}[/bold]" to confirm:',
                id="confirm_prompt",
            ),
            Input(placeholder=self._confirm_text, id="confirm_input"),
            Horizontal(
                Button("Cancel", variant="default", id="btn_cancel"),
                Button(
                    self._action_label,
                    variant=button_variant,
                    id="btn_confirm",
                    disabled=True,
                ),
                id="btn_row",
            ),
            id="modal_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Auto-focus the input field on mount."""
        self.query_one("#confirm_input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Enable/disable confirm button based on exact text match."""
        if event.input.id == "confirm_input":
            btn = self.query_one("#btn_confirm", Button)
            btn.disabled = event.value != self._confirm_text

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn_confirm":
            self.dismiss(True)
        elif event.button.id == "btn_cancel":
            self.dismiss(False)

    def action_action_cancel(self) -> None:
        """Cancel and dismiss with False."""
        self.dismiss(False)

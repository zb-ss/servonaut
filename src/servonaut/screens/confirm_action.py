"""Reusable confirmation modal for destructive operations."""

from __future__ import annotations

from typing import List, Union

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.content import Content
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Static

from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)
from servonaut.widgets.safe_header import SafeHeader


class ConfirmActionScreen(ModalScreen[bool]):
    """Reusable modal for confirming destructive operations.

    Returns True (confirmed) or False (cancelled) via self.dismiss().
    Usage: confirmed = await self.app.push_screen_wait(ConfirmActionScreen(...))

    A real ``ModalScreen`` subclass, not a plain ``Screen`` styled like
    one: surfaces that suppress input while a confirmation is up (the
    hands-free conversation loop's transcript gate, for instance) detect
    "a confirmation is open" via ``isinstance(screen, ModalScreen)``, so
    the base class is load-bearing — do not downgrade it to ``Screen``.
    """

    BINDINGS = [
        Binding("escape", "action_cancel", "Cancel", show=True),
    ]

    def __init__(
        self,
        title: str,
        description: Union[str, Content],
        consequences: List[str],
        confirm_text: str,
        action_label: str,
        severity: str = "danger",
    ) -> None:
        """Initialize the confirmation modal.

        Args:
            title: Dialog title, e.g. "Reinstall VPS".
            description: Text explaining the operation: a markup string, or
                ``Content`` when it carries a name from outside the app.
            consequences: List of consequences shown as bullet points.
            confirm_text: Exact text the user must type to enable confirm button.
            action_label: Label for the confirm button.
            severity: "danger" (red) or "warning" (amber).
        """
        super().__init__(classes="dialog-screen")
        self._title = title
        self._description = description
        self._consequences = consequences
        self._confirm_text = confirm_text
        self._action_label = action_label
        self._severity = severity

    def compose(self) -> ComposeResult:
        """Compose the confirmation modal UI."""
        button_variant = "error" if self._severity == "danger" else "warning"

        severity_text = (
            "This action CANNOT be undone."
            if self._severity == "danger"
            else "Please review carefully before proceeding."
        )

        consequence_widgets: List[Static] = [
            Static(
                f"  • {c}",
                classes="consequence_item dialog-consequence",
            )
            for c in self._consequences
        ]

        yield SafeHeader()
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                f"[bold]{self._title}[/bold]",
                id="modal_title",
            ),
            body=DialogBody(
                Static(
                    self._description,
                    id="modal_description",
                    classes="dialog-description",
                ),
                Static("This will:", id="consequences_label"),
                *consequence_widgets,
            ),
            status=Vertical(
                Static(
                    f"[bold]{severity_text}[/bold]",
                    id="severity_message",
                    classes="dialog-emphasis",
                ),
                Static(
                    Content.assemble('Type "', (self._confirm_text, "bold"), '" to confirm:'),
                    id="confirm_prompt",
                ),
                Input(placeholder=self._confirm_text, id="confirm_input"),
            ),
            actions=DialogActions(
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
            severity="danger" if self._severity == "danger" else "warning",
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

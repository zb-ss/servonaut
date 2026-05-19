"""Confirmation modal for the destructive "clear cache" action on
:class:`SecretsScreen`.

Pattern follows existing y/n modals in the codebase: ModalScreen
returning a bool via :meth:`Screen.dismiss`. The parent SecretsScreen
attaches a callback to do the actual cache clear so this modal stays
side-effect-free.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ConfirmClearCacheModal(ModalScreen[bool]):
    """Asks "really clear the cached team secrets-config?"

    Cheap modal — single question, two buttons + keyboard shortcuts.
    Returns ``True`` on confirm, ``False`` (or ``None`` via Esc) on
    cancel. The receiving SecretsScreen reads the result and only
    mutates state on True.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("y", "confirm", "Yes", show=True),
        Binding("n", "cancel", "No", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold yellow]Clear the cached team secrets-config?[/bold yellow]\n\n"
                "  The provider will fall back to the local store until you "
                "refresh from the server.\n"
                "  No on-disk secrets are deleted — only the cached "
                "team-config metadata.\n\n"
                "  [bold cyan]y[/bold cyan] confirm   "
                "[bold cyan]n[/bold cyan] / [bold cyan]esc[/bold cyan] cancel",
                id="confirm_clear_text",
            ),
            Horizontal(
                Button("Confirm", id="confirm_clear_yes", variant="warning"),
                Button("Cancel", id="confirm_clear_no", variant="default"),
                id="confirm_clear_buttons",
            ),
            id="confirm_clear_container",
        )

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "confirm_clear_yes":
            self.dismiss(True)
        else:
            self.dismiss(False)

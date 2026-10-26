"""Small modal for renaming one SSH key inside the Servonaut Vault."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from servonaut.services.vault.display import terminal_safe
from servonaut.services.vault.items import clean_item_name
from servonaut.widgets.safe_header import SafeHeader


class VaultRenameKeyModal(ModalScreen[Optional[str]]):
    """Collect a valid key name, preserving the full current name for editing."""

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    DEFAULT_CSS = """
    VaultRenameKeyModal { align: center middle; }
    VaultRenameKeyModal #vault_rename_key_modal {
        width: 60;
        max-width: 92%;
        height: auto;
        padding: 1 2;
        border: round $primary;
        background: $surface;
    }
    VaultRenameKeyModal #vault_rename_key_input { margin-top: 1; }
    VaultRenameKeyModal #vault_rename_key_feedback { color: $text-warning; height: auto; min-height: 1; }
    VaultRenameKeyModal #vault_rename_key_buttons { height: auto; margin-top: 1; }
    VaultRenameKeyModal #vault_rename_key_cancel,
    VaultRenameKeyModal #vault_rename_key_save { width: 1fr; min-width: 0; }
    """

    def __init__(self, current_name: Optional[str] = None) -> None:
        super().__init__()
        self._current_name = terminal_safe(current_name) if isinstance(current_name, str) else ""

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Vertical(
            Static("[bold]Rename vault key[/bold]"),
            Input(value=self._current_name, id="vault_rename_key_input"),
            Static("", id="vault_rename_key_feedback"),
            Horizontal(
                Button("Cancel", id="vault_rename_key_cancel"),
                Button("Save", variant="primary", id="vault_rename_key_save"),
                id="vault_rename_key_buttons",
            ),
            id="vault_rename_key_modal",
        )

    def on_mount(self) -> None:
        self.query_one("#vault_rename_key_input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "vault_rename_key_cancel":
            self.dismiss(None)
            return
        if event.button.id == "vault_rename_key_save":
            self._submit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "vault_rename_key_input":
            self._submit()

    def _submit(self) -> None:
        value = self.query_one("#vault_rename_key_input", Input).value
        feedback = self.query_one("#vault_rename_key_feedback", Static)
        if not terminal_safe(value).strip():
            feedback.update("Name is required.")
            return
        try:
            name = clean_item_name(value)
        except ValueError:
            feedback.update("Name must be at most 200 characters.")
            return
        self.dismiss(name)

    def action_cancel(self) -> None:
        self.dismiss(None)

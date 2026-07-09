"""Per-key passphrase prompt for the Bitwarden key-import flow.

A brief blocking interaction (one masked field), so it is a
:class:`~textual.screen.ModalScreen`. The prompt names the key file being
decrypted; Skip moves on without importing that key.

Security: the passphrase is read from a ``password=True`` Input and handed
straight back to the caller (which passes it to the in-process decryptor —
never to a subprocess argv, a log line, or disk). It is never logged or echoed.
"""

from __future__ import annotations

from typing import Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class BwPassphraseModal(ModalScreen[Optional[str]]):
    """Prompt for the passphrase of one encrypted SSH key file.

    Dismisses the entered passphrase, or ``None`` on Skip / Escape.
    """

    BINDINGS = [
        Binding("escape", "skip", "Skip"),
    ]

    DEFAULT_CSS = ""  # styling lives in the styles bundle (secrets.tcss)

    def __init__(self, filename: str) -> None:
        super().__init__()
        self._filename = filename

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Encrypted SSH key[/bold cyan]",
                id="bw_passphrase_title",
            ),
            Static(
                f"Enter the passphrase for [bold]{escape(self._filename)}[/bold] "
                "to decrypt it for import. Skip to leave this key out.",
                id="bw_passphrase_prompt",
            ),
            Input(placeholder="Passphrase", password=True, id="bw_passphrase_input"),
            Horizontal(
                Button("Skip", variant="default", id="bw_passphrase_skip_btn"),
                Button("Unlock", variant="primary", id="bw_passphrase_unlock_btn"),
                classes="bw_passphrase_actions",
            ),
            id="bw_passphrase_container",
        )

    def on_mount(self) -> None:
        try:
            self.query_one("#bw_passphrase_input", Input).focus()
        except Exception:  # noqa: BLE001
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "bw_passphrase_input":
            self.action_unlock()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "bw_passphrase_skip_btn":
            self.dismiss(None)
        elif event.button.id == "bw_passphrase_unlock_btn":
            self.action_unlock()

    def action_unlock(self) -> None:
        passphrase = self.query_one("#bw_passphrase_input", Input).value
        if not passphrase:
            self.app.notify(
                "Passphrase is required — or Skip this key.",
                severity="warning",
                markup=False,
            )
            return
        self.dismiss(passphrase)

    def action_skip(self) -> None:
        self.dismiss(None)

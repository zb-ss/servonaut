"""PassphraseEnrolModal — prompts the user to choose an encryption passphrase.

Used by ``_prompt_memory_passphrase`` in ``app.py`` when the memory keypair
has not been enrolled yet.  Returns a :class:`PassphraseResult` on
confirmation, or ``None`` on cancellation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static, Switch

logger = logging.getLogger(__name__)

# Strength labels and their CSS colours.  Index == score (0–4).
_STRENGTH_LABEL = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
_STRENGTH_COLOR = ["red", "red", "yellow", "green", "green"]


@dataclass
class PassphraseResult:
    """Result returned by :class:`PassphraseEnrolModal` on confirmation.

    Attributes:
        passphrase: The confirmed passphrase string.
        remember: Whether the user opted in to storing the passphrase in
            the OS keychain (only ever ``True`` when the keychain is
            actually available on this device).
    """

    passphrase: str
    remember: bool = False


class PassphraseEnrolModal(ModalScreen[Optional[PassphraseResult]]):
    """Modal dialog for enrolling the memory-sync encryption passphrase.

    Compose: title, blurb, two password inputs, live strength readout,
    optional "Remember on this device" switch (keychain opt-in), Cancel
    and Enrol buttons.  The Enrol button is disabled until the score
    is >= 3 AND both inputs match (enrol mode) or any input is present
    (unlock mode).

    Args:
        mode: ``"enrol"`` (create new keypair) or ``"unlock"`` (enter
              existing passphrase to unwrap a stored keypair).

    Returns via dismiss():
        :class:`PassphraseResult` on confirmation, or ``None`` on
        cancellation.
    """

    DEFAULT_CSS = """
    PassphraseEnrolModal {
        align: center middle;
    }

    #enrol-container {
        width: 60%;
        max-width: 64;
        height: auto;
        background: $surface;
        border: round $accent;
        padding: 1 2;
    }

    #enrol-title {
        text-style: bold;
        padding: 0 0 1 0;
    }

    #enrol-blurb {
        padding: 0 0 1 0;
        color: $text-muted;
    }

    #enrol-pass1,
    #enrol-pass2 {
        margin: 0 0 1 0;
        width: 1fr;
    }

    #enrol-strength {
        padding: 0 0 1 0;
        height: 1;
        color: $text-muted;
    }

    #enrol-mismatch {
        padding: 0 0 1 0;
        height: 1;
        color: $error;
    }

    #enrol-remember-row {
        height: auto;
        align: left middle;
        padding: 0 0 1 0;
    }

    #enrol-remember-label {
        width: auto;
        padding: 0 1 0 0;
        color: $text-muted;
    }

    #enrol-pass2.hidden,
    #enrol-strength.hidden,
    #enrol-mismatch.hidden,
    #enrol-remember-row.hidden {
        display: none;
        height: 0;
    }

    #enrol-btn-row {
        layout: horizontal;
        height: auto;
        align: right middle;
    }

    #enrol-btn-row Button {
        margin-left: 1;
        min-width: 12;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("enter", "confirm", "Enrol", show=False),
    ]

    def __init__(self, mode: str = "enrol") -> None:
        super().__init__()
        self._mode = mode
        # Lazily check keychain availability at construction time.  Using a
        # lazy import avoids a hard dep on keyring at module load.
        try:
            from servonaut.services.memory import passphrase_store as _ps
            self._remember_available = _ps.keyring_available()
        except Exception:
            self._remember_available = False

    def compose(self) -> ComposeResult:
        is_enrol = self._mode == "enrol"
        title = (
            "[bold cyan]Enrol Memory Encryption Keypair[/bold cyan]"
            if is_enrol
            else "[bold cyan]Unlock Memory Encryption Keypair[/bold cyan]"
        )
        blurb = (
            "[yellow]Warning: this passphrase cannot be recovered. "
            "If lost, your synced memory data will be permanently inaccessible.[/yellow]"
            if is_enrol
            else "[dim]Enter your passphrase to decrypt the stored keypair.[/dim]"
        )
        btn_label = "Enrol" if is_enrol else "Unlock"
        remember_classes = "" if self._remember_available else "hidden"
        yield Container(
            Static(title, id="enrol-title"),
            Static(blurb, id="enrol-blurb"),
            Input(placeholder="Passphrase", password=True, id="enrol-pass1"),
            Input(
                placeholder="Confirm passphrase",
                password=True,
                id="enrol-pass2",
                classes="" if is_enrol else "hidden",
            ),
            Static("Strength: —", id="enrol-strength", classes="" if is_enrol else "hidden"),
            Static("", id="enrol-mismatch", classes="" if is_enrol else "hidden"),
            Horizontal(
                Static(
                    "Remember on this device (auto-unlock)",
                    id="enrol-remember-label",
                ),
                Switch(value=False, id="enrol-remember"),
                id="enrol-remember-row",
                classes=remember_classes,
            ),
            Horizontal(
                Button("Cancel", variant="default", id="enrol-btn-cancel"),
                Button(btn_label, variant="primary", id="enrol-btn-confirm", disabled=True),
                id="enrol-btn-row",
            ),
            id="enrol-container",
        )

    def on_mount(self) -> None:
        self.query_one("#enrol-pass1", Input).focus()

    # ------------------------------------------------------------------
    # Input change handler — updates strength readout and button state
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        pass1 = self.query_one("#enrol-pass1", Input).value
        pass2 = self.query_one("#enrol-pass2", Input).value
        self._update_strength(pass1)
        self._update_confirm_state(pass1, pass2)

    def _update_strength(self, passphrase: str) -> None:
        try:
            from servonaut.services.memory.crypto import estimate_pw_score
            score = estimate_pw_score(passphrase)
        except Exception:
            score = min(len(passphrase) // 4, 4)
        score = max(0, min(score, 4))
        label = _STRENGTH_LABEL[score]
        color = _STRENGTH_COLOR[score]
        static = self.query_one("#enrol-strength", Static)
        static.update(f"Strength: [{color}]{label}[/{color}]")
        self._last_score = score

    def _update_confirm_state(self, pass1: str, pass2: str) -> None:
        score = getattr(self, "_last_score", 0)
        is_enrol = self._mode == "enrol"
        if is_enrol:
            mismatch = pass1 and pass2 and pass1 != pass2
            ok = score >= 3 and pass1 == pass2 and bool(pass1)
        else:
            mismatch = False
            ok = bool(pass1)
        self.query_one("#enrol-mismatch", Static).update(
            "[red]Passphrases do not match.[/red]" if mismatch else ""
        )
        btn = self.query_one("#enrol-btn-confirm", Button)
        btn.disabled = not ok

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "enrol-btn-confirm":
            self.action_confirm()
        elif event.button.id == "enrol-btn-cancel":
            self.action_cancel()

    def action_confirm(self) -> None:
        btn = self.query_one("#enrol-btn-confirm", Button)
        if btn.disabled:
            return
        passphrase = self.query_one("#enrol-pass1", Input).value
        if not passphrase:
            return
        remember = False
        if self._remember_available:
            try:
                remember = bool(self.query_one("#enrol-remember", Switch).value)
            except Exception:
                remember = False
        self.dismiss(PassphraseResult(passphrase=passphrase, remember=remember))

    def action_cancel(self) -> None:
        self.dismiss(None)

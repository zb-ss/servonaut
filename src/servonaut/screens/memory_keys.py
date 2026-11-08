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
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static, Switch
from servonaut.widgets.secret_input import SecretInput
from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)

logger = logging.getLogger(__name__)

# Strength labels. Index == score (0–4).
_STRENGTH_LABEL = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]


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

    Show the active rules, two inputs, strength, and validation feedback.
    Enable Enrol when the shared assessment accepts two identical entries.
    Unlock requires only a nonempty entry for the existing passphrase.

    Args:
        mode: ``"enrol"`` (create new keypair) or ``"unlock"`` (enter
              existing passphrase to unwrap a stored keypair).

    Returns via dismiss():
        :class:`PassphraseResult` on confirmation, or ``None`` on
        cancellation.
    """

    DEFAULT_CLASSES = "dialog-screen"
    # on_mount focuses the first field itself; the automatic focus would
    # animate a scroll against the first, not yet final, layout.
    AUTO_FOCUS = ""

    # Enrol shows rules, two fields and feedback, so on shorter terminals the
    # shared frame gives its padding to the content (see dialogs.tcss).
    VERTICAL_BREAKPOINTS = [(0, "-dialog-minimal"), (24, "-dialog-tight"), (40, "-dialog-roomy")]

    DEFAULT_CSS = """
    #enrol-blurb {
        margin-bottom: 1;
        color: $text-muted;
    }

    #enrol-pass1_field,
    #enrol-pass2_field {
        margin: 0;
        width: 1fr;
    }

    #enrol-pass1_field {
        margin-bottom: 1;
    }

    #enrol-rules,
    #enrol-strength {
        padding: 0;
        height: auto;
        color: $text-muted;
    }

    #enrol-rules {
        margin-bottom: 1;
    }

    #enrol-mismatch {
        padding: 0;
        height: auto;
        color: $text-error;
    }

    #enrol-mismatch.ready {
        color: $text-success;
    }

    #enrol-remember-row {
        height: auto;
        align: left middle;
        padding: 0;
    }

    #enrol-remember-label {
        width: 1fr;
        padding: 0 1 0 0;
        color: $text-muted;
    }

    #enrol-pass2_field.hidden,
    #enrol-rules.hidden,
    #enrol-strength.hidden,
    #enrol-mismatch.hidden,
    #enrol-remember-row.hidden {
        display: none;
        height: 0;
    }

    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("enter", "confirm", "Enrol", show=False),
    ]

    def __init__(
        self,
        mode: str = "enrol",
        *,
        remember_default: bool = False,
    ) -> None:
        super().__init__()
        self._mode = mode
        self._remember_default = remember_default
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
            "[bold $text-accent]Enrol Memory Encryption Keypair[/bold $text-accent]"
            if is_enrol
            else "[bold $text-accent]Unlock Memory Encryption Keypair[/bold $text-accent]"
        )
        blurb = (
            "[bold]Warning: this passphrase cannot be recovered. "
            "If lost, your synced memory data will be permanently inaccessible.[/bold]"
            if is_enrol
            else "Enter your passphrase to decrypt the stored keypair."
        )
        btn_label = "Enrol" if is_enrol else "Unlock"
        remember_classes = "" if self._remember_available else "hidden"
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(title, id="enrol-title"),
            body=DialogBody(
                Static(blurb, id="enrol-blurb"),
                Static("", id="enrol-rules", markup=False, classes="" if is_enrol else "hidden"),
                SecretInput(placeholder="Passphrase", id="enrol-pass1"),
                SecretInput(
                    placeholder="Confirm passphrase",
                    id="enrol-pass2",
                    classes="" if is_enrol else "hidden",
                ),
                Static("Strength: —", id="enrol-strength", classes="" if is_enrol else "hidden"),
                Static("", id="enrol-mismatch", markup=False, classes="" if is_enrol else "hidden"),
                Horizontal(
                    Static(
                        "Keep unlocked for 30 days (secure OS keychain)",
                        id="enrol-remember-label",
                    ),
                    Switch(value=self._remember_default, id="enrol-remember"),
                    id="enrol-remember-row",
                    classes=remember_classes,
                ),
                id="enrol-body",
            ),
            actions=DialogActions(
                Button("Cancel", variant="default", id="enrol-btn-cancel"),
                Button(btn_label, variant="primary", id="enrol-btn-confirm", disabled=True),
                id="enrol-btn-row",
            ),
            id="enrol-container",
            size="standard",
        )

    def on_mount(self) -> None:
        self._update_validation()
        self.query_one("#enrol-pass1", Input).focus(scroll_visible=False)

    def on_resize(self) -> None:
        self.call_after_refresh(self._show_focused_control)

    def _show_focused_control(self) -> None:
        """Keep the active control visible after a viewport resize."""
        if self.focused is not None:
            self.focused.scroll_visible(animate=False, immediate=True)

    # ------------------------------------------------------------------
    # Input change handler — updates strength readout and button state
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        self._update_validation()
        if self._mode == "enrol":
            self.call_after_refresh(self._show_feedback)

    def _show_feedback(self) -> None:
        """Keep the reason Enrol is disabled in view while the user types."""
        self.query_one("#enrol-mismatch", Static).scroll_visible(animate=False, immediate=True)

    def _update_validation(self) -> None:
        pass1 = self.query_one("#enrol-pass1", Input).value
        pass2 = self.query_one("#enrol-pass2", Input).value
        if self._mode == "enrol":
            from servonaut.services.memory.crypto import assess_passphrase

            assessment = assess_passphrase(pass1)
            self.query_one("#enrol-rules", Static).update("\n".join(
                f"{'✓' if met else '○'} {rule}"
                for rule, met in zip(assessment.requirements, assessment.requirements_met, strict=True)
            ))
            score = assessment.score
            strength = (
                f"[bold]{_STRENGTH_LABEL[score]} ({score}/4)[/bold]"
                if assessment.checked else "unavailable"
            )
            self.query_one("#enrol-strength", Static).update(
                f"Strength: {strength}. "
                f"Required: {_STRENGTH_LABEL[assessment.minimum_score]} ({assessment.minimum_score}/4)."
            )
            feedback = (
                [message for message in assessment.feedback if message not in assessment.requirements]
                if pass1 else ["Enter a passphrase."]
            )
            if pass1 and not pass2:
                feedback.append("Enter the same passphrase in the confirmation field.")
            elif pass2 and pass1 != pass2:
                feedback.append("Passphrases do not match.")
            ok = bool(pass1) and assessment.acceptable and pass1 == pass2
            if ok:
                feedback = ["Passphrases match. You can enrol."]
            elif pass1 and pass1 == pass2 and not feedback:
                feedback = ["Passphrases match. Meet the rules to enrol."]
            message = self.query_one("#enrol-mismatch", Static)
            message.update("\n".join(feedback))
            message.set_class(ok, "ready")
        else:
            ok = bool(pass1)
        self.query_one("#enrol-btn-confirm", Button).disabled = not ok

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "enrol-btn-confirm":
            self.action_confirm()
        elif event.button.id == "enrol-btn-cancel":
            self.action_cancel()

    def action_confirm(self) -> None:
        self._update_validation()
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

"""Bitwarden unlock modal — state-aware ``bw unlock`` prompt.

Brief blocking interaction (a single password field), so it is a
:class:`~textual.screen.ModalScreen`, mirroring the Memory Sync unlock UX. The
body is state-aware: it asks :class:`BwSessionService.status` first and shows the
install / login guidance / unlock form / auto-dismiss path accordingly.

Security: the master password is read from a ``password=True`` Input and handed
straight to :meth:`BwSessionService.unlock` (env, never argv). It is never logged
or echoed.
"""

from __future__ import annotations

import logging
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Static

from servonaut.services.bw_errors import BwError
from servonaut.services.bw_session_service import BwAuthState, BwSessionService

logger = logging.getLogger(__name__)

_CLI_DOCS_URL = "https://bitwarden.com/help/cli/"


class BwUnlockModal(ModalScreen[bool]):
    """Prompt the user to unlock their Bitwarden vault.

    Dismisses ``True`` once a session is held (either it was already unlocked, or
    the user unlocked successfully), ``False`` on cancel / unusable state.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "unlock", "Unlock", show=False),
    ]

    DEFAULT_CSS = ""  # styling lives in app.css

    def __init__(self, session_service: Optional[BwSessionService] = None) -> None:
        super().__init__()
        self._svc = session_service

    def _service(self) -> Optional[BwSessionService]:
        return self._svc or getattr(self.app, "bw_session_service", None)

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold cyan]Unlock Bitwarden Vault[/bold cyan]", id="bw_unlock_title"),
            Vertical(
                Static("[dim]Checking Bitwarden status…[/dim]"),
                id="bw_unlock_body",
            ),
            id="bw_unlock_container",
        )

    def on_mount(self) -> None:
        self.run_worker(self._load_state(), group="bw_session", exclusive=True)

    async def _load_state(self) -> None:
        """Resolve the bw auth state and render the matching body."""
        svc = self._service()
        if svc is None:
            self._render_unavailable()
            return

        try:
            state = await svc.status()
        except Exception as exc:  # noqa: BLE001 — status() is defensive, but never crash the modal
            logger.debug("bw status failed in unlock modal: %s", exc)
            self._render_unavailable()
            return

        if state is BwAuthState.UNLOCKED:
            self.dismiss(True)
            return
        if state is BwAuthState.NOT_INSTALLED:
            self._render_not_installed()
            return
        if state is BwAuthState.UNAUTHENTICATED:
            self._render_unauthenticated()
            return
        self._render_locked()

    # ------------------------------------------------------------------
    # state renderers
    # ------------------------------------------------------------------

    def _body(self) -> Vertical:
        body = self.query_one("#bw_unlock_body", Vertical)
        body.remove_children()
        return body

    def _render_unavailable(self) -> None:
        self._body().mount(
            Static(
                "Bitwarden session service is unavailable. Sign in to Servonaut and try again.",
            ),
            Horizontal(Button("Close", variant="default", id="bw_close_btn"), classes="bw_unlock_actions"),
        )

    def _render_not_installed(self) -> None:
        self._body().mount(
            Static("The Bitwarden CLI (`bw`) is not installed or not on your PATH."),
            Static(f"[dim]Install it from {_CLI_DOCS_URL}[/dim]"),
            Horizontal(Button("Close", variant="default", id="bw_close_btn"), classes="bw_unlock_actions"),
        )

    def _render_unauthenticated(self) -> None:
        self._body().mount(
            Static("You are not logged in to Bitwarden."),
            Static(
                "[dim]Run `bw login` in your terminal once (email + master password "
                "+ 2FA). Servonaut handles unlock, not login.[/dim]"
            ),
            Horizontal(Button("Close", variant="default", id="bw_close_btn"), classes="bw_unlock_actions"),
        )

    def _render_locked(self) -> None:
        self._body().mount(
            Static("Enter your Bitwarden master password to unlock the vault for this session."),
            Input(placeholder="Master password", password=True, id="bw_master_pw"),
            Checkbox(
                "Remember on this device (coming soon)",
                value=False,
                disabled=True,
                id="bw_remember",
            ),
            Horizontal(
                Button("Cancel", variant="default", id="bw_cancel_btn"),
                Button("Unlock", variant="primary", id="bw_unlock_btn"),
                classes="bw_unlock_actions",
            ),
        )
        try:
            self.query_one("#bw_master_pw", Input).focus()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id in {"bw_cancel_btn", "bw_close_btn"}:
            self.dismiss(False)
        elif btn_id == "bw_unlock_btn":
            self.action_unlock()

    def action_cancel(self) -> None:
        self.dismiss(False)

    def action_unlock(self) -> None:
        """Kick off the unlock worker (no-op when the form isn't shown)."""
        try:
            self.query_one("#bw_master_pw", Input)
        except Exception:  # noqa: BLE001 — form not rendered (install/login state)
            return
        self.run_worker(self._do_unlock(), group="bw_session", exclusive=True)

    async def _do_unlock(self) -> None:
        svc = self._service()
        if svc is None:
            self.app.notify("Bitwarden session service unavailable.", severity="error", markup=False)
            return

        master_password = self.query_one("#bw_master_pw", Input).value
        if not master_password:
            self.app.notify("Master password is required.", severity="warning", markup=False)
            return

        try:
            await svc.unlock(master_password)
        except BwError as exc:
            self.app.notify(exc.message, severity="error", markup=False)
            return
        except Exception as exc:  # noqa: BLE001
            self.app.notify(f"Unlock failed: {exc}", severity="error", markup=False)
            return

        self.app.notify("Bitwarden vault unlocked for this session.", markup=False)
        self.dismiss(True)

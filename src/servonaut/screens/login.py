"""Login screen for servonaut.dev OAuth2 device flow authentication."""

from __future__ import annotations

import logging
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


# Features that exist on the backend's plan mapping but haven't shipped on
# the CLI side yet. We suppress them from the login screen's "what you
# unlock" pitch and the logged-in entitlements list so users don't see
# features they can't actually use. When one of these lands, remove it
# from the set and it will start rendering in both places automatically.
_UNRELEASED_FEATURES = {
    "premium_ai",
    "gcp_provider",
    "azure_provider",
    "team_workspaces",
}

# Entitlements that exist but should NOT appear in the consumer-facing
# Account feature list. Currently just admin-granted overrides: they are
# never plan-derived (backend only emits them via EntitlementOverride.
# custom_limits) so showing them as "✗ Dangerous AI tools" to every user
# is noise. Surface remains via auth.has_dangerous_ai_tools where it gates
# real UI (chat panel tool gate).
_ADMIN_ONLY_FEATURES = {
    "allow_dangerous_ai_tools",
}


class PassphraseModal(ModalScreen[Optional[str]]):
    """Prompt the user for a sync passphrase.

    When confirm=True (first-push), two inputs are shown and must match.
    Dismisses with the passphrase string, or None on cancel.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    def __init__(self, confirm: bool = False, title: str = "Enter Sync Passphrase") -> None:
        super().__init__()
        self._confirm = confirm
        self._title = title

    def compose(self) -> ComposeResult:
        from servonaut.services import config_crypto
        hint = (
            f"Minimum {config_crypto.MIN_PASSPHRASE_LEN} characters. "
            "Warning: if you forget this passphrase, synced data cannot be recovered."
        )
        widgets: list = [
            Static(f"[bold cyan]{self._title}[/bold cyan]", id="passphrase_title"),
            Static(hint, id="passphrase_hint"),
            Input(placeholder="passphrase", id="input_passphrase", password=True),
        ]
        if self._confirm:
            widgets.append(
                Input(placeholder="confirm passphrase", id="input_passphrase_confirm", password=True)
            )
        widgets.append(Static("", id="passphrase_error"))
        widgets.append(
            Horizontal(
                Button("OK", variant="primary", id="btn_passphrase_ok"),
                Button("Cancel", id="btn_passphrase_cancel"),
                id="passphrase_buttons",
            )
        )
        yield Container(*widgets, id="passphrase_container")

    def on_mount(self) -> None:
        self.query_one("#input_passphrase", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "input_passphrase" and self._confirm:
            self.query_one("#input_passphrase_confirm", Input).focus()
            return
        self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_passphrase_ok":
            self._submit()
        elif event.button.id == "btn_passphrase_cancel":
            self.dismiss(None)

    def _submit(self) -> None:
        from servonaut.services import config_crypto
        value = self.query_one("#input_passphrase", Input).value
        error_widget = self.query_one("#passphrase_error", Static)

        if len(value) < config_crypto.MIN_PASSPHRASE_LEN:
            error_widget.update(
                f"[red]Passphrase must be at least {config_crypto.MIN_PASSPHRASE_LEN} characters.[/red]"
            )
            return

        if self._confirm:
            confirm_value = self.query_one("#input_passphrase_confirm", Input).value
            if value != confirm_value:
                error_widget.update("[red]Passphrases do not match.[/red]")
                return

        self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class LoginScreen(Screen):
    """OAuth2 device flow login screen for servonaut.dev."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self, return_to: Optional[str] = None) -> None:
        """Open the login screen.

        Args:
            return_to: Optional screen slug to switch to after a successful
                login. Currently ``"memory_sync"`` (back to
                MemorySyncSetupScreen) and ``"sync_config"`` (forward to
                SnapshotManagerScreen) are recognised. None (default)
                parks the user on the logged-in view.
        """
        super().__init__()
        self._polling: bool = False
        self._device_code: Optional[str] = None
        self._return_to: Optional[str] = return_to

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Container(
                    Static("[bold cyan]👤 Servonaut Account[/bold cyan]", id="login_title"),

                    # No httpx / service unavailable
                    Static(
                        "[yellow]Authentication is unavailable.[/yellow]\n"
                        "Install httpx to enable: [dim]pip install 'servonaut[pro]'[/dim]",
                        id="no_httpx_notice",
                        classes="login_notice"
                    ),

                    # Logged-out state
                    Container(
                        Static(
                            "Log in to unlock cloud features:\n\n"
                            "  [green]✓[/green] Config sync across machines\n"
                            "  [green]✓[/green] MCP relay — let AI agents "
                            "dispatch commands to this machine",
                            id="login_description",
                        ),
                        Button("Login with servonaut.dev", variant="primary", id="btn_login"),
                        id="logged_out_container",
                        classes="auth_state_container"
                    ),

                    # Device flow in progress (hidden by default)
                    Container(
                        Static("Open this URL and enter the code:", id="device_code_info"),
                        Static("", id="device_url"),
                        Static("", id="device_code"),
                        Static("[dim]Waiting for authorization...[/dim]", id="device_status"),
                        Button("Cancel", id="btn_cancel_login"),
                        id="device_flow_container",
                        classes="auth_state_container"
                    ),

                    # Logged-in state (hidden by default)
                    Container(
                        Container(
                            Static("", id="account_info"),
                            Static("", id="plan_info"),
                            id="account_info_header"
                        ),
                        Static("", id="entitlements_info"),
                        id="logged_in_container",
                        classes="auth_state_container"
                    ),

                    # Action row — kept outside the state containers so Back
                    # sits next to Login/Logout/Cancel uniformly. The buttons
                    # toggle visibility based on state but their position is
                    # stable, which keeps the modal's visual rhythm.
                    Horizontal(
                        Button("Logout", variant="error", id="btn_logout"),
                        Button("Back", id="btn_back"),
                        id="login_actions",
                    ),
                    id="login_box"
                ),
                id="login_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        """Show appropriate state based on current auth status."""
        self._hide_all_sections()

        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            self._show_no_httpx_state()
            return

        if auth.is_authenticated:
            # Validate token server-side in background; show logged-in optimistically
            self._show_logged_in_state()
            self.run_worker(self._validate_session(), exclusive=False)
            # Already-logged-in users coming via a return_to redirect
            # shouldn't get parked on this screen.
            self._maybe_redirect_after_login()
        else:
            self._show_logged_out_state()

    def _maybe_redirect_after_login(self) -> None:
        """Bounce the user to a follow-up screen if requested via ``return_to``.

        Only fires when the caller explicitly opted into a redirect — the
        plain login screen still parks on its logged-in view by default so
        the existing UX (sidebar nav, account info) is unchanged.
        """
        if self._return_to == "memory_sync":
            from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen
            self.app.switch_screen(MemorySyncSetupScreen())
        elif self._return_to == "sync_config":
            # Same entitlement check the sidebar nav applies — a logged-in
            # Free user shouldn't bounce into a screen that immediately
            # tells them sync is unavailable.
            auth = getattr(self.app, "auth_service", None)
            if auth and auth.has_feature("config_sync"):
                from servonaut.screens.snapshot_manager import SnapshotManagerScreen
                self.app.switch_screen(SnapshotManagerScreen())

    # ------------------------------------------------------------------
    # UI state helpers
    # ------------------------------------------------------------------

    def _hide_all_sections(self) -> None:
        """Hide every conditional section, plus every per-state action button.

        Each show_* method re-shows what its state needs.
        """
        for widget_id in (
            "no_httpx_notice",
            "logged_out_container",
            "device_flow_container",
            "logged_in_container",
            "login_actions",
            "btn_back",
            "btn_logout",
        ):
            self.query_one(f"#{widget_id}").display = False

    def _show_logged_out_state(self) -> None:
        self.query_one("#logged_out_container").display = True
        # Logged-out: only Back is relevant (Login button lives inside the
        # state container above, Logout is hidden).
        self.query_one("#login_actions").display = True
        self.query_one("#btn_back").display = True

    def _show_device_flow_state(self) -> None:
        self.query_one("#device_flow_container").display = True
        # Device flow has its own Cancel button — don't show login_actions
        # so the user doesn't see a parallel Back/Logout pair.

    def _show_no_httpx_state(self) -> None:
        self.query_one("#no_httpx_notice").display = True
        self.query_one("#login_actions").display = True
        self.query_one("#btn_back").display = True

    def _show_logged_in_state(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return

        email = ""
        # Try token-level email first, then entitlements
        if hasattr(auth, "_token") and auth._token:
            email = auth._token.email or ""
        entitlements = auth._get_cached_entitlements() if hasattr(auth, "_get_cached_entitlements") else None
        if not email and entitlements:
            email = entitlements.get("email", "")

        # If email is still missing, _validate_session (from on_mount) will
        # refresh the token and update the display
        if not email:
            email = "verifying..."

        plan = auth.plan
        features = auth.get_plan_features() if hasattr(auth, "get_plan_features") else {}

        # Human-readable feature names. Unreleased features are filtered
        # below so the user doesn't see things they can't use yet — even if
        # the backend's plan map still lists them. Keys without a label here
        # fall back to the raw slug, which is a screaming hint to add one.
        feature_labels = {
            "config_sync": "Config sync across machines",
            "premium_ai": "Premium AI providers",
            "gcp_provider": "GCP provider support",
            "azure_provider": "Azure provider support",
            "team_workspaces": "Team workspaces",
            "memory_sync": "Memory Sync (encrypted fleet memory backup)",
            "memory_drift": "Drift detection across re-probes",
            "memory_digest": "Periodic email digests of memory changes",
            "memory_team_share": "Share encrypted memory with team-mates",
            "memory_ai_summary": "AI-generated memory summaries",
            "memory_compliance_export": "Signed compliance export tarball",
            "secrets_management": "Secrets management",
            "secrets_team_shared": "Team-shared secrets",
        }
        feature_lines = []
        for feat, enabled in features.items():
            if feat in _UNRELEASED_FEATURES or feat in _ADMIN_ONLY_FEATURES:
                continue
            label = feature_labels.get(feat, feat)
            if enabled:
                feature_lines.append(f"  [green]✓[/green] {label}")
            else:
                feature_lines.append(f"  [dim]✗ {label}[/dim]")
        if not feature_lines:
            feature_lines = ["  [dim]No features listed[/dim]"]

        self.query_one("#account_info", Static).update(f"[bold]Logged in as:[/bold] {email}")
        self.query_one("#plan_info", Static).update(f"[bold]Plan:[/bold] {plan}")
        self.query_one("#entitlements_info", Static).update(
            "[bold]Features:[/bold]\n" + "\n".join(feature_lines)
        )

        self.query_one("#logged_in_container").display = True
        self.query_one("#login_actions").display = True
        self.query_one("#btn_logout").display = True
        self.query_one("#btn_back").display = True

    async def _validate_session(self) -> None:
        """Validate the token server-side; update UI accordingly.

        If the session was revoked, clears local auth and switches to
        logged-out state. If valid, updates email from the refresh response.
        """
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return
        try:
            valid = await auth.validate_token()
            if not valid:
                self.notify("Session was revoked. Please log in again.", severity="warning")
                self._hide_all_sections()
                self._show_logged_out_state()
                return
            # Refresh succeeded — update email if now available
            if hasattr(auth, "_token") and auth._token and auth._token.email:
                self.query_one("#account_info", Static).update(
                    f"[bold]Logged in as:[/bold] {auth._token.email}"
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "btn_login":
            self._start_login()
        elif button_id == "btn_cancel_login":
            self._cancel_login()
        elif button_id == "btn_logout":
            self.run_worker(self._do_logout(), exclusive=True, name="logout")
        elif button_id == "btn_back":
            self.action_back()

    def _start_login(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            self.notify("Authentication service not available.", severity="error")
            return
        self._hide_all_sections()
        self.query_one("#device_status", Static).update("[dim]Initiating device flow...[/dim]")
        self._show_device_flow_state()
        self._polling = True
        self.run_worker(self._do_device_flow(), exclusive=True, name="device_flow")

    def _cancel_login(self) -> None:
        self._polling = False
        self._device_code = None
        self._hide_all_sections()
        self._show_logged_out_state()
        self.query_one("#device_status", Static).update("[dim]Waiting for authorization...[/dim]")

    # ------------------------------------------------------------------
    # Async workers
    # ------------------------------------------------------------------

    async def _do_device_flow(self) -> None:
        """Start device flow then poll for token."""
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return

        try:
            flow = await auth.start_device_flow()
        except Exception as exc:
            logger.error("Device flow initiation failed: %s", exc)
            msg = str(exc)[:200]
            self.notify(f"Login failed: {msg}", severity="error")
            self._hide_all_sections()
            self._show_logged_out_state()
            return

        device_code = flow.get("device_code", "")
        user_code = flow.get("user_code", "")
        verification_uri = flow.get("verification_uri", "https://servonaut.dev/activate")
        interval = flow.get("interval", 5)

        self._device_code = device_code
        # Rich's [link=…] emits an OSC 8 hyperlink so OSC 8-aware terminals
        # keep the URL as one clickable region even if it visually wraps.
        # The URL has to be quoted because Rich's markup parser treats the
        # ':' after 'https' as a style separator otherwise.
        self.query_one("#device_url", Static).update(
            f'[link="{verification_uri}"][cyan]{verification_uri}[/cyan][/link]'
        )
        self.query_one("#device_code", Static).update(f"[bold]Code: {user_code}[/bold]")
        self.query_one("#device_status", Static).update(
            "[dim]Waiting for authorization... (polls every few seconds)[/dim]"
        )

        if not self._polling:
            return

        success = await auth.poll_for_token(device_code, interval=interval)

        if not self._polling:
            # User cancelled while we were polling
            return

        self._polling = False
        self._hide_all_sections()
        if success:
            # Initialize paid-tier services now that we're authenticated
            init = getattr(self.app, "init_paid_services", None)
            if init:
                init()
            self._show_logged_in_state()
            self.notify("Logged in successfully!", severity="information")
            # Kick off the in-process relay listener. The app is responsible
            # for deciding applicability (plan, entitlements, external listener)
            # and surfaces its own toast on the outcome.
            on_login = getattr(self.app, "on_user_login_success", None)
            if callable(on_login):
                on_login()
            self._maybe_redirect_after_login()
        else:
            self._show_logged_out_state()
            self.notify("Authorization failed or timed out.", severity="warning")

    async def _do_logout(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return
        try:
            await auth.logout()
            on_logout = getattr(self.app, "on_user_logout", None)
            if callable(on_logout):
                on_logout()
            self._hide_all_sections()
            self._show_logged_out_state()
            self.notify("Logged out.", severity="information")
        except Exception as exc:
            logger.error("Logout error: %s", exc)
            self.notify(f"Logout error: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()


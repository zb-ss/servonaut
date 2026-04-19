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


class SyncActionModal(ModalScreen[Optional[str]]):
    """Ask the user whether to Push, Pull, or Manage snapshots.

    Dismisses with "push", "pull", "manage", or None (cancel).
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold cyan]Sync Config[/bold cyan]", id="sync_action_title"),
            Static(
                "[dim]Choose an action:[/dim]",
                id="sync_action_hint",
            ),
            Button("Push (upload local config)", variant="primary", id="btn_push"),
            Button("Pull (download latest)", variant="default", id="btn_pull"),
            Button("Manage snapshots", variant="default", id="btn_manage"),
            Button("Cancel", id="btn_cancel_sync"),
            id="sync_action_container",
        )

    def on_mount(self) -> None:
        self.query_one("#btn_push", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_push":
            self.dismiss("push")
        elif event.button.id == "btn_pull":
            self.dismiss("pull")
        elif event.button.id == "btn_manage":
            self.dismiss("manage")
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


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

    def __init__(self) -> None:
        super().__init__()
        self._polling: bool = False
        self._device_code: Optional[str] = None

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
                            "  [green]✓[/green] Team workspaces\n"
                            "  [green]✓[/green] Premium AI providers\n"
                            "  [green]✓[/green] GCP / Azure provider support",
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
                        Horizontal(
                            Button("🔄 Sync Config", variant="default", id="btn_sync"),
                            Button("Logout", variant="error", id="btn_logout"),
                            id="logged_in_actions"
                        ),
                        # Inline sync options — hidden until "Sync Config" is clicked
                        Container(
                            Static("[bold cyan]Sync Config[/bold cyan]", id="inline_sync_title"),
                            Static("[dim]Choose an action:[/dim]", id="inline_sync_hint"),
                            Horizontal(
                                Button("Push", variant="primary", id="btn_inline_push"),
                                Button("Pull", variant="default", id="btn_inline_pull"),
                                Button("Manage snapshots", variant="default", id="btn_inline_manage"),
                                id="inline_sync_actions",
                            ),
                            Button("Cancel", id="btn_inline_cancel"),
                            id="sync_inline_container",
                        ),
                        id="logged_in_container",
                        classes="auth_state_container"
                    ),

                    # Always visible
                    Button("Back", id="btn_back"),
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
            self.query_one("#no_httpx_notice").display = True
            self.query_one("#btn_back").display = True
            return

        if auth.is_authenticated:
            # Validate token server-side in background; show logged-in optimistically
            self._show_logged_in_state()
            self.run_worker(self._validate_session(), exclusive=False)
        else:
            self._show_logged_out_state()

    # ------------------------------------------------------------------
    # UI state helpers
    # ------------------------------------------------------------------

    def _hide_all_sections(self) -> None:
        """Hide every conditional section."""
        for widget_id in (
            "no_httpx_notice",
            "logged_out_container",
            "device_flow_container",
            "logged_in_container",
            "sync_inline_container",
            "btn_back",
        ):
            self.query_one(f"#{widget_id}").display = False

    def _show_logged_out_state(self) -> None:
        self.query_one("#logged_out_container").display = True
        self.query_one("#btn_back").display = True

    def _show_device_flow_state(self) -> None:
        self.query_one("#device_flow_container").display = True

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

        # Human-readable feature names
        feature_labels = {
            "config_sync": "Config sync across machines",
            "premium_ai": "Premium AI providers",
            "gcp_provider": "GCP provider support",
            "azure_provider": "Azure provider support",
            "team_workspaces": "Team workspaces",
        }
        feature_lines = []
        for feat, enabled in features.items():
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
        elif button_id == "btn_sync":
            self._show_sync_options()
        elif button_id == "btn_inline_cancel":
            self._hide_sync_options()
        elif button_id == "btn_inline_push":
            self._on_sync_action_chosen("push")
        elif button_id == "btn_inline_pull":
            self._on_sync_action_chosen("pull")
        elif button_id == "btn_inline_manage":
            self._on_sync_action_chosen("manage")
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

    def _show_sync_options(self) -> None:
        """Show the inline push/pull selector."""
        self.query_one("#logged_in_actions").display = False
        self.query_one("#sync_inline_container").display = True

    def _hide_sync_options(self) -> None:
        """Hide the inline sync options."""
        self.query_one("#sync_inline_container").display = False
        self.query_one("#logged_in_actions").display = True

    def _on_sync_action_chosen(self, action: str) -> None:
        self._hide_sync_options()
        
        if action == "manage":
            from servonaut.screens.snapshot_manager import SnapshotManagerScreen
            self.app.push_screen(SnapshotManagerScreen())
            return

        from servonaut.services import config_crypto
        if not config_crypto.HAS_CRYPTOGRAPHY:
            self.notify(
                "Install cryptography: pip install 'servonaut[sync]'",
                severity="error",
            )
            return

        sync = getattr(self.app, "config_sync_service", None)
        if sync is None:
            self.notify("Config sync is not available on this plan.", severity="warning")
            return

        is_first_push = action == "push" and not sync.has_probe()
        modal_title = "Set Sync Passphrase" if is_first_push else "Enter Sync Passphrase"
        self.app.push_screen(
            PassphraseModal(confirm=is_first_push, title=modal_title),
            callback=lambda pp: self._on_passphrase_received(action, pp, attempt=1),
        )

    def _on_passphrase_received(
        self, action: str, passphrase: Optional[str], attempt: int
    ) -> None:
        if passphrase is None:
            return
        self.run_worker(
            self._do_sync_encrypted(action, passphrase, attempt),
            exclusive=True,
            name="sync_config",
        )

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
        self.query_one("#device_url", Static).update(f"[cyan]{verification_uri}[/cyan]")
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

    async def _do_sync_encrypted(self, action: str, passphrase: str, attempt: int) -> None:
        """Execute push or pull with client-side encryption, retrying on wrong passphrase."""
        from servonaut.services import config_crypto

        sync = getattr(self.app, "config_sync_service", None)
        if sync is None:
            self.notify("Config sync is not available on this plan.", severity="warning")
            return

        _MAX_ATTEMPTS = 3
        try:
            if action == "push":
                result = await sync.push(passphrase=passphrase)
                msg = result.get("message", "Config pushed successfully.")
                self.notify(msg, severity="information")
            else:
                remote_data = await sync.pull(passphrase=passphrase)
                sync.apply_remote_config(remote_data)
                self.notify("Config pulled and applied.", severity="information")
        except config_crypto.DecryptionError:
            if attempt < _MAX_ATTEMPTS:
                self.notify("Wrong passphrase, please try again.", severity="error")
                self.app.push_screen(
                    PassphraseModal(confirm=False, title="Enter Sync Passphrase"),
                    callback=lambda pp: self._on_passphrase_received(action, pp, attempt + 1),
                )
            else:
                self.notify("Too many wrong attempts. Sync aborted.", severity="error")
        except Exception as exc:
            logger.error("Config sync error: %s", exc)
            self.notify(f"Sync failed: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()


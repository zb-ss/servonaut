"""Login screen for servonaut.dev OAuth2 device flow authentication."""

from __future__ import annotations

import logging
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


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
                Static("[bold cyan]Servonaut Account[/bold cyan]", id="login_title"),

                # No httpx / service unavailable
                Static(
                    "[yellow]Authentication is unavailable.[/yellow]\n"
                    "Install httpx to enable: [dim]pip install 'servonaut[pro]'[/dim]",
                    id="no_httpx_notice",
                ),

                # Logged-out state
                Static(
                    "Log in to unlock cloud features:\n"
                    "  [dim]• Config sync across machines[/dim]\n"
                    "  [dim]• Team workspaces[/dim]\n"
                    "  [dim]• Premium AI providers[/dim]\n"
                    "  [dim]• GCP / Azure provider support[/dim]",
                    id="login_description",
                ),
                Button("Login with servonaut.dev", variant="primary", id="btn_login"),

                # Device flow in progress (hidden by default)
                Static("Open this URL and enter the code:", id="device_code_info"),
                Static("", id="device_url"),
                Static("", id="device_code"),
                Static("[dim]Waiting for authorization...[/dim]", id="device_status"),
                Button("Cancel", id="btn_cancel_login"),

                # Logged-in state (hidden by default)
                Static("", id="account_info"),
                Static("", id="plan_info"),
                Static("", id="entitlements_info"),
                Button("Logout", variant="error", id="btn_logout"),
                Button("Sync Config", variant="default", id="btn_sync"),

                # Always visible
                Button("Back", id="btn_back"),

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
            self._show_logged_in_state()
        else:
            self._show_logged_out_state()

    # ------------------------------------------------------------------
    # UI state helpers
    # ------------------------------------------------------------------

    def _hide_all_sections(self) -> None:
        """Hide every conditional section."""
        for widget_id in (
            "no_httpx_notice",
            "login_description",
            "btn_login",
            "device_code_info",
            "device_url",
            "device_code",
            "device_status",
            "btn_cancel_login",
            "account_info",
            "plan_info",
            "entitlements_info",
            "btn_logout",
            "btn_sync",
            "btn_back",
        ):
            self.query_one(f"#{widget_id}").display = False

    def _show_logged_out_state(self) -> None:
        self.query_one("#login_description").display = True
        self.query_one("#btn_login").display = True
        self.query_one("#btn_back").display = True

    def _show_device_flow_state(self) -> None:
        self.query_one("#device_code_info").display = True
        self.query_one("#device_url").display = True
        self.query_one("#device_code").display = True
        self.query_one("#device_status").display = True
        self.query_one("#btn_cancel_login").display = True

    def _show_logged_in_state(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return

        email = "unknown"
        entitlements = auth._get_cached_entitlements() if hasattr(auth, "_get_cached_entitlements") else None
        if entitlements:
            email = entitlements.get("email", "unknown")

        plan = auth.plan
        features: dict = {}
        if entitlements:
            features = entitlements.get("features", {})

        feature_lines = [
            f"  [green]✓[/green] {feat}"
            for feat, enabled in features.items()
            if enabled
        ] or ["  [dim]No features listed[/dim]"]

        self.query_one("#account_info", Static).update(f"[bold]Logged in as:[/bold] {email}")
        self.query_one("#plan_info", Static).update(f"[bold]Plan:[/bold] {plan}")
        self.query_one("#entitlements_info", Static).update(
            "[bold]Features:[/bold]\n" + "\n".join(feature_lines)
        )

        self.query_one("#account_info").display = True
        self.query_one("#plan_info").display = True
        self.query_one("#entitlements_info").display = True
        self.query_one("#btn_logout").display = True
        self.query_one("#btn_sync").display = True
        self.query_one("#btn_back").display = True

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
            self.run_worker(self._do_sync(), exclusive=True, name="sync_config")
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
            self.notify(f"Login failed: {exc}", severity="error")
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
            self._show_logged_in_state()
            self.notify("Logged in successfully!", severity="information")
        else:
            self._show_logged_out_state()
            self.notify("Authorization failed or timed out.", severity="warning")

    async def _do_logout(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return
        try:
            await auth.logout()
            self._hide_all_sections()
            self._show_logged_out_state()
            self.notify("Logged out.", severity="information")
        except Exception as exc:
            logger.error("Logout error: %s", exc)
            self.notify(f"Logout error: {exc}", severity="error")

    async def _do_sync(self) -> None:
        sync = getattr(self.app, "config_sync_service", None)
        if sync is None:
            self.notify("Config sync is not available on this plan.", severity="warning")
            return
        try:
            result = await sync.push()
            msg = result.get("message", "Config synced successfully.")
            self.notify(msg, severity="information")
        except Exception as exc:
            logger.error("Config sync error: %s", exc)
            self.notify(f"Sync failed: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()

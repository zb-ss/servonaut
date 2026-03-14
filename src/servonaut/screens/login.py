"""Login screen for OAuth2 device flow authentication."""
from __future__ import annotations

import logging
import webbrowser
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Button

from servonaut.widgets.progress_indicator import ProgressIndicator

logger = logging.getLogger(__name__)


class LoginScreen(Screen):
    """OAuth2 device flow login screen."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self, on_complete: Optional[callable] = None) -> None:
        super().__init__()
        self._on_complete = on_complete

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static("[bold cyan]Servonaut Account[/bold cyan]", id="login_header"),
            Static("", id="login_status"),
            Vertical(
                Static("", id="login_code_label"),
                Static("", id="login_code"),
                Static("", id="login_url"),
                id="login_code_container",
            ),
            ProgressIndicator(),
            Static("", id="login_result"),
            Button("Open Browser", id="btn_open_browser", variant="primary"),
            Button("Cancel", id="btn_cancel", variant="error"),
            id="login_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Start the device flow on mount."""
        self.query_one("#btn_open_browser").display = False
        self.query_one("#login_code_container").display = False
        self.query_one("#login_status", Static).update(
            "[dim]Connecting to servonaut.dev...[/dim]"
        )
        progress = self.query_one(ProgressIndicator)
        progress.start("Initiating login...")
        self.run_worker(self._start_flow(), name="device_flow", exclusive=True)

    async def _start_flow(self) -> None:
        """Initiate device flow and begin polling."""
        progress = self.query_one(ProgressIndicator)
        status = self.query_one("#login_status", Static)

        try:
            auth = self.app.auth_service
            data = await auth.start_device_flow()

            user_code = data.get("user_code", "???")
            verification_uri = data.get("verification_uri", "")
            device_code = data.get("device_code", "")
            interval = data.get("interval", 5)

            # Display the code
            self.query_one("#login_code_container").display = True
            self.query_one("#login_code_label", Static).update(
                "[bold]Enter this code on servonaut.dev:[/bold]"
            )
            self.query_one("#login_code", Static).update(
                f"[bold yellow on dark_blue]  {user_code}  [/bold yellow on dark_blue]"
            )
            if verification_uri:
                self.query_one("#login_url", Static).update(
                    f"[dim]Visit: [link={verification_uri}]{verification_uri}[/link][/dim]"
                )

            # Show browser button
            self.query_one("#btn_open_browser").display = True
            self._verification_uri = verification_uri

            # Try to auto-open browser
            if verification_uri:
                try:
                    webbrowser.open(verification_uri)
                    status.update("[dim]Browser opened. Waiting for authorization...[/dim]")
                except Exception:
                    status.update(
                        "[dim]Open the URL above in your browser and enter the code.[/dim]"
                    )

            progress.start("Waiting for authorization...")

            # Poll for token
            success = await auth.poll_for_token(device_code, interval)

            progress.stop()

            if success:
                plan = auth.plan
                result = self.query_one("#login_result", Static)
                result.update(
                    f"[bold green]Logged in successfully![/bold green]\n"
                    f"Plan: [cyan]{plan}[/cyan]"
                )
                self.query_one("#login_code_container").display = False
                self.query_one("#btn_open_browser").display = False
                self.query_one("#btn_cancel", Button).label = "Done"

                if self._on_complete:
                    self._on_complete(True)
            else:
                result = self.query_one("#login_result", Static)
                result.update(
                    "[bold red]Authorization failed or timed out.[/bold red]\n"
                    "[dim]Please try again.[/dim]"
                )
                if self._on_complete:
                    self._on_complete(False)

        except Exception as e:
            progress.stop()
            status.update(f"[red]Error: {e}[/red]")
            logger.error("Login flow error: %s", e)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_open_browser":
            if hasattr(self, '_verification_uri') and self._verification_uri:
                try:
                    webbrowser.open(self._verification_uri)
                    self.notify("Browser opened")
                except Exception as e:
                    self.notify(f"Could not open browser: {e}", severity="error")
        elif event.button.id == "btn_cancel":
            self.action_back()

    def action_back(self) -> None:
        self.app.pop_screen()

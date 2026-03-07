"""SSH Key Management screen for Servonaut v2.0."""

from __future__ import annotations
import subprocess
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Input, Button, DataTable
from textual.worker import Worker

from servonaut.screens._binding_guard import check_action_passthrough


class KeyManagementScreen(Screen):
    """SSH key management screen."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        """Compose the key management UI."""
        yield Header()
        yield ScrollableContainer(
            Static("[bold cyan]SSH Key Management[/bold cyan]", id="keys_header"),

            # Section 1: Default Key
            Static("[bold]Default SSH Key[/bold]", classes="section_header"),
            Static("Not set", id="current_default_key"),
            Horizontal(
                Input(placeholder="Path to default SSH key...", id="input_default_key"),
                Button("Set Default", id="btn_set_default", variant="primary"),
                classes="setting_row"
            ),

            # Section 2: Instance Key Mappings
            Static("[bold]Instance Key Mappings[/bold]", classes="section_header"),
            Static("[dim]Instance-specific SSH key overrides[/dim]", classes="note"),
            DataTable(id="instance_keys_table"),

            # Section 3: SSH Agent
            Static("[bold]SSH Agent[/bold]", classes="section_header"),
            Static("Status: Checking...", id="agent_status"),
            Horizontal(
                Input(placeholder="Path to key to add to agent...", id="input_agent_key"),
                Button("Add to Agent", id="btn_add_agent", variant="primary"),
                classes="setting_row"
            ),
            Button("List Agent Keys", id="btn_list_agent"),
            Static("", id="agent_keys_output"),

            # Section 4: Available Keys
            Static("[bold]Available SSH Keys[/bold]", classes="section_header"),
            Static("[dim]Keys found in ~/.ssh/[/dim]", classes="note"),
            DataTable(id="available_keys_table"),

            id="keys_container"
        )
        yield Footer()

    def on_mount(self) -> None:
        """Load key information when screen mounts."""
        self._load_default_key()
        self._load_instance_mappings()
        self._check_agent_status()
        self._load_available_keys()

    def _load_default_key(self) -> None:
        """Load and display current default key."""
        config = self.app.config_manager.get()
        default_key = config.default_key

        if default_key:
            self.query_one("#current_default_key", Static).update(
                f"Current: [bold]{default_key}[/bold]"
            )
            # Pre-fill input with current default
            self.query_one("#input_default_key", Input).value = default_key
        else:
            self.query_one("#current_default_key", Static).update(
                "[dim]Not set[/dim]"
            )

    def _load_instance_mappings(self) -> None:
        """Load and display instance-specific key mappings."""
        config = self.app.config_manager.get()
        table = self.query_one("#instance_keys_table", DataTable)

        # Clear and setup table
        table.clear(columns=True)
        table.add_columns("Instance ID", "Key Path", "Actions")

        # Add mappings
        if config.instance_keys:
            for instance_id, key_path in config.instance_keys.items():
                table.add_row(instance_id, key_path, "[Remove]")
        else:
            # Show empty state
            table.add_row("[dim]No instance-specific keys configured[/dim]", "", "")

    def _check_agent_status(self) -> None:
        """Check SSH agent status. Auto-start if not running."""
        import logging
        logger = logging.getLogger(__name__)

        try:
            is_running = self.app.ssh_service.check_ssh_agent()

            if is_running:
                self.query_one("#agent_status", Static).update(
                    "Status: [bold green]Running[/bold green]"
                )
            else:
                # Try to auto-start the agent
                logger.info("SSH agent not detected, attempting auto-start...")
                started = self.app.ssh_service.start_ssh_agent()
                if started:
                    self.query_one("#agent_status", Static).update(
                        "Status: [bold green]Running[/bold green] [dim](auto-started)[/dim]"
                    )
                    self.app.notify("SSH agent started automatically")
                else:
                    self.query_one("#agent_status", Static).update(
                        "Status: [bold red]Not Running[/bold red] — "
                        "could not auto-start. Run: eval $(ssh-agent)"
                    )
        except Exception as e:
            logger.error("Error checking SSH agent status: %s", e)
            self.query_one("#agent_status", Static).update(
                "Status: [yellow]Unknown[/yellow] — error checking agent"
            )

    def _load_available_keys(self) -> None:
        """Load and display available SSH keys from ~/.ssh/."""
        keys = self.app.ssh_service.list_available_keys()
        table = self.query_one("#available_keys_table", DataTable)

        # Clear and setup table
        table.clear(columns=True)
        table.add_columns("Key Path")

        # Add keys
        if keys:
            for key_path in keys:
                table.add_row(key_path)
        else:
            table.add_row("[dim]No SSH keys found in ~/.ssh/[/dim]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events.

        Args:
            event: Button pressed event.
        """
        button_id = event.button.id

        if button_id == "btn_set_default":
            self._set_default_key()
        elif button_id == "btn_add_agent":
            self._add_key_to_agent()
        elif button_id == "btn_list_agent":
            self._list_agent_keys()

    def _set_default_key(self) -> None:
        """Set the default SSH key."""
        input_field = self.query_one("#input_default_key", Input)
        key_path = input_field.value.strip()

        if not key_path:
            self.notify("Please enter a key path", severity="warning")
            return

        # Expand ~ in path
        from pathlib import Path
        expanded_path = Path(key_path).expanduser()

        # Check if key exists
        if not expanded_path.exists():
            self.notify(f"Key file not found: {key_path}", severity="error")
            return

        # Check permissions
        if not self.app.ssh_service.check_key_permissions(str(expanded_path)):
            self.notify(
                "Warning: Key has incorrect permissions (should be 600 or 400)",
                severity="warning"
            )

        # Set as default
        try:
            self.app.ssh_service.set_default_key(key_path)
            self._load_default_key()
            self.notify(f"Default key set to: {key_path}", severity="information")
        except Exception as e:
            self.notify(f"Error setting default key: {e}", severity="error")

    def _add_key_to_agent(self) -> None:
        """Add a key to SSH agent (in worker thread)."""
        import logging
        from pathlib import Path

        logger = logging.getLogger(__name__)
        input_field = self.query_one("#input_agent_key", Input)
        key_path = input_field.value.strip()

        if not key_path:
            self.app.notify("Please enter a key path", severity="warning")
            input_field.focus()
            return

        # Validate key path exists
        expanded_path = Path(key_path).expanduser()
        if not expanded_path.exists():
            self.app.notify(f"Key file not found: {key_path}", severity="error")
            logger.error("Key file not found: %s", key_path)
            return

        # Ensure agent is running (auto-start if needed)
        try:
            if not self.app.ssh_service.check_ssh_agent():
                if not self.app.ssh_service.start_ssh_agent():
                    self.app.notify(
                        "SSH agent is not running and could not be started.",
                        severity="error"
                    )
                    return
                self.app.notify("SSH agent started automatically")
                self._check_agent_status()
        except Exception as e:
            logger.error("Error checking SSH agent: %s", e)
            self.app.notify("Error checking SSH agent status", severity="error")
            return

        # Run in worker to avoid blocking UI
        self.app.notify("Adding key to SSH agent...", severity="information")
        self.run_worker(self._add_key_worker(key_path), name="add_key", exclusive=True)

    async def _add_key_worker(self, key_path: str) -> bool:
        """Worker to add key to SSH agent.

        Args:
            key_path: Path to SSH key.

        Returns:
            True if successful.
        """
        return self.app.ssh_service.add_key_to_agent(key_path)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle worker completion.

        Args:
            event: Worker state changed event.
        """
        if event.worker.name == "add_key" and event.worker.is_finished:
            if event.worker.error:
                self.notify(
                    f"Error adding key: {event.worker.error}",
                    severity="error"
                )
            elif event.worker.result:
                self.notify("Key added to SSH agent successfully", severity="information")
                # Clear input
                self.query_one("#input_agent_key", Input).value = ""
            else:
                self.notify("Failed to add key to SSH agent", severity="error")

        elif event.worker.name == "list_agent_keys" and event.worker.is_finished:
            if event.worker.error:
                self.notify(
                    f"Error listing agent keys: {event.worker.error}",
                    severity="error"
                )
            else:
                output = event.worker.result or "No keys in agent"
                self.query_one("#agent_keys_output", Static).update(
                    f"[dim]{output}[/dim]"
                )

    def _list_agent_keys(self) -> None:
        """List keys currently loaded in SSH agent."""
        import logging
        logger = logging.getLogger(__name__)

        # Ensure agent is running (auto-start if needed)
        try:
            if not self.app.ssh_service.check_ssh_agent():
                if not self.app.ssh_service.start_ssh_agent():
                    self.app.notify(
                        "SSH agent is not running and could not be started.",
                        severity="error"
                    )
                    return
                self.app.notify("SSH agent started automatically")
                self._check_agent_status()
        except Exception as e:
            logger.error("Error checking SSH agent: %s", e)
            self.app.notify("Error checking SSH agent status", severity="error")
            return

        # Run in worker
        self.app.notify("Listing agent keys...", severity="information")
        self.run_worker(
            self._list_agent_keys_worker(),
            name="list_agent_keys",
            exclusive=True
        )

    async def _list_agent_keys_worker(self) -> str:
        """Worker to list SSH agent keys.

        Returns:
            Output from ssh-add -l.
        """
        try:
            result = subprocess.run(
                ['ssh-add', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                return result.stdout.strip() or "No keys loaded"
            elif result.returncode == 1:
                return "No keys loaded in agent"
            else:
                return f"Error: {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except Exception as e:
            return f"Error: {e}"

    def action_refresh(self) -> None:
        """Refresh all key information."""
        self._load_default_key()
        self._load_instance_mappings()
        self._check_agent_status()
        self._load_available_keys()
        self.notify("Key information refreshed", severity="information")

    def action_back(self) -> None:
        """Navigate back to main menu."""
        self.app.pop_screen()

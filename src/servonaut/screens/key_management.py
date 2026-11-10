"""SSH Key Management screen for Servonaut v2.0."""

from __future__ import annotations
import subprocess
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal, ScrollableContainer

from servonaut.widgets.action_button import ActionButton
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen
from textual.widgets import Footer, Static, Input, Button, DataTable, Label
from textual.worker import Worker

from servonaut.screens._binding_guard import check_action_passthrough


class KeyManagementScreen(WorkspaceScreen):
    """SSH key management screen."""

    CHAT_REFLOW = True
    # Body padding and scrollbar (4) plus the widest fixed row: two
    # mapping inputs with their margins beside the Add mapping button.
    CHAT_MIN_CONTENT_WIDTH = 48
    # Below this width, connection settings and local-agent tools stack.
    CONTENT_NARROW_WIDTH = 104

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("delete", "remove_mapping", "Remove override", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        """Separate connection policy from keys available on this computer."""
        yield SafeHeader()
        yield WorkspaceControls("SSH Keys")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            with ScrollableContainer(id="keys_container", classes="workspace-content"):
                yield Static("SSH keys", id="keys_header")
                yield Static(
                    "Set your connection default, then add exceptions for individual servers.",
                    id="keys_intro",
                )
                with Horizontal(id="keys_sections"):
                    with Vertical(id="key_connection_column"):
                        yield Static("Connection keys", classes="key-column-title")
                        with Vertical(classes="key-section"):
                            yield Static("Default SSH key", classes="key-section-title")
                            yield Static("Used when a server has no key override.", classes="key-section-note")
                            yield Static("Not set", id="current_default_key")
                            yield Label("Key path")
                            with Horizontal(classes="setting_row"):
                                yield Input(placeholder="~/.ssh/id_ed25519", id="input_default_key")
                                yield Button("Set default", id="btn_set_default", variant="primary")
                        with Vertical(id="instance_key_section", classes="key-section"):
                            yield Static("Per-server overrides", classes="key-section-title")
                            yield Static("Use a different key for a specific instance ID.", classes="key-section-note")
                            with Horizontal(classes="setting_row", id="key_mapping_fields"):
                                with Vertical(classes="key-field"):
                                    yield Label("Instance ID")
                                    yield Input(placeholder="Instance ID", id="input_mapping_instance")
                                with Vertical(classes="key-field"):
                                    yield Label("Key path")
                                    yield Input(placeholder="~/.ssh/server_key", id="input_mapping_key")
                                yield Button("Add mapping", id="btn_add_mapping", variant="primary")
                            yield DataTable(id="instance_keys_table")
                            yield ActionButton(
                                "Remove override", "Del", role="error",
                                id="btn_remove_mapping", classes="key-remove",
                            )
                            yield Static("Select a mapping row, then remove its override.", classes="key-section-note")
                    with Vertical(id="key_local_column"):
                        yield Static("On this computer", classes="key-column-title")
                        with Vertical(id="agent_key_section", classes="key-section"):
                            yield Static("SSH agent", classes="key-section-title")
                            yield Static("Status: Checking...", id="agent_status")
                            yield Label("Key to load into the agent")
                            with Horizontal(classes="setting_row"):
                                yield Input(placeholder="Path to SSH key", id="input_agent_key")
                                yield Button("Add to agent", id="btn_add_agent", variant="primary")
                            yield Button("List agent keys", id="btn_list_agent")
                            yield Static("", id="agent_keys_output")
                        with Vertical(id="available_key_section", classes="key-section"):
                            yield Static("Available key files", classes="key-section-title")
                            yield Static("Discovered in ~/.ssh/", classes="key-section-note")
                            yield DataTable(id="available_keys_table")
        yield Footer()

    def on_mount(self) -> None:
        """Load key information when screen mounts."""
        self._load_default_key()
        self._load_instance_mappings()
        self._check_agent_status()
        self._load_available_keys()

    def refresh_after_demo_toggle(self) -> None:
        """Re-render every key path, instance id and agent listing."""
        self._load_default_key()
        self._load_instance_mappings()
        self._load_available_keys()
        # ``ssh-add -l`` output was rendered for the old mode; list again.
        self.query_one("#agent_keys_output", Static).update("")

    def _load_default_key(self) -> None:
        """Load and display current default key."""
        config = self.app.config_manager.get()
        default_key = config.default_key

        def _k(x: str) -> str:
            # Key paths carry real names; show the same fake the fleet uses.
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.redact_key_name(x)
            return x

        if default_key:
            self.query_one("#current_default_key", Static).update(
                f"Current: [bold]{_k(default_key)}[/bold]"
            )
            # Pre-fill input with current default — not in demo mode, where
            # the editable field would put the real path on screen.
            field = self.query_one("#input_default_key", Input)
            if not (self.app.demo_mode and self.app.redaction_service):
                field.value = default_key
            elif field.value == default_key:
                field.value = ""
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
        table.add_columns("Instance ID", "Key path")

        def _k(x: str) -> str:
            # Key paths carry real names; show the same fake the fleet uses.
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.redact_key_name(x)
            return x

        def _i(x: str) -> str:
            # Same fake id the fleet table shows for this instance.
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.redact_instance_id(x)
            return x

        # Add mappings. Rows may show demo-mode fakes; removal needs the
        # real id, so remember it per row.
        self._mapping_ids = {}
        if config.instance_keys:
            for instance_id, key_path in config.instance_keys.items():
                row_key = table.add_row(_i(instance_id), _k(key_path))
                self._mapping_ids[row_key] = instance_id
        else:
            # Show empty state
            table.add_row("[dim]No instance-specific keys configured[/dim]", "")

    def _check_agent_status(self) -> None:
        """Check SSH agent status. Auto-start if not running."""
        import logging
        logger = logging.getLogger(__name__)

        try:
            is_running = self.app.ssh_service.check_ssh_agent()

            if is_running:
                self.query_one("#agent_status", Static).update(
                    "Status: [bold $text-success]Running[/bold $text-success]"
                )
            else:
                # Try to auto-start the agent
                logger.info("SSH agent not detected, attempting auto-start...")
                started = self.app.ssh_service.start_ssh_agent()
                if started:
                    self.query_one("#agent_status", Static).update(
                        "Status: [bold $text-success]Running[/bold $text-success] [dim](auto-started)[/dim]"
                    )
                    self.app.notify("SSH agent started automatically")
                else:
                    self.query_one("#agent_status", Static).update(
                        "Status: [bold $text-error]Not running[/bold $text-error] — "
                        "could not auto-start. Run: eval $(ssh-agent)"
                    )
        except Exception as e:
            logger.error("Error checking SSH agent status: %s", e)
            self.query_one("#agent_status", Static).update(
                "Status: [$text-warning]Unknown[/$text-warning] — error checking agent"
            )

    def _load_available_keys(self) -> None:
        """Load and display available SSH keys from ~/.ssh/."""
        keys = self.app.ssh_service.list_available_keys()
        table = self.query_one("#available_keys_table", DataTable)

        # Clear and setup table
        table.clear(columns=True)
        table.add_columns("Key path")

        def _k(x: str) -> str:
            # Key paths carry real names; show the same fake the fleet uses.
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.redact_key_name(x)
            return x

        # Add keys
        if keys:
            for key_path in keys:
                table.add_row(_k(key_path))
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
        elif button_id == "btn_add_mapping":
            self._add_instance_mapping()
        elif button_id == "btn_remove_mapping":
            self.action_remove_mapping()
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
            self.notify(f"Error setting default key: {e}", severity="error", markup=False)

    def _add_instance_mapping(self) -> None:
        """Add an instance-specific SSH key mapping."""
        from pathlib import Path

        instance_id = self.query_one("#input_mapping_instance", Input).value.strip()
        key_path = self.query_one("#input_mapping_key", Input).value.strip()

        if not instance_id:
            self.notify("Enter an instance ID", severity="warning")
            self.query_one("#input_mapping_instance", Input).focus()
            return
        if not key_path:
            self.notify("Enter a key path", severity="warning")
            self.query_one("#input_mapping_key", Input).focus()
            return

        expanded = Path(key_path).expanduser()
        if not expanded.exists():
            self.notify(f"Key file not found: {key_path}", severity="error")
            return

        try:
            self.app.ssh_service.set_key_path(instance_id, key_path)
            self._load_instance_mappings()
            self.query_one("#input_mapping_instance", Input).value = ""
            self.query_one("#input_mapping_key", Input).value = ""
            self.notify(f"Key mapping added: {instance_id} → {key_path}", severity="information")
        except Exception as e:
            self.notify(f"Error adding key mapping: {e}", severity="error", markup=False)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Selecting a mapping row removes its override."""
        if event.data_table.id == "instance_keys_table":
            self._remove_mapping(event.row_key)

    def action_remove_mapping(self) -> None:
        """Remove the override of the highlighted mapping row."""
        table = self.query_one("#instance_keys_table", DataTable)
        if table.row_count == 0:
            return
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        if row_key not in getattr(self, "_mapping_ids", {}):
            self.notify("No key override to remove", severity="warning")
            return
        self._remove_mapping(row_key)

    def _remove_mapping(self, row_key) -> None:
        table = self.query_one("#instance_keys_table", DataTable)
        row_data = table.get_row(row_key)
        if not row_data or len(row_data) < 2:
            return

        shown_id = str(row_data[0])
        instance_id = getattr(self, "_mapping_ids", {}).get(row_key)
        if instance_id is None:
            return  # Empty state row

        config = self.app.config_manager.get()
        if instance_id in config.instance_keys:
            del config.instance_keys[instance_id]
            self.app.config_manager.save(config)
            self._load_instance_mappings()
            self.notify(f"Removed key mapping for {shown_id}", severity="information")

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
                    severity="error",
                    markup=False,
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
                    severity="error",
                    markup=False,
                )
            else:
                output = event.worker.result or "No keys in agent"
                if self.app.demo_mode and self.app.redaction_service:
                    output = self.app.redaction_service.scrub_stream(output)
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
        self.dismiss(None)

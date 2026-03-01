"""SCP transfer screen for Servonaut v2.0."""

from __future__ import annotations
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Input, Button, RadioSet, RadioButton
from textual.worker import Worker


class SCPTransferScreen(Screen):
    """Screen for SCP file transfers (upload/download).

    Allows user to select direction and specify paths.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        """Initialize SCP transfer screen.

        Args:
            instance: Instance dictionary with connection details.
        """
        super().__init__()
        self._instance = instance
        self._transfer_direction = "upload"  # "upload" or "download"

    def compose(self) -> ComposeResult:
        """Compose the SCP transfer UI."""
        yield Header()
        yield Container(
            Static(
                f"[bold cyan]SCP File Transfer[/bold cyan]\n"
                f"Instance: {self._instance.get('name') or self._instance.get('id')}",
                id="transfer_banner"
            ),
            Vertical(
                Static("[bold]Transfer Direction:[/bold]", id="direction_label"),
                RadioSet(
                    RadioButton("Upload (Local → Remote)", value=True, id="radio_upload"),
                    RadioButton("Download (Remote → Local)", id="radio_download"),
                    id="direction_selector"
                ),
                Static("[bold]Local Path:[/bold]", id="local_path_label"),
                Input(placeholder="/path/to/local/file", id="local_path_input"),
                Static("[bold]Remote Path:[/bold]", id="remote_path_label"),
                Input(placeholder="/path/to/remote/file", id="remote_path_input"),
                Horizontal(
                    Button("Start Transfer", id="transfer_button"),
                    Button("Cancel", variant="default", id="cancel_button"),
                    id="button_container"
                ),
                Static("", id="status_output"),
                id="transfer_form"
            ),
            id="transfer_container"
        )
        yield Footer()

    def on_mount(self) -> None:
        """Focus local path input when mounted."""
        local_input = self.query_one("#local_path_input", Input)
        local_input.focus()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle direction selection change.

        Args:
            event: RadioSet changed event.
        """
        if event.radio_set.id == "direction_selector":
            selected = event.pressed
            if selected.id == "radio_upload":
                self._transfer_direction = "upload"
                self.app.notify("Direction: Upload (Local → Remote)", severity="information")
            elif selected.id == "radio_download":
                self._transfer_direction = "download"
                self.app.notify("Direction: Download (Remote → Local)", severity="information")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events.

        Args:
            event: Button pressed event.
        """
        if event.button.id == "transfer_button":
            self._start_transfer()
        elif event.button.id == "cancel_button":
            self.action_back()

    def _start_transfer(self) -> None:
        """Start SCP transfer based on current form inputs."""
        import logging
        from pathlib import Path

        logger = logging.getLogger(__name__)
        local_path_input = self.query_one("#local_path_input", Input)
        remote_path_input = self.query_one("#remote_path_input", Input)
        status_output = self.query_one("#status_output", Static)

        local_path = local_path_input.value.strip()
        remote_path = remote_path_input.value.strip()

        # Validate inputs
        if not local_path:
            self.app.notify("Please enter a local path", severity="warning")
            local_path_input.focus()
            return

        if not remote_path:
            self.app.notify("Please enter a remote path", severity="warning")
            remote_path_input.focus()
            return

        # For uploads, validate local path exists
        if self._transfer_direction == "upload":
            expanded_local_path = Path(local_path).expanduser()
            if not expanded_local_path.exists():
                self.app.notify(f"Local path not found: {local_path}", severity="error")
                logger.error("Upload failed: local path does not exist: %s", local_path)
                status_output.update(f"[red]Error:[/red] Local path not found: {local_path}")
                return

        # Update status
        status_output.update(f"[yellow]Preparing {self._transfer_direction}...[/yellow]")

        # Resolve connection profile
        profile = self.app.connection_service.resolve_profile(self._instance)

        # Get SSH key
        key_path = self.app.ssh_service.get_key_path(self._instance['id'])
        if not key_path and self._instance.get('key_name'):
            key_path = self.app.ssh_service.discover_key(self._instance['key_name'])

        # Get target host and proxy args
        host = self.app.connection_service.get_target_host(self._instance, profile)
        proxy_args = []
        if profile:
            proxy_args = self.app.connection_service.get_proxy_args(profile)

        # Get username from profile or use default
        username = self.app.config_manager.get().default_username

        # Build SCP command
        if self._transfer_direction == "upload":
            command = self.app.scp_service.build_upload_command(
                local_path=local_path,
                remote_path=remote_path,
                host=host,
                username=username,
                key_path=key_path,
                proxy_args=proxy_args
            )
        else:  # download
            command = self.app.scp_service.build_download_command(
                remote_path=remote_path,
                local_path=local_path,
                host=host,
                username=username,
                key_path=key_path,
                proxy_args=proxy_args
            )

        # Execute transfer in worker
        status_output.update(f"[yellow]Transferring...[/yellow]")
        self.run_worker(
            self.app.scp_service.execute_transfer(command),
            name="scp_transfer",
            exclusive=True
        )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle worker state changes.

        Args:
            event: Worker state changed event.
        """
        if event.worker.name == "scp_transfer":
            if event.worker.is_finished:
                status_output = self.query_one("#status_output", Static)

                if event.worker.error:
                    error_msg = str(event.worker.error)
                    status_output.update(f"[red]Transfer failed:[/red] {error_msg}")
                    self.app.notify(f"Transfer failed: {error_msg}", severity="error")
                else:
                    returncode, stdout, stderr = event.worker.result

                    if returncode == 0:
                        status_output.update("[green]Transfer completed successfully![/green]")
                        self.app.notify("Transfer completed", severity="information")
                    else:
                        error_msg = stderr or "Unknown error"
                        status_output.update(f"[red]Transfer failed:[/red] {error_msg}")
                        self.app.notify(f"Transfer failed: {error_msg}", severity="error")

    def action_back(self) -> None:
        """Navigate back to previous screen."""
        self.app.pop_screen()

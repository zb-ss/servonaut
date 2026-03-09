"""Command overlay modal for Servonaut v2.0."""

from __future__ import annotations
import shlex
import subprocess
import logging
import threading
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from servonaut.screens._binding_guard import check_action_passthrough

from servonaut.widgets.command_output import CommandOutput

logger = logging.getLogger(__name__)


class CommandOverlay(ModalScreen):
    """Modal screen for executing SSH commands on a remote server.

    Displays a command output log at top and an input field at bottom.
    Commands are executed via SSH and output is displayed in real-time.
    Maintains command history for navigation with up/down arrows.
    """

    BINDINGS = [
        Binding("escape", "close_overlay", "Close", show=True),
        Binding("ctrl+c", "stop_or_close", "Stop", show=False),
        Binding("ctrl+r", "show_command_picker", "Picker", show=True),
        Binding("ctrl+s", "save_command", "Save Cmd", show=True),
        Binding("up", "history_prev", "Previous", show=False),
        Binding("down", "history_next", "Next", show=False),
        Binding("y", "copy_output", "Copy", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        """Initialize command overlay.

        Args:
            instance: Instance dictionary with connection details.
        """
        super().__init__()
        self._instance = instance
        self._history: List[str] = []
        self._history_index = -1
        self._running_process: Optional[subprocess.Popen] = None
        self._output_lines: List[str] = []

        # Resolve connection details
        self._profile = None
        self._host = None
        self._proxy_args: List[str] = []
        self._username = None
        self._key_path = None

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        """Compose the command overlay UI."""
        yield Container(
            Static(self._build_header_text(), id="command_header"),
            CommandOutput(id="command_output"),
            Static(
                "[dim]Ctrl+R[/dim] Picker  "
                "[dim]Ctrl+S[/dim] Save  "
                "[dim]↑↓[/dim] History  "
                "[dim]Ctrl+C[/dim] Stop  "
                "[dim]Y[/dim] Copy  "
                "[dim]Esc[/dim] Close",
                id="command_hints",
            ),
            Input(
                placeholder="Enter command to execute...",
                id="command_input"
            ),
            id="command_overlay_container"
        )

    def on_mount(self) -> None:
        """Initialize connection details and focus input on mount."""
        # Resolve connection details — check for missing profiles
        self._profile = self.app.connection_service.resolve_profile(self._instance)
        self._host = self.app.connection_service.get_target_host(
            self._instance,
            self._profile
        )
        if self._profile:
            self._proxy_args = self.app.connection_service.get_proxy_args(
                self._profile
            )

        # Warn if a connection rule matched but the profile is missing
        self._missing_profile = self._detect_missing_profile()

        config = self.app.config_manager.get()
        if self._instance.get('is_custom'):
            self._username = self._instance.get('username') or 'root'
            self._key_path = self._instance.get('ssh_key') or self._instance.get('key_name') or None
        else:
            self._username = (
                (self._profile.username if self._profile else None)
                or config.default_username
            )
            self._key_path = self.app.ssh_service.get_key_path(self._instance['id'])
            if not self._key_path and self._instance.get('key_name'):
                self._key_path = self.app.ssh_service.discover_key(self._instance['key_name'])

        # Load persisted history for this instance
        if self.app.command_history:
            self._history = list(
                self.app.command_history.get_instance_history(self._instance['id'])
            )
            self._history_index = len(self._history)

        # Show welcome message
        output = self.query_one("#command_output", CommandOutput)
        welcome = f"Connected to {self._instance.get('name') or self._instance.get('id')}"
        output.append_output(f"[dim]{welcome}[/dim]")
        self._output_lines.append(welcome)
        if self._missing_profile:
            warning = (
                f"Warning: Connection profile '{self._missing_profile}' not found. "
                f"Connecting directly (no bastion). Add the profile in Settings if "
                f"this server requires a jump host."
            )
            output.append_error(
                f"[bold yellow]Warning:[/bold yellow] Connection profile "
                f"'{self._missing_profile}' not found. Connecting directly "
                f"(no bastion). Add the profile in Settings if this server "
                f"requires a jump host."
            )
            self._output_lines.append(warning)
        hint = "Type commands below. Ctrl+C stops a running command, Escape closes."
        output.append_output(f"[dim]{hint}[/dim]\n")
        self._output_lines.append(hint)

        # Focus input
        self.query_one("#command_input", Input).focus()

    def _detect_missing_profile(self) -> Optional[str]:
        """Check if a connection rule matched but its profile is missing.

        Returns:
            The missing profile name, or None if no issue.
        """
        config = self.app.config_manager.get()
        from servonaut.utils.match_utils import matches_conditions
        for rule in config.connection_rules:
            if matches_conditions(self._instance, rule.match_conditions):
                profile_exists = any(
                    p.name == rule.profile_name
                    for p in config.connection_profiles
                )
                if not profile_exists:
                    return rule.profile_name
                return None
        return None

    def _build_header_text(self) -> str:
        """Build header text with server name and prompt.

        Returns:
            Rich-formatted header string.
        """
        name = self._instance.get('name') or self._instance.get('id', 'unknown')
        return f"[bold cyan]Command Execution:[/bold cyan] {name}"

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle command input submission.

        Args:
            event: Input submitted event.
        """
        if event.input.id != "command_input":
            return

        command = event.value.strip()
        if not command:
            return

        # Clear input
        event.input.value = ""

        # Add to history
        if not self._history or self._history[-1] != command:
            self._history.append(command)
        self._history_index = len(self._history)

        # Persist to disk
        if self.app.command_history:
            self.app.command_history.add_to_history(self._instance['id'], command)

        # Execute command
        self._execute_command(command)

    # Commands that require a real terminal (TUI/ncurses/interactive)
    INTERACTIVE_COMMANDS = {
        'top', 'htop', 'vim', 'vi', 'nvim', 'nano', 'less', 'more',
        'man', 'watch', 'tmux', 'screen', 'mc', 'nmon', 'iftop',
        'nethogs', 'cfdisk', 'ncdu', 'ranger', 'mutt', 'lynx',
    }
    INTERACTIVE_SUBCOMMANDS = {
        'pm2 monit', 'pm2 dash',
        'docker exec -it', 'docker run -it',
    }

    def _is_interactive_command(self, command: str) -> bool:
        """Check if command requires an interactive terminal."""
        parts = command.split()
        if not parts:
            return False
        if parts[0] in self.INTERACTIVE_COMMANDS:
            return True
        # Check two-word and three-word patterns
        for pattern in self.INTERACTIVE_SUBCOMMANDS:
            if command.startswith(pattern):
                return True
        return False

    def _execute_command(self, command: str) -> None:
        """Execute a command on the remote server via SSH.

        Args:
            command: Command string to execute.
        """
        output_widget = self.query_one("#command_output", CommandOutput)

        # Show command in output
        prompt = f"{self._username}@{self._instance.get('name', 'server')}:~"
        command_line = f"{prompt}$ {command}"
        output_widget.append_command(command_line)
        self._output_lines.append(command_line)

        # Block interactive/TUI commands that need a real terminal
        if self._is_interactive_command(command):
            output_widget.append_error(
                f"[bold yellow]{command.split()[0]}[/bold yellow] requires an "
                f"interactive terminal and cannot run here."
            )
            output_widget.append_output(
                "[dim]Press Escape to close, then press s to open an SSH terminal.[/dim]\n"
            )
            return

        output_widget.append_output("[dim]Ctrl+C to stop[/dim]")

        # Use bash -ic (interactive) so .bashrc is fully sourced, including
        # nvm/rbenv/pyenv init blocks guarded by the non-interactive check.
        login_command = f'bash -ic {shlex.quote(command)}'

        # Build SSH command
        ssh_cmd = self.app.ssh_service.build_ssh_command(
            host=self._host,
            username=self._username,
            key_path=self._key_path,
            remote_command=login_command,
            proxy_args=self._proxy_args
        )

        logger.debug("Command overlay executing: %s", ' '.join(ssh_cmd))

        # Run in threaded worker so subprocess I/O doesn't block the event loop
        self.run_worker(
            lambda: self._run_ssh_command(ssh_cmd, output_widget),
            name=f"exec_{len(self._history)}",
            thread=True,
            exclusive=False,
            exit_on_error=False,
        )

    def _run_ssh_command(
        self,
        ssh_cmd: List[str],
        output_widget: CommandOutput
    ) -> None:
        """Run SSH command in a thread with streaming output.

        Uses subprocess.Popen for reliable piped I/O and call_from_thread()
        to safely update the UI from the worker thread.

        Args:
            ssh_cmd: SSH command list from build_ssh_command.
            output_widget: CommandOutput widget to write results to.
        """
        try:
            self.app.call_from_thread(
                output_widget.append_output, "[dim]Connecting...[/dim]"
            )
            process = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )
            self._running_process = process

            def _read_stderr() -> None:
                for raw_line in iter(process.stderr.readline, b''):
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\n")
                    if not line:
                        continue
                    # Filter bash -i job control noise
                    if "no job control" in line or "terminal process group" in line:
                        continue
                    self._output_lines.append(line)
                    self.app.call_from_thread(output_widget.append_error, line)

            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stderr_thread.start()

            # Read stdout line-by-line in this thread
            for raw_line in iter(process.stdout.readline, b''):
                line = raw_line.decode("utf-8", errors="replace").rstrip("\n")
                self._output_lines.append(line)
                self.app.call_from_thread(output_widget.append_output, line)

            stderr_thread.join(timeout=5)
            return_code = process.wait()

            if return_code != 0 and return_code not in (-15, -9):
                exit_msg = f"Command exited with code {return_code}"
                self._output_lines.append(exit_msg)
                self.app.call_from_thread(
                    output_widget.append_error,
                    f"[dim]{exit_msg}[/dim]",
                )

        except Exception as e:
            error_str = str(e)
            if "Connection refused" in error_str:
                msg = "Connection refused. Check if instance is accessible."
            elif "timed out" in error_str.lower():
                msg = "Connection timed out. Check network and security groups."
            elif "permission denied" in error_str.lower():
                msg = "Permission denied. Check SSH key and username."
            else:
                msg = f"Error: {error_str}"
            self._output_lines.append(msg)
            self.app.call_from_thread(output_widget.append_error, msg)
            logger.error("SSH command failed: %s", e, exc_info=True)

        finally:
            self._running_process = None
            try:
                self.app.call_from_thread(output_widget.append_output, "")
            except Exception:
                logger.warning("Could not write final separator (overlay may be closed)")

    def _stop_running_process(self) -> None:
        """Terminate the currently running subprocess, if any."""
        if self._running_process and self._running_process.returncode is None:
            self._running_process.terminate()
            output_widget = self.query_one("#command_output", CommandOutput)
            output_widget.append_output("[dim]Stopped.[/dim]")

    def action_stop_or_close(self) -> None:
        """Stop running command if active, otherwise close the overlay."""
        if self._running_process and self._running_process.returncode is None:
            self._stop_running_process()
        else:
            self.action_close_overlay()

    def action_copy_output(self) -> None:
        """Copy command output to the clipboard."""
        if self._output_lines:
            self.app.copy_to_clipboard("\n".join(self._output_lines))
            self.notify("Copied to clipboard")
        else:
            self.notify("Nothing to copy", severity="warning")

    def action_close_overlay(self) -> None:
        """Close the command overlay modal, terminating any running process."""
        if self._running_process and self._running_process.returncode is None:
            self._running_process.terminate()
        self.app.pop_screen()

    def action_history_prev(self) -> None:
        """Navigate to previous command in history."""
        if not self._history:
            return

        if self._history_index > 0:
            self._history_index -= 1
            command_input = self.query_one("#command_input", Input)
            command_input.value = self._history[self._history_index]
            command_input.cursor_position = len(command_input.value)

    def action_history_next(self) -> None:
        """Navigate to next command in history."""
        if not self._history:
            return

        if self._history_index < len(self._history) - 1:
            self._history_index += 1
            command_input = self.query_one("#command_input", Input)
            command_input.value = self._history[self._history_index]
            command_input.cursor_position = len(command_input.value)
        else:
            # Clear input if at end of history
            self._history_index = len(self._history)
            command_input = self.query_one("#command_input", Input)
            command_input.value = ""

    def action_show_command_picker(self) -> None:
        """Show the command picker modal (Ctrl+R)."""
        if not self.app.command_history:
            return

        from servonaut.screens.command_picker import CommandPickerModal

        saved = self.app.command_history.get_saved_commands()
        # Show global history in reverse (newest first)
        recent = list(reversed(self.app.command_history.get_global_history()))

        def _on_pick(command: str | None) -> None:
            if command:
                cmd_input = self.query_one("#command_input", Input)
                cmd_input.value = command
                cmd_input.cursor_position = len(command)
                cmd_input.focus()

        self.app.push_screen(
            CommandPickerModal(saved_commands=saved, recent_commands=recent),
            callback=_on_pick,
        )

    def action_save_command(self) -> None:
        """Save the current input as a named command (Ctrl+S)."""
        if not self.app.command_history:
            return

        command_input = self.query_one("#command_input", Input)
        command = command_input.value.strip()

        if not command:
            self.notify("Enter a command first", severity="warning")
            return

        from servonaut.screens.command_picker import SaveCommandModal

        def _on_name(name: str | None) -> None:
            if name:
                self.app.command_history.save_command(name, command)
                self.notify(f"Saved: {name}", severity="information")
                self.query_one("#command_input", Input).focus()

        self.app.push_screen(SaveCommandModal(command), callback=_on_name)

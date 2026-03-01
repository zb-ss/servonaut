"""Real-time remote log viewer screen for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, RichLog

logger = logging.getLogger(__name__)


class LogViewerScreen(Screen):
    """Real-time remote log viewer via SSH tail -f."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("p", "toggle_pause", "Pause/Resume", show=True),
        Binding("c", "clear_output", "Clear", show=True),
        Binding("l", "pick_log", "Switch Log", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        """Initialize log viewer screen.

        Args:
            instance: Instance dictionary with connection details.
        """
        super().__init__()
        self._instance = instance
        self._process: Optional[asyncio.subprocess.Process] = None
        self._is_paused: bool = False
        self._current_log: Optional[str] = None
        self._available_logs: List[str] = []
        self._stream_task: Optional[asyncio.Task] = None

    def compose(self) -> ComposeResult:
        """Compose the log viewer UI."""
        name = self._instance.get("name") or self._instance.get("id", "unknown")
        yield Header()
        yield Container(
            Static(
                f"[bold cyan]Log Viewer:[/bold cyan] {name}  [dim]Probing available logs...[/dim]",
                id="log_header",
            ),
            RichLog(id="log_output", highlight=True, markup=True),
            Static(
                "[dim]P: Pause | C: Clear | L: Switch Log | Esc: Back[/dim]",
                id="log_hints",
            ),
            id="log_viewer_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Probe for available logs and start streaming."""
        self.run_worker(self._probe_and_start(), name="probe_logs", exclusive=True)

    async def _probe_and_start(self) -> None:
        """Probe available log paths, then start streaming the first one."""
        output = self.query_one("#log_output", RichLog)
        output.write("[dim]Probing for readable log files...[/dim]")

        available = await self.app.log_viewer_service.probe_log_paths(
            self._instance,
            self.app.ssh_service,
            self.app.connection_service,
        )
        self._available_logs = available

        if available:
            self._current_log = available[0]
            self._update_header()
            await self._start_tail(self._current_log)
        else:
            output.write(
                "[yellow]No readable log files found on this server.[/yellow]\n"
                "[dim]Check permissions or add custom paths in settings.[/dim]"
            )
            self.app.notify("No readable log files found", severity="warning")

    def _update_header(self) -> None:
        """Update header with current log path."""
        name = self._instance.get("name") or self._instance.get("id", "unknown")
        log_label = self._current_log or "none"
        paused = "  [yellow][PAUSED][/yellow]" if self._is_paused else ""
        self.query_one("#log_header", Static).update(
            f"[bold cyan]Log Viewer:[/bold cyan] {name}  "
            f"[dim]Viewing:[/dim] {log_label}{paused}"
        )

    async def _start_tail(self, log_path: str) -> None:
        """Stop any running tail, then start a new one for log_path."""
        await self._stop_tail()

        config = self.app.config_manager.get()
        profile = self.app.connection_service.resolve_profile(self._instance)
        host = self.app.connection_service.get_target_host(self._instance, profile)

        proxy_args: List[str] = []
        if profile:
            proxy_args = self.app.connection_service.get_proxy_args(profile)

        username = config.default_username
        key_path: Optional[str] = self.app.ssh_service.get_key_path(
            self._instance["id"]
        )
        if not key_path and self._instance.get("key_name"):
            key_path = self.app.ssh_service.discover_key(self._instance["key_name"])

        tail_cmd = self.app.log_viewer_service.get_tail_command(
            log_path, config.log_viewer_tail_lines
        )
        ssh_cmd = self.app.ssh_service.build_ssh_command(
            host=host,
            username=username,
            key_path=key_path,
            proxy_args=proxy_args,
            remote_command=tail_cmd,
        )

        logger.debug("Starting log tail: %s", " ".join(ssh_cmd))

        try:
            self._process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._stream_task = asyncio.create_task(self._stream_output())
        except Exception as e:
            logger.error("Failed to start tail process: %s", e)
            output = self.query_one("#log_output", RichLog)
            output.write(f"[red]Error starting tail: {e}[/red]")

    async def _stream_output(self) -> None:
        """Stream stdout from the tail process into the RichLog widget."""
        if not self._process or not self._process.stdout:
            return

        output = self.query_one("#log_output", RichLog)
        config = self.app.config_manager.get()
        max_lines = config.log_viewer_max_lines
        line_count = 0

        try:
            while self._process.returncode is None:
                line = await self._process.stdout.readline()
                if not line:
                    break
                if not self._is_paused:
                    text = line.decode("utf-8", errors="replace").rstrip()
                    output.write(text)
                    line_count += 1
                    if line_count >= max_lines:
                        output.clear()
                        line_count = 0
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Error streaming log output: %s", e)

    async def _stop_tail(self) -> None:
        """Terminate the running tail subprocess and cancel the stream task."""
        if self._stream_task and not self._stream_task.done():
            self._stream_task.cancel()
            try:
                await self._stream_task
            except asyncio.CancelledError:
                pass
            self._stream_task = None

        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=3)
            except (asyncio.TimeoutError, ProcessLookupError):
                pass
            except Exception as e:
                logger.warning("Error stopping tail process: %s", e)
            self._process = None

    def action_toggle_pause(self) -> None:
        """Pause or resume log output streaming."""
        self._is_paused = not self._is_paused
        self._update_header()
        state = "paused" if self._is_paused else "resumed"
        self.app.notify(f"Log streaming {state}")

    def action_clear_output(self) -> None:
        """Clear the log output display."""
        self.query_one("#log_output", RichLog).clear()

    def action_pick_log(self) -> None:
        """Present available logs for the user to choose from."""
        if not self._available_logs:
            self.app.notify("No available logs to switch to", severity="warning")
            return

        from textual.widgets import Select

        # Build a simple notification listing options and switch to next
        current_idx = 0
        if self._current_log in self._available_logs:
            current_idx = self._available_logs.index(self._current_log)
        next_idx = (current_idx + 1) % len(self._available_logs)
        next_log = self._available_logs[next_idx]

        output = self.query_one("#log_output", RichLog)
        output.write(
            f"\n[dim]--- Switching to {next_log} ---[/dim]\n"
        )
        self._current_log = next_log
        self._update_header()
        self.run_worker(self._start_tail(next_log), name="switch_log", exclusive=True)

    def action_back(self) -> None:
        """Stop tail and return to server actions."""
        self.run_worker(self._cleanup_and_pop(), name="cleanup", exclusive=False)

    async def _cleanup_and_pop(self) -> None:
        """Stop subprocess then pop screen."""
        await self._stop_tail()
        self.app.pop_screen()

    async def on_unmount(self) -> None:
        """Ensure cleanup on unmount."""
        await self._stop_tail()

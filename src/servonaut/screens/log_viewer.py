"""Real-time remote log viewer screen for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.events import Key
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, RichLog

from servonaut.screens.log_picker import LogPickerModal, AddPathModal, ADD_PATH_SENTINEL

logger = logging.getLogger(__name__)


class LogViewerScreen(Screen):
    """Real-time remote log viewer via SSH tail -f.

    Supports active logs (tail -f), rotated logs (tail), and compressed
    logs (zcat/bzcat). Includes a log picker modal, directory scanning,
    custom path addition, and sending buffer to AI analysis.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("p", "toggle_pause", "Pause/Resume", show=True),
        Binding("c", "clear_output", "Clear", show=True),
        Binding("l", "pick_log", "Pick Log", show=True),
        Binding("a", "send_to_ai", "Send to AI", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        super().__init__()
        self._instance = instance
        self._process: Optional[asyncio.subprocess.Process] = None
        self._is_paused: bool = False
        self._current_log: Optional[str] = None
        self._available_logs: List[str] = []
        self._discovered_logs: List[str] = []
        self._stream_task: Optional[asyncio.Task] = None
        self._content_buffer: List[str] = []
        self._is_static_view: bool = False
        self._ai_screen_pushed: bool = False
        self._paused_before_modal: bool = False

    def compose(self) -> ComposeResult:
        name = self._instance.get("name") or self._instance.get("id", "unknown")
        yield Header()
        yield Container(
            Static(
                f"[bold cyan]Log Viewer:[/bold cyan] {name}  [dim]Probing available logs...[/dim]",
                id="log_header",
            ),
            RichLog(id="log_output", highlight=True, markup=True),
            Static(
                "[dim]P: Pause | C: Clear | L: Pick Log | +: Add Path | A: Send to AI | Esc: Back[/dim]",
                id="log_hints",
            ),
            id="log_viewer_container",
        )
        yield Footer()

    def on_key(self, event: Key) -> None:
        """Handle keys that can't be expressed as Textual bindings."""
        if event.character == "+":
            self.action_add_path()
            event.prevent_default()

    def on_mount(self) -> None:
        """Probe for available logs and start streaming."""
        self.run_worker(self._probe_and_start(), name="probe_logs", exclusive=True)

    async def _probe_and_start(self) -> None:
        """Probe available log paths, then start streaming the first one.

        Also kicks off background directory scanning.
        """
        output = self.query_one("#log_output", RichLog)
        output.write("[dim]Probing for readable log files...[/dim]")

        try:
            available = await self.app.log_viewer_service.probe_log_paths(
                self._instance,
                self.app.ssh_service,
                self.app.connection_service,
            )
        except Exception as e:
            logger.error("Error probing log paths: %s", e)
            output.write(f"[red]Error probing logs: {e}[/red]")
            return

        self._available_logs = available

        if available:
            self._current_log = available[0]
            self._update_header()
            await self._start_stream(self._current_log)
        else:
            output.write(
                "[yellow]No readable log files found on this server.[/yellow]\n"
                "[dim]Press L to pick a log or + to add a custom path.[/dim]"
            )
            self.app.notify("No readable log files found", severity="warning")

        # Kick off background directory scan
        self.run_worker(self._background_scan(), name="dir_scan", exclusive=False)

    async def _background_scan(self) -> None:
        """Scan remote directories in the background to discover more log files."""
        try:
            discovered = await self.app.log_viewer_service.scan_log_directories(
                self._instance,
                self.app.ssh_service,
                self.app.connection_service,
            )
            self._discovered_logs = discovered
            count = len(set(discovered) - set(self._available_logs))
            if count > 0:
                self.app.notify(f"Discovered {count} additional log files")
        except Exception as e:
            logger.debug("Background scan failed: %s", e)

    def _update_header(self) -> None:
        """Update header with current log path and status."""
        name = self._instance.get("name") or self._instance.get("id", "unknown")
        log_label = self._current_log or "none"
        status_parts = []
        if self._is_paused:
            status_parts.append("[yellow][PAUSED][/yellow]")
        if self._is_static_view:
            classification = self.app.log_viewer_service.classify_log_file(log_label)
            status_parts.append(f"[dim][{classification}][/dim]")
        status = "  " + " ".join(status_parts) if status_parts else ""
        self.query_one("#log_header", Static).update(
            f"[bold cyan]Log Viewer:[/bold cyan] {name}  "
            f"[dim]Viewing:[/dim] {log_label}{status}"
        )

    async def _start_stream(self, log_path: str) -> None:
        """Stop any running stream, then start a new one for log_path."""
        await self._stop_stream()
        self._content_buffer.clear()

        service = self.app.log_viewer_service
        classification = service.classify_log_file(log_path)
        self._is_static_view = classification in ("compressed", "rotated")

        config = self.app.config_manager.get()
        read_cmd = service.get_read_command(log_path, config.log_viewer_tail_lines)

        conn = service._resolve_connection(
            self._instance,
            self.app.ssh_service,
            self.app.connection_service,
        )
        ssh_cmd = self.app.ssh_service.build_ssh_command(
            host=conn["host"],
            username=conn["username"],
            key_path=conn["key_path"],
            proxy_args=conn["proxy_args"],
            remote_command=read_cmd,
            port=conn["port"],
        )

        logger.debug("Starting log stream: %s", " ".join(str(a) for a in ssh_cmd))

        try:
            self._process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._stream_task = asyncio.create_task(self._stream_output())
            # Schedule empty-file check after a short delay
            self.set_timer(3.0, self._check_empty_output)
        except Exception as e:
            logger.error("Failed to start stream process: %s", e)
            output = self.query_one("#log_output", RichLog)
            output.write(f"[red]Error starting stream: {e}[/red]")

    async def _stream_output(self) -> None:
        """Stream stdout from the process into the RichLog widget."""
        if not self._process or not self._process.stdout:
            return

        output = self.query_one("#log_output", RichLog)
        config = self.app.config_manager.get()
        max_lines = config.log_viewer_max_lines
        line_count = 0

        try:
            while self._process.returncode is None:
                # When paused, stop reading entirely so the event loop
                # stays free for modals / keyboard input.  The OS pipe
                # buffer holds incoming data until we resume.
                if self._is_paused:
                    await asyncio.sleep(0.1)
                    continue

                line = await self._process.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                self._content_buffer.append(text)
                output.write(Text(text))
                line_count += 1
                if line_count >= max_lines:
                    output.clear()
                    line_count = 0
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Error streaming log output: %s", e)

        # For static views, show end-of-file marker or empty notice
        if self._is_static_view:
            if self._content_buffer:
                output.write("\n[dim]--- End of file ---[/dim]")
            else:
                output.write("[yellow]File is empty (0 lines)[/yellow]")

    def _check_empty_output(self) -> None:
        """Show hint if no log output has arrived after the initial delay."""
        if self._content_buffer or self._is_static_view:
            return
        # Process still alive but no output — file is likely empty
        if self._process and self._process.returncode is None:
            output = self.query_one("#log_output", RichLog)
            output.write(
                "[yellow]No output received — file may be empty or inactive.[/yellow]\n"
                "[dim]New lines will appear here as they are written to the log.[/dim]"
            )

    async def _stop_stream(self) -> None:
        """Terminate the running subprocess and cancel the stream task."""
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
                logger.warning("Error stopping stream process: %s", e)
            self._process = None

    def action_toggle_pause(self) -> None:
        """Pause or resume log output streaming."""
        self._is_paused = not self._is_paused
        self._update_header()
        state = "paused" if self._is_paused else "resumed"
        self.app.notify(f"Log streaming {state}")

    def action_clear_output(self) -> None:
        """Clear the log output display and content buffer."""
        self.query_one("#log_output", RichLog).clear()
        self._content_buffer.clear()

    def _pause_stream_for_modal(self) -> None:
        """Pause DOM writes while a modal is open to keep the event loop free."""
        self._paused_before_modal = self._is_paused
        self._is_paused = True

    def _resume_stream_after_modal(self) -> None:
        """Restore pause state after modal closes."""
        self._is_paused = self._paused_before_modal

    def action_pick_log(self) -> None:
        """Open the log picker modal."""
        self._pause_stream_for_modal()
        self.app.push_screen(
            LogPickerModal(
                available_logs=self._available_logs,
                discovered_logs=self._discovered_logs,
                current_log=self._current_log,
                classify_fn=self.app.log_viewer_service.classify_log_file,
            ),
            callback=self._on_log_picked,
        )

    def _on_log_picked(self, result: Optional[str]) -> None:
        """Handle log picker result."""
        self._resume_stream_after_modal()

        if result is None:
            return

        if result == ADD_PATH_SENTINEL:
            self.action_add_path()
            return

        output = self.query_one("#log_output", RichLog)
        output.clear()
        self._content_buffer.clear()
        output.write(f"[dim]Connecting to {result}...[/dim]")
        self._current_log = result
        self._update_header()
        self.app.notify(f"Loading {result.split('/')[-1]}...")
        self.run_worker(self._start_stream(result), name="switch_log", exclusive=True)

    def action_add_path(self) -> None:
        """Open the add-path modal."""
        self._pause_stream_for_modal()
        self.app.push_screen(AddPathModal(), callback=self._on_path_added)

    def _on_path_added(self, result: Optional[str]) -> None:
        """Handle add-path modal result."""
        self._resume_stream_after_modal()

        if result is None:
            return

        instance_id = self._instance.get("id", "")
        service = self.app.log_viewer_service
        existing = service.get_custom_paths(instance_id)
        if result not in existing:
            existing.append(result)
            service.set_custom_paths(instance_id, existing)
            self.app.notify(f"Added custom path: {result}")

        # Add to available list if not already there
        if result not in self._available_logs:
            self._available_logs.append(result)

        # Switch to the new path
        output = self.query_one("#log_output", RichLog)
        output.clear()
        self._content_buffer.clear()
        output.write(f"[dim]Connecting to {result}...[/dim]")
        self._current_log = result
        self._update_header()
        self.app.notify(f"Loading {result.split('/')[-1]}...")
        self.run_worker(self._start_stream(result), name="switch_log", exclusive=True)

    def action_send_to_ai(self) -> None:
        """Send the content buffer to AI analysis screen."""
        if self._ai_screen_pushed:
            self.app.notify("AI analysis already open", severity="warning")
            return

        if not self._content_buffer:
            self.app.notify("No log content to analyze", severity="warning")
            return

        from servonaut.screens.ai_analysis import AIAnalysisScreen

        # Cap buffer to last N lines to avoid blocking TextArea with huge input
        config = self.app.config_manager.get()
        max_lines = config.log_viewer_tail_lines
        lines = self._content_buffer[-max_lines:]
        text = "\n".join(lines)

        self._ai_screen_pushed = True
        self.app.push_screen(
            AIAnalysisScreen(text=text, instance=self._instance),
            callback=self._on_ai_screen_dismissed,
        )

    def _on_ai_screen_dismissed(self, result: object) -> None:
        """Clear the guard flag when AI screen is dismissed."""
        self._ai_screen_pushed = False

    def action_back(self) -> None:
        """Stop stream and return to server actions."""
        self.run_worker(self._cleanup_and_pop(), name="cleanup", exclusive=False)

    async def _cleanup_and_pop(self) -> None:
        """Stop subprocess then pop screen."""
        await self._stop_stream()
        self.app.pop_screen()

    async def on_unmount(self) -> None:
        """Ensure cleanup on unmount."""
        await self._stop_stream()

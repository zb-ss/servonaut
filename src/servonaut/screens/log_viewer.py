"""Real-time remote log viewer screen for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
import queue
import subprocess
import threading
from typing import List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.events import Key
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, RichLog

from servonaut.widgets.sidebar import Sidebar

from servonaut.screens.log_picker import (
    LogPickerModal,
    AddPathModal,
    AddDirectoryModal,
    ManagePathsModal,
    ADD_PATH_SENTINEL,
    REMOVE_PATH_SENTINEL,
    EDIT_PATH_SENTINEL,
)

logger = logging.getLogger(__name__)

# Sentinel pushed into the line queue to signal end-of-stream.
_EOF = None


class LogViewerScreen(Screen):
    """Real-time remote log viewer via SSH tail -f.

    Architecture: a dedicated OS thread reads lines from the SSH subprocess
    and queues them.  A Textual interval timer drains the queue and writes
    batched output to the RichLog widget on the main thread.  This keeps
    all blocking I/O off the asyncio event loop so key events are never
    starved.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("p", "toggle_pause", "Pause/Resume", show=True),
        Binding("c", "clear_output", "Clear", show=True),
        Binding("m", "manage_paths", "Manage Paths", show=True),
        Binding("l", "pick_log", "Pick Log", show=True),
        Binding("a", "send_to_ai", "Send to AI", show=True),
        Binding("y", "copy_output", "Copy", show=True),
    ]

    # How often the main-thread timer drains the line queue (seconds).
    _FLUSH_INTERVAL = 0.10
    # Max lines written per timer tick to keep the event loop responsive.
    _MAX_LINES_PER_FLUSH = 10

    def __init__(self, instance: dict) -> None:
        super().__init__()
        self._instance = instance
        self._process: Optional[subprocess.Popen] = None
        self._is_paused: bool = False
        self._current_log: Optional[str] = None
        self._available_logs: List[str] = []
        self._discovered_logs: List[str] = []
        self._content_buffer: List[str] = []
        self._is_static_view: bool = False
        self._ai_screen_pushed: bool = False
        self._paused_before_modal: bool = False

        # Threading primitives for the reader thread.
        self._line_queue: queue.Queue = queue.Queue()
        self._stop_event: threading.Event = threading.Event()
        self._pause_event: threading.Event = threading.Event()
        self._pause_event.set()  # Start unpaused
        self._reader_thread: Optional[threading.Thread] = None
        self._flush_timer = None

    def compose(self) -> ComposeResult:
        name = self._instance.get("name") or self._instance.get("id", "unknown")
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(
                    f"[bold cyan]Log Viewer:[/bold cyan] {name}  [dim]Probing available logs...[/dim]",
                    id="log_header",
                ),
                RichLog(id="log_output", highlight=True, markup=True),
                Static(
                    "[dim]P: Pause | C: Clear | L: Pick Log | M: Manage Paths | +: Add Path | A: Send to AI | Y: Copy | Esc: Back[/dim]",
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

    # ------------------------------------------------------------------
    # Stream lifecycle
    # ------------------------------------------------------------------

    async def _start_stream(self, log_path: str) -> None:
        """Stop any running stream, then start a new one for *log_path*."""
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
            # Use blocking Popen — the reader thread handles all I/O.
            self._process = subprocess.Popen(
                [str(a) for a in ssh_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )

            self._stop_event.clear()
            self._reader_thread = threading.Thread(
                target=self._reader_thread_fn, daemon=True,
            )
            self._reader_thread.start()

            # Periodic timer drains queued lines → RichLog (main thread).
            self._flush_timer = self.set_interval(
                self._FLUSH_INTERVAL, self._flush_pending,
            )
            self.set_timer(3.0, self._check_empty_output)
        except Exception as e:
            logger.error("Failed to start stream process: %s", e)
            output = self.query_one("#log_output", RichLog)
            output.write(f"[red]Error starting stream: {e}[/red]")

    def _reader_thread_fn(self) -> None:
        """Read lines from the subprocess stdout in a dedicated OS thread.

        Blocks on ``readline()`` — this is intentional; the thread exists
        precisely so that this blocking call never touches the asyncio
        event loop.
        """
        proc = self._process
        if not proc or not proc.stdout:
            self._line_queue.put(_EOF)
            return

        try:
            for raw_line in proc.stdout:
                # Honour pause: block here until _pause_event is set.
                self._pause_event.wait()
                if self._stop_event.is_set():
                    break
                text = raw_line.decode("utf-8", errors="replace").rstrip()
                self._line_queue.put(text)
        except Exception as e:
            if not self._stop_event.is_set():
                logger.error("Reader thread error: %s", e)
        finally:
            # Check stderr for errors when stdout ends
            if proc and proc.stderr:
                try:
                    stderr_data = proc.stderr.read()
                    if stderr_data:
                        err_text = stderr_data.decode("utf-8", errors="replace").strip()
                        # Filter out SSH warnings, show real errors
                        err_lines = [
                            l for l in err_text.splitlines()
                            if not l.startswith("Warning:") and l.strip()
                        ]
                        if err_lines:
                            self._line_queue.put(f"[red]SSH error: {err_lines[-1]}[/red]")
                except Exception:
                    pass
            self._line_queue.put(_EOF)

    def _flush_pending(self) -> None:
        """Timer callback (main thread): drain the queue and write to RichLog.

        Caps the number of lines per tick to avoid blocking the event loop
        when a burst of log data arrives (e.g. after resuming from pause).
        Remaining lines stay in the queue for the next tick.
        """
        lines: List[str] = []
        eof = False
        limit = self._MAX_LINES_PER_FLUSH
        try:
            while len(lines) < limit:
                item = self._line_queue.get_nowait()
                if item is _EOF:
                    eof = True
                    break
                lines.append(item)
        except queue.Empty:
            pass

        if lines:
            self._content_buffer.extend(lines)
            output = self.query_one("#log_output", RichLog)
            output.write(Text("\n".join(lines)))

            config = self.app.config_manager.get()
            if len(self._content_buffer) >= config.log_viewer_max_lines:
                output.clear()
                self._content_buffer.clear()

        if eof:
            self._on_stream_ended()

    def _on_stream_ended(self) -> None:
        """Handle end-of-stream: stop the timer and show markers."""
        if self._flush_timer:
            self._flush_timer.stop()
            self._flush_timer = None

        if self._is_static_view:
            output = self.query_one("#log_output", RichLog)
            if self._content_buffer:
                output.write("\n[dim]--- End of file ---[/dim]")
            else:
                output.write("[yellow]File is empty (0 lines)[/yellow]")

    def _check_empty_output(self) -> None:
        """Show hint if no log output has arrived after the initial delay."""
        if self._content_buffer or self._is_static_view:
            return
        if self._reader_thread and self._reader_thread.is_alive():
            output = self.query_one("#log_output", RichLog)
            output.write(
                "[yellow]No output received — file may be empty or inactive.[/yellow]\n"
                "[dim]New lines will appear here as they are written to the log.[/dim]"
            )

    async def _stop_stream(self) -> None:
        """Terminate the reader thread and subprocess."""
        # Stop the flush timer first.
        if self._flush_timer:
            self._flush_timer.stop()
            self._flush_timer = None

        # Signal the reader thread to exit.
        self._stop_event.set()
        self._pause_event.set()  # Unblock if waiting on pause

        # Terminate process to unblock readline() in the thread.
        if self._process:
            try:
                self._process.terminate()
            except Exception:
                pass

        # Wait for the thread (in an executor to avoid blocking the loop).
        if self._reader_thread and self._reader_thread.is_alive():
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._reader_thread.join, 3.0)
            # If still alive after timeout, force-kill the process.
            if self._reader_thread.is_alive() and self._process:
                try:
                    self._process.kill()
                except Exception:
                    pass
        self._reader_thread = None

        # Final process cleanup.
        if self._process:
            try:
                self._process.wait(timeout=2)
            except Exception:
                pass
            self._process = None

        # Drain any stale items from the queue.
        while not self._line_queue.empty():
            try:
                self._line_queue.get_nowait()
            except queue.Empty:
                break

    # ------------------------------------------------------------------
    # Pause / resume
    # ------------------------------------------------------------------

    def action_toggle_pause(self) -> None:
        """Pause or resume log output streaming."""
        self._is_paused = not self._is_paused
        if self._is_paused:
            self._pause_event.clear()
        else:
            self._pause_event.set()
        self._update_header()
        state = "paused" if self._is_paused else "resumed"
        self.app.notify(f"Log streaming {state}")

    def action_clear_output(self) -> None:
        """Clear the log output display and content buffer."""
        self.query_one("#log_output", RichLog).clear()
        self._content_buffer.clear()

    def action_copy_output(self) -> None:
        """Copy the current log buffer to the clipboard."""
        if self._content_buffer:
            self.app.copy_to_clipboard("\n".join(self._content_buffer))
            self.notify("Copied to clipboard")
        else:
            self.notify("Nothing to copy", severity="warning")

    def _pause_stream_for_modal(self) -> None:
        """Pause reading and stop flush timer while a modal/screen is on top."""
        self._paused_before_modal = self._is_paused
        self._is_paused = True
        self._pause_event.clear()
        # Stop timer to free the event loop entirely for the overlay screen
        if self._flush_timer:
            self._flush_timer.stop()
            self._flush_timer = None

    def _resume_stream_after_modal(self) -> None:
        """Restore pause state and restart flush timer after modal closes."""
        self._is_paused = self._paused_before_modal
        if not self._is_paused:
            self._pause_event.set()
            # Restart the flush timer
            if self._flush_timer is None:
                self._flush_timer = self.set_interval(
                    self._FLUSH_INTERVAL, self._flush_pending,
                )

    # ------------------------------------------------------------------
    # Log picker / add path
    # ------------------------------------------------------------------

    def action_pick_log(self) -> None:
        """Open the log picker modal."""
        self._pause_stream_for_modal()
        self.app.push_screen(
            LogPickerModal(
                available_logs=self._available_logs,
                discovered_logs=self._discovered_logs,
                current_log=self._current_log,
                classify_fn=self.app.log_viewer_service.classify_log_file,
                instance=self._instance,
                log_viewer_service=self.app.log_viewer_service,
            ),
            callback=self._on_log_picked,
        )

    def action_manage_paths(self) -> None:
        """Open the manage custom paths modal directly."""
        self._pause_stream_for_modal()
        instance_id = self._instance.get("id", "")
        current_paths = self.app.log_viewer_service.get_custom_paths(instance_id)
        self.app.push_screen(
            ManagePathsModal(
                custom_paths=current_paths,
                instance=self._instance,
            ),
            callback=self._on_manage_result,
        )

    def _on_manage_result(self, result: Optional[str]) -> None:
        """Handle manage paths modal result — reuse _on_log_picked logic."""
        self._on_log_picked(result)

    def _on_log_picked(self, result: Optional[str]) -> None:
        """Handle log picker result.

        Handles:
        - None: cancelled
        - ADD_PATH_SENTINEL: open add-file modal
        - "adddir:<path>": open add-directory flow
        - "browse:<path>": save as custom path and switch to it
        - EDIT_PATH_SENTINEL + "old\\nnew": edit a custom path
        - REMOVE_PATH_SENTINEL + path: remove a custom path
        - Any other string: switch to that log
        """
        self._resume_stream_after_modal()

        if result is None:
            return

        if result == ADD_PATH_SENTINEL:
            self.action_add_path()
            return

        if result.startswith("adddir:"):
            directory = result[len("adddir:"):]
            self._pause_stream_for_modal()
            self.run_worker(
                self._add_directory(directory),
                name="add_directory",
                exclusive=False,
            )
            return

        if result.startswith("browse:"):
            path = result[len("browse:"):]
            self._save_and_switch(path)
            return

        if result.startswith(EDIT_PATH_SENTINEL):
            payload = result[len(EDIT_PATH_SENTINEL):]
            parts = payload.split("\n", 1)
            if len(parts) == 2:
                self._edit_custom_path(parts[0], parts[1])
            return

        if result.startswith(REMOVE_PATH_SENTINEL):
            path = result[len(REMOVE_PATH_SENTINEL):]
            self._remove_custom_path(path)
            return

        self._switch_to_log(result)

    def _save_and_switch(self, path: str) -> None:
        """Save a path as custom and switch to viewing it."""
        instance_id = self._instance.get("id", "")
        service = self.app.log_viewer_service
        existing = service.get_custom_paths(instance_id)
        if path not in existing:
            existing.append(path)
            service.set_custom_paths(instance_id, existing)
        if path not in self._available_logs:
            self._available_logs.append(path)
        self._switch_to_log(path)

    def _switch_to_log(self, log_path: str) -> None:
        """Switch the viewer to a different log file."""
        output = self.query_one("#log_output", RichLog)
        output.clear()
        self._content_buffer.clear()
        output.write(f"[dim]Connecting to {log_path}...[/dim]")
        self._current_log = log_path
        self._update_header()
        self.app.notify(f"Loading {log_path.split('/')[-1]}...")
        self.run_worker(self._start_stream(log_path), name="switch_log", exclusive=True)

    def _edit_custom_path(self, old_path: str, new_path: str) -> None:
        """Replace old_path with new_path in custom paths config."""
        instance_id = self._instance.get("id", "")
        service = self.app.log_viewer_service
        existing = service.get_custom_paths(instance_id)
        if old_path in existing:
            idx = existing.index(old_path)
            existing[idx] = new_path
            service.set_custom_paths(instance_id, existing)
        # Update available logs
        if old_path in self._available_logs:
            i = self._available_logs.index(old_path)
            self._available_logs[i] = new_path
        elif new_path not in self._available_logs:
            self._available_logs.append(new_path)
        # If currently viewing the old path, switch to new
        if self._current_log == old_path:
            self._switch_to_log(new_path)
        self.app.notify(f"Updated: {new_path.split('/')[-1]}")

    def _remove_custom_path(self, path: str) -> None:
        """Remove a custom path from config and available logs."""
        instance_id = self._instance.get("id", "")
        service = self.app.log_viewer_service
        existing = service.get_custom_paths(instance_id)
        if path in existing:
            existing.remove(path)
            service.set_custom_paths(instance_id, existing)
            self.app.notify(f"Removed: {path}")
        # Remove from available list too
        if path in self._available_logs:
            self._available_logs.remove(path)
        # If we were viewing the removed path, go back to first available
        if self._current_log == path:
            if self._available_logs:
                self._switch_to_log(self._available_logs[0])
            else:
                self._current_log = None
                self._update_header()

    async def _add_directory(self, directory: str) -> None:
        """Scan a remote directory and add discovered log files to available list."""
        self.app.notify(f"Scanning directory: {directory}...")
        try:
            discovered = await self.app.log_viewer_service.add_custom_directory(
                self._instance,
                directory,
                self.app.ssh_service,
                self.app.connection_service,
            )
        except Exception as e:
            logger.error("Error adding directory %s: %s", directory, e)
            self.app.notify(f"Error scanning {directory}: {e}", severity="error")
            self._resume_stream_after_modal()
            return

        # Merge discovered files into available_logs and discovered_logs
        new_paths = [p for p in discovered if p not in self._available_logs]
        self._available_logs.extend(new_paths)
        for p in new_paths:
            if p not in self._discovered_logs:
                self._discovered_logs.append(p)

        if new_paths:
            self.app.notify(f"Added {len(new_paths)} log files from {directory}")
        else:
            self.app.notify(f"No log files found in {directory}", severity="warning")

        self._resume_stream_after_modal()

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
        self._switch_to_log(result)

    # ------------------------------------------------------------------
    # AI analysis
    # ------------------------------------------------------------------

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
        self._pause_stream_for_modal()
        self.app.push_screen(
            AIAnalysisScreen(text=text, instance=self._instance),
            callback=self._on_ai_screen_dismissed,
        )

    def _on_ai_screen_dismissed(self, result: object) -> None:
        """Clear the guard flag when AI screen is dismissed."""
        self._ai_screen_pushed = False
        self._resume_stream_after_modal()

    # ------------------------------------------------------------------
    # Navigation / cleanup
    # ------------------------------------------------------------------

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

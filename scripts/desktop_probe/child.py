"""Run real Servonaut screens with synthetic, in-memory collaborators only."""

# The script error hook must precede application imports.

from __future__ import annotations

import asyncio
import os
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .diagnostics import exception_hook, report_exception

if __name__ == "__main__":
    sys.excepthook = exception_hook

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.drivers.web_driver import WebDriver
from textual.screen import Screen
from textual.widgets import Footer, Header, Input, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.widgets.command_output import CommandOutput
from servonaut.widgets.sidebar import Sidebar

from .config import load_config


class ParentAwareDriver(WebDriver):
    """Treat pipe EOF as app exit, including when the host is killed."""

    def run_input_thread(self) -> None:
        try:
            super().run_input_thread()
        finally:
            # Upstream stops reading at EOF but leaves the application running.
            try:
                self._app.call_from_thread(self._app.exit)
            except RuntimeError:
                pass  # The app loop has already stopped on normal shutdown.


class ProbeStreamScreen(Screen):
    """Exercise a real RichLog and Input without invoking a remote service."""

    BINDINGS = [Binding("escape", "back", "Back", show=True)]

    def __init__(self) -> None:
        super().__init__()
        self._stream_index = 0
        self._stream_timer = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(
                    "[bold cyan]Renderer interaction exercise[/bold cyan]",
                    id="probe_stream_header",
                ),
                CommandOutput(id="probe_stream_output"),
                Input(
                    placeholder="Paste Unicode text here (probe only)",
                    id="probe_paste_input",
                ),
                Static(
                    "[dim]F8: modal | Esc: back | Mouse wheel: scroll the output[/dim]",
                    id="probe_stream_hint",
                ),
                id="probe_stream_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        output = self.query_one("#probe_stream_output", CommandOutput)
        output.append_output("[dim]Starting synthetic streamed output...[/dim]")
        self.query_one("#probe_paste_input", Input).focus()
        config = load_config()
        self._stream_timer = self.set_interval(
            config.stream_update_interval_seconds, self._append_stream_update
        )

    def _append_stream_update(self) -> None:
        config = load_config()
        self._stream_index += 1
        output = self.query_one("#probe_stream_output", CommandOutput)
        output.append_output(
            f"[cyan]stream {self._stream_index:02d}[/cyan] "
            "Unicode: Δ café 你好"
        )
        if self._stream_index < config.stream_update_count:
            return
        output.append_output("[bold green]Synthetic stream complete.[/bold green]")
        self.query_one("#probe_stream_hint", Static).update(
            "[dim]Stream complete. Mouse wheel scrolls the RichLog; Esc returns.[/dim]"
        )
        if self._stream_timer is not None:
            self._stream_timer.pause()

    def action_back(self) -> None:
        self.app.pop_screen()


class ProbeApp(ServonautApp):
    """Reuse the actual app, CSS, instance screen, help and sidebar."""

    BINDINGS = [
        *ServonautApp.BINDINGS,
        Binding("f8", "show_probe_modal", "Probe modal", show=True),
        Binding("f9", "show_probe_stream", "Probe stream", show=True),
    ]

    def _handle_exception(self, error: Exception) -> None:
        report_exception(error)
        super()._handle_exception(error)

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()  # Textual otherwise also calls the base on_mount.
        config = AppConfig()
        self.config_manager = SimpleNamespace(get=lambda: config)
        self.cache_service = SimpleNamespace(
            is_fresh=lambda: True, get_age=lambda: timedelta(0)
        )
        self.keyword_store = SimpleNamespace(search=lambda query: [])
        self.instances = [
            {
                "id": "web-1",
                "name": "web-1",
                "type": "example",
                "state": "running",
                "public_ip": None,
                "private_ip": "10.0.0.10",
                "region": "example",
                "key_name": "",
                "provider": "custom",
            }
        ]
        self.push_screen(InstanceListScreen())

    def on_sidebar_navigation_requested(
        self, message: Sidebar.NavigationRequested
    ) -> None:
        message.stop()
        message.prevent_default()
        if message.target_id == "nav_list":
            super().on_sidebar_navigation_requested(message)
        else:
            self.notify("This probe enables Instances, Help and renderer exercises.")

    def action_show_probe_modal(self) -> None:
        """Open the production confirmation modal with inert synthetic text."""
        self.push_screen(
            ConfirmActionScreen(
                title="Renderer interaction confirmation",
                description="Synthetic probe only; no action is performed.",
                consequences=["Exercises modal input and button focus."],
                confirm_text="CONFIRM",
                action_label="Continue",
                severity="warning",
            )
        )

    def action_show_probe_stream(self) -> None:
        """Open the isolated streaming/clipboard renderer exercise."""
        self.push_screen(ProbeStreamScreen())


def deny_external_access(event: str, args: tuple[Any, ...]) -> None:
    """Fail closed if a fixture accidentally reaches IO-capable services."""
    if event in {
        "socket.connect",
        "subprocess.Popen",
        "os.system",
        "os.mkdir",
        "os.remove",
        "os.rmdir",
        "os.rename",
        "os.chmod",
        "os.truncate",
    }:
        raise PermissionError("External operations are disabled in the probe")
    if event != "open" or not isinstance(args[0], (str, bytes, os.PathLike)):
        return
    path = Path(os.fsdecode(args[0])).expanduser()
    protected = {".servonaut", ".aws", ".ssh", ".secrets", ".config"}
    if any(
        part in protected or part == ".env" or part.startswith(".env.")
        for candidate in (path, path.resolve())
        for part in candidate.parts
    ):
        raise PermissionError("User data is disabled in the probe")
    mode, flags = args[1:3]
    if (mode and any(char in mode for char in "wax+")) or flags & (
        os.O_WRONLY | os.O_RDWR | os.O_CREAT
    ):
        raise PermissionError("File writes are disabled in the probe")


async def run_fixture() -> int:
    # Windows constructs asyncio's internal wakeup socket pair with connect().
    # Initialize the loop first; application IO remains blocked on every OS.
    sys.addaudithook(deny_external_access)
    app = ProbeApp(driver_class=ParentAwareDriver)
    await app.run_async()
    return app.return_code or 0


def main() -> None:
    sys.dont_write_bytecode = True
    raise SystemExit(asyncio.run(run_fixture()))


if __name__ == "__main__":
    main()

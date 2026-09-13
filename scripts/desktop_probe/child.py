"""Run real Servonaut screens with synthetic, in-memory collaborators only."""

# The script error hook must precede application imports.

from __future__ import annotations

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
from textual.drivers.web_driver import WebDriver

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.widgets.sidebar import Sidebar


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


class ProbeApp(ServonautApp):
    """Reuse the actual app, CSS, instance screen, help and sidebar."""

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
            self.notify("This probe enables Instances and Help only.")


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


def main() -> None:
    sys.dont_write_bytecode = True
    sys.addaudithook(deny_external_access)
    app = ProbeApp(driver_class=ParentAwareDriver)
    app.run()
    raise SystemExit(app.return_code or 0)


if __name__ == "__main__":
    main()

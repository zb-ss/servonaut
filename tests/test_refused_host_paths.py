"""A server whose address carries shell syntax is refused with a message, never a crash.

A custom server, a teammate's shared server or a provider record can hold a
host such as ``web-1;x``. Every place that builds an ssh or scp command for it
must show the refusal and keep the app (or the service) running.
"""
from __future__ import annotations

import asyncio
import html
import json
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, MemoryConfig
from servonaut.services.host_key_recording import visit_for_host_key as record_host_key
from servonaut.services.memory import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.services.scan_service import ScanConnectionError, ScanService
from servonaut.utils.ssh_names import check_ssh_target

BAD_HOST = "web-1;x"
MESSAGE = "Not connecting"


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

def test_a_scan_of_such_a_server_reports_the_refusal(tmp_path) -> None:
    from servonaut.config.manager import ConfigManager
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.ssh_service import SSHService

    manager = ConfigManager(config_path=tmp_path / "config.json")
    config = manager.get()
    config.default_scan_paths = ["/var/log"]
    manager.save(config)
    instance = {"id": "c-1", "name": "bad-1", "is_custom": True, "host": BAD_HOST,
                "public_ip": BAD_HOST, "username": "ubuntu", "port": 22}
    scanner = ScanService(manager)
    with pytest.raises(ScanConnectionError) as caught:
        asyncio.run(scanner.scan_server(instance, SSHService(manager), ConnectionService(manager)))
    assert caught.value.reason == "invalid host or user name"
    assert MESSAGE in caught.value.describe(redact=False)
    assert BAD_HOST not in caught.value.describe(redact=True)


def test_recording_a_host_key_returns_the_refusal_as_a_sentence() -> None:
    from servonaut.services.ssh_service import SSHService

    ssh = MagicMock(spec=SSHService)
    ssh.build_ssh_command.side_effect = lambda host, username, **kw: check_ssh_target(host, username)
    ssh.get_key_path.return_value = None
    connection = MagicMock()
    connection.resolve_profile.return_value = None
    connection.get_target_host.return_value = BAD_HOST
    connection.get_proxy_args.return_value = []
    connection.get_extra_options.return_value = []
    connection.get_target_port.return_value = 22
    sentence = asyncio.run(record_host_key(
        {"id": "c-1", "host": BAD_HOST, "public_ip": BAD_HOST, "username": "ubuntu"},
        connection, ssh, "ubuntu", timeout=1,
    ))
    assert sentence is not None and MESSAGE in sentence


def test_a_memory_build_reports_the_refusal(tmp_path) -> None:
    from tests.test_memory_ssh_connections import (
        FakeSsh, _Patches, _Prober, _connection_service, _fake_build, _no_wait, _patched, _row,
    )

    ssh = MagicMock()
    ssh.get_key_path.return_value = "/keys/k"

    def build(host, username, **kwargs):
        check_ssh_target(host, username)
        return _fake_build(host, username, **kwargs)

    ssh.build_ssh_command.side_effect = build
    connection = _connection_service(None)
    connection.get_target_host.return_value = BAD_HOST
    service = MemoryService(
        store=MemoryStore(root=tmp_path / "store"), config=MemoryConfig(),
        ssh_service=ssh, connection_service=connection,
    )
    service._probers = [_Prober(["a", "b"])]
    row = dict(_row(), private_ip=BAD_HOST)
    fake = FakeSsh()
    with _Patches(_patched(fake, _no_wait)):
        report = asyncio.run(service.build_report(row, ["os"]))
    assert not report.successes
    text = " ".join(f.message for f in report.failures)
    assert MESSAGE in text


# ---------------------------------------------------------------------------
# The real app
# ---------------------------------------------------------------------------

def _seed_home(home: Path) -> None:
    (home / ".servonaut").mkdir(parents=True, exist_ok=True)
    key = home / "k.pem"
    key.write_text("x")
    key.chmod(0o600)
    (home / ".servonaut" / "config.json").write_text(json.dumps({
        "version": 7,
        "custom_servers": [{"name": "bad-1", "host": BAD_HOST, "username": "ubuntu", "port": 22,
                            "ssh_key": str(key)}],
        "default_scan_paths": ["/var/log"],
    }))


async def _drive(monkeypatch, tmp_path, action):
    from textual.app import App

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(App, "open_url", lambda self, url, *, new_tab=True: None)
    _seed_home(tmp_path)
    app = ServonautApp(config_path=tmp_path / ".servonaut" / "config.json")
    errors = []
    original = app._handle_exception
    app._handle_exception = lambda error: (errors.append(f"{type(error).__name__}: {error}"), original(error))
    async with app.run_test(size=(160, 50), notifications=True) as pilot:
        for _ in range(60):
            await pilot.pause(0.1)
            if any(r.get("name") == "bad-1" for r in app.instances):
                break
        row = next(r for r in app.instances if r.get("name") == "bad-1")
        await action(app, pilot, row)
        for _ in range(20):
            await pilot.pause(0.1)
        toasts = [str(n.message) for n in app._notifications]
        shown = html.unescape(re.sub(r"<[^>]+>", "", app.export_screenshot())).replace("\xa0", " ")
        return app.is_running, errors, toasts, shown


async def _log_viewer_pick(app, pilot, row):
    from servonaut.screens.log_viewer import LogViewerScreen

    screen = LogViewerScreen(row)
    app.push_screen(screen)
    await pilot.pause(1.0)
    screen._switch_to_log("/var/log/syslog")


async def _log_viewer_open(app, pilot, row):
    from servonaut.screens.log_viewer import LogViewerScreen

    app.push_screen(LogViewerScreen(row))
    await pilot.pause(1.0)


async def _file_browser(app, pilot, row):
    from servonaut.screens.file_browser import FileBrowserScreen

    app.push_screen(FileBrowserScreen(row))
    await pilot.pause(1.0)
    await pilot.press("down", "enter")
    await pilot.pause(1.0)


async def _command_overlay(app, pilot, row):
    from servonaut.screens.command_overlay import CommandOverlay

    overlay = CommandOverlay(row)
    app.push_screen(overlay)
    await pilot.pause(0.5)
    overlay._execute_command("uptime")


async def _scp_upload(app, pilot, row):
    from servonaut.screens.scp_transfer import SCPTransferScreen

    screen = SCPTransferScreen(row)
    app.push_screen(screen)
    await pilot.pause(0.5)
    screen.query_one("#local_path_input").value = str(Path.home() / ".servonaut" / "config.json")
    screen.query_one("#remote_path_input").value = "/tmp/x"
    if screen.query("#transfer_button"):
        await pilot.click("#transfer_button")


async def _server_actions_connect(app, pilot, row):
    from servonaut.screens.server_actions import ServerActionsScreen

    app.push_screen(ServerActionsScreen(row))
    await pilot.pause(1.0)
    await pilot.press("3")
    await pilot.pause(0.5)


PATHS = {
    "log_viewer_pick_log": _log_viewer_pick,
    "log_viewer_open": _log_viewer_open,
    "file_browser_expand": _file_browser,
    "command_overlay_run": _command_overlay,
    "scp_upload": _scp_upload,
    "server_actions_ssh": _server_actions_connect,
}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", list(PATHS))
async def test_the_app_shows_the_refusal_and_keeps_running(monkeypatch, tmp_path, path) -> None:
    running, errors, toasts, shown = await _drive(monkeypatch, tmp_path, PATHS[path])
    assert running
    assert errors == []
    assert any(MESSAGE in toast for toast in toasts) or MESSAGE in shown


@pytest.mark.asyncio
async def test_a_vault_flow_gets_the_refusal_as_its_own_kind_of_error(tmp_path) -> None:
    from servonaut.services.vault.ca_enrollment import EnrollmentError
    from servonaut.services.vault.remote_executor import SshHostExecutor
    from tests.services.vault.test_remote_executor import _Connection, _Resolver

    class Ssh:
        def get_key_path(self, *_): return None
        def discover_key(self, *_): return None
        def build_ssh_command(self, **kwargs):
            check_ssh_target(kwargs["host"], kwargs["username"])
            return ["ssh"]

    pins = tmp_path / "known_hosts"
    pins.write_text("web ssh-ed25519 AAAA\n", encoding="ascii")
    pins.chmod(0o600)
    executor = SshHostExecutor(
        {"is_custom": True, "host": BAD_HOST, "username": "root", "port": 22},
        Ssh(), _Connection(), _Resolver(), known_hosts_path=pins,
    )
    with pytest.raises(EnrollmentError, match=MESSAGE):
        await executor._exec(("true",))

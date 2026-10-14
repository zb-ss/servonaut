"""Run Command shows, in demo mode, the login stand-in the server details show.

The overlay connects with the real login (from the real record or the
connection profile); on screen and in the copy buffer, demo mode shows the
same stand-in the server details panel shows for that login.
"""
from __future__ import annotations

import asyncio
import copy
import io
from pathlib import Path
from typing import Any, List, Tuple
from unittest.mock import MagicMock, patch

import pytest
from textual.app import App

from servonaut.config.schema import AppConfig, CustomServer
from servonaut.screens.command_overlay import CommandOverlay
from servonaut.services.connection_service import ConnectionService
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.redaction_service import RedactionService
from servonaut.services.ssh_service import SSHService
from servonaut.widgets.command_output import CommandOutput

REAL_LOGIN = "deploy"


def _config_manager() -> MagicMock:
    manager = MagicMock()
    manager.get.return_value = AppConfig(default_username="ec2-user")
    return manager


def _custom_server() -> dict:
    server = CustomServer(name="web-1", host="10.0.0.5", username=REAL_LOGIN, port=22)
    return CustomServerService(_config_manager()).to_instance_dict(server)


def _aws_instance() -> dict:
    return {
        "id": "i-0abc1234", "name": "web-2", "state": "running",
        "public_ip": "9.9.9.9", "private_ip": "10.0.0.6", "region": "us-east-1",
        "key_name": "",
    }


class _OverlayHost(App):
    """Shows *real* as the instance list does: redacted in place in demo mode."""

    def __init__(self, real: dict, *, demo: bool) -> None:
        super().__init__()
        self.config_manager = _config_manager()
        self.connection_service = ConnectionService(self.config_manager)
        self.ssh_service = SSHService(self.config_manager)
        self.command_history = None
        self.demo_mode = demo
        self.redaction_service = RedactionService() if demo else None
        self._real = real
        self.row = copy.deepcopy(real)
        if demo:
            self.redaction_service.register_real_ids([real["id"]])
            self.redaction_service.redact_instance(self.row)

    def connection_instance(self, instance: dict) -> dict:
        """The real record behind the displayed row (see ServonautApp)."""
        return copy.deepcopy(self._real)

    def on_mount(self) -> None:
        self.push_screen(CommandOverlay(self.row))


def _on_screen(overlay: CommandOverlay) -> str:
    return "\n".join(strip.text for strip in overlay.query_one(CommandOutput).lines)


async def _run_uptime(app: _OverlayHost) -> Tuple[List[str], List[str], str]:
    """The ssh argv, the copy buffer and the screen text after running ``uptime``."""
    with patch.object(CommandOverlay, "_run_ssh_command") as run:
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await pilot.pause()
            overlay = app.screen
            overlay._execute_command("uptime")
            await overlay.workers.wait_for_complete()
            await pilot.pause()
            buffer, shown = list(overlay._output_lines), _on_screen(overlay)
    return run.call_args.args[0], buffer, shown


@pytest.mark.asyncio
async def test_demo_mode_prompt_shows_the_login_the_server_details_show() -> None:
    app = _OverlayHost(_custom_server(), demo=True)
    stand_in = app.row["username"]  # what the server details panel shows
    assert stand_in != REAL_LOGIN

    argv, buffer, shown = await _run_uptime(app)

    prompt = f"{stand_in}@{app.row['name']}:~$ uptime"
    assert prompt in buffer and prompt in shown
    assert f"{REAL_LOGIN}@" not in "\n".join(buffer) and f"{REAL_LOGIN}@" not in shown
    assert f"{REAL_LOGIN}@10.0.0.5" in argv  # ssh still logs in as the real user


@pytest.mark.asyncio
async def test_outside_demo_mode_the_prompt_shows_the_real_login() -> None:
    app = _OverlayHost(_custom_server(), demo=False)

    argv, buffer, shown = await _run_uptime(app)

    assert f"{REAL_LOGIN}@web-1:~$ uptime" in buffer
    assert f"{REAL_LOGIN}@web-1:~$ uptime" in shown
    assert f"{REAL_LOGIN}@10.0.0.5" in argv


@pytest.mark.asyncio
async def test_demo_mode_prompt_hides_a_login_from_the_connection_settings() -> None:
    # A cloud instance has no login of its own: it comes from the default
    # username (or a connection profile), which demo mode also hides.
    app = _OverlayHost(_aws_instance(), demo=True)
    stand_in = RedactionService().redact_username("ec2-user")
    assert stand_in != "ec2-user"

    argv, buffer, shown = await _run_uptime(app)

    assert f"{stand_in}@{app.row['name']}:~$ uptime" in buffer
    assert "ec2-user@" not in shown
    assert "ec2-user@9.9.9.9" in argv


class _FinishedSsh:
    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self.stdout, self.stderr = io.BytesIO(stdout), io.BytesIO(stderr)
        self.returncode, self._exit = None, returncode

    def wait(self) -> int:
        self.returncode = self._exit
        return self._exit


def _ssh_saying(channel: str, text: str):
    """A fake Popen: ssh (or the remote command) prints *text* on *channel*."""
    def popen(argv: Any, *args: Any, **kwargs: Any) -> _FinishedSsh:
        argv = [str(part) for part in argv]
        if channel == "log":  # ssh's own messages go to its private log (-E)
            Path(argv[argv.index("-E") + 1]).write_text(text + "\n")
        data = (text + "\n").encode()
        return _FinishedSsh(
            stdout=data if channel == "stdout" else b"",
            stderr=data if channel == "stderr" else b"",
            returncode=255,
        )
    return popen


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["log", "stderr", "stdout"])
async def test_demo_mode_hides_the_login_ssh_quotes(channel: str) -> None:
    app = _OverlayHost(_custom_server(), demo=True)
    stand_in = app.row["username"]
    refused = f"{REAL_LOGIN}@10.0.0.5: Permission denied (publickey)."

    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await pilot.pause()
        overlay = app.screen
        output = overlay.query_one(CommandOutput)
        with patch("servonaut.screens.command_overlay.subprocess.Popen", _ssh_saying(channel, refused)):
            await asyncio.to_thread(overlay._run_ssh_command, ["ssh", "--", "deploy@10.0.0.5", "true"], output)
        await pilot.pause()
        buffer, shown = "\n".join(overlay._output_lines), _on_screen(overlay)

    assert "Permission denied" in buffer and "Permission denied" in shown
    assert f"{stand_in}@" in buffer and f"{stand_in}@" in shown
    assert f"{REAL_LOGIN}@" not in buffer and f"{REAL_LOGIN}@" not in shown

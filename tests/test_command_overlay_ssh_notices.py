"""Run Command shows ssh's note about a saved host key as information, not as an error.

On a first connection OpenSSH (``StrictHostKeyChecking=accept-new``) saves the
server's host key and says "Warning: Permanently added ... to the list of known
hosts." The command still runs, so the overlay dims that line instead of
printing it in the red used for ssh's failures.
"""
from __future__ import annotations

import asyncio
import io
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from textual.app import App
from textual.strip import Strip

from servonaut.config.schema import AppConfig, CustomServer
from servonaut.screens.command_overlay import CommandOverlay
from servonaut.services.connection_service import ConnectionService
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.ssh_service import SSHService
from servonaut.utils.ssh_utils import is_known_hosts_notice
from servonaut.widgets.command_output import CommandOutput

SAVED_KEY = "Warning: Permanently added '[10.0.0.5]:2222' (ED25519) to the list of known hosts."
REFUSED = "deploy@10.0.0.5: Permission denied (publickey)."


def _config_manager() -> MagicMock:
    manager = MagicMock()
    manager.get.return_value = AppConfig(default_username="ec2-user")
    return manager


class _OverlayHost(App):
    def __init__(self) -> None:
        super().__init__()
        self.config_manager = _config_manager()
        self.connection_service = ConnectionService(self.config_manager)
        self.ssh_service = SSHService(self.config_manager)
        self.command_history = None
        self.demo_mode = False
        self.redaction_service = None
        server = CustomServer(name="web-1", host="10.0.0.5", username="deploy", port=2222)
        self.row = CustomServerService(self.config_manager).to_instance_dict(server)

    def connection_instance(self, instance: dict) -> dict:
        return dict(self.row)

    def on_mount(self) -> None:
        self.push_screen(CommandOverlay(self.row))


class _FinishedSsh:
    def __init__(self, stdout: bytes, returncode: int) -> None:
        self.stdout, self.stderr = io.BytesIO(stdout), io.BytesIO(b"")
        self.returncode, self._exit = None, returncode

    def wait(self) -> int:
        self.returncode = self._exit
        return self._exit


def _ssh(log: str, stdout: bytes, returncode: int):
    """A fake Popen: ssh writes *log* to its private log (-E), the command prints *stdout*."""
    def popen(argv: Any, *args: Any, **kwargs: Any) -> _FinishedSsh:
        argv = [str(part) for part in argv]
        Path(argv[argv.index("-E") + 1]).write_text(log + "\n")
        return _FinishedSsh(stdout, returncode)
    return popen


async def _lines_after(log: str, stdout: bytes = b"", returncode: int = 0) -> list[Strip]:
    app = _OverlayHost()
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await pilot.pause()
        output = app.screen.query_one(CommandOutput)
        with patch("servonaut.screens.command_overlay.subprocess.Popen", _ssh(log, stdout, returncode)):
            await asyncio.to_thread(app.screen._run_ssh_command, ["ssh", "deploy@10.0.0.5", "uptime"], output)
        await pilot.pause()
        return list(output.lines)


def _line(lines: list[Strip], text: str) -> Strip:
    return next(strip for strip in lines if text in strip.text)


def _is_red(strip: Strip) -> bool:
    return any(
        segment.style is not None and segment.style.color is not None and segment.style.color.name == "red"
        for segment in strip if segment.text.strip()
    )


def _is_dim(strip: Strip) -> bool:
    return all(segment.style is not None and segment.style.dim for segment in strip if segment.text.strip())


@pytest.mark.asyncio
async def test_a_saved_host_key_is_shown_dimmed_not_as_an_error() -> None:
    lines = await _lines_after(SAVED_KEY, stdout=b" 10:00:00 up 3 days, load average: 0.00\n")

    notice = _line(lines, "Permanently added")
    assert _is_dim(notice)
    assert not _is_red(notice)
    assert any("up 3 days" in strip.text for strip in lines)


@pytest.mark.asyncio
async def test_ssh_failures_are_still_shown_in_red() -> None:
    lines = await _lines_after(REFUSED, returncode=255)

    assert _is_red(_line(lines, "Permission denied"))


@pytest.mark.parametrize("line, expected", [
    (SAVED_KEY, True),
    ("Warning: Permanently added 'web-1,10.0.0.5' (ECDSA) to the list of known hosts.", True),
    ("  " + SAVED_KEY + "  ", True),
    ("Warning: the ECDSA host key for 'web-1' differs from the key for the IP address '10.0.0.5'", False),
    ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", False),
    (REFUSED, False),
    ("", False),
])
def test_only_the_saved_host_key_note_counts_as_a_notice(line: str, expected: bool) -> None:
    assert is_known_hosts_notice(line) is expected


@pytest.mark.asyncio
async def test_the_servers_output_is_shown_as_text_not_markup() -> None:
    planted = "[link=https://evil.example]https://docs.example.com[/link] [bold]x[/bold] [/oops]"
    lines = await _lines_after("", stdout=planted.encode() + b"\n")

    # The log may wrap the line; read it back whole.
    shown = " ".join(strip.text.strip() for strip in lines if strip.text.strip())
    assert planted in shown
    # No hidden link: what the line says is all it is.
    assert all(
        segment.style is None or not segment.style.link for strip in lines for segment in strip
    )

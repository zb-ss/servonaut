"""A server's host or user name with control characters is never launched.

The SSH wrapper script echoes the command line into a new terminal window
before ssh runs. Names from a team's shared servers must not be able to write
terminal sequences there, so the launch is refused before any script exists.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.services.terminal_service import TerminalService

HOSTILE_HOST = "web\x1b]52;c;aGVsbG8=\x07\x1b]0;pwned\x07-1.example"
HOSTILE_USER = "admin\x1b[2J\x9b31m"
HOST = "web-1" + "." + "example"


def _target(user: str, host: str) -> str:
    return f"{user}@{host}"


def _service(tmp_path: Path) -> TerminalService:
    service = TerminalService(
        data_root=tmp_path, command_resolver=lambda name: f"/usr/bin/{name}",
    )
    service._detected = "xterm"
    service._detected_path = "/usr/bin/xterm"
    return service


def _launch(service: TerminalService, command: list[str]) -> tuple[bool, int]:
    with patch("servonaut.services.terminal_service.get_os", return_value="linux"), patch(
        "servonaut.services.terminal_service.subprocess.Popen"
    ) as popen:
        launched = service.launch_ssh_in_terminal(command)
    return launched, popen.call_count


def _written_files(tmp_path: Path) -> list[Path]:
    return [path for path in tmp_path.rglob("*") if path.is_file()]


@pytest.mark.parametrize(
    "target",
    [_target("admin", HOSTILE_HOST), _target(HOSTILE_USER, HOST)],
    ids=["host", "user"],
)
def test_hostile_target_is_refused_before_a_script_is_written(
    tmp_path: Path, target: str
) -> None:
    service = _service(tmp_path)
    launched, popen_calls = _launch(service, ["ssh", "-p", "22", target])

    assert launched is False
    assert popen_calls == 0
    assert _written_files(tmp_path) == []
    message = service.last_error or ""
    assert "user or host name" in message
    assert "\x1b" not in message and "\x07" not in message and "\x9b" not in message
    assert "\\x1b" in message


def test_hostile_key_path_is_refused_and_named(tmp_path: Path) -> None:
    service = _service(tmp_path)
    launched, _ = _launch(service, ["ssh", "-i", "/keys/a\x1b]0;x\x07", _target("admin", "web-1")])
    assert launched is False
    assert "key file path" in (service.last_error or "")
    assert _written_files(tmp_path) == []


def test_benign_command_is_launched_with_an_unchanged_script(tmp_path: Path) -> None:
    service = _service(tmp_path)
    command = ["ssh", "-p", "2222", _target("admin", HOST)]
    launched, popen_calls = _launch(service, command)

    assert launched is True
    assert popen_calls == 1
    (script,) = _written_files(tmp_path)
    line = shlex.join(["/usr/bin/ssh", *command[1:]])
    assert script.read_text(encoding="utf-8") == f"""#!/bin/bash
printf '%s\\n' 'Connecting:'
printf '%s\\n' {shlex.quote(line)}
printf '%s\\n' '---'
{line}
exit_code=$?
if [ $exit_code -ne 0 ]; then
    printf '\\n--- SSH exited with code %s ---\\n' "$exit_code"
    printf '%s\\n' 'Press Enter to close this window...'
    read -r
fi
"""


def test_echoed_command_line_is_inert_even_if_validation_is_bypassed(tmp_path: Path) -> None:
    service = _service(tmp_path)
    wrapper = service._create_posix_wrapper(["ssh", _target("admin", HOSTILE_HOST)])
    content = Path(wrapper).read_text(encoding="utf-8")
    display_line = content.splitlines()[2]
    assert "\x1b" not in display_line and "\x07" not in display_line
    assert "\\x1b" in display_line

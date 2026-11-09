"""Names read back from a server must reach its shell as one inert word.

Any local account on a managed server can create a file called ``x;cmd;.log``
or ``$(cmd)``. Each builder that interpolates such a name into a remote command
is exercised here with hostile names, and the command is also run locally under
``sh -c`` against a temporary directory to show that nothing extra executes.
"""
from __future__ import annotations

import asyncio
import gzip
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig
from servonaut.services.log_viewer_service import LogViewerService
from servonaut.services.scan_service import ScanService
from servonaut.utils.remote_shell import shell_path, shell_word
from servonaut.widgets.remote_tree import RemoteTree

MARKER = "injected-marker"

HOSTILE_NAMES = {
    "semicolon": f"x;touch {MARKER};.log",
    "space": "a b c.log",
    "substitution": f"$(touch {MARKER}).log",
    "backticks": f"`touch {MARKER}`.log",
    "single_quote": f"it's;touch {MARKER}.log",
    "double_quote": f'say"; touch {MARKER}; ".log',
    "leading_dash": "-n",
    "newline": f"a\ntouch {MARKER}\nb.log",
    "pipe_and_glob": f"a|touch {MARKER}|*.log",
}

CONNECTION = {"host": "h", "username": "u", "key_path": None, "proxy_args": [], "port": None}


class _Manager:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def get(self) -> AppConfig:
        return self._config


def _sh(command: str, cwd, env=None) -> str:
    return subprocess.run(
        ["sh", "-c", command], cwd=cwd, env=env, capture_output=True, text=True,
        timeout=20, check=False,
    ).stdout


def _async_value(value):
    async def _inner(*_args, **_kwargs):
        return value

    return _inner


def _ssh_recorder() -> MagicMock:
    ssh = MagicMock()
    ssh.build_ssh_command.side_effect = lambda **kw: ["ssh", kw["remote_command"]]
    return ssh


@pytest.fixture
def service() -> LogViewerService:
    return LogViewerService(_Manager(AppConfig()))


def _local_path(name: str, directory) -> str:
    """A name that starts with ``-`` is addressed relative, like the tool would see it."""
    return name if name.startswith("-") else str(directory / name)


@pytest.mark.parametrize("name", HOSTILE_NAMES.values(), ids=HOSTILE_NAMES.keys())
def test_shell_word_is_one_inert_word(name, tmp_path):
    (tmp_path / name).write_text("content\n")
    assert _sh(f"cat {shell_word(name)}", tmp_path) == "content\n"
    assert not (tmp_path / MARKER).exists()


@pytest.mark.parametrize("name", HOSTILE_NAMES.values(), ids=HOSTILE_NAMES.keys())
def test_tail_command_runs_nothing_extra(service, name, tmp_path):
    (tmp_path / name).write_text("line one\n")
    command = service.get_tail_command(_local_path(name, tmp_path), num_lines=5, follow=False)
    assert _sh(command, tmp_path) == "line one\n"
    assert not (tmp_path / MARKER).exists()


@pytest.mark.parametrize("name", HOSTILE_NAMES.values(), ids=HOSTILE_NAMES.keys())
def test_rotated_read_command_runs_nothing_extra(service, name, tmp_path):
    rotated = f"{name}.1"
    (tmp_path / rotated).write_text("old line\n")
    command = service.get_read_command(_local_path(rotated, tmp_path), num_lines=5)
    assert _sh(command, tmp_path) == "old line\n"
    assert not (tmp_path / MARKER).exists()


def test_tail_command_quotes_a_hostile_name(service):
    command = service.get_tail_command("/var/log/x;reboot;.log", follow=True)
    assert command == "tail -n 100 -f '/var/log/x;reboot;.log'"


def test_plain_paths_are_left_alone(service):
    assert service.get_tail_command("/var/log/syslog") == "tail -n 100 -f /var/log/syslog"
    assert service.get_read_command("/var/log/syslog.1") == "tail -n 100 /var/log/syslog.1"


def test_decompress_tool_is_chosen_from_the_real_extension(service):
    assert service.get_read_command("/var/log/a b;c.bz2") == "bzcat '/var/log/a b;c.bz2'"
    assert service.get_read_command("/var/log/$(x).xz") == "xzcat '/var/log/$(x).xz'"
    assert service.get_read_command("/var/log/it's.zst") == "zstdcat '/var/log/it'\"'\"'s.zst'"


def test_decompress_command_runs_nothing_extra(service, tmp_path):
    name = f"x;touch {MARKER};.gz"
    with gzip.open(tmp_path / name, "wb") as handle:
        handle.write(b"zipped\n")
    command = service.get_read_command(str(tmp_path / name))
    assert command.startswith("zcat '")
    assert _sh(command, tmp_path) == "zipped\n"
    assert not (tmp_path / MARKER).exists()


def test_leading_dash_name_is_not_an_option(service):
    assert service.get_tail_command("-f", follow=False) == "tail -n 100 ./-f"


def test_probe_command_quotes_configured_and_custom_paths():
    config = AppConfig(
        log_viewer_default_paths=["/var/log/x;y.log"],
        log_viewer_custom_paths={"i-1": ["/tmp/$(z).log"]},
    )
    probe_service = LogViewerService(_Manager(config))
    seen = []

    async def runner(command):
        seen.append(command)
        return "", "", 0

    asyncio.run(probe_service.probe_log_paths({"id": "i-1"}, MagicMock(), MagicMock(), runner=runner))
    assert seen == [
        "test -r '/var/log/x;y.log' && printf '%s\\n' '/var/log/x;y.log'; "
        "test -r '/tmp/$(z).log' && printf '%s\\n' '/tmp/$(z).log'"
    ]


def test_scan_command_quotes_directories():
    config = AppConfig(log_viewer_scan_directories=["/var/log", "/srv/my logs;x"])
    scan_service = LogViewerService(_Manager(config))
    scan_service.resolve_connection = _async_value(CONNECTION)
    ssh = _ssh_recorder()
    with patch("servonaut.services.log_viewer_service.run_ssh_subprocess", _async_value((b"", b""))):
        asyncio.run(scan_service.scan_log_directories({"id": "i-1"}, ssh, MagicMock()))
    command = ssh.build_ssh_command.call_args.kwargs["remote_command"]
    assert command.startswith("find /var/log '/srv/my logs;x' -maxdepth ")


def test_add_directory_quotes_the_directory():
    dir_service = LogViewerService(_Manager(AppConfig()))
    dir_service.get_custom_paths = lambda _id: []
    dir_service.set_custom_paths = lambda _id, _paths: None
    dir_service.resolve_connection = _async_value(CONNECTION)
    ssh = _ssh_recorder()
    with patch("servonaut.services.log_viewer_service.run_ssh_subprocess", _async_value((b"", b""))):
        asyncio.run(dir_service.add_custom_directory({"id": "i-1"}, "/srv/$(x)", ssh, MagicMock()))
    command = ssh.build_ssh_command.call_args.kwargs["remote_command"]
    assert command.startswith("find '/srv/$(x)' ")


# ---------------------------------------------------------------------------
# Directory listings (remote tree, path scan)
# ---------------------------------------------------------------------------

def test_shell_path_keeps_the_home_shortcut():
    assert shell_path("~") == '"$HOME"'
    assert shell_path("~/my dir;x") == '"$HOME"/' + "'my dir;x'"
    assert shell_path("/srv/ok") == "/srv/ok"
    assert shell_path("-rf") == "./-rf"


def test_shell_path_home_expands_and_nothing_else(tmp_path):
    (tmp_path / "my dir").mkdir()
    (tmp_path / "my dir" / "inside").write_text("")
    out = _sh(f"cd {shell_path('~/my dir')} && ls", tmp_path, env={**os.environ, "HOME": str(tmp_path)})
    assert out == "inside\n"


def _tree() -> RemoteTree:
    ssh = _ssh_recorder()
    ssh.get_key_path.return_value = "/key.pem"
    ssh.discover_key.return_value = None
    ssh.build_ssh_command.side_effect = lambda **kw: ["ssh", "host", kw["remote_command"]]
    return RemoteTree(
        instance={"id": "i-1", "name": "web", "public_ip": "1.2.3.4", "ssh_key": "/key.pem"},
        ssh_service=ssh,
        connection_service=MagicMock(),
        username="ec2-user",
        scan_paths=["/srv"],
    )


_REAL_RUN = subprocess.run


def _run_locally(cwd):
    def run(cmd, **_kwargs):
        done = _REAL_RUN(
            ["sh", "-c", cmd[-1]], cwd=cwd, capture_output=True, text=True, timeout=20, check=False,
        )
        return SimpleNamespace(returncode=done.returncode, stdout=done.stdout, stderr=done.stderr)

    return run


@pytest.mark.parametrize("name", HOSTILE_NAMES.values(), ids=HOSTILE_NAMES.keys())
def test_expanding_a_directory_with_a_hostile_name_runs_nothing_extra(name, tmp_path):
    directory = tmp_path / name
    directory.mkdir()
    (directory / "inside.txt").write_text("")
    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_run_locally(tmp_path)):
        entries = _tree()._fetch_directory_contents(_local_path(name, tmp_path))
    assert [e["name"] for e in entries] == ["inside.txt"]
    assert not (tmp_path / MARKER).exists()
    assert not (directory / MARKER).exists()


def test_symlink_resolution_quotes_the_directory(tmp_path):
    directory = tmp_path / f'a";touch {MARKER};"'
    directory.mkdir()
    (directory / "target.txt").write_text("")
    (directory / "link").symlink_to("target.txt")
    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_run_locally(tmp_path)):
        entries = _tree()._fetch_directory_contents(str(directory))
    assert {e["name"]: e["type"] for e in entries}["link"] == "file"
    assert not (tmp_path / MARKER).exists()
    assert not (directory / MARKER).exists()


def test_path_scan_quotes_a_scan_path():
    scan = ScanService.__new__(ScanService)
    commands = []
    target = SimpleNamespace(
        host="h", host_key_target=None,
        argv=lambda command: commands.append(command) or ["ssh", command],
    )
    scan._run_ssh = _async_value(SimpleNamespace(returncode=0, stdout="x", stderr=""))
    scan._raise_for_host_key_problem = lambda *_a, **_k: None
    asyncio.run(scan._run_path_scan("/srv/a b;c", target))
    asyncio.run(scan._run_path_scan("~/logs", target))
    assert commands == [
        "ls -la '/srv/a b;c' 2>/dev/null",
        'ls -la "$HOME"/logs 2>/dev/null',
    ]


@pytest.mark.parametrize("path", ["$HOME/logs/a b.log", "${HOME}/logs/a b.log", "~/logs/a b.log"])
def test_a_home_prefix_written_any_of_three_ways_still_means_the_home(tmp_path, path) -> None:
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "a b.log").write_text("home log\n")
    out = _sh(f"cat {shell_path(path)}", tmp_path, env={**os.environ, "HOME": str(tmp_path)})
    assert out == "home log\n"


def test_only_a_leading_home_is_expanded() -> None:
    assert shell_path("$HOME") == '"$HOME"'
    assert shell_path("/srv/$HOME/x") == "'/srv/$HOME/x'"
    assert shell_path("$HOMEX/y") == "'$HOMEX/y'"
    assert shell_path("$OTHER/y") == "'$OTHER/y'"


def test_the_probe_prints_a_name_with_a_backslash_exactly(tmp_path) -> None:
    name = "a\\cb"
    (tmp_path / name).write_text("x")
    asked = f"test -r {shell_path(str(tmp_path / name))} && printf '%s\\n' {shell_path(str(tmp_path / name))}"
    assert _sh(asked, tmp_path) == f"{tmp_path / name}\n"

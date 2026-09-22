"""Contract tests for external terminal breakaway isolation.

Verifies that Windows external terminal launches receive controlled
CREATE_BREAKAWAY_FROM_JOB so they escape desktop shell job containment,
while private child process trees never receive breakaway permission.
"""

from __future__ import annotations

import inspect
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from servonaut.desktop import process_tree
from servonaut.desktop.process_tree import PosixProcessTree
from servonaut.services.terminal_service import TerminalService

_CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def _mock_resolver(*available: str):
    paths = {name: rf"C:\\Tools\\{name}" for name in available}
    return lambda command: paths.get(command)


def _system_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "Windows" / "System32"
    directory.mkdir(parents=True)
    powershell = directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    powershell.parent.mkdir(parents=True)
    powershell.touch()
    cmd = directory / "cmd.exe"
    cmd.touch()
    return directory


def test_windows_terminal_wt_includes_breakaway_flag(tmp_path: Path) -> None:
    service = TerminalService(
        data_root=tmp_path,
        command_resolver=_mock_resolver("ssh", "wt.exe"),
    )
    popen = MagicMock()
    sys_dir = _system_directory(tmp_path)

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=sys_dir,
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "remote-host"])

    assert popen.called
    kwargs = popen.call_args.kwargs
    creationflags = kwargs.get("creationflags", 0)
    assert creationflags & _CREATE_BREAKAWAY_FROM_JOB == _CREATE_BREAKAWAY_FROM_JOB


def test_windows_terminal_cmd_includes_breakaway_flag(tmp_path: Path) -> None:
    service = TerminalService(
        data_root=tmp_path,
        command_resolver=_mock_resolver("ssh", "cmd.exe"),
    )
    popen = MagicMock()
    sys_dir = _system_directory(tmp_path)

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=sys_dir,
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "remote-host"])

    assert popen.called
    kwargs = popen.call_args.kwargs
    creationflags = kwargs.get("creationflags", 0)
    assert creationflags & _CREATE_BREAKAWAY_FROM_JOB == _CREATE_BREAKAWAY_FROM_JOB


def test_windows_terminal_launch_fallback_on_oserror(tmp_path: Path) -> None:
    service = TerminalService(
        data_root=tmp_path,
        command_resolver=_mock_resolver("ssh", "wt.exe"),
    )
    sys_dir = _system_directory(tmp_path)

    calls: list[int] = []

    def mock_popen(*args, **kwargs):
        flags = kwargs.get("creationflags", 0)
        calls.append(flags)
        if flags & _CREATE_BREAKAWAY_FROM_JOB:
            raise OSError(5, "Access is denied")
        return MagicMock()

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=sys_dir,
        ),
        patch(
            "servonaut.services.terminal_service.subprocess.Popen",
            side_effect=mock_popen,
        ),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "remote-host"])

    assert len(calls) == 2
    # First call attempted with breakaway
    assert calls[0] & _CREATE_BREAKAWAY_FROM_JOB == _CREATE_BREAKAWAY_FROM_JOB
    # Second fallback call was without breakaway
    assert calls[1] & _CREATE_BREAKAWAY_FROM_JOB == 0


def test_child_process_does_not_have_breakaway_flag() -> None:
    """Verify that desktop child process creation does not pass CREATE_BREAKAWAY_FROM_JOB."""
    source = inspect.getsource(process_tree.spawn_desktop_child)
    # The spawn_desktop_child function must not pass _CREATE_BREAKAWAY_FROM_JOB to child Popen
    assert "creationflags=_CREATE_NEW_PROCESS_GROUP" in source
    assert "_CREATE_BREAKAWAY_FROM_JOB" not in source


@pytest.mark.skipif(os.name == "nt", reason="POSIX-specific session isolation test")
def test_external_terminal_survives_parent_on_posix() -> None:
    """External terminal launched with start_new_session survives while private child tree is killed."""
    # Start an external terminal double
    ext_proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # Start a private child process tree
        child_proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        tree = PosixProcessTree(child_proc)

        # Verify both are running
        assert ext_proc.poll() is None
        assert tree.poll() is None

        # Terminate the private tree
        tree.terminate(grace_seconds=0.5)
        tree.close()

        # The private child must be dead
        assert tree.poll() is not None

        # The external terminal double must still be alive!
        assert ext_proc.poll() is None
    finally:
        ext_proc.kill()
        ext_proc.wait()

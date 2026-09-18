"""Portable process-control tests, including Windows-only execution coverage."""
from __future__ import annotations

import math
import os
import sys

import pytest

from servonaut.services import process_control


def test_detached_options_are_platform_specific_and_non_shell():
    posix = process_control.detached_popen_kwargs("linux")
    windows = process_control.detached_popen_kwargs("win32")

    assert posix["start_new_session"] is True
    assert posix["shell"] is False
    assert "creationflags" not in posix
    assert windows["shell"] is False
    assert "start_new_session" not in windows
    assert windows["creationflags"]


def test_spawn_terminate_and_wait_for_real_child():
    child = process_control.spawn_detached(
        [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    try:
        assert process_control.is_process_alive(child.pid)
        process_control.terminate_process(child.pid)
        assert process_control.wait_for_process_exit(child.pid, 3.0)
    finally:
        if process_control.is_process_alive(child.pid):
            process_control.terminate_process(child.pid)


def test_invalid_process_inputs_are_safe():
    assert process_control.is_process_alive(None) is False
    assert process_control.is_process_alive(0) is False
    with pytest.raises(ValueError, match="argv"):
        process_control.spawn_detached([])
    for timeout in (-1, math.inf, -math.inf, math.nan, True):
        with pytest.raises(ValueError, match="finite non-negative"):
            process_control.wait_for_process_exit(os.getpid(), timeout)


def test_windows_liveness_branch_never_uses_os_kill(monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(process_control.sys, "platform", "win32")
    monkeypatch.setattr(
        process_control,
        "_is_windows_process_alive",
        lambda pid: calls.append(pid) or True,
    )
    monkeypatch.setattr(process_control.os, "kill", lambda *_: pytest.fail("kill called"))

    assert process_control.is_process_alive(42) is True
    assert calls == [42]


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows API execution")
def test_windows_native_liveness_executes_without_signal_emulation():
    assert process_control.is_process_alive(os.getpid()) is True


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows API execution")
def test_windows_system_directory_is_absolute_existing_directory():
    system_directory = process_control.windows_system_directory()
    assert system_directory.is_absolute()
    assert system_directory.is_dir()

"""Small, platform-aware helpers for detached child processes.

The relay control path must never use ``os.kill(pid, 0)`` on Windows.  Python
maps that call to process termination there, so liveness is queried through a
read-only process handle instead.
"""
from __future__ import annotations

import ctypes
import math
import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Final

_PROCESS_QUERY_LIMITED_INFORMATION: Final = 0x1000
_PROCESS_TERMINATE: Final = 0x0001
_STILL_ACTIVE: Final = 259
_ERROR_ACCESS_DENIED: Final = 5
_ERROR_INVALID_PARAMETER: Final = 87
_CREATE_NEW_PROCESS_GROUP: Final = 0x00000200
_DETACHED_PROCESS: Final = 0x00000008


def detached_popen_kwargs(platform_name: str) -> dict[str, object]:
    """Return the isolated stdio/session options for ``platform_name``.

    This is deliberately pure so the platform-specific construction can be
    asserted on every CI platform without starting a child process.
    """
    common: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "shell": False,
    }
    if platform_name == "win32":
        return {
            **common,
            "creationflags": _CREATE_NEW_PROCESS_GROUP | _DETACHED_PROCESS,
        }
    return {**common, "start_new_session": True}


def windows_system_directory() -> Path:
    """Return the strict-resolved native Windows system directory.

    This deliberately does not consult ``PATH`` or environment variables such
    as ``SYSTEMROOT``.  Consumers use it to resolve trusted Windows helpers.
    """
    if sys.platform != "win32":
        raise OSError("Windows system directory is unavailable on this platform")
    try:
        kernel32 = _kernel32()
        get_system_directory = kernel32.GetSystemDirectoryW
        get_system_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        get_system_directory.restype = ctypes.c_uint
        buffer_size = 32768
        buffer = ctypes.create_unicode_buffer(buffer_size)
        length = get_system_directory(buffer, buffer_size)
        if length == 0 or length >= buffer_size:
            raise OSError(ctypes.get_last_error(), "Could not discover system directory")
        return Path(buffer.value).resolve(strict=True)
    except (AttributeError, OSError, ValueError) as error:
        raise OSError("Could not discover Windows system directory") from error


def spawn_detached(argv: Sequence[str]) -> subprocess.Popen[bytes]:
    """Start ``argv`` without inheriting the terminal or standard streams."""
    command = _validate_argv(argv)
    return subprocess.Popen(command, **detached_popen_kwargs(sys.platform))


def is_process_alive(pid: int | None) -> bool:
    """Return whether ``pid`` is alive without signalling it on Windows."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if sys.platform == "win32":
        return _is_windows_process_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def terminate_process(pid: int) -> None:
    """Request termination for a live process; a dead PID is a no-op.

    Callers that terminate a relay must first verify its actively-held lock
    owner.  That verification binds this generic PID operation to a relay
    instance rather than stale PID-file metadata.
    """
    if not is_process_alive(pid):
        return
    if sys.platform == "win32":
        _terminate_windows_process(pid)
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return


def wait_for_process_exit(pid: int, timeout_seconds: float) -> bool:
    """Wait up to ``timeout_seconds`` for a process to disappear."""
    if isinstance(timeout_seconds, bool):
        raise ValueError(  # noqa: TRY004 - bool is a numerically invalid value
            "timeout_seconds must be a finite non-negative number"
        )
    try:
        timeout_seconds = float(timeout_seconds)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "timeout_seconds must be a finite non-negative number"
        ) from error
    if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        raise ValueError("timeout_seconds must be a finite non-negative number")
    deadline = time.monotonic() + timeout_seconds
    while True:
        # A detached child can remain a POSIX zombie until its parent reaps
        # it.  It has exited and must not make callers wait for PID reuse.
        if _reap_exited_child(pid) or not is_process_alive(pid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def _validate_argv(argv: Sequence[str]) -> list[str]:
    command = list(argv)
    if not command or any(not isinstance(arg, str) or not arg for arg in command):
        raise ValueError("argv must contain non-empty string arguments")
    return command


def _reap_exited_child(pid: int) -> bool:
    """Reap an exited POSIX child when this process owns it."""
    if sys.platform == "win32":
        return False
    try:
        waited_pid, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    return waited_pid == pid


def _kernel32() -> object:
    """Load the native process API only when running on Windows."""
    return ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]


def _is_windows_process_alive(pid: int) -> bool:
    kernel32 = _kernel32()
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    handle = open_process(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        # Access denial still proves that the PID exists.  We must not fall
        # back to os.kill(), whose Windows behaviour is destructive.
        return ctypes.get_last_error() == _ERROR_ACCESS_DENIED
    try:
        exit_code = ctypes.c_ulong()
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        get_exit_code.restype = ctypes.c_bool
        if not get_exit_code(handle, ctypes.byref(exit_code)):
            return ctypes.get_last_error() != _ERROR_INVALID_PARAMETER
        return exit_code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def _terminate_windows_process(pid: int) -> None:
    """Terminate through a process handle, avoiding a signal emulation."""
    kernel32 = _kernel32()
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    handle = open_process(_PROCESS_TERMINATE, False, pid)
    if not handle:
        if ctypes.get_last_error() in {_ERROR_INVALID_PARAMETER, _ERROR_ACCESS_DENIED}:
            return
        raise OSError(ctypes.get_last_error(), "Unable to open process for termination")
    try:
        if not kernel32.TerminateProcess(handle, 1):
            error = ctypes.get_last_error()
            if error != _ERROR_INVALID_PARAMETER:
                raise OSError(error, "Unable to terminate process")
    finally:
        kernel32.CloseHandle(handle)

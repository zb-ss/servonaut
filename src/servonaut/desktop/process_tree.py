"""Owned desktop child process tree management and platform isolation.

Implements native process group isolation on POSIX and Job Object containment
on Windows, ensuring deterministic lifecycle ownership and descendant cleanup.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import BinaryIO, Final, Protocol

from servonaut.desktop.control import (
    DesktopControlError,
    ParentStartupGate,
    encode_control_frame,
    read_child_frame,
)
from servonaut.desktop.model import (
    ErrorResponse,
    PosixListener,
    ReadyResponse,
    SecretToken,
    StartRequest,
    WindowsSharedListener,
)

# Win32 Constants for Job Objects and Process Management
_PROCESS_SET_QUOTA: Final = 0x0100
_PROCESS_TERMINATE: Final = 0x0001
_CREATE_NEW_PROCESS_GROUP: Final = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB: Final = 0x01000000

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x2000
_JOB_OBJECT_LIMIT_BREAKAWAY_OK: Final = 0x0800
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Final = 9


class ProcessTreeError(RuntimeError):
    """Raised when process spawning, job assignment, or tree lifecycle fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = message


class OwnedProcessTree(Protocol):
    """Protocol for an owned child process tree with deterministic lifecycle."""

    @property
    def process(self) -> subprocess.Popen[bytes]: ...

    @property
    def pid(self) -> int: ...

    @property
    def stdin(self) -> BinaryIO | None: ...

    @property
    def stdout(self) -> BinaryIO | None: ...

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def terminate(self, *, grace_seconds: float = 2.0) -> None: ...

    def close(self) -> None: ...


# --- Win32 Job Object Structures & Helper Functions ---


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryLimit", ctypes.c_size_t),
        ("PeakJobMemoryLimit", ctypes.c_size_t),
    ]


def _kernel32() -> object:
    if sys.platform != "win32":
        raise OSError("Win32 API is unavailable on this platform")
    return ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]


def _create_job_object() -> ctypes.c_void_p:
    kernel32 = _kernel32()
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    create_job.restype = ctypes.c_void_p
    handle = create_job(None, None)
    if not handle:
        raise ProcessTreeError(f"create-job-failed:{ctypes.get_last_error()}")
    return handle


def _set_job_limits(job_handle: ctypes.c_void_p) -> None:
    kernel32 = _kernel32()
    set_info = kernel32.SetInformationJobObject
    set_info.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    set_info.restype = ctypes.c_bool

    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_BREAKAWAY_OK
    )

    success = set_info(
        job_handle,
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not success:
        raise ProcessTreeError(f"set-job-limits-failed:{ctypes.get_last_error()}")


def _assign_process_to_job(job_handle: ctypes.c_void_p, pid: int) -> None:
    kernel32 = _kernel32()
    open_proc = kernel32.OpenProcess
    open_proc.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    open_proc.restype = ctypes.c_void_p

    proc_handle = open_proc(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
    if not proc_handle:
        raise ProcessTreeError(f"open-process-failed:{ctypes.get_last_error()}")

    try:
        assign_proc = kernel32.AssignProcessToJobObject
        assign_proc.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        assign_proc.restype = ctypes.c_bool
        success = assign_proc(job_handle, proc_handle)
        if not success:
            raise ProcessTreeError(f"assign-job-failed:{ctypes.get_last_error()}")
    finally:
        _close_handle(proc_handle)


def _terminate_job(job_handle: ctypes.c_void_p, exit_code: int = 1) -> None:
    kernel32 = _kernel32()
    term_job = kernel32.TerminateJobObject
    term_job.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    term_job.restype = ctypes.c_bool
    term_job(job_handle, exit_code)


def _close_handle(handle: ctypes.c_void_p) -> None:
    if not handle:
        return
    with contextlib.suppress(OSError, ValueError, AttributeError):
        kernel32 = _kernel32()
        close_h = kernel32.CloseHandle
        close_h.argtypes = [ctypes.c_void_p]
        close_h.restype = ctypes.c_bool
        close_h(handle)


# --- POSIX Owned Process Tree Implementation ---


class PosixProcessTree:
    """Owned child process tree backed by a POSIX process group and session."""

    def __init__(
        self,
        proc: subprocess.Popen[bytes],
        *,
        listener: socket.socket | None = None,
    ) -> None:
        self._proc = proc
        self._listener = listener
        self._closed = False

    @property
    def process(self) -> subprocess.Popen[bytes]:
        return self._proc

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def stdin(self) -> BinaryIO | None:
        return self._proc.stdin

    @property
    def stdout(self) -> BinaryIO | None:
        return self._proc.stdout

    def poll(self) -> int | None:
        return self._proc.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self._proc.wait(timeout=timeout)

    def terminate(self, *, grace_seconds: float = 2.0) -> None:
        """Terminate the child and its entire process group with graceful fallback."""
        if self._proc.poll() is not None:
            return

        # 1. Graceful closure: close stdin to signal EOF on the control pipe
        if self._proc.stdin and not self._proc.stdin.closed:
            try:
                self._proc.stdin.close()
            except OSError:
                pass

        try:
            self._proc.wait(timeout=max(0.01, grace_seconds))
            return
        except subprocess.TimeoutExpired:
            pass

        # 2. SIGTERM to the process group
        try:
            os.killpg(self._proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass

        try:
            self._proc.wait(timeout=min(0.5, max(0.01, grace_seconds / 2)))
            return
        except subprocess.TimeoutExpired:
            pass

        # 3. SIGKILL forced cleanup of the process group
        try:
            os.killpg(self._proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

        try:
            self._proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass

    def close(self) -> None:
        """Idempotently terminate the process tree and clean up owned resources."""
        if self._closed:
            return
        self._closed = True

        try:
            self.terminate()
        finally:
            for stream in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
                if stream and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass
            if self._listener is not None:
                try:
                    self._listener.close()
                except OSError:
                    pass
                self._listener = None


# --- Windows Owned Process Tree Implementation ---


class WindowsJobProcessTree:
    """Owned child process tree backed by a Win32 Job Object with kill-on-close."""

    def __init__(
        self,
        proc: subprocess.Popen[bytes],
        job_handle: ctypes.c_void_p,
        *,
        listener: socket.socket | None = None,
    ) -> None:
        self._proc = proc
        self._job_handle: ctypes.c_void_p | None = job_handle
        self._listener = listener
        self._closed = False

    @property
    def process(self) -> subprocess.Popen[bytes]:
        return self._proc

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def stdin(self) -> BinaryIO | None:
        return self._proc.stdin

    @property
    def stdout(self) -> BinaryIO | None:
        return self._proc.stdout

    def poll(self) -> int | None:
        return self._proc.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self._proc.wait(timeout=timeout)

    def terminate(self, *, grace_seconds: float = 2.0) -> None:
        """Terminate the child and its entire Job Object with graceful fallback."""
        if self._proc.poll() is not None:
            return

        # 1. Graceful closure: close stdin to signal EOF on the control pipe
        if self._proc.stdin and not self._proc.stdin.closed:
            try:
                self._proc.stdin.close()
            except OSError:
                pass

        try:
            self._proc.wait(timeout=max(0.01, grace_seconds))
            return
        except subprocess.TimeoutExpired:
            pass

        # 2. Forced termination via Job Object
        if self._job_handle:
            with contextlib.suppress(OSError, ProcessTreeError):
                _terminate_job(self._job_handle, 1)

        with contextlib.suppress(subprocess.TimeoutExpired):
            self._proc.wait(timeout=1.0)

    def close(self) -> None:
        """Idempotently terminate the process tree, release the Job Object, and clean up."""
        if self._closed:
            return
        self._closed = True

        try:
            self.terminate()
        finally:
            if self._job_handle:
                _close_handle(self._job_handle)
                self._job_handle = None

            for stream in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
                if stream and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass

            if self._listener is not None:
                try:
                    self._listener.close()
                except OSError:
                    pass
                self._listener = None


# --- High-Level Spawning & Lifecycle Handshake ---


def _validate_argv(argv: Sequence[str]) -> list[str]:
    cmd = list(argv)
    if not cmd:
        raise ProcessTreeError("argv-empty")
    for arg in cmd:
        if type(arg) is not str or not arg:
            raise ProcessTreeError("invalid-argv-arg")
    return cmd


def _normalize_platform(name: str | None) -> str:
    if name is None:
        return "nt" if sys.platform == "win32" else "posix"
    if name in {"win32", "windows", "nt"}:
        return "nt"
    return "posix"


def spawn_desktop_child(
    argv: Sequence[str],
    *,
    listener: socket.socket | None = None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    platform_name: str | None = None,
) -> OwnedProcessTree:
    """Spawn a child process bound to an owned process tree.

    On POSIX, creates a new session/process group with passed listener fd.
    On Windows, creates a Job Object with kill-on-close and assigns the blocked child.
    """
    cmd = _validate_argv(argv)
    target_platform = _normalize_platform(platform_name)

    child_env = dict(os.environ if env is None else env)
    if not getattr(sys, "frozen", False):
        repo_src = str(Path(__file__).resolve().parents[2])
        existing_pp = child_env.get("PYTHONPATH", "")
        if repo_src not in existing_pp.split(os.pathsep):
            child_env["PYTHONPATH"] = (
                f"{repo_src}{os.pathsep}{existing_pp}" if existing_pp else repo_src
            )

    if target_platform == "nt":
        job_handle = _create_job_object()
        try:
            _set_job_limits(job_handle)
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=_CREATE_NEW_PROCESS_GROUP,
                cwd=str(cwd) if cwd else None,
                env=child_env,
            )
            try:
                _assign_process_to_job(job_handle, proc.pid)
            except Exception:
                with contextlib.suppress(OSError):
                    proc.kill()
                raise
            return WindowsJobProcessTree(proc, job_handle, listener=listener)
        except Exception:
            _close_handle(job_handle)
            raise

    # POSIX (Linux, macOS, etc.)
    pass_fds: tuple[int, ...] = ()
    if listener is not None:
        pass_fds = (listener.fileno(),)

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        pass_fds=pass_fds,
        close_fds=True,
        cwd=str(cwd) if cwd else None,
        env=child_env,
    )
    return PosixProcessTree(proc, listener=listener)


def _read_child_frame_with_timeout(
    stream: BinaryIO,
    timeout: float,
    *,
    poll_child: Callable[[], int | None],
) -> ReadyResponse | ErrorResponse:
    q: queue.Queue[tuple[ReadyResponse | ErrorResponse | None, Exception | None]] = (
        queue.Queue()
    )

    def reader() -> None:
        try:
            resp = read_child_frame(stream)
            q.put((resp, None))
        except (DesktopControlError, OSError, ValueError) as e:
            q.put((None, e))

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    deadline = time.monotonic() + max(0.01, timeout)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProcessTreeError("startup-timeout")

        # Check if child process exited early
        exit_code = poll_child()
        if exit_code is not None:
            try:
                resp, exc = q.get_nowait()
                if resp is not None:
                    return resp
            except queue.Empty:
                pass
            raise ProcessTreeError(f"child-exited-early:{exit_code}")

        try:
            wait_slice = min(0.05, remaining)
            resp, exc = q.get(timeout=wait_slice)
            if exc is not None:
                exit_code = poll_child()
                if exit_code is not None:
                    raise ProcessTreeError(f"child-exited-early:{exit_code}")
                if isinstance(exc, DesktopControlError):
                    raise ProcessTreeError(
                        f"control-protocol-error:{exc.code}"
                    ) from exc
                raise ProcessTreeError(f"control-stream-error:{exc}") from exc
            assert resp is not None
            return resp
        except queue.Empty:
            continue


def launch_and_handshake_desktop_child(
    argv: Sequence[str],
    *,
    origin: str,
    token: SecretToken,
    listener: socket.socket,
    startup_timeout: float = 5.0,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    platform_name: str | None = None,
) -> tuple[OwnedProcessTree, ReadyResponse]:
    """Launch the validated desktop child and perform the one-shot control handshake."""
    target_platform = _normalize_platform(platform_name)

    tree = spawn_desktop_child(
        argv,
        listener=listener,
        cwd=cwd,
        env=env,
        platform_name=target_platform,
    )

    try:
        if target_platform == "nt":
            listener_data = listener.share(tree.pid)
            start_listener = WindowsSharedListener(data=listener_data)
        else:
            start_listener = PosixListener(fd=listener.fileno())

        start_req = StartRequest(
            origin=origin,
            token=token,
            listener=start_listener,
        )

        if not tree.stdin:
            raise ProcessTreeError("child-stdin-unavailable")

        encoded_frame = encode_control_frame(start_req)
        tree.stdin.write(encoded_frame)
        tree.stdin.flush()

        if not tree.stdout:
            raise ProcessTreeError("child-stdout-unavailable")

        response = _read_child_frame_with_timeout(
            tree.stdout,
            startup_timeout,
            poll_child=tree.poll,
        )

        gate = ParentStartupGate(expected_origin=origin)
        gate.accept(response)

        if isinstance(response, ErrorResponse):
            raise ProcessTreeError(f"child-error:{response.code.value}")

        return tree, response

    except Exception:
        tree.close()
        raise

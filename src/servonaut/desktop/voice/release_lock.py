"""Cross-process file locks for the managed voice runtime.

A running voice worker holds a shared lock on ``.in-use`` inside the release
it runs from, so pruning and removal can tell that the release is still
needed. Run as::

    python -I -m servonaut.desktop.voice.release_lock --hold <file> -- <worker args>

this module takes that lock and then runs the voice worker in the same
process, so the lock lives exactly as long as the worker.

Only the standard library is used: this module runs inside the managed
runtime, which carries none of Servonaut's own dependencies.
"""

from __future__ import annotations

import errno
import functools
import os
import runpy
import sys
import time
from pathlib import Path
from typing import Any, Final, Optional, Sequence

WORKER_MODULE: Final = "servonaut.desktop.voice.worker"
IN_USE_FILENAME: Final = ".in-use"

_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_WOULD_BLOCK: Final = frozenset({errno.EWOULDBLOCK, errno.EAGAIN})
_POLL_INTERVAL_SECONDS: Final = 0.05
# Pruning and removal probe a release with a momentary exclusive lock; a
# starting worker waits that long before treating the release as removed.
_PROBE_WAIT_SECONDS: Final = 1.0
_EXIT_USAGE: Final = 2
_EXIT_RELEASE_BUSY: Final = 3

# Win32 LockFileEx flags and the error it reports for a conflicting lock.
_LOCKFILE_FAIL_IMMEDIATELY: Final = 0x1
_LOCKFILE_EXCLUSIVE_LOCK: Final = 0x2
_ERROR_LOCK_VIOLATION: Final = 33


class LockTimeoutError(OSError):
    """Raised when a lock stays held by someone else until the timeout."""


def try_lock(fd: int, *, exclusive: bool) -> bool:
    """Lock ``fd`` without blocking; False when another holder conflicts.

    Errors other than a conflicting lock are raised, never reported as held.
    """
    if sys.platform == "win32":
        return _windows_try_lock(fd, exclusive=exclusive)
    import fcntl

    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in _WOULD_BLOCK:
            return False
        raise
    return True


def unlock(fd: int) -> None:
    """Release a lock taken with :func:`try_lock`."""
    if sys.platform == "win32":
        _windows_unlock(fd)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


def open_and_lock(path: Path, *, exclusive: bool, timeout: float) -> int:
    """Open or create ``path`` and lock it, polling until ``timeout``.

    Returns the locked descriptor; closing it releases the lock.

    Raises:
        LockTimeoutError: If the lock stays held elsewhere.
        OSError: If the file cannot be opened or locked.
    """
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | _O_CLOEXEC, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while not try_lock(fd, exclusive=exclusive):
            if time.monotonic() >= deadline:
                raise LockTimeoutError(errno.EWOULDBLOCK, "lock is held", str(path))
            time.sleep(_POLL_INTERVAL_SECONDS)
    except BaseException:
        os.close(fd)
        raise
    return fd


def can_lock(path: Path, *, exclusive: bool) -> bool:
    """Whether ``path`` could be locked right now; never creates the file.

    A shared probe detects an exclusive holder without disturbing other
    readers; an exclusive probe detects any holder at all.
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | _O_CLOEXEC)
    except FileNotFoundError:
        return True
    try:
        if not try_lock(fd, exclusive=exclusive):
            return False
        unlock(fd)
        return True
    finally:
        os.close(fd)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Hold a release's in-use lock, then run the voice worker in-process."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 3 or args[0] != "--hold" or args[2] != "--":
        print("usage: release_lock --hold <file> -- <worker arguments>", file=sys.stderr)
        return _EXIT_USAGE
    try:
        # The descriptor stays open, and the lock held, until the process ends.
        open_and_lock(Path(args[1]), exclusive=False, timeout=_PROBE_WAIT_SECONDS)
    except LockTimeoutError:
        print("This voice runtime is being removed.", file=sys.stderr)
        return _EXIT_RELEASE_BUSY
    sys.argv = [WORKER_MODULE, *args[3:]]
    runpy.run_module(WORKER_MODULE, run_name="__main__", alter_sys=True)
    return 0


def _windows_try_lock(fd: int, *, exclusive: bool) -> bool:
    import ctypes
    import msvcrt

    lock_file, _ = _windows_lock_api()
    flags = _LOCKFILE_FAIL_IMMEDIATELY | (_LOCKFILE_EXCLUSIVE_LOCK if exclusive else 0)
    overlapped = _overlapped()
    if lock_file(msvcrt.get_osfhandle(fd), flags, 0, 1, 0, ctypes.byref(overlapped)):
        return True
    code = ctypes.get_last_error()
    if code == _ERROR_LOCK_VIOLATION:
        return False
    raise ctypes.WinError(code)


def _windows_unlock(fd: int) -> None:
    import ctypes
    import msvcrt

    _, unlock_file = _windows_lock_api()
    overlapped = _overlapped()
    if not unlock_file(msvcrt.get_osfhandle(fd), 0, 1, 0, ctypes.byref(overlapped)):
        raise ctypes.WinError(ctypes.get_last_error())


@functools.lru_cache(maxsize=1)
def _windows_lock_api() -> tuple[Any, Any]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    lock_file = kernel32.LockFileEx
    lock_file.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p,
    ]
    lock_file.restype = wintypes.BOOL
    unlock_file = kernel32.UnlockFileEx
    unlock_file.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    ]
    unlock_file.restype = wintypes.BOOL
    return lock_file, unlock_file


def _overlapped() -> Any:
    """A zeroed OVERLAPPED selecting byte offset 0."""
    return _overlapped_type()()


@functools.lru_cache(maxsize=1)
def _overlapped_type() -> Any:
    import ctypes
    from ctypes import wintypes

    class _Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    return _Overlapped


if __name__ == "__main__":
    sys.exit(main())

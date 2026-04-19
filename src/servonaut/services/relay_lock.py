"""File-backed advisory lock that mediates between the two relay modes.

Two processes must never run a `RelayListener` at once:
* the TUI's in-process listener (mode=``tui``);
* the detached ``servonaut connect --bg`` listener (mode=``bg``).

A single exclusive flock on ``~/.servonaut/relay.lock`` is the only arbiter.
Whichever process owns the flock is the authoritative listener. The file's
JSON payload is just introspection — ``{"pid": 123, "mode": "tui"}`` so the
other process can tell the user what's holding it.

Cross-platform: POSIX uses ``fcntl.flock``; Windows uses ``msvcrt.locking``.
The kernel drops the lock automatically on FD close (process exit), so a
crashed holder does not wedge the lock file.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_LOCK_PATH = Path.home() / ".servonaut" / "relay.lock"


class RelayAlreadyActiveError(RuntimeError):
    """Raised when acquiring the relay lock fails because another listener holds it.

    ``owner`` carries the introspection payload (pid + mode + when it was
    acquired) so callers can show a meaningful message instead of the generic
    "already running".
    """

    def __init__(self, owner: "LockOwner") -> None:
        super().__init__(
            f"Relay listener already active: mode={owner.mode} pid={owner.pid}"
        )
        self.owner = owner


@dataclass(frozen=True)
class LockOwner:
    """Introspection payload stored in the lock file while held."""
    pid: Optional[int]
    mode: Optional[str]
    acquired_at: Optional[float] = None

    @classmethod
    def unknown(cls) -> "LockOwner":
        return cls(pid=None, mode=None, acquired_at=None)


def _acquire_exclusive_nonblocking(fd: int) -> bool:
    """Attempt a non-blocking exclusive lock on ``fd``. Returns True on success."""
    if sys.platform == "win32":
        import msvcrt  # type: ignore[import-not-found]
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl  # POSIX
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (BlockingIOError, OSError):
        return False


def _release(fd: int) -> None:
    """Release the lock on ``fd``. Idempotent; errors are swallowed."""
    if sys.platform == "win32":
        import msvcrt
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        return
    import fcntl
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


def read_owner(lock_path: Path = DEFAULT_LOCK_PATH) -> LockOwner:
    """Return the PID+mode recorded in the lock file, or ``LockOwner.unknown()``.

    Does not attempt to acquire the lock. Safe to call from any process.
    """
    try:
        if not lock_path.exists() or lock_path.stat().st_size == 0:
            return LockOwner.unknown()
        data = json.loads(lock_path.read_text() or "{}")
    except (OSError, ValueError):
        return LockOwner.unknown()
    if not isinstance(data, dict):
        return LockOwner.unknown()
    return LockOwner(
        pid=data.get("pid") if isinstance(data.get("pid"), int) else None,
        mode=data.get("mode") if isinstance(data.get("mode"), str) else None,
        acquired_at=(
            float(data["acquired_at"])
            if isinstance(data.get("acquired_at"), (int, float))
            else None
        ),
    )


def is_pid_alive(pid: Optional[int]) -> bool:
    """Best-effort check that ``pid`` is currently a running process."""
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we can't signal it — still "alive".
        return True
    except OSError:
        return False


class RelayLock:
    """Exclusive advisory lock for the relay listener.

    Use as a context manager::

        with RelayLock(mode='tui') as lock:
            await listener.run()

    The flock is released automatically on ``__exit__`` (and on process exit if
    the caller forgets to release). If another process holds the lock,
    :class:`RelayAlreadyActiveError` is raised with introspection about the
    current owner.
    """

    def __init__(self, mode: str, path: Path = DEFAULT_LOCK_PATH) -> None:
        if mode not in {"tui", "bg"}:
            raise ValueError(f"mode must be 'tui' or 'bg', got {mode!r}")
        self._mode = mode
        self._path = Path(path)
        self._fd: Optional[int] = None
        self._held = False

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def path(self) -> Path:
        return self._path

    def acquire(self) -> "RelayLock":
        """Acquire the lock or raise :class:`RelayAlreadyActiveError`."""
        if self._held:
            raise RelayAlreadyActiveError(
                LockOwner(pid=os.getpid(), mode=self._mode, acquired_at=None)
            )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # O_CREAT so the file materialises; we never truncate it during open
        # because a concurrent reader must be able to see the owner info.
        self._fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        if not _acquire_exclusive_nonblocking(self._fd):
            owner = read_owner(self._path)
            os.close(self._fd)
            self._fd = None
            raise RelayAlreadyActiveError(owner)
        self._held = True
        self._write_owner()
        return self

    def _write_owner(self) -> None:
        """Record pid+mode in the lock file so other processes can introspect."""
        import time
        assert self._fd is not None
        try:
            os.lseek(self._fd, 0, os.SEEK_SET)
            os.ftruncate(self._fd, 0)
            payload = json.dumps({
                "pid": os.getpid(),
                "mode": self._mode,
                "acquired_at": time.time(),
            })
            os.write(self._fd, payload.encode("utf-8"))
        except OSError as e:
            logger.warning("Could not write relay lock owner metadata: %s", e)

    def release(self) -> None:
        """Release the lock and truncate the file."""
        if not self._held or self._fd is None:
            return
        try:
            os.lseek(self._fd, 0, os.SEEK_SET)
            os.ftruncate(self._fd, 0)
        except OSError:
            pass
        _release(self._fd)
        try:
            os.close(self._fd)
        except OSError:
            pass
        self._fd = None
        self._held = False

    def __enter__(self) -> "RelayLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

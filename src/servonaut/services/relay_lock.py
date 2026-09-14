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
import math
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_LOCK_PATH = Path.home() / ".servonaut" / "relay.lock"
_WINDOWS_LOCK_BYTE = b"\0"
_WINDOWS_METADATA_OFFSET = 1
MAX_LOCK_METADATA_BYTES = 4096


class RelayAlreadyActiveError(RuntimeError):
    """Raised when acquiring the relay lock fails because another listener holds it.

    ``owner`` carries the introspection payload (pid + mode + when it was
    acquired) so callers can show a meaningful message instead of the generic
    "already running".
    """

    def __init__(self, owner: LockOwner) -> None:
        super().__init__(
            f"Relay listener already active: mode={owner.mode} pid={owner.pid}"
        )
        self.owner = owner


@dataclass(frozen=True)
class LockOwner:
    """Introspection payload stored in the lock file while held."""
    pid: int | None
    mode: str | None
    acquired_at: float | None = None

    @classmethod
    def unknown(cls) -> LockOwner:
        return cls(pid=None, mode=None, acquired_at=None)


def _acquire_exclusive_nonblocking(fd: int) -> bool:
    """Attempt a non-blocking exclusive lock on ``fd``. Returns True on success."""
    if sys.platform == "win32":
        import msvcrt  # type: ignore[import-not-found]
        # ``msvcrt.locking`` operates on a byte range.  Ensure the first byte
        # exists before taking that range for a freshly-created lock file.
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError:
            return False
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
            os.lseek(fd, 0, os.SEEK_SET)
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
        metadata_offset = _WINDOWS_METADATA_OFFSET if sys.platform == "win32" else 0
        if (
            not lock_path.exists()
            or lock_path.stat().st_size <= metadata_offset
            or lock_path.stat().st_size - metadata_offset > MAX_LOCK_METADATA_BYTES
        ):
            return LockOwner.unknown()
        # msvcrt byte-range locks are mandatory.  The lock byte remains at
        # offset zero while held, so never read that byte from another handle.
        with lock_path.open("rb") as owner_file:
            owner_file.seek(metadata_offset)
            raw_metadata = owner_file.read(MAX_LOCK_METADATA_BYTES + 1)
        if len(raw_metadata) > MAX_LOCK_METADATA_BYTES:
            return LockOwner.unknown()
        data = json.loads(raw_metadata.decode("utf-8") or "{}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return LockOwner.unknown()
    if not isinstance(data, dict):
        return LockOwner.unknown()
    pid = data.get("pid")
    mode = data.get("mode")
    acquired_at = data.get("acquired_at")
    if (
        not _is_plain_int(pid)
        or pid <= 0
        or not isinstance(mode, str)
        or mode not in {"tui", "bg"}
        or not _is_valid_acquired_at(acquired_at)
    ):
        return LockOwner.unknown()
    return LockOwner(
        pid=pid,
        mode=mode,
        acquired_at=float(acquired_at) if acquired_at is not None else None,
    )


def active_owner(lock_path: Path = DEFAULT_LOCK_PATH) -> LockOwner | None:
    """Return the owner only while the OS-level relay lock is held.

    The JSON payload is advisory and can survive a crash.  This probe attempts
    a non-blocking acquisition before trusting it, so callers can distinguish
    stale metadata from an active listener.  ``None`` means the lock is free;
    an unknown owner means a lock is held but its metadata is unusable.
    """
    try:
        fd = os.open(lock_path, os.O_RDWR)
    except FileNotFoundError:
        return None
    except OSError:
        return LockOwner.unknown()

    if _acquire_exclusive_nonblocking(fd):
        _release(fd)
        try:
            os.close(fd)
        except OSError:
            pass
        return None

    try:
        return read_owner(lock_path)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def is_active_owner(
    pid: int,
    mode: str,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> bool:
    """Return whether a held lock currently names exactly ``pid`` and ``mode``."""
    owner = active_owner(lock_path)
    return owner is not None and owner.pid == pid and owner.mode == mode


def is_pid_alive(pid: int | None) -> bool:
    """Best-effort, non-destructive check that ``pid`` is currently running."""
    from servonaut.services.process_control import is_process_alive

    return is_process_alive(pid)


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_valid_acquired_at(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
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
        self._fd: int | None = None
        self._held = False

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def path(self) -> Path:
        return self._path

    @property
    def is_held(self) -> bool:
        """Whether this instance currently owns the OS-level lock."""
        return self._held

    def acquire(self) -> RelayLock:
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
        assert self._fd is not None
        try:
            metadata_offset = (
                _WINDOWS_METADATA_OFFSET if sys.platform == "win32" else 0
            )
            os.lseek(self._fd, metadata_offset, os.SEEK_SET)
            os.ftruncate(self._fd, metadata_offset)
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
        if sys.platform == "win32":
            # Keep the mandatory byte-range lock intact until after it is
            # released.  Truncating it first can leave metadata unreadable.
            _release(self._fd)
            try:
                os.lseek(self._fd, 0, os.SEEK_SET)
                os.ftruncate(self._fd, 0)
            except OSError:
                pass
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
            self._held = False
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

    def __enter__(self) -> RelayLock:  # noqa: PYI034 - Python 3.10 support
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

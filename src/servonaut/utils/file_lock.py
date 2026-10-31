"""Exclusive advisory lock on a file, shared between processes.

The app, a standalone MCP server and the CLI can run on one machine at once;
a ``threading`` lock only orders threads of one process. This lock is taken
on a small file instead, with the same primitive as the relay and OAuth
locks (:func:`servonaut.services.relay_lock.try_lock_exclusive`: ``flock`` on
POSIX, ``msvcrt.locking`` on Windows). The kernel drops it when the
descriptor closes, so a crashed holder never wedges the file.

Two :class:`FileLock` objects on one path exclude each other, within a
process as well as across processes. Waiting is bounded: :meth:`acquire` polls
and gives up with :class:`FileLockTimeout`, an ``OSError``, so callers that
already treat an ``OSError`` as a failed write keep their behaviour.
"""
from __future__ import annotations

import contextlib
import errno
import logging
import os
import stat
import time
from pathlib import Path
from typing import Iterator, Optional, Union

from servonaut.services.relay_lock import try_lock_exclusive, unlock

logger = logging.getLogger(__name__)

_DIR_MODE = 0o700
_FILE_MODE = 0o600

#: Paths already warned about; a refused lock is logged once per process, not
#: on every pass that trips over it.
_WARNED: set = set()


def _owner_uid() -> Optional[int]:
    """The user a lock folder or file must belong to (``None`` where there are no uids)."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid is not None else None


class FileLockTimeout(OSError):
    """The lock stayed busy for the whole wait."""


class UnsafeLockError(OSError):
    """A lock folder or file that is not ours or not a plain folder or file."""


class FileLock:
    """One advisory lock on *path*; the file is created 0600 in a 0700 folder.

    With ``private_dir`` the folder must be a real directory (not a link)
    owned by the current user; a looser mode is tightened to 0700. The lock
    file is never opened through a link, must belong to the current user and
    is tightened to 0600. A refusal raises :class:`UnsafeLockError`.

    Not re-entrant: a second :meth:`try_acquire` on the same object while held
    is refused like any other holder. Callers that need re-entrancy count
    their own nesting (see ``MemoryStore.annotation_lock``).
    """

    def __init__(self, path: Union[str, Path], *, private_dir: bool = False) -> None:
        self._path = Path(path)
        self._private_dir = private_dir
        self._fd: Optional[int] = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def try_acquire(self) -> bool:
        """Take the lock if it is free right now; ``False`` when another holder has it."""
        if self._fd is not None:
            return False
        fd = self._open()
        if not try_lock_exclusive(fd):
            os.close(fd)
            return False
        self._fd = fd
        return True

    def acquire(self, timeout: float, poll_seconds: float) -> None:
        """Take the lock, polling every *poll_seconds* for at most *timeout* seconds.

        Raises:
            FileLockTimeout: still busy after *timeout*.
            OSError: the lock file cannot be created or opened.
        """
        self.acquire_until(time.monotonic() + max(timeout, 0.0), poll_seconds)

    def acquire_until(self, deadline: float, poll_seconds: float) -> None:
        """Like :meth:`acquire`, with the bound given as a ``time.monotonic()`` deadline.

        Lets a caller that spent part of one budget elsewhere (another lock)
        hand over only what is left. Never sleeps past the deadline.
        """
        while not self.try_acquire():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FileLockTimeout(f"{self._path.name} is held by another process")
            time.sleep(min(poll_seconds, remaining))

    def release(self) -> None:
        """Let go of the lock; safe to call when not held."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        unlock(fd)
        os.close(fd)

    @contextlib.contextmanager
    def hold(self, timeout: float, poll_seconds: float) -> Iterator[None]:
        """Hold the lock for the ``with`` block (bounded wait, see :meth:`acquire`)."""
        self.acquire(timeout, poll_seconds)
        try:
            yield
        finally:
            self.release()

    def _open(self) -> int:
        directory = self._path.parent
        if self._private_dir:
            self._check_private_dir(directory)
        elif not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            # mkdir's mode is cut by the umask; the lock folder is private.
            os.chmod(directory, _DIR_MODE)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self._path, flags, _FILE_MODE)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                self._refuse("the lock file is a link")
            raise
        try:
            self._check_file(fd)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _check_private_dir(self, directory: Path) -> None:
        try:
            info = os.lstat(directory)
        except FileNotFoundError:
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, _DIR_MODE)
            return
        if not stat.S_ISDIR(info.st_mode):
            self._refuse("the lock folder is a link or not a folder")
        uid = _owner_uid()
        if uid is not None and info.st_uid != uid:
            self._refuse("the lock folder belongs to another user")
        if uid is not None and stat.S_IMODE(info.st_mode) != _DIR_MODE:
            os.chmod(directory, _DIR_MODE)

    def _check_file(self, fd: int) -> None:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            self._refuse("the lock file is not a plain file")
        uid = _owner_uid()
        if uid is None:
            return
        if info.st_uid != uid:
            self._refuse("the lock file belongs to another user")
        if stat.S_IMODE(info.st_mode) != _FILE_MODE:
            os.fchmod(fd, _FILE_MODE)

    def _refuse(self, reason: str) -> None:
        key = str(self._path)
        if key not in _WARNED:
            _WARNED.add(key)
            logger.warning("Lock %s refused: %s", self._path.name, reason)
        raise UnsafeLockError(f"{self._path.name}: {reason}")

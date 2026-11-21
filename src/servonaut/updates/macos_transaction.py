"""Durable on-disk state for replacing an eligible macOS application bundle."""

from __future__ import annotations

import ctypes
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from servonaut.utils.atomic_file import write_json_atomic

BUNDLE_NAME = "Servonaut.app"
WORK_NAME = ".servonaut-desktop-update"
_RENAME_SWAP = 0x00000002  # Darwin sys/stdio.h
_RENAME_EXCL = 0x00000004


class MacUpdateError(RuntimeError):
    """Automatic installation cannot safely proceed."""


@dataclass(frozen=True)
class DirectoryIdentity:
    device: int
    inode: int


def identity(path: Path) -> DirectoryIdentity | None:
    """Identify a real directory across an atomic rename."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise MacUpdateError("The update destination is not a user-owned directory.")
    return DirectoryIdentity(info.st_dev, info.st_ino)


def rename_native(source: Path, destination: Path, *, exchange: bool = False) -> None:
    """Use Darwin's atomic swap or no-replace rename."""
    try:
        rename = ctypes.CDLL(None, use_errno=True).renamex_np
    except AttributeError as exc:
        raise MacUpdateError("Atomic application replacement is unavailable.") from exc
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    flag = _RENAME_SWAP if exchange else _RENAME_EXCL
    if rename(os.fsencode(source), os.fsencode(destination), flag):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class SwapJournal:
    """Expected roles of the directories in one prepared replacement."""

    old: DirectoryIdentity
    new: DirectoryIdentity
    archived_previous: DirectoryIdentity | None

    @classmethod
    def read(cls, journal: Path) -> SwapJournal:
        def decode(pair: object) -> DirectoryIdentity:
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("Invalid directory identity")
            if any(type(value) is not int or value <= 0 for value in pair):
                raise ValueError("Invalid directory identity")
            return DirectoryIdentity(*pair)

        try:
            with journal.open("rb") as stream:
                raw = json.loads(stream.read(4097))
            if not isinstance(raw, dict) or set(raw) != {"old", "new", "prior"}:
                raise ValueError("Invalid update journal")
            old, new = decode(raw["old"]), decode(raw["new"])
            prior = None if raw["prior"] is None else decode(raw["prior"])
            if len({old, new, prior}) != 3 or old.device != new.device:
                raise ValueError("Invalid update journal")
            if prior is not None and old.device != prior.device:
                raise ValueError("Invalid backup identity")
            return cls(old, new, prior)
        except (OSError, ValueError, TypeError) as exc:
            raise MacUpdateError("The application update journal could not be verified.") from exc

    def write(self, journal: Path) -> None:
        def encode(item: DirectoryIdentity | None) -> list[int] | None:
            return [item.device, item.inode] if item is not None else None

        write_json_atomic(journal, {
            "old": encode(self.old),
            "new": encode(self.new),
            "prior": encode(self.archived_previous),
        })
        sync_directory(journal.parent)


@dataclass(frozen=True)
class BundleTransaction:
    """Reconcile, commit or roll back while holding exclusive admission."""

    installed: Path
    work: Path
    rename: Callable[..., None] = rename_native

    @property
    def journal_path(self) -> Path:
        return self.work / "replacement.json"

    @property
    def incoming(self) -> Path:
        return self.work / BUNDLE_NAME

    @property
    def previous(self) -> Path:
        return self.installed.with_name(f"{self.installed.name}.previous")

    @property
    def archived(self) -> Path:
        return self.work / "earlier.app"

    def prepare(self, known_previous: DirectoryIdentity | None) -> SwapJournal:
        old, new = identity(self.installed), identity(self.incoming)
        if old is None or new is None or old == new or old.device != new.device:
            raise MacUpdateError("Both application bundles must be on the same volume.")
        actual_previous = identity(self.previous)
        if actual_previous is not None and actual_previous != known_previous:
            raise MacUpdateError("An unrecognized previous application is present.")
        if self.journal_path.exists() or identity(self.archived) is not None:
            raise MacUpdateError("An earlier application update needs recovery.")
        journal = SwapJournal(old, new, actual_previous)
        journal.write(self.journal_path)
        return journal

    def _move(self, source: Path, destination: Path, *, exchange: bool = False) -> None:
        self.rename(source, destination, exchange=exchange)
        sync_directory(self.work)
        sync_directory(self.installed.parent)

    def commit(self, journal: SwapJournal) -> None:
        if identity(self.installed) != journal.old or identity(self.incoming) != journal.new:
            raise MacUpdateError("The installed or staged application changed.")
        if journal.archived_previous is not None:
            if identity(self.previous) != journal.archived_previous:
                raise MacUpdateError("The previous application changed.")
            self._move(self.previous, self.archived)
        self._move(self.incoming, self.installed, exchange=True)
        self.file_previous(journal)

    def file_previous(self, journal: SwapJournal) -> None:
        if identity(self.installed) != journal.new:
            raise MacUpdateError("The installed application does not match the journal.")
        if identity(self.archived) != journal.archived_previous:
            raise MacUpdateError("The earlier backup does not match the journal.")
        if identity(self.previous) == journal.old and identity(self.incoming) is None:
            return
        if identity(self.incoming) != journal.old or identity(self.previous) is not None:
            raise MacUpdateError("The displaced application could not be identified.")
        self._move(self.incoming, self.previous)

    def rollback(self, journal: SwapJournal) -> None:
        current = identity(self.installed)
        if current == journal.new:
            self.file_previous(journal)
            self._move(self.installed, self.previous, exchange=True)
        elif current != journal.old:
            raise MacUpdateError("The installed application does not match the journal.")
        self._restore_previous(journal)
        self.journal_path.unlink()
        sync_directory(self.work)

    def _restore_previous(self, journal: SwapJournal) -> None:
        previous = identity(self.previous)
        if previous == journal.new:
            if identity(self.incoming) is not None:
                raise MacUpdateError("The failed update could not be retained safely.")
            self._move(self.previous, self.incoming)
        elif previous not in (None, journal.archived_previous):
            raise MacUpdateError("The previous application changed.")
        archived = identity(self.archived)
        if archived is not None:
            if archived != journal.archived_previous or identity(self.previous) is not None:
                raise MacUpdateError("The earlier backup could not be restored.")
            self._move(self.archived, self.previous)
        if identity(self.previous) != journal.archived_previous:
            raise MacUpdateError("The earlier backup could not be found.")

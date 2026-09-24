"""Link-preserving payload traversal shared by the distribution packagers.

Entries are read with ``lstat`` exactly as the standalone CLI archiver reads
them: a symbolic link is packaged as a link (never as a copy of its target, and
never dropped because it points at a directory), and every link must resolve
inside the payload through the same confined resolver.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat

from scripts.standalone_cli.artifact_filesystem import validate_relative_links
from scripts.standalone_cli.artifact_types import ArtifactEvidenceError, PayloadEntry

_LINK_PLATFORM = "posix"


class PayloadTreeError(ValueError):
    """Raised when a payload contains an entry that cannot be packaged safely."""


def walk_payload(root: Path, *, allow_symlinks: bool = True) -> list[PayloadEntry]:
    """Return every entry below ``root`` sorted by path, without following links.

    Raises:
        PayloadTreeError: For special files, for links when ``allow_symlinks`` is
            false, and for links that are absolute, dangling, cyclic or escape
            ``root``.
    """
    entries: list[PayloadEntry] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as scanner:
            children = sorted(scanner, key=lambda item: item.name)
        for child in children:
            entry = _payload_entry(root, Path(child.path), allow_symlinks)
            entries.append(entry)
            if entry.kind == "directory":
                pending.append(Path(child.path))
    entries.sort(key=lambda entry: entry.relative_path.as_posix())
    _validate_links(entries)
    return entries


def _payload_entry(root: Path, path: Path, allow_symlinks: bool) -> PayloadEntry:
    relative = PurePosixPath(path.relative_to(root).as_posix())
    status = path.lstat()
    mode = stat.S_IMODE(status.st_mode)
    if stat.S_ISDIR(status.st_mode):
        return PayloadEntry(relative, "directory", mode, 0, None, None)
    if stat.S_ISREG(status.st_mode):
        return PayloadEntry(relative, "file", mode, status.st_size, None, None)
    if stat.S_ISLNK(status.st_mode):
        if not allow_symlinks:
            raise PayloadTreeError(
                f"Payload entry '{relative}' is a symbolic link, which this package format cannot contain."
            )
        return PayloadEntry(relative, "symlink", mode, 0, None, os.readlink(path))
    raise PayloadTreeError(
        f"Payload entry '{relative}' is not a regular file, directory or symbolic link."
    )


def _validate_links(entries: list[PayloadEntry]) -> None:
    if not any(entry.kind == "symlink" for entry in entries):
        return
    try:
        validate_relative_links(entries, _LINK_PLATFORM, _link_resolution_budget(entries))
    except ArtifactEvidenceError as error:
        raise PayloadTreeError(f"Unsafe symbolic link in payload: {error}") from error


def _link_resolution_budget(entries: list[PayloadEntry]) -> int:
    """Return a resolver step budget that this tree's links can never exhaust.

    The payload is already fully enumerated, so the budget only has to exceed
    the work its links can demand: resolving one target component costs at most
    one step per directory level plus two bookkeeping steps. Scaling with the
    tree keeps large payloads working without a fixed entry limit.
    """
    depth = max(len(entry.relative_path.parts) for entry in entries)
    link_components = sum(
        len(entry.link_target.split("/")) + 1
        for entry in entries
        if entry.kind == "symlink" and entry.link_target is not None
    )
    return len(entries) + 1 + link_components * (2 * depth + 2)

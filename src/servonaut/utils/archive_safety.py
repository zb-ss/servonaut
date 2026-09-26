"""Safe extraction of downloaded tar archives.

Model archives come from the network, so every member is vetted before
anything touches the disk, and one bad member fails the whole archive: a
tampered archive must produce nothing, not a partial tree. Only plain
files and directories are accepted — links of any kind and special files
are refused outright on every Python version, which closes the symlink
chain escapes that older interpreters (without the PEP 706 ``data``
filter) would otherwise follow.
"""

from __future__ import annotations

import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import List

_DRIVE_LETTER = re.compile(r"^[A-Za-z]:")


class UnsafeArchiveError(ValueError):
    """Raised when an archive member could escape or subvert its destination."""


def tar_member_rejection(member: tarfile.TarInfo) -> str:
    """Why *member* must not be extracted, or an empty string if it may.

    Rejects the classic archive attacks: absolute paths, Windows drive
    letters, ``..`` traversal, links pointing anywhere, and special files.
    Only plain files and directories survive.
    """
    name = member.name.replace("\\", "/")
    if name.startswith("/"):
        return "absolute path"
    if _DRIVE_LETTER.match(name):
        return "drive letter"
    if ".." in PurePosixPath(name).parts:
        return "parent-directory traversal"
    if member.issym() or member.islnk():
        return "link member"
    if not (member.isfile() or member.isdir()):
        return "special file"
    return ""


def vetted_tar_members(archive: tarfile.TarFile) -> List[tarfile.TarInfo]:
    """Return every member of *archive*, or raise if any one is unsafe.

    Raises:
        UnsafeArchiveError: Naming the first rejected member and why.
    """
    members = archive.getmembers()
    for member in members:
        reason = tar_member_rejection(member)
        if reason:
            raise UnsafeArchiveError(
                f"Unsafe archive member {member.name!r}: {reason}"
            )
    return members


def extract_tar_safely(archive: tarfile.TarFile, destination: Path) -> None:
    """Extract *archive* into *destination* after vetting every member.

    Raises:
        UnsafeArchiveError: If any member is rejected; nothing is extracted.
    """
    members = vetted_tar_members(archive)
    destination.mkdir(parents=True, exist_ok=True)
    if hasattr(tarfile, "data_filter"):
        # PEP 706 filter as a second layer where the runtime has it; the
        # vetting above is the layer guaranteed on every interpreter.
        archive.extractall(destination, members=members, filter="data")
    else:  # pragma: no cover — depends on the patch level of 3.10/3.11
        archive.extractall(destination, members=members)  # noqa: S202 — members vetted above

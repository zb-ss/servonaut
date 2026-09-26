"""Read the runtime marker a release artifact carries, without unpacking it.

Every packaged build writes ``servonaut-runtime.json`` beside its executables.
Release tooling reads it back out of the finished artifact to check that the
release channel and packaging revision the build stamped match the release
being cut. Archives are streamed and only the marker member is read.
"""

from __future__ import annotations

import json
import tarfile
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final

from servonaut.distribution.manifest import ArtifactKind, ManifestError, ReleaseArtifact

MARKER_NAME: Final = "servonaut-runtime.json"
# A marker is a handful of scalar fields; the runtime refuses larger ones too.
_MAX_MARKER_BYTES: Final = 256 * 1024
_AR_MAGIC: Final = b"!<arch>\n"
_AR_HEADER_BYTES: Final = 60
_DEB_DATA_MODES: Final = {
    "data.tar": "r|",
    "data.tar.gz": "r|gz",
    "data.tar.xz": "r|xz",
}


class ArtifactMarkerError(ManifestError):
    """Raised when an artifact's runtime marker is missing, repeated or unreadable."""


def read_artifact_marker(artifact: ReleaseArtifact, path: Path) -> dict[str, object]:
    """Return the runtime marker inside one release artifact file.

    Standalone archives carry the marker at their root and Debian packages
    under ``/opt/<package>/``. Disk images and Windows Installer databases
    cannot be read with the standard library, so they are refused: a release
    that cannot prove its identity does not pass.
    """
    reader = _reader_for(artifact)
    try:
        raw = reader(path)
    except ArtifactMarkerError:
        raise
    except (OSError, EOFError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise ArtifactMarkerError("The artifact could not be read.") from error
    try:
        marker = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ArtifactMarkerError("The artifact's runtime marker is not valid JSON.") from error
    if not isinstance(marker, dict):
        raise ArtifactMarkerError("The artifact's runtime marker is not a JSON object.")
    return marker


def _reader_for(artifact: ReleaseArtifact) -> Callable[[Path], bytes]:
    if artifact.kind is ArtifactKind.STANDALONE_CLI:
        if artifact.filename.endswith(".tar.gz"):
            return _root_marker_from_tar
        if artifact.filename.endswith(".zip"):
            return _root_marker_from_zip
        raise ArtifactMarkerError("The standalone archive format is not supported.")
    if artifact.kind is ArtifactKind.UBUNTU_DEB:
        return _marker_from_deb
    raise ArtifactMarkerError(
        "The runtime marker of this artifact kind cannot be read here."
    )


def _root_marker_from_tar(path: Path) -> bytes:
    with path.open("rb") as handle:
        return _single_tar_marker(handle, "r|gz", _is_root_marker)


def _root_marker_from_zip(path: Path) -> bytes:
    with zipfile.ZipFile(path) as archive:
        members = [
            info
            for info in archive.infolist()
            if not info.is_dir() and _is_root_marker(PurePosixPath(info.filename))
        ]
        if len(members) != 1:
            raise ArtifactMarkerError(_count_message(len(members)))
        if members[0].file_size > _MAX_MARKER_BYTES:
            raise ArtifactMarkerError("The artifact's runtime marker is too large.")
        with archive.open(members[0]) as member:
            return _read_bounded(member)


def _marker_from_deb(path: Path) -> bytes:
    with path.open("rb") as handle:
        if handle.read(len(_AR_MAGIC)) != _AR_MAGIC:
            raise ArtifactMarkerError("The Debian package is not an ar archive.")
        while True:
            header = handle.read(_AR_HEADER_BYTES)
            if not header:
                raise ArtifactMarkerError("The Debian package has no data archive.")
            name, size = _ar_member(header)
            if name in _DEB_DATA_MODES:
                member = _BoundedReader(handle, size)
                return _single_tar_marker(member, _DEB_DATA_MODES[name], _is_opt_marker)
            handle.seek(size + size % 2, 1)


def _ar_member(header: bytes) -> tuple[str, int]:
    if len(header) != _AR_HEADER_BYTES or header[58:60] != b"`\n":
        raise ArtifactMarkerError("The Debian package has a malformed member header.")
    try:
        name = header[0:16].decode("ascii").rstrip(" ").removesuffix("/")
        size = int(header[48:58].decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        raise ArtifactMarkerError("The Debian package has a malformed member header.") from None
    if size < 0:
        raise ArtifactMarkerError("The Debian package has a malformed member header.")
    return name, size


def _single_tar_marker(
    stream: BinaryIO, mode: str, is_marker: Callable[[PurePosixPath], bool]
) -> bytes:
    """Stream the whole archive so a repeated marker cannot shadow the first."""
    found: bytes | None = None
    count = 0
    with tarfile.open(fileobj=stream, mode=mode) as archive:
        for member in archive:
            if not is_marker(PurePosixPath(member.name)):
                continue
            count += 1
            if not member.isreg() or member.size > _MAX_MARKER_BYTES or count > 1:
                continue
            extracted = archive.extractfile(member)
            if extracted is not None:
                found = _read_bounded(extracted)
    if count != 1 or found is None:
        raise ArtifactMarkerError(_count_message(count))
    return found


def _is_root_marker(path: PurePosixPath) -> bool:
    return _parts(path) == (MARKER_NAME,)


def _is_opt_marker(path: PurePosixPath) -> bool:
    parts = _parts(path)
    return len(parts) == 3 and parts[0] == "opt" and parts[2] == MARKER_NAME


def _parts(path: PurePosixPath) -> tuple[str, ...]:
    return tuple(part for part in path.parts if part not in {".", "/"})


def _count_message(count: int) -> str:
    if count == 0:
        return "The artifact carries no runtime marker."
    return "The artifact's runtime marker is missing, repeated or not a regular file."


def _read_bounded(stream: BinaryIO) -> bytes:
    data = stream.read(_MAX_MARKER_BYTES + 1)
    if len(data) > _MAX_MARKER_BYTES:
        raise ArtifactMarkerError("The artifact's runtime marker is too large.")
    return data


class _BoundedReader:
    """A read-only view of ``size`` bytes from the current position of a stream."""

    def __init__(self, stream: BinaryIO, size: int) -> None:
        self._stream = stream
        self._remaining = size

    def read(self, size: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if size < 0 or size > self._remaining:
            size = self._remaining
        data = self._stream.read(size)
        self._remaining -= len(data)
        return data


def identity_mismatches(
    marker: Mapping[str, object],
    *,
    artifact: ReleaseArtifact,
    product_version: str,
    channel: str,
    packaging_revision: int,
) -> tuple[str, ...]:
    """Name each marker field that disagrees with the release being cut."""
    expected: dict[str, object] = {
        "distribution": artifact.distribution.value,
        "product_version": product_version,
        "channel": channel,
        "packaging_revision": packaging_revision,
    }
    return tuple(
        field
        for field, value in expected.items()
        if type(marker.get(field)) is not type(value) or marker.get(field) != value
    )

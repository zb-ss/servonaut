"""Deterministic archive creation and safe extraction for payload snapshots."""

from __future__ import annotations

import gzip
import os
import shutil
import stat
import tarfile
import tempfile
import time
import zipfile
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType

from scripts.standalone_cli.artifact_filesystem import (
    _sha256_file,
    validate_relative_links,
)
from scripts.standalone_cli.artifact_types import (
    ArchiveOwner,
    ArtifactEvidenceError,
    PayloadEntry,
    PayloadSnapshot,
)
from scripts.standalone_cli.evidence_policy_types import EvidenceLimits, EvidencePolicy
from scripts.standalone_cli.model import TargetSpec

_ARCHIVE_COMPARE_CHUNK_SIZE = 1024 * 1024
_ARCHIVE_READ_ERRORS = (
    tarfile.TarError,
    zipfile.BadZipFile,
    gzip.BadGzipFile,
    zlib.error,
    EOFError,
    RuntimeError,
)
_TAR_MEMBER_KINDS = {
    tarfile.REGTYPE: "file",
    tarfile.AREGTYPE: "file",
    tarfile.DIRTYPE: "directory",
    tarfile.SYMTYPE: "symlink",
}
_TAR_EXTENDED_HEADER_TYPES = frozenset(
    {
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
    }
)
# Our writer ends the stream with two zero blocks padded to a full record, so
# at most this much zero-filled data may follow the first end-of-archive block.
_TAR_END_PADDING_BYTES = tarfile.RECORDSIZE + tarfile.BLOCKSIZE


def create_archive_from_snapshot(
    snapshot: PayloadSnapshot,
    target: TargetSpec,
    policy: EvidencePolicy,
    output_dir: Path,
) -> ArchiveOwner:
    """Write a deterministic archive into one new private cooperative output root."""
    _validate_snapshot_for_target(snapshot, target, policy.limits)
    _validate_archive_policy(policy)
    epoch = _source_date_epoch()
    return _create_archive_with_epoch(snapshot, target, policy, output_dir, epoch)


def _create_archive_with_epoch(
    snapshot: PayloadSnapshot,
    target: TargetSpec,
    policy: EvidencePolicy,
    output_dir: Path,
    epoch: int,
) -> ArchiveOwner:
    """Write one deterministic archive with an already captured source epoch."""
    _validate_snapshot_for_target(snapshot, target, policy.limits)
    _validate_archive_policy(policy)
    _validate_source_date_epoch(epoch)
    output_identity = _create_archive_output_root(output_dir)
    archive_name = target.artifact_name_template.format(
        product_version=str(snapshot.marker["product_version"]),
        target=target.name,
        extension=target.archive_extension,
    )
    destination = output_dir / archive_name
    staging: Path | None = None
    archive_identity: tuple[int, int] | None = None
    completed = False
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=".archive-", suffix=".tmp", dir=output_dir
        )
        os.close(descriptor)
        staging = Path(temporary_path)
        if target.archive_format == "tar.gz":
            _write_tar_gz(snapshot, staging, epoch, policy.archive_compression_level)
        elif target.archive_format == "zip":
            _write_zip(snapshot, staging, epoch, policy.archive_compression_level)
        else:
            raise ArtifactEvidenceError("target archive format is invalid")
        _regular_file(staging, "archive staging")
        if destination.exists() or destination.is_symlink():
            raise ArtifactEvidenceError("archive output already exists")
        staging.replace(destination)
        status = destination.lstat()
        if not stat.S_ISREG(status.st_mode):
            raise ArtifactEvidenceError("archive output is invalid")
        archive_identity = status.st_dev, status.st_ino
        owner = ArchiveOwner(
            path=destination,
            output_root=output_dir,
            device=status.st_dev,
            inode=status.st_ino,
            sha256=_sha256_file(destination),
            output_device=output_identity[0],
            output_inode=output_identity[1],
            archive_profile=MappingProxyType(
                _archive_profile(target, policy.archive_compression_level)
            ),
            source_date_epoch=epoch,
        )
        completed = True
        return owner
    finally:
        if staging is not None:
            _remove_regular_file(staging)
        if not completed:
            if archive_identity is not None:
                _remove_owned_archive(destination, output_dir, archive_identity)
            _remove_empty_output_root(output_dir, output_identity)


def _verify_repeated_archive(
    snapshot: PayloadSnapshot,
    target: TargetSpec,
    policy: EvidencePolicy,
    primary_owner: ArchiveOwner,
) -> None:
    """Prove one validated snapshot serializes identically without retaining a copy."""
    primary_size = _validate_repeated_primary(snapshot, target, policy, primary_owner)
    repeat_root = primary_owner.output_root.parent / "archive-repeat"
    if repeat_root == primary_owner.output_root or not _path_is_absent(repeat_root):
        raise ArtifactEvidenceError("repeated archive output is invalid")

    repeated_owner: ArchiveOwner | None = None
    try:
        repeated_owner = _create_archive_with_epoch(
            snapshot,
            target,
            policy,
            repeat_root,
            primary_owner.source_date_epoch,
        )
        repeated_size = _owned_archive_size(repeated_owner)
        if (
            repeated_owner.path.name != primary_owner.path.name
            or dict(repeated_owner.archive_profile)
            != dict(primary_owner.archive_profile)
            or repeated_owner.source_date_epoch != primary_owner.source_date_epoch
            or repeated_size != primary_size
        ):
            raise ArtifactEvidenceError("repeated archive differs")
        _compare_archive_bytes(primary_owner.path, repeated_owner.path, primary_size)
    finally:
        if repeated_owner is not None:
            delete_owned_archive(repeated_owner)
            if (
                not _path_is_absent(repeated_owner.path)
                or not _path_is_absent(repeated_owner.output_root)
                or not _primary_owner_matches(primary_owner, primary_size)
            ):
                raise ArtifactEvidenceError("repeated archive cleanup failed")


def _validate_repeated_primary(
    snapshot: PayloadSnapshot,
    target: TargetSpec,
    policy: EvidencePolicy,
    primary_owner: ArchiveOwner,
) -> int:
    if primary_owner.output_root != primary_owner.output_root.parent / "archive":
        raise ArtifactEvidenceError("repeated archive primary is invalid")
    if primary_owner.path.parent != primary_owner.output_root:
        raise ArtifactEvidenceError("repeated archive primary is invalid")
    _validate_source_date_epoch(primary_owner.source_date_epoch)
    expected_name = target.artifact_name_template.format(
        product_version=str(snapshot.marker["product_version"]),
        target=target.name,
        extension=target.archive_extension,
    )
    if primary_owner.path.name != expected_name or dict(
        primary_owner.archive_profile
    ) != _archive_profile(target, policy.archive_compression_level):
        raise ArtifactEvidenceError("repeated archive primary is invalid")
    _validate_snapshot_for_target(snapshot, target, policy.limits)
    _validate_archive_policy(policy)
    return _owned_archive_size(primary_owner)


def _owned_archive_size(owner: ArchiveOwner) -> int:
    try:
        archive_status = owner.path.lstat()
        root_status = owner.output_root.lstat()
    except OSError as error:
        raise ArtifactEvidenceError("repeated archive primary is invalid") from error
    if (
        not stat.S_ISREG(archive_status.st_mode)
        or archive_status.st_dev != owner.device
        or archive_status.st_ino != owner.inode
        or owner.path.parent != owner.output_root
        or not stat.S_ISDIR(root_status.st_mode)
        or root_status.st_dev != owner.output_device
        or root_status.st_ino != owner.output_inode
    ):
        raise ArtifactEvidenceError("repeated archive primary is invalid")
    return archive_status.st_size


def _compare_archive_bytes(primary: Path, repeated: Path, size: int) -> None:
    try:
        with primary.open("rb") as first, repeated.open("rb") as second:
            remaining = size
            while remaining:
                chunk_size = min(_ARCHIVE_COMPARE_CHUNK_SIZE, remaining)
                first_chunk = first.read(chunk_size)
                second_chunk = second.read(chunk_size)
                if (
                    len(first_chunk) != chunk_size
                    or len(second_chunk) != chunk_size
                    or first_chunk != second_chunk
                ):
                    raise ArtifactEvidenceError("repeated archive differs")
                remaining -= chunk_size
            if first.read(1) or second.read(1):
                raise ArtifactEvidenceError("repeated archive differs")
    except OSError as error:
        raise ArtifactEvidenceError("repeated archive differs") from error


def _primary_owner_matches(owner: ArchiveOwner, size: int) -> bool:
    try:
        return _owned_archive_size(owner) == size
    except ArtifactEvidenceError:
        return False


def _path_is_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def delete_owned_archive(owner: ArchiveOwner) -> None:
    """Delete only a regular archive still matching its recorded identity and hash."""
    try:
        status = owner.path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_dev != owner.device
            or status.st_ino != owner.inode
            or owner.path.parent != owner.output_root
            or _sha256_file(owner.path) != owner.sha256
        ):
            return
        owner.path.unlink()
        _remove_empty_output_root(
            owner.output_root, (owner.output_device, owner.output_inode)
        )
    except (ArtifactEvidenceError, OSError):
        return


def extract_archive_safely(
    archive: Path, destination: Path, limits: EvidenceLimits
) -> Path:
    """Pre-validate and extract one archive into a new private destination."""
    archive = _regular_file(archive, "archive")
    _validate_limits(limits)
    if destination.exists() or destination.is_symlink():
        raise ArtifactEvidenceError("extraction destination already exists")
    reader: tarfile.TarFile | zipfile.ZipFile | None = None
    identity: tuple[int, int] | None = None
    try:
        members, reader = _archive_members(archive, limits)
        _validate_archive_members(
            members, archive.suffix == ".zip", limits.max_payload_entries
        )
        destination.mkdir(mode=0o700)
        identity = _directory_identity(destination)
        _write_extraction(members, reader, destination, limits)
        return destination
    except _ARCHIVE_READ_ERRORS as error:
        if reader is not None:
            reader.close()
            reader = None
        if identity is not None:
            _remove_owned_tree(destination, identity)
        raise ArtifactEvidenceError("archive could not be read") from error
    except BaseException:
        if reader is not None:
            reader.close()
            reader = None
        if identity is not None:
            _remove_owned_tree(destination, identity)
        raise
    finally:
        if reader is not None:
            reader.close()


def extract_archive_for_smoke(archive: Path, destination: Path) -> Path:
    """Safely extract for smoke using the same configured evidence limits."""
    from scripts.standalone_cli.evidence_policy import load_evidence_policy

    policy_path = (
        Path(__file__).resolve().parents[2]
        / "packaging"
        / "standalone_cli"
        / "evidence-policy.json"
    )
    return extract_archive_safely(
        archive, destination, load_evidence_policy(policy_path).limits
    )


class _ArchiveMember:
    def __init__(
        self,
        relative_path: PurePosixPath,
        kind: str,
        mode: int,
        size: int,
        link_target: str | None,
        source: tarfile.TarInfo | zipfile.ZipInfo,
    ) -> None:
        self.relative_path = relative_path
        self.kind = kind
        self.mode = mode
        self.size = size
        self.link_target = link_target
        self.source = source


def _write_tar_gz(
    snapshot: PayloadSnapshot, destination: Path, epoch: int, compression_level: int
) -> None:
    with (
        destination.open("wb") as raw,
        gzip.GzipFile(
            fileobj=raw,
            mode="wb",
            filename="",
            mtime=epoch,
            compresslevel=compression_level,
        ) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive,
    ):
        for entry in snapshot.entries:
            info = tarfile.TarInfo(_member_name(entry))
            info.mode = entry.mode
            info.mtime = epoch
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if entry.kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif entry.kind == "file":
                info.type = tarfile.REGTYPE
                info.size = entry.size
                with (snapshot.root / entry.relative_path).open("rb") as source:
                    archive.addfile(info, source)
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = entry.link_target or ""
                archive.addfile(info)


def _write_zip(
    snapshot: PayloadSnapshot, destination: Path, epoch: int, compression_level: int
) -> None:
    timestamp = _zip_timestamp(epoch)
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=compression_level,
    ) as archive:
        for entry in snapshot.entries:
            if entry.kind == "symlink":
                raise ArtifactEvidenceError(
                    "Windows archives cannot contain symbolic links"
                )
            info = zipfile.ZipInfo(_member_name(entry), date_time=timestamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            if entry.kind == "directory":
                info.external_attr = ((entry.mode & 0o777) << 16) | 0x10
                archive.writestr(info, b"")
                continue
            info.external_attr = (stat.S_IFREG | (entry.mode & 0o777)) << 16
            with (
                archive.open(info, "w") as target,
                (snapshot.root / entry.relative_path).open("rb") as source,
            ):
                shutil.copyfileobj(source, target, length=1024 * 1024)


def _archive_members(
    archive: Path, limits: EvidenceLimits
) -> tuple[list[_ArchiveMember], tarfile.TarFile | zipfile.ZipFile]:
    try:
        if archive.suffix == ".zip":
            reader = zipfile.ZipFile(archive)
            try:
                members: list[_ArchiveMember] = []
                regular_total = 0
                for info in reader.infolist():
                    kind = "directory" if info.is_dir() else "file"
                    mode = (info.external_attr >> 16) & 0o777
                    raw_mode = (info.external_attr >> 16) & 0o170000
                    if raw_mode == stat.S_IFLNK:
                        kind = "symlink"
                    regular_total = _check_member_limits(
                        len(members), kind, info.file_size, regular_total, limits
                    )
                    members.append(
                        _ArchiveMember(
                            _archive_relative(info.filename),
                            kind,
                            mode,
                            info.file_size,
                            None,
                            info,
                        )
                    )
                return members, reader
            except BaseException:
                reader.close()
                raise
        if archive.name.endswith(".tar.gz"):
            reader = tarfile.open(  # noqa: SIM115 - caller closes it.
                archive,
                "r:gz",
                tarinfo=_bounded_tar_info(limits.max_metadata_file_bytes),
            )
            try:
                members = []
                regular_total = 0
                for info in reader:
                    kind = _TAR_MEMBER_KINDS[info.type]
                    regular_total = _check_member_limits(
                        len(members), kind, info.size, regular_total, limits
                    )
                    members.append(
                        _ArchiveMember(
                            _archive_relative(info.name),
                            kind,
                            info.mode,
                            info.size,
                            info.linkname if info.issym() else None,
                            info,
                        )
                    )
                _verify_gzip_stream_end(reader)
                return members, reader
            except BaseException:
                reader.close()
                raise
        raise ArtifactEvidenceError("archive format is unsupported")
    except _ARCHIVE_READ_ERRORS as error:
        raise ArtifactEvidenceError("archive could not be read") from error


def _bounded_tar_info(max_header_bytes: int) -> type[tarfile.TarInfo]:
    """Return a header type that is checked before tarfile reads any body.

    ``tarfile`` loads PAX and GNU long-name bodies into memory and skips the
    bodies of other members only when it reads the following header, so the
    size and type checks run in ``_proc_member``, the per-header hook that
    ``tarfile`` documents for subclasses.
    """

    class _BoundedTarInfo(tarfile.TarInfo):
        def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
            if self.type in _TAR_EXTENDED_HEADER_TYPES:
                if self.size > max_header_bytes:
                    raise ArtifactEvidenceError(
                        "archive extended header exceeds its size limit"
                    )
            elif self.type not in _TAR_MEMBER_KINDS:
                raise ArtifactEvidenceError("archive contains an unsupported member")
            return super()._proc_member(archive)

    return _BoundedTarInfo


def _verify_gzip_stream_end(reader: tarfile.TarFile) -> None:
    """Read to the end of the gzip stream so its CRC and length are verified."""
    stream = reader.fileobj
    if stream is None:
        raise ArtifactEvidenceError("archive could not be read")
    consumed = 0
    while chunk := stream.read(min(64 * 1024, _TAR_END_PADDING_BYTES - consumed + 1)):
        consumed += len(chunk)
        if consumed > _TAR_END_PADDING_BYTES or any(chunk):
            raise ArtifactEvidenceError("archive has data after its end marker")


def _validate_archive_members(
    members: list[_ArchiveMember], windows: bool, max_steps: int
) -> None:
    by_path: dict[PurePosixPath, _ArchiveMember] = {}
    for member in members:
        if member.relative_path in by_path:
            raise ArtifactEvidenceError("archive contains duplicate member paths")
        if isinstance(member.source, zipfile.ZipInfo) and member.source.flag_bits & 0x1:
            raise ArtifactEvidenceError("archive contains an encrypted member")
        if member.kind not in {"directory", "file", "symlink"}:
            raise ArtifactEvidenceError("archive contains an unsupported member")
        if windows and member.kind == "symlink":
            raise ArtifactEvidenceError("Windows archive contains a symbolic link")
        by_path[member.relative_path] = member
    entries = tuple(
        PayloadEntry(
            member.relative_path,
            member.kind,  # type: ignore[arg-type]
            member.mode,
            member.size,
            None,
            member.link_target,
        )
        for member in members
    )
    validate_relative_links(entries, "win32" if windows else "posix", max_steps)
    for member in members:
        parent = member.relative_path.parent
        while parent != PurePosixPath("."):
            parent_member = by_path.get(parent)
            if parent_member is not None and parent_member.kind != "directory":
                raise ArtifactEvidenceError("archive member has a non-directory parent")
            parent = parent.parent


def _write_extraction(
    members: list[_ArchiveMember],
    reader: tarfile.TarFile | zipfile.ZipFile,
    destination: Path,
    limits: EvidenceLimits,
) -> None:
    directories = sorted(
        (member for member in members if member.kind == "directory"),
        key=lambda member: (
            len(member.relative_path.parts),
            member.relative_path.as_posix(),
        ),
    )
    files = sorted(
        (member for member in members if member.kind == "file"),
        key=lambda member: member.relative_path.as_posix(),
    )
    links = _ordered_links(members)
    for member in directories:
        path = _destination_path(destination, member.relative_path)
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    for member in files:
        path = _destination_path(destination, member.relative_path)
        _ensure_directory_parent(destination, path.parent)
        with _member_stream(reader, member.source) as source, path.open("xb") as target:
            _copy_bounded(source, target, member.size, limits.max_regular_file_bytes)
        path.chmod(member.mode or 0o600)
    for member in links:
        path = _destination_path(destination, member.relative_path)
        _ensure_directory_parent(destination, path.parent)
        os.symlink(member.link_target, path)
    for member in reversed(directories):
        _destination_path(destination, member.relative_path).chmod(member.mode)


def _ordered_links(members: list[_ArchiveMember]) -> list[_ArchiveMember]:
    """Return a deterministic link order without requiring target ordering."""
    return sorted(
        (member for member in members if member.kind == "symlink"),
        key=lambda member: member.relative_path.as_posix(),
    )


def _member_stream(
    reader: tarfile.TarFile | zipfile.ZipFile, source: tarfile.TarInfo | zipfile.ZipInfo
):
    if isinstance(reader, tarfile.TarFile):
        stream = reader.extractfile(source)
        if stream is None:
            raise ArtifactEvidenceError("archive member could not be read")
        return stream
    return reader.open(source)


def _destination_path(destination: Path, relative: PurePosixPath) -> Path:
    path = destination.joinpath(*relative.parts)
    try:
        path.relative_to(destination)
    except ValueError as error:
        raise ArtifactEvidenceError("archive member escapes extraction root") from error
    return path


def _ensure_directory_parent(destination: Path, path: Path) -> None:
    try:
        path.relative_to(destination)
    except ValueError as error:
        raise ArtifactEvidenceError("archive member escapes extraction root") from error
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = path
    while current != destination:
        status = current.lstat()
        if not stat.S_ISDIR(status.st_mode):
            raise ArtifactEvidenceError("archive member has an unsafe parent")
        current = current.parent


def _validate_snapshot_for_target(
    snapshot: PayloadSnapshot, target: TargetSpec, limits: EvidenceLimits
) -> None:
    if not snapshot.root.is_dir():
        raise ArtifactEvidenceError("payload snapshot root is unavailable")
    validate_relative_links(
        snapshot.entries, target.platform, limits.max_payload_entries
    )


def _validate_archive_policy(policy: EvidencePolicy) -> None:
    if (
        type(policy.archive_compression_level) is not int
        or not 0 <= policy.archive_compression_level <= 9
    ):
        raise ArtifactEvidenceError("archive compression level is invalid")


def _archive_profile(target: TargetSpec, compression_level: int) -> dict[str, object]:
    if target.archive_format == "tar.gz":
        return {
            "format": "tar.gz",
            "compression": "gzip",
            "compression_level": compression_level,
            "container_format": "pax",
            "timestamp_policy": "source-date-epoch",
            "ownership_policy": "uid-gid-zero-empty-names",
        }
    if target.archive_format == "zip":
        return {
            "format": "zip",
            "compression": "deflate",
            "compression_level": compression_level,
            "container_format": "zip",
            "timestamp_policy": "zip-clamped-source-date-epoch",
            "ownership_policy": "zip-unix-modes",
        }
    raise ArtifactEvidenceError("target archive format is invalid")


def _create_archive_output_root(path: Path) -> tuple[int, int]:
    if path.exists() or path.is_symlink():
        raise ArtifactEvidenceError("archive output directory already exists")
    try:
        parent_status = path.parent.lstat()
        if not stat.S_ISDIR(parent_status.st_mode):
            raise ArtifactEvidenceError("archive output parent is invalid")
        path.mkdir(mode=0o700)
        return _directory_identity(path)
    except OSError as error:
        raise ArtifactEvidenceError(
            "archive output directory could not be created"
        ) from error


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        status = path.lstat()
    except OSError as error:
        raise ArtifactEvidenceError(
            "archive output directory is unavailable"
        ) from error
    if not stat.S_ISDIR(status.st_mode):
        raise ArtifactEvidenceError("archive output directory is invalid")
    return status.st_dev, status.st_ino


def _regular_file(path: Path, label: str) -> Path:
    try:
        status = path.lstat()
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISREG(status.st_mode):
        raise ArtifactEvidenceError(f"{label} is invalid")
    return path


def _source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        epoch = int(raw) if raw is not None else -1
    except ValueError as error:
        raise ArtifactEvidenceError("SOURCE_DATE_EPOCH is invalid") from error
    _validate_source_date_epoch(epoch)
    return epoch


def _validate_source_date_epoch(epoch: int) -> None:
    if type(epoch) is not int or epoch < 0:
        raise ArtifactEvidenceError("SOURCE_DATE_EPOCH is required")


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    minimum = 315532800
    maximum = 4354819198
    return time.gmtime(min(max(epoch, minimum), maximum))[:6]


def _member_name(entry: PayloadEntry) -> str:
    name = entry.relative_path.as_posix()
    return f"{name}/" if entry.kind == "directory" else name


def _archive_relative(raw: str) -> PurePosixPath:
    if not raw or "\x00" in raw or "\\" in raw:
        raise ArtifactEvidenceError("archive member path is unsafe")
    path = PurePosixPath(raw)
    windows_path = PureWindowsPath(raw)
    if (
        path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
    ):
        raise ArtifactEvidenceError("archive member path is unsafe")
    return path


def _check_member_limits(
    member_count: int,
    kind: str,
    size: int,
    regular_total: int,
    limits: EvidenceLimits,
) -> int:
    if member_count >= limits.max_payload_entries:
        raise ArtifactEvidenceError("archive member limit exceeded")
    if kind == "file" and size > limits.max_regular_file_bytes:
        raise ArtifactEvidenceError("archive regular-file limit exceeded")
    if kind == "file" and regular_total + size > limits.max_expanded_payload_bytes:
        raise ArtifactEvidenceError("archive expanded-size limit exceeded")
    return regular_total + size if kind == "file" else regular_total


def _copy_bounded(
    source: object, target: object, expected_size: int, limit: int
) -> None:
    if expected_size > limit:
        raise ArtifactEvidenceError("archive regular-file limit exceeded")
    copied = 0
    while True:
        chunk = source.read(min(1024 * 1024, limit - copied + 1))  # type: ignore[attr-defined]
        if not chunk:
            break
        copied += len(chunk)
        if copied > limit or copied > expected_size:
            raise ArtifactEvidenceError("archive member data exceeds its declared size")
        target.write(chunk)  # type: ignore[attr-defined]
    if copied != expected_size:
        raise ArtifactEvidenceError("archive member data has an invalid size")


def _validate_limits(limits: EvidenceLimits) -> None:
    if not all(
        type(value) is int and value > 0
        for value in (
            limits.max_metadata_file_bytes,
            limits.max_payload_entries,
            limits.max_regular_file_bytes,
            limits.max_expanded_payload_bytes,
        )
    ):
        raise ArtifactEvidenceError("evidence limits are invalid")


def _remove_regular_file(path: Path) -> None:
    try:
        if stat.S_ISREG(path.lstat().st_mode):
            path.unlink()
    except OSError:
        return


def _remove_owned_archive(
    path: Path, output_root: Path, identity: tuple[int, int]
) -> None:
    try:
        status = path.lstat()
        if (
            stat.S_ISREG(status.st_mode)
            and path.parent == output_root
            and (status.st_dev, status.st_ino) == identity
        ):
            path.unlink()
    except OSError:
        return


def _remove_empty_output_root(path: Path, identity: tuple[int, int]) -> None:
    try:
        if _directory_identity(path) == identity:
            path.rmdir()
    except (ArtifactEvidenceError, OSError):
        return


def _remove_owned_tree(path: Path, identity: tuple[int, int]) -> None:
    try:
        status = path.lstat()
        if stat.S_ISDIR(status.st_mode) and (status.st_dev, status.st_ino) == identity:
            shutil.rmtree(path)
    except OSError:
        return

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


def create_archive_from_snapshot(
    snapshot: PayloadSnapshot,
    target: TargetSpec,
    policy: EvidencePolicy,
    output_dir: Path,
) -> ArchiveOwner:
    """Write a deterministic archive into one new private cooperative output root."""
    _validate_snapshot_for_target(snapshot, target)
    _validate_archive_policy(policy)
    epoch = _source_date_epoch()
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
        _validate_archive_members(members, archive.suffix == ".zip")
        destination.mkdir(mode=0o700)
        identity = _directory_identity(destination)
        _write_extraction(members, reader, destination, limits)
        return destination
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, RuntimeError) as error:
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
            reader = tarfile.open(archive, "r:gz")  # noqa: SIM115 - caller closes it.
            try:
                members = []
                regular_total = 0
                for info in reader:
                    if info.isdir():
                        kind = "directory"
                    elif info.isreg():
                        kind = "file"
                    elif info.issym():
                        kind = "symlink"
                    else:
                        kind = "unsupported"
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
                return members, reader
            except BaseException:
                reader.close()
                raise
        raise ArtifactEvidenceError("archive format is unsupported")
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, RuntimeError) as error:
        raise ArtifactEvidenceError("archive could not be read") from error


def _validate_archive_members(members: list[_ArchiveMember], windows: bool) -> None:
    by_path: dict[PurePosixPath, _ArchiveMember] = {}
    for member in members:
        if member.relative_path in by_path:
            raise ArtifactEvidenceError("archive contains duplicate member paths")
        if (
            isinstance(member.source, zipfile.ZipInfo)
            and member.source.flag_bits & 0x1
        ):
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
    validate_relative_links(entries, "win32" if windows else "posix")
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
    links = {
        member.relative_path: member for member in members if member.kind == "symlink"
    }
    ordered: list[_ArchiveMember] = []
    states: dict[PurePosixPath, int] = {}
    for path in sorted(links, key=lambda item: item.as_posix()):
        stack: list[tuple[PurePosixPath, bool]] = [(path, False)]
        while stack:
            current, leaving = stack.pop()
            state = states.get(current, 0)
            if leaving:
                states[current] = 2
                ordered.append(links[current])
                continue
            if state == 2:
                continue
            if state == 1:
                raise ArtifactEvidenceError("archive symbolic link cycle detected")
            states[current] = 1
            stack.append((current, True))
            member = links[current]
            target = _link_target_path(member.relative_path, member.link_target or "")
            if target in links:
                stack.append((target, False))
    return ordered


def _link_target_path(source: PurePosixPath, target: str) -> PurePosixPath:
    parts = list(source.parent.parts)
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            parts.pop()
        else:
            parts.append(part)
    return PurePosixPath(*parts)


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
    snapshot: PayloadSnapshot, target: TargetSpec
) -> None:
    if not snapshot.root.is_dir():
        raise ArtifactEvidenceError("payload snapshot root is unavailable")
    validate_relative_links(snapshot.entries, target.platform)


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
    if epoch < 0:
        raise ArtifactEvidenceError("SOURCE_DATE_EPOCH is required")
    return epoch


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

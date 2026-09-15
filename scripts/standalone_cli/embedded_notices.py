"""Finite, hash-bound notices embedded in standalone payloads."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from scripts.standalone_cli.model import BuildValidationError, TargetSpec

_TARGETS = frozenset(
    {
        "windows-x64",
        "macos-x64",
        "macos-arm64",
        "linux-x64-ubuntu-22.04",
    }
)
_CONFIG_FIELDS = frozenset({"schema_version", "notices"})
_NOTICE_FIELDS = frozenset(
    {
        "distribution",
        "version",
        "source_relative_path",
        "payload_path",
        "sha256_by_target",
    }
)
_CANONICAL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,255}$")
_PAYLOAD_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STAGING_DIRECTORY = "third-party-notices"


@dataclass(frozen=True)
class EmbeddedNoticePolicy:
    """One reviewed notice source and its exact target byte identities."""

    distribution: str
    version: str
    source_relative_path: PurePosixPath
    payload_path: PurePosixPath
    sha256_by_target: Mapping[str, str]


@dataclass(frozen=True)
class EmbeddedNoticeRecord:
    """Public-safe provenance for one retained notice."""

    distribution: str
    version: str
    source_wheel_sha256: str
    payload_path: PurePosixPath
    sha256: str


@dataclass(frozen=True)
class StagedEmbeddedNotices:
    """Builder-owned notice staging root and its canonical records."""

    staging_root: Path
    records: tuple[EmbeddedNoticeRecord, ...]


def load_embedded_notice_policy(
    path: Path, max_bytes: int
) -> tuple[EmbeddedNoticePolicy, ...]:
    """Load the exact five-row reviewed notice policy."""
    raw = _load_json(path, "embedded notice policy", max_bytes)
    if (
        not isinstance(raw, dict)
        or set(raw) != _CONFIG_FIELDS
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] != 1
        or not isinstance(raw.get("notices"), list)
        or len(raw["notices"]) != 5
    ):
        raise BuildValidationError("embedded notice policy is invalid")
    notices = tuple(_notice_policy(row) for row in raw["notices"])
    identities = [notice.distribution for notice in notices]
    paths = [notice.payload_path for notice in notices]
    if identities != sorted(identities) or len(set(identities)) != len(identities):
        raise BuildValidationError("embedded notice policy is invalid")
    if len(set(paths)) != len(paths):
        raise BuildValidationError("embedded notice policy is invalid")
    return notices


def prepare_embedded_notices(
    config_path: Path,
    site_packages: Path,
    pip_report: Path,
    target: TargetSpec,
    metadata_root: Path,
    max_file_bytes: int,
) -> StagedEmbeddedNotices:
    """Copy exact reviewed notice bytes out of an installed locked environment."""
    if not isinstance(target, TargetSpec) or target.name not in _TARGETS:
        raise BuildValidationError("embedded notice target is invalid")
    policy = load_embedded_notice_policy(config_path, max_file_bytes)
    site_root = _physical_directory(site_packages, "isolated site-packages")
    metadata = _physical_directory(metadata_root, "build metadata staging root")
    wheel_hashes = _pip_report_hashes(pip_report, max_file_bytes)
    prepared: list[tuple[EmbeddedNoticePolicy, bytes, str]] = []
    for notice in policy:
        package = wheel_hashes.get(notice.distribution)
        if package is None or package[0] != notice.version:
            raise BuildValidationError("embedded notice package identity is invalid")
        data = _source_bytes(site_root, notice, target.name, max_file_bytes)
        prepared.append((notice, data, package[1]))

    staging_root = metadata / _STAGING_DIRECTORY
    try:
        staging_root.mkdir()
    except OSError as error:
        raise BuildValidationError("embedded notice staging is unavailable") from error
    records: list[EmbeddedNoticeRecord] = []
    for notice, data, wheel_sha256 in prepared:
        destination = staging_root / notice.payload_path.name
        try:
            with destination.open("xb") as output:
                output.write(data)
            status = destination.lstat()
        except OSError as error:
            raise BuildValidationError("embedded notice staging failed") from error
        digest = hashlib.sha256(data).hexdigest()
        if (
            not stat.S_ISREG(status.st_mode)
            or destination.is_symlink()
            or status.st_nlink != 1
            or status.st_size != len(data)
            or _sha256_file(destination, max_file_bytes) != digest
        ):
            raise BuildValidationError("staged embedded notice is invalid")
        records.append(
            EmbeddedNoticeRecord(
                distribution=notice.distribution,
                version=notice.version,
                source_wheel_sha256=wheel_sha256,
                payload_path=notice.payload_path,
                sha256=digest,
            )
        )
    return StagedEmbeddedNotices(staging_root.resolve(strict=True), tuple(records))


def validate_payload_embedded_notices(
    payload_root: Path,
    staged: StagedEmbeddedNotices,
    max_file_bytes: int,
) -> None:
    """Bind the five final PyInstaller notice copies to their retained sources."""
    if not isinstance(staged, StagedEmbeddedNotices):
        raise BuildValidationError("embedded notice record is invalid")
    _validate_records(staged.records)
    root = _physical_directory(payload_root, "PyInstaller payload")
    for record in staged.records:
        _validate_record(record)
        candidate = root.joinpath(*record.payload_path.parts)
        try:
            status = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise BuildValidationError(
                "PyInstaller embedded notice is unavailable"
            ) from error
        if (
            resolved != candidate
            or not stat.S_ISREG(status.st_mode)
            or candidate.is_symlink()
            or status.st_nlink != 1
            or status.st_size <= 0
            or status.st_size > max_file_bytes
            or _sha256_file(candidate, max_file_bytes) != record.sha256
        ):
            raise BuildValidationError("PyInstaller embedded notice is invalid")


def write_embedded_notice_metadata(
    destination: Path, staged: StagedEmbeddedNotices
) -> None:
    """Serialize the canonical public-safe five-notice attestation."""
    if not isinstance(staged, StagedEmbeddedNotices):
        raise BuildValidationError("embedded notice record is invalid")
    _validate_records(staged.records)
    rows: list[dict[str, object]] = []
    for record in staged.records:
        rows.append(
            {
                "distribution": record.distribution,
                "version": record.version,
                "source_wheel_sha256": record.source_wheel_sha256,
                "payload_path": record.payload_path.as_posix(),
                "sha256": record.sha256,
            }
        )
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as output:
            json.dump({"schema_version": 1, "notices": rows}, output, sort_keys=True)
            output.write("\n")
    except OSError as error:
        raise BuildValidationError("embedded notice metadata is unavailable") from error


def _notice_policy(raw: object) -> EmbeddedNoticePolicy:
    if not isinstance(raw, dict) or set(raw) != _NOTICE_FIELDS:
        raise BuildValidationError("embedded notice policy is invalid")
    distribution = raw.get("distribution")
    version = raw.get("version")
    source_value = raw.get("source_relative_path")
    payload_value = raw.get("payload_path")
    target_hashes = raw.get("sha256_by_target")
    if (
        not isinstance(distribution, str)
        or not _CANONICAL_NAME.fullmatch(distribution)
        or not isinstance(version, str)
        or not _VERSION.fullmatch(version)
        or not isinstance(source_value, str)
        or not isinstance(payload_value, str)
        or not isinstance(target_hashes, dict)
        or set(target_hashes) != _TARGETS
        or any(
            not isinstance(value, str) or not _SHA256.fullmatch(value)
            for value in target_hashes.values()
        )
    ):
        raise BuildValidationError("embedded notice policy is invalid")
    source_path = _canonical_relative_path(source_value)
    payload_path = _canonical_relative_path(payload_value)
    expected_dist_info = f"{distribution.replace('-', '_')}-{version}.dist-info"
    if (
        source_path.parts[:2] != (expected_dist_info, "licenses")
        or len(source_path.parts) != 3
        or source_path.name not in {"LICENSE", "COPYING.txt"}
        or payload_path.parts[:2] != ("_internal", "notices")
        or len(payload_path.parts) != 3
        or not _PAYLOAD_NAME.fullmatch(payload_path.name)
    ):
        raise BuildValidationError("embedded notice policy is invalid")
    return EmbeddedNoticePolicy(
        distribution,
        version,
        source_path,
        payload_path,
        MappingProxyType(dict(target_hashes)),
    )


def _pip_report_hashes(path: Path, max_bytes: int) -> dict[str, tuple[str, str]]:
    raw = _load_json(path, "pip installation report", max_bytes)
    if (
        not isinstance(raw, dict)
        or raw.get("version") != "1"
        or not isinstance(raw.get("install"), list)
    ):
        raise BuildValidationError("pip installation report is invalid")
    packages: dict[str, tuple[str, str]] = {}
    for item in raw["install"]:
        if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict):
            raise BuildValidationError("pip installation report is invalid")
        name = item["metadata"].get("name")
        version = item["metadata"].get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise BuildValidationError("pip installation report is invalid")
        canonical_name = _canonicalize_name(name)
        if canonical_name in packages:
            raise BuildValidationError("pip installation report is invalid")
        download = item.get("download_info")
        archive = download.get("archive_info") if isinstance(download, dict) else None
        hashes = archive.get("hashes") if isinstance(archive, dict) else None
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise BuildValidationError("pip installation report is invalid")
        packages[canonical_name] = (version, digest.casefold())
    return packages


def _source_bytes(
    site_root: Path,
    notice: EmbeddedNoticePolicy,
    target_name: str,
    max_bytes: int,
) -> bytes:
    candidate = site_root.joinpath(*notice.source_relative_path.parts)
    try:
        status = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(site_root)
    except (OSError, ValueError) as error:
        raise BuildValidationError("embedded notice source is unavailable") from error
    if (
        resolved != candidate
        or not stat.S_ISREG(status.st_mode)
        or candidate.is_symlink()
        or status.st_size <= 0
        or status.st_size > max_bytes
    ):
        raise BuildValidationError("embedded notice source is invalid")
    data = _read_bounded(candidate, "embedded notice source", max_bytes)
    if hashlib.sha256(data).hexdigest() != notice.sha256_by_target[target_name]:
        raise BuildValidationError("embedded notice source hash is invalid")
    return data


def _physical_directory(path: Path, label: str) -> Path:
    absolute = path.absolute()
    try:
        status = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise BuildValidationError(f"{label} is unavailable") from error
    if (
        resolved != absolute
        or not stat.S_ISDIR(status.st_mode)
        or absolute.is_symlink()
    ):
        raise BuildValidationError(f"{label} is invalid")
    return resolved


def _validate_record(record: object) -> None:
    if (
        not isinstance(record, EmbeddedNoticeRecord)
        or not _CANONICAL_NAME.fullmatch(record.distribution)
        or not _VERSION.fullmatch(record.version)
        or not _SHA256.fullmatch(record.source_wheel_sha256)
        or not _SHA256.fullmatch(record.sha256)
        or record.payload_path.parts[:2] != ("_internal", "notices")
        or len(record.payload_path.parts) != 3
        or not _PAYLOAD_NAME.fullmatch(record.payload_path.name)
    ):
        raise BuildValidationError("embedded notice record is invalid")


def _validate_records(records: object) -> None:
    if not isinstance(records, tuple) or len(records) != 5:
        raise BuildValidationError("embedded notice record is invalid")
    for record in records:
        _validate_record(record)
    identities = [record.distribution for record in records]
    payload_paths = [record.payload_path for record in records]
    if (
        identities != sorted(identities)
        or len(set(identities)) != len(identities)
        or len(set(payload_paths)) != len(payload_paths)
    ):
        raise BuildValidationError("embedded notice record is invalid")


def _load_json(path: Path, label: str, max_bytes: int) -> object:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise BuildValidationError("embedded notice size limit is invalid")
    raw = _read_bounded(path, label, max_bytes)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise BuildValidationError(f"{label} is invalid") from error


def _read_bounded(path: Path, label: str, max_bytes: int) -> bytes:
    try:
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode) or path.is_symlink():
            raise BuildValidationError(f"{label} is invalid")
        with path.open("rb") as source:
            raw = source.read(max_bytes + 1)
    except BuildValidationError:
        raise
    except OSError as error:
        raise BuildValidationError(f"{label} is unavailable") from error
    if len(raw) > max_bytes:
        raise BuildValidationError(f"{label} exceeds its size limit")
    return raw


def _sha256_file(path: Path, max_bytes: int) -> str:
    return hashlib.sha256(
        _read_bounded(path, "embedded notice file", max_bytes)
    ).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BuildValidationError("embedded notice JSON has duplicate keys")
        result[key] = value
    return result


def _canonical_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise BuildValidationError("embedded notice path is invalid")
    return path


def _canonicalize_name(value: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", value).casefold()
    if not _CANONICAL_NAME.fullmatch(normalized):
        raise BuildValidationError("pip installation report is invalid")
    return normalized

"""License notices taken from the pinned source archives a desktop build compiles.

On Linux the desktop builds PyGObject and pycairo from their source
distributions, and the wheels built from them carry no license files. The
build therefore downloads the same hash-pinned source archives the target lock
names, extracts the reviewed license texts and embeds them beside the other
third-party notices. Every text is bound to its reviewed SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from scripts.desktop_shell.model import DESKTOP_TARGET_NAMES
from scripts.standalone_cli.pinned_asset import (
    AssetRules,
    Opener,
    check_download_url,
    download_pinned_asset,
    extract_pinned_member,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_NOTICE_POLICY_PATH = (
    _REPO_ROOT / "packaging" / "desktop_shell" / "source-notices.json"
)
_POLICY_FIELDS = frozenset({"schema_version", "download", "archives"})
_DOWNLOAD_FIELDS = frozenset(
    {
        "origin_host",
        "max_archive_bytes",
        "max_expanded_bytes",
        "download_timeout_seconds",
        "socket_timeout_seconds",
    }
)
_ARCHIVE_FIELDS = frozenset(
    {"distribution", "version", "targets", "url", "sha256", "notices"}
)
_NOTICE_FIELDS = frozenset({"member", "payload_path", "sha256"})
_CANONICAL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
_PAYLOAD_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HOST = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_ARCHIVE_SUFFIX = ".tar.gz"


class SourceNoticeError(ValueError):
    """Raised when a source notice policy, download or payload copy is invalid."""


@dataclass(frozen=True)
class SourceNotice:
    """One reviewed license text inside a source archive."""

    member: PurePosixPath
    payload_path: PurePosixPath
    sha256: str


@dataclass(frozen=True)
class SourceArchive:
    """One hash-pinned source archive and the notices it provides."""

    distribution: str
    version: str
    targets: frozenset[str]
    url: str
    sha256: str
    notices: tuple[SourceNotice, ...]


@dataclass(frozen=True)
class SourceNoticePolicy:
    """Reviewed source archives, their notices and the download bounds."""

    origin_host: str
    max_archive_bytes: int
    max_expanded_bytes: int
    download_timeout_seconds: int
    socket_timeout_seconds: int
    archives: tuple[SourceArchive, ...]

    def for_target(self, target_name: str) -> tuple[SourceArchive, ...]:
        return tuple(archive for archive in self.archives if target_name in archive.targets)

    def payload_notices(self, target_name: str) -> dict[str, str]:
        """Map each notice file name the target's payload carries to its SHA-256."""
        return {
            notice.payload_path.name: notice.sha256
            for archive in self.for_target(target_name)
            for notice in archive.notices
        }


@dataclass(frozen=True)
class SourceNoticeRecord:
    """Public-safe provenance of one embedded source notice."""

    distribution: str
    version: str
    source_archive_sha256: str
    payload_path: PurePosixPath
    sha256: str


def load_source_notice_policy(path: Path = SOURCE_NOTICE_POLICY_PATH) -> SourceNoticePolicy:
    """Load and validate the reviewed source notice policy."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceNoticeError("source notice policy is unavailable") from error
    if not isinstance(raw, dict) or set(raw) != _POLICY_FIELDS or raw["schema_version"] != 1:
        raise SourceNoticeError("source notice policy is invalid")
    download = raw["download"]
    if not isinstance(download, dict) or set(download) != _DOWNLOAD_FIELDS:
        raise SourceNoticeError("source notice download bounds are invalid")
    origin_host = download["origin_host"]
    bounds = [download[key] for key in sorted(_DOWNLOAD_FIELDS - {"origin_host"})]
    if not isinstance(origin_host, str) or not _HOST.fullmatch(origin_host) or any(
        type(value) is not int or value <= 0 for value in bounds
    ):
        raise SourceNoticeError("source notice download bounds are invalid")
    archives = raw["archives"]
    if not isinstance(archives, list) or not archives:
        raise SourceNoticeError("source notice policy lists no archives")
    policy = SourceNoticePolicy(
        origin_host=origin_host,
        max_archive_bytes=download["max_archive_bytes"],
        max_expanded_bytes=download["max_expanded_bytes"],
        download_timeout_seconds=download["download_timeout_seconds"],
        socket_timeout_seconds=download["socket_timeout_seconds"],
        archives=tuple(_archive(row, origin_host) for row in archives),
    )
    names = [archive.distribution for archive in policy.archives]
    payload_paths = [n.payload_path for a in policy.archives for n in a.notices]
    if names != sorted(set(names)) or len(set(payload_paths)) != len(payload_paths):
        raise SourceNoticeError("source notice policy is invalid")
    return policy


def require_locked_archives(archives: tuple[SourceArchive, ...], lock_text: str) -> None:
    """Every archive must be the pinned version and a hashed artifact of the lock."""
    for archive in archives:
        version, hashes = _locked_pin(lock_text, archive.distribution)
        if version != archive.version or archive.sha256 not in hashes:
            raise SourceNoticeError(
                f"source notice archive of {archive.distribution} is not the one "
                "the target lock pins"
            )


def stage_source_notices(
    policy: SourceNoticePolicy,
    target_name: str,
    lock_text: str,
    staging_root: Path,
    work_dir: Path,
    *,
    opener: Opener | None = None,
) -> tuple[SourceNoticeRecord, ...]:
    """Extract the target's reviewed notices into the notice staging root."""
    archives = policy.for_target(target_name)
    require_locked_archives(archives, lock_text)
    rules = _asset_rules(policy.origin_host)
    records: list[SourceNoticeRecord] = []
    for archive in archives:
        with tempfile.TemporaryDirectory(dir=work_dir) as download_dir:
            archive_path = Path(download_dir) / f"{archive.distribution}{_ARCHIVE_SUFFIX}"
            download_pinned_asset(
                rules,
                archive.url,
                archive_path,
                archive.sha256,
                max_bytes=policy.max_archive_bytes,
                deadline_seconds=policy.download_timeout_seconds,
                socket_timeout_seconds=policy.socket_timeout_seconds,
                opener=opener,
            )
            for notice in archive.notices:
                destination = staging_root / notice.payload_path.name
                extract_pinned_member(
                    rules,
                    archive_path,
                    "tar.gz",
                    notice.member.as_posix(),
                    destination,
                    policy.max_expanded_bytes,
                )
                if _sha256_file(destination) != notice.sha256:
                    destination.unlink()
                    raise SourceNoticeError(
                        f"{notice.member} does not match its reviewed text"
                    )
                records.append(
                    SourceNoticeRecord(
                        distribution=archive.distribution,
                        version=archive.version,
                        source_archive_sha256=archive.sha256,
                        payload_path=notice.payload_path,
                        sha256=notice.sha256,
                    )
                )
    return tuple(records)


def validate_payload_source_notices(
    payload_root: Path, records: tuple[SourceNoticeRecord, ...], max_bytes: int
) -> None:
    """Bind each notice PyInstaller copied into the payload to its reviewed text."""
    for record in records:
        candidate = payload_root.joinpath(*record.payload_path.parts)
        try:
            status = candidate.lstat()
        except OSError as error:
            raise SourceNoticeError(
                f"payload notice is missing: {record.payload_path.name}"
            ) from error
        if (
            not stat.S_ISREG(status.st_mode)
            or not 0 < status.st_size <= max_bytes
            or _sha256_file(candidate) != record.sha256
        ):
            raise SourceNoticeError(f"payload notice is invalid: {record.payload_path.name}")


def write_source_notice_metadata(
    destination: Path, records: tuple[SourceNoticeRecord, ...]
) -> None:
    """Record which source archive each embedded notice came from."""
    rows = [
        {
            "distribution": record.distribution,
            "version": record.version,
            "source_archive_sha256": record.source_archive_sha256,
            "payload_path": record.payload_path.as_posix(),
            "sha256": record.sha256,
        }
        for record in records
    ]
    with destination.open("x", encoding="utf-8", newline="\n") as output:
        json.dump({"schema_version": 1, "notices": rows}, output, sort_keys=True)
        output.write("\n")


def _archive(raw: object, origin_host: str) -> SourceArchive:
    if not isinstance(raw, dict) or set(raw) != _ARCHIVE_FIELDS:
        raise SourceNoticeError("source notice archive is invalid")
    distribution, version, targets = raw["distribution"], raw["version"], raw["targets"]
    url, sha256, notices = raw["url"], raw["sha256"], raw["notices"]
    if (
        not isinstance(distribution, str)
        or not _CANONICAL_NAME.fullmatch(distribution)
        or not isinstance(version, str)
        or not _VERSION.fullmatch(version)
        or not isinstance(targets, list)
        or not targets
        or any(target not in DESKTOP_TARGET_NAMES for target in targets)
        or not isinstance(sha256, str)
        or not _SHA256.fullmatch(sha256)
        or not isinstance(url, str)
        or not url.endswith(f"/{distribution}-{version}{_ARCHIVE_SUFFIX}")
        or not isinstance(notices, list)
        or not notices
    ):
        raise SourceNoticeError(f"source notice archive {distribution!r} is invalid")
    check_download_url(_RULES, url, frozenset({origin_host}), is_redirect=False)
    root = f"{distribution}-{version}"
    return SourceArchive(
        distribution=distribution,
        version=version,
        targets=frozenset(targets),
        url=url,
        sha256=sha256,
        notices=tuple(_notice(row, root) for row in notices),
    )


def _notice(raw: object, archive_root: str) -> SourceNotice:
    if not isinstance(raw, dict) or set(raw) != _NOTICE_FIELDS:
        raise SourceNoticeError("source notice is invalid")
    member, payload_path, sha256 = raw["member"], raw["payload_path"], raw["sha256"]
    if not all(isinstance(value, str) for value in (member, payload_path, sha256)):
        raise SourceNoticeError("source notice is invalid")
    member_path = PurePosixPath(member)
    payload = PurePosixPath(payload_path)
    if (
        len(member_path.parts) != 2
        or member_path.parts[0] != archive_root
        or member_path.name in {".", ".."}
        or payload.parts[:2] != ("_internal", "notices")
        or len(payload.parts) != 3
        or not _PAYLOAD_NAME.fullmatch(payload.name)
        or not _SHA256.fullmatch(sha256)
    ):
        raise SourceNoticeError(f"source notice {member!r} is invalid")
    return SourceNotice(member_path, payload, sha256)


def _locked_pin(lock_text: str, distribution: str) -> tuple[str, frozenset[str]]:
    """Return the pinned version and hashes of one lock entry."""
    lines = iter(lock_text.splitlines())
    for line in lines:
        name, separator, rest = line.partition("==")
        if not separator or name.strip().lower() != distribution:
            continue
        version = re.split(r"[\s;\\]", rest.strip(), maxsplit=1)[0]
        hashes: set[str] = set()
        current = line
        while current.rstrip().endswith("\\"):
            current = next(lines, "")
            hashes.update(re.findall(r"--hash=sha256:([0-9a-f]{64})", current))
        return version, frozenset(hashes)
    raise SourceNoticeError(f"the target lock does not pin {distribution}")


def _asset_rules(origin_host: str) -> AssetRules:
    """Source archives come from, and redirect only within, the pinned host."""

    def validate(url: str, is_redirect: bool) -> None:
        check_download_url(_RULES, url, frozenset({origin_host}), is_redirect=is_redirect)

    return AssetRules("source notice archive", SourceNoticeError, validate)


def _unused_url_rule(url: str, is_redirect: bool) -> None:
    raise AssertionError("the error-only rules never validate a URL")


_RULES = AssetRules("source notice archive", SourceNoticeError, _unused_url_rule)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

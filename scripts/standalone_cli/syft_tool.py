"""Checksum-pinned acquisition and bounded execution of the Syft scanner."""

from __future__ import annotations

import json
import os
import re
import stat
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.bounded_command import run_bounded_command
from scripts.standalone_cli.model import TargetSpec
from scripts.standalone_cli.pinned_asset import (
    AssetRules,
    check_download_url,
    download_pinned_asset,
    extract_pinned_member,
)

_POLICY_FIELDS = frozenset({"schema_version", "tool"})
_TOOL_FIELDS = frozenset(
    {
        "name",
        "version",
        "manifest",
        "max_download_bytes",
        "max_process_output_bytes",
        "max_sbom_bytes",
        "version_timeout_seconds",
        "scan_timeout_seconds",
        "download_timeout_seconds",
        "redirect_hosts",
        "targets",
    }
)
_MANIFEST_FIELDS = frozenset({"url", "sha256"})
_TARGET_FIELDS = frozenset(
    {
        "archive",
        "url",
        "sha256",
        "format",
        "executable",
        "platform",
        "architecture",
    }
)
_TARGET_NAMES = frozenset(
    {"windows-x64", "macos-x64", "macos-arm64", "linux-x64-ubuntu-22.04"}
)
_TARGET_IDENTITIES = {
    "windows-x64": ("zip", "syft.exe", "windows", "amd64"),
    "macos-x64": ("tar.gz", "syft", "darwin", "amd64"),
    "macos-arm64": ("tar.gz", "syft", "darwin", "arm64"),
    "linux-x64-ubuntu-22.04": ("tar.gz", "syft", "linux", "amd64"),
}
_ORIGIN_HOST = "github.com"
_HOSTNAME_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_HOSTNAME_LABEL}(?:\.{_HOSTNAME_LABEL})+$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_ROW_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")


@dataclass(frozen=True)
class SyftTarget:
    """One native Syft release artifact selected by target policy."""

    archive: str
    url: str
    sha256: str
    archive_format: Literal["zip", "tar.gz"]
    executable: str
    platform: str
    architecture: str


@dataclass(frozen=True)
class SyftPolicy:
    """Strict executable policy for acquiring and running Syft."""

    version: str
    manifest_url: str
    manifest_sha256: str
    max_download_bytes: int
    max_process_output_bytes: int
    max_sbom_bytes: int
    version_timeout_seconds: int
    scan_timeout_seconds: int
    download_timeout_seconds: int
    redirect_hosts: frozenset[str]
    targets: Mapping[str, SyftTarget]


def _asset_rules(redirect_hosts: frozenset[str] = frozenset()) -> AssetRules:
    """Syft assets start at the release origin and redirect only to reviewed hosts."""

    def validate(url: str, is_redirect: bool) -> None:
        hosts = redirect_hosts if is_redirect else frozenset({_ORIGIN_HOST})
        _validate_download_url(url, hosts, is_redirect=is_redirect)

    return AssetRules("Syft", ArtifactEvidenceError, validate)


def load_syft_policy(policy_path: Path) -> SyftPolicy:
    """Load the strict Syft release policy without accepting extensions."""
    path = _require_regular_file(policy_path, "Syft tool policy")
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as error:
        raise ArtifactEvidenceError("Syft tool policy is not valid JSON") from error
    if not isinstance(raw, dict) or set(raw) != _POLICY_FIELDS:
        raise ArtifactEvidenceError("Syft tool policy fields are invalid")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ArtifactEvidenceError("Syft tool policy version is unsupported")
    tool = raw["tool"]
    if not isinstance(tool, dict) or set(tool) != _TOOL_FIELDS:
        raise ArtifactEvidenceError("Syft tool definition fields are invalid")
    if tool["name"] != "syft":
        raise ArtifactEvidenceError("Syft tool identity is invalid")
    version = tool["version"]
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise ArtifactEvidenceError("Syft tool version is invalid")
    manifest = tool["manifest"]
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS:
        raise ArtifactEvidenceError("Syft manifest policy is invalid")
    manifest_url = _policy_url(manifest["url"], version, is_manifest=True)
    manifest_sha256 = _digest(manifest["sha256"], "Syft manifest")
    max_download = _bounded_int(
        tool["max_download_bytes"], "Syft download limit", 1, 1_073_741_824
    )
    max_process_output = _bounded_int(
        tool["max_process_output_bytes"], "Syft process output limit", 1, 16_777_216
    )
    max_sbom = _bounded_int(tool["max_sbom_bytes"], "Syft SBOM limit", 1, 1_073_741_824)
    version_timeout = _bounded_int(
        tool["version_timeout_seconds"], "Syft version timeout", 1, 600
    )
    scan_timeout = _bounded_int(
        tool["scan_timeout_seconds"], "Syft scan timeout", 1, 3_600
    )
    download_timeout = _bounded_int(
        tool["download_timeout_seconds"], "Syft download timeout", 1, 3_600
    )
    redirect_hosts = _redirect_hosts(tool["redirect_hosts"])
    targets_raw = tool["targets"]
    if not isinstance(targets_raw, dict) or set(targets_raw) != _TARGET_NAMES:
        raise ArtifactEvidenceError("Syft target set is invalid")
    targets = {
        name: _parse_target(name, target, version, manifest_url)
        for name, target in targets_raw.items()
    }
    return SyftPolicy(
        version=version,
        manifest_url=manifest_url,
        manifest_sha256=manifest_sha256,
        max_download_bytes=max_download,
        max_process_output_bytes=max_process_output,
        max_sbom_bytes=max_sbom,
        version_timeout_seconds=version_timeout,
        scan_timeout_seconds=scan_timeout,
        download_timeout_seconds=download_timeout,
        redirect_hosts=redirect_hosts,
        targets=targets,
    )


def _redirect_hosts(value: object) -> frozenset[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 8
        or any(
            not isinstance(host, str) or not _HOSTNAME_RE.fullmatch(host)
            for host in value
        )
        or len(set(value)) != len(value)
    ):
        raise ArtifactEvidenceError("Syft redirect hosts are invalid")
    return frozenset(value)


def acquire_syft(tool_policy: Path, target: TargetSpec, cache_dir: Path) -> Path:
    """Download, verify, safely extract, and identify the selected Syft binary."""
    if not isinstance(target, TargetSpec):
        raise TypeError("target must be a TargetSpec")
    policy = load_syft_policy(tool_policy)
    selected = _select_target(policy, target)
    cache = _require_private_directory(cache_dir, "Syft cache")
    download_dir = _create_private_directory(cache / "downloads")
    tool_dir = _create_private_directory(cache / "tool")
    verification_dir = _create_private_directory(cache / "verification")
    manifest_path = download_dir / "checksums.txt"
    _download(policy.manifest_url, manifest_path, policy.manifest_sha256, policy)
    manifest = _parse_manifest(manifest_path, policy.max_download_bytes)
    if manifest.get(selected.archive) != selected.sha256:
        raise ArtifactEvidenceError("Syft manifest does not match selected asset")
    archive_path = download_dir / selected.archive
    _download(selected.url, archive_path, selected.sha256, policy)
    executable = _extract_verified_executable(
        archive_path, selected, tool_dir, policy.max_download_bytes
    )
    _verify_syft_version(executable, policy, selected, verification_dir)
    return executable


def run_syft_scan(
    executable: Path,
    policy: SyftPolicy,
    target: TargetSpec,
    payload_root: Path,
    product_version: str,
    raw_output: Path,
    config_root: Path,
) -> None:
    """Run the verified scanner against one validated filesystem payload."""
    if not isinstance(target, TargetSpec):
        raise TypeError("target must be a TargetSpec")
    _select_target(policy, target)
    binary = _require_regular_file(executable, "Syft executable")
    payload = _require_directory(payload_root, "payload root")
    config = _require_private_directory(config_root, "Syft configuration")
    output = _confined_new_file(raw_output, config, "Syft SBOM output")
    environment = _tool_environment(config)
    stdout = run_bounded_command(
        [
            str(binary),
            "scan",
            f"dir:{payload}",
            "--base-path",
            str(payload),
            "--quiet",
            "--source-name",
            "servonaut",
            "--source-version",
            product_version,
            "--output",
            "cyclonedx-json@1.6",
        ],
        environment,
        config,
        policy.scan_timeout_seconds,
        policy.max_sbom_bytes,
        policy.max_process_output_bytes,
        "Syft payload scan",
    )
    _write_private_file(output, stdout, "Syft SBOM output")
    _require_bounded_regular_file(output, "Syft SBOM output", policy.max_sbom_bytes)


def _parse_target(
    name: str, raw: object, version: str, manifest_url: str
) -> SyftTarget:
    if not isinstance(raw, dict) or set(raw) != _TARGET_FIELDS:
        raise ArtifactEvidenceError("Syft target fields are invalid")
    expected_format, expected_executable, expected_platform, expected_arch = (
        _TARGET_IDENTITIES[name]
    )
    archive = raw["archive"]
    if (
        not isinstance(archive, str)
        or not archive
        or len(archive) > 128
        or PurePosixPath(archive).name != archive
        or "\\" in archive
    ):
        raise ArtifactEvidenceError("Syft archive name is invalid")
    url = _policy_url(raw["url"], version, archive=archive)
    expected_url = urllib.parse.urljoin(manifest_url, archive)
    if url != expected_url:
        raise ArtifactEvidenceError("Syft asset URL does not match its manifest")
    archive_format = raw["format"]
    executable = raw["executable"]
    platform = raw["platform"]
    architecture = raw["architecture"]
    if (
        archive_format != expected_format
        or executable != expected_executable
        or platform != expected_platform
        or architecture != expected_arch
    ):
        raise ArtifactEvidenceError("Syft target identity is invalid")
    return SyftTarget(
        archive=archive,
        url=url,
        sha256=_digest(raw["sha256"], "Syft asset"),
        archive_format=archive_format,
        executable=executable,
        platform=platform,
        architecture=architecture,
    )


def _select_target(policy: SyftPolicy, target: TargetSpec) -> SyftTarget:
    selected = policy.targets.get(target.name)
    expected_platform = "windows" if target.platform == "win32" else target.platform
    expected_architecture = (
        "amd64" if target.architecture == "x86_64" else target.architecture
    )
    if (
        selected is None
        or selected.platform != expected_platform
        or selected.architecture != expected_architecture
    ):
        raise ArtifactEvidenceError("Syft target is unsupported")
    return selected


def _policy_url(
    value: object,
    version: str,
    *,
    archive: str | None = None,
    is_manifest: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ArtifactEvidenceError("Syft release URL is invalid")
    _validate_download_url(value, frozenset({_ORIGIN_HOST}), is_redirect=False)
    parsed = urllib.parse.urlsplit(value)
    release_prefix = f"/anchore/syft/releases/download/v{version}/"
    expected_name = f"syft_{version}_checksums.txt" if is_manifest else archive
    if (
        parsed.hostname != _ORIGIN_HOST
        or not parsed.path.startswith(release_prefix)
        or PurePosixPath(parsed.path).name != expected_name
        or parsed.path != release_prefix + expected_name
    ):
        raise ArtifactEvidenceError("Syft release URL is invalid")
    return value


def _validate_download_url(
    value: str, allowed_hosts: frozenset[str], *, is_redirect: bool
) -> None:
    check_download_url(_asset_rules(), value, allowed_hosts, is_redirect=is_redirect)


def _download(
    url: str,
    destination: Path,
    expected_sha256: str,
    policy: SyftPolicy,
) -> None:
    """Fetch one pinned asset within the policy size and time limits."""
    _validate_download_url(url, frozenset({_ORIGIN_HOST}), is_redirect=False)
    download_pinned_asset(
        _asset_rules(policy.redirect_hosts),
        url,
        destination,
        expected_sha256,
        max_bytes=policy.max_download_bytes,
        deadline_seconds=policy.download_timeout_seconds,
        socket_timeout_seconds=policy.version_timeout_seconds,
    )


def _parse_manifest(path: Path, max_bytes: int) -> dict[str, str]:
    raw = _read_bounded(path, "Syft checksum manifest", max_bytes)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArtifactEvidenceError("Syft checksum manifest is invalid") from error
    records: dict[str, str] = {}
    for line in text.splitlines():
        match = _MANIFEST_ROW_RE.fullmatch(line)
        if match is None:
            raise ArtifactEvidenceError("Syft checksum manifest is invalid")
        digest, name = match.groups()
        if name in records:
            raise ArtifactEvidenceError("Syft checksum manifest has duplicate assets")
        records[name] = digest
    if not records:
        raise ArtifactEvidenceError("Syft checksum manifest is empty")
    return records


def _extract_verified_executable(
    archive_path: Path,
    target: SyftTarget,
    tool_dir: Path,
    max_bytes: int,
) -> Path:
    destination = tool_dir / target.executable
    if target.archive_format == "zip":
        _extract_zip_member(archive_path, target.executable, destination, max_bytes)
    else:
        _extract_tar_member(archive_path, target.executable, destination, max_bytes)
    if os.name != "nt":
        destination.chmod(0o700)
    return _require_regular_file(destination, "Syft executable")


def _extract_zip_member(
    archive_path: Path, member_name: str, destination: Path, max_bytes: int
) -> None:
    extract_pinned_member(
        _asset_rules(), archive_path, "zip", member_name, destination, max_bytes
    )


def _extract_tar_member(
    archive_path: Path, member_name: str, destination: Path, max_bytes: int
) -> None:
    extract_pinned_member(
        _asset_rules(), archive_path, "tar.gz", member_name, destination, max_bytes
    )


def _verify_syft_version(
    executable: Path,
    policy: SyftPolicy,
    target: SyftTarget,
    config_root: Path,
) -> None:
    environment = _tool_environment(config_root)
    stdout = run_bounded_command(
        [str(executable), "version", "-o", "json"],
        environment,
        config_root,
        policy.version_timeout_seconds,
        policy.max_process_output_bytes,
        policy.max_process_output_bytes,
        "Syft version check",
    )
    try:
        result = json.loads(stdout.decode("utf-8"), object_pairs_hook=_unique_object)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as error:
        raise ArtifactEvidenceError("Syft version response is invalid") from error
    if not isinstance(result, dict):
        raise ArtifactEvidenceError("Syft version response is invalid")
    expected_platform = f"{target.platform}/{target.architecture}"
    if (
        result.get("application") != "syft"
        or result.get("version") != policy.version
        or result.get("platform") != expected_platform
    ):
        raise ArtifactEvidenceError("Syft executable identity does not match policy")


def _tool_environment(config_root: Path) -> dict[str, str]:
    home = _create_private_directory(config_root / "home")
    cache = _create_private_directory(config_root / "cache")
    config = _create_private_directory(config_root / "config")
    temporary = _create_private_directory(config_root / "temp")
    environment = {
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "SYFT_LOG_QUIET": "true",
    }
    if os.name == "nt":
        environment.update(
            {
                "APPDATA": str(config),
                "LOCALAPPDATA": str(cache),
                "TEMP": str(temporary),
                "TMP": str(temporary),
                "USERPROFILE": str(home),
            }
        )
        system_root = os.environ.get("SystemRoot")
        if system_root:
            environment["SystemRoot"] = system_root
    return environment


def _require_regular_file(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ArtifactEvidenceError(f"{label} path is invalid")
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISREG(status.st_mode) or resolved != path:
        raise ArtifactEvidenceError(f"{label} is not a regular file")
    return resolved


def _require_private_directory(path: Path, label: str) -> Path:
    resolved = _require_directory(path, label)
    status = path.lstat()
    if os.name != "nt" and stat.S_IMODE(status.st_mode) & 0o077:
        raise ArtifactEvidenceError(f"{label} permissions are not private")
    return resolved


def _require_directory(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ArtifactEvidenceError(f"{label} path is invalid")
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(status.st_mode) or resolved != path:
        raise ArtifactEvidenceError(f"{label} is not a directory")
    return resolved


def _create_private_directory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700)
        if os.name != "nt":
            path.chmod(0o700)
    except OSError as error:
        raise ArtifactEvidenceError(
            "Syft private directory could not be created"
        ) from error
    return _require_private_directory(path, "Syft private directory")


def _confined_new_file(path: Path, root: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ArtifactEvidenceError(f"{label} path is invalid")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} parent is unavailable") from error
    if parent != root or path.name in {"", ".", ".."}:
        raise ArtifactEvidenceError(f"{label} escapes its private root")
    candidate = parent / path.name
    if candidate.exists() or candidate.is_symlink():
        raise ArtifactEvidenceError(f"{label} already exists")
    return candidate


def _write_private_file(path: Path, data: bytes, label: str) -> None:
    descriptor = -1
    identity: tuple[int, int] | None = None
    completed = False
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        status = os.fstat(descriptor)
        identity = status.st_dev, status.st_ino
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        completed = True
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} could not be written") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if identity is not None and not completed:
            _remove_owned_file(path, identity)


def _remove_owned_file(path: Path, identity: tuple[int, int]) -> None:
    try:
        status = path.lstat()
        if stat.S_ISREG(status.st_mode) and (status.st_dev, status.st_ino) == identity:
            path.unlink()
    except OSError:
        return


def _require_bounded_regular_file(path: Path, label: str, max_bytes: int) -> Path:
    resolved = _require_regular_file(path, label)
    try:
        size = resolved.stat().st_size
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if size > max_bytes:
        raise ArtifactEvidenceError(f"{label} exceeds its size limit")
    return resolved


def _read_bounded(path: Path, label: str, max_bytes: int) -> bytes:
    resolved = _require_bounded_regular_file(path, label, max_bytes)
    try:
        with resolved.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} could not be read") from error
    if len(data) > max_bytes:
        raise ArtifactEvidenceError(f"{label} exceeds its size limit")
    return data


def _bounded_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ArtifactEvidenceError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ArtifactEvidenceError(f"{label} checksum is invalid")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactEvidenceError("JSON object contains a duplicate field")
        result[key] = value
    return result

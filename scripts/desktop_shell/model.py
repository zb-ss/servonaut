"""Strict data-only models for desktop shell target policy, assets, and ABI."""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

from scripts.standalone_cli.release_identity import (
    DEVELOPMENT_IDENTITY,
    ReleaseIdentity,
)

_SCHEMA_VERSION = 1
_PACKAGING_ROOT = Path(__file__).resolve().parents[2] / "packaging"
# The desktop payload embeds the same reviewed dependency notices as the
# standalone payload, so both builds share one notice policy.
EMBEDDED_NOTICE_POLICY_PATH = (
    _PACKAGING_ROOT / "standalone_cli" / "embedded-notices.json"
)
PAYLOAD_NOTICES_DIRECTORY = PurePosixPath("_internal/notices")
RUNTIME_NOTICE_NAME = "CPython-LICENSE.txt"
PYINSTALLER_WARNING_NAME = "warn-servonaut_desktop.txt"
# Executable roles in the order the spec creates their Analysis and PYZ steps.
EXECUTABLE_ROLES = ("gui", "child", "console")
_BUILD_POLICY_PATH = _PACKAGING_ROOT / "desktop_shell" / "build-policy.json"
_BUILD_POLICY_BOUNDS = {
    "venv_bootstrap_timeout_seconds": (1, 3600),
    "dependency_install_timeout_seconds": (1, 7200),
    "interpreter_probe_timeout_seconds": (1, 600),
    "pyinstaller_timeout_seconds": (1, 7200),
    "failure_output_tail_chars": (256, 1024 * 1024),
    "max_metadata_file_bytes": (1024, 256 * 1024 * 1024),
}
_SIZE_BASELINE_FIELDS = frozenset(
    {"target", "max_expanded_bytes", "max_regular_file_count", "rationale"}
)
_VOICE_RUNTIME_POLICY_PATH = _PACKAGING_ROOT / "desktop_shell" / "voice-runtime.json"
_VOICE_REQUIREMENTS_DIR = _PACKAGING_ROOT / "desktop_shell" / "requirements"
# The unlocked voice runtime requirements every target lock is generated from.
VOICE_REQUIREMENTS_INPUT = _VOICE_REQUIREMENTS_DIR / "voice.in"
# Where the payload keeps the managed voice runtime inputs; the frozen app reads
# them from its resource root (``_internal``) under ``voice/``.
VOICE_PAYLOAD_DIRECTORY = PurePosixPath("_internal/voice")
VOICE_REQUIREMENTS_NAME = "voice-requirements.txt"
VOICE_MANIFEST_NAME = "voice-runtime.json"
VOICE_WHEEL_PATTERN = "servonaut-*-py3-none-any.whl"
_VOICE_RUNTIME_FIELDS = frozenset(
    {
        "$comment",
        "schema_version",
        "minimum_release_age_days",
        "python_version",
        "uv",
        "uv_command_timeout_seconds",
        "stall_timeout_seconds",
        "provision_timeout_seconds",
        "build_download",
    }
)
_VOICE_POLICY_BOUNDS = {
    "minimum_release_age_days": (1, 90),
    "uv_command_timeout_seconds": (1, 7200),
    "stall_timeout_seconds": (1, 3600),
    "provision_timeout_seconds": (1, 14400),
}
_VOICE_DOWNLOAD_BOUNDS = {
    "timeout_seconds": (1, 3600),
    "socket_timeout_seconds": (1, 600),
    "max_archive_bytes": (1024, 512 * 1024 * 1024),
    "max_member_bytes": (1024, 512 * 1024 * 1024),
}
_UV_FIELDS = frozenset({"version", "origin_host", "redirect_hosts", "targets"})
_HOSTNAME_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_HOSTNAME_LABEL}(?:\.{_HOSTNAME_LABEL})+$")
_UV_ARCHIVE_FIELDS = frozenset({"url", "sha256", "member"})
_UV_EXECUTABLES = {
    "win32": ("uv.exe", "zip"),
    "darwin": ("uv", "tar.gz"),
    "linux": ("uv", "tar.gz"),
}
_EXACT_PYTHON_RE = re.compile(r"^3\.12\.(?:0|[1-9][0-9]?)$")
_UV_VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_ARCHIVE_MEMBER_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
# Ubuntu 22.04, the oldest supported Linux desktop, ships glibc 2.35; 2.17 is
# the manylinux2014 floor.
_LINUX_GLIBC_MINORS = range(35, 16, -1)
_TARGET_IDENTITIES = {
    "windows-x64": ("win32", "x86_64", "zip", "requirements/windows-x64.txt", None),
    "macos-x64": ("darwin", "x86_64", "tar.gz", "requirements/macos-x64.txt", "13.0"),
    "macos-arm64": (
        "darwin",
        "arm64",
        "tar.gz",
        "requirements/macos-arm64.txt",
        "13.0",
    ),
    "linux-x64-ubuntu-22.04": (
        "linux",
        "x86_64",
        "tar.gz",
        "requirements/linux-x64-ubuntu-22.04.txt",
        None,
    ),
}
_TARGET_FIELDS = frozenset(
    {
        "platform",
        "architecture",
        "python_version",
        "requirements_lock",
        "archive",
        "forbidden_modules",
        "forbidden_path_patterns",
        "voice_bundle_paths",
        "frontend_assets_lock",
        "frontend_licenses",
        "size_baselines",
        "macos_minimum_version",
        "linux_abi",
    }
)
DESKTOP_TARGET_NAMES = frozenset(_TARGET_IDENTITIES)
_ARCHIVE_FIELDS = frozenset({"format", "extension", "name_template"})
_LINUX_ABI_FIELDS = frozenset(
    {
        "python_version",
        "pygobject_version",
        "pycairo_version",
        "glib_floor",
        "gtk_version",
        "webkit_api",
        "build_platform",
        "qualification_platforms",
        "prohibited_copied_distro_modules",
        "prohibited_bundled_closures",
    }
)
_ASSET_FIELDS = frozenset(
    {
        "source",
        "route",
        "content_type",
        "source_sha256",
        "source_size",
        "transformed_sha256",
        "transformed_size",
        "transform",
        "license",
    }
)
_LICENSE_FIELDS = frozenset(
    {
        "name",
        "spdx_expression",
        "upstream_component",
        "upstream_version",
        "copyright",
        "notice",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TARGET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)$")


class DesktopPolicyValidationError(ValueError):
    """Raised when desktop target policy, asset manifest, or ABI spec is malformed."""


@dataclass(frozen=True)
class LinuxAbiSpec:
    """Explicit Linux GI/WebKit ABI contract for Ubuntu 22.04/24.04."""

    python_version: str
    pygobject_version: str
    pycairo_version: str
    glib_floor: str
    gtk_version: str
    webkit_api: str
    build_platform: str
    qualification_platforms: tuple[str, ...]
    prohibited_copied_distro_modules: tuple[str, ...]
    prohibited_bundled_closures: tuple[str, ...]


@dataclass(frozen=True)
class DesktopTargetSpec:
    """Validated platform-specific desktop target policy."""

    name: str
    policy_path: Path
    platform: Literal["win32", "darwin", "linux"]
    architecture: Literal["x86_64", "arm64"]
    python_version: Literal["3.12"]
    requirements_lock: Path
    archive_format: Literal["zip", "tar.gz"]
    archive_extension: Literal["zip", "tar.gz"]
    artifact_name_template: str
    forbidden_modules: tuple[str, ...]
    forbidden_path_patterns: tuple[str, ...]
    # The managed voice runtime inputs: exempt from forbidden_path_patterns
    # because inspection verifies them file by file against their manifest.
    voice_bundle_paths: tuple[str, ...]
    frontend_assets_lock: Path
    frontend_licenses: Path
    size_baselines: Path
    macos_minimum_version: str | None
    linux_abi: LinuxAbiSpec | None


@dataclass(frozen=True)
class DesktopSizeBaseline:
    """Reviewed upper bounds for one target's expanded onedir payload."""

    max_expanded_bytes: int
    max_regular_file_count: int


@dataclass(frozen=True)
class DesktopBuildPolicy:
    """Process and metadata bounds shared by the desktop build and inspection."""

    venv_bootstrap_timeout_seconds: int
    dependency_install_timeout_seconds: int
    interpreter_probe_timeout_seconds: int
    pyinstaller_timeout_seconds: int
    failure_output_tail_chars: int
    max_metadata_file_bytes: int


@dataclass(frozen=True)
class UvArchiveSpec:
    """One pinned upstream uv release archive and the executable inside it."""

    url: str
    sha256: str
    member: PurePosixPath
    archive_format: Literal["zip", "tar.gz"]
    executable_name: str


@dataclass(frozen=True)
class VoiceRuntimePolicy:
    """Pinned inputs and bounds for the managed desktop voice runtime."""

    policy_path: Path
    # Supply-chain cooldown for choosing uv, Python and voice lock pins.
    minimum_release_age_days: int
    python_version: str
    uv_version: str
    # Every pinned archive URL is on this host; redirects may reach only these.
    uv_origin_host: str
    uv_redirect_hosts: frozenset[str]
    uv_archives: dict[str, UvArchiveSpec]
    uv_command_timeout_seconds: int
    stall_timeout_seconds: int
    provision_timeout_seconds: int
    download_timeout_seconds: int
    socket_timeout_seconds: int
    max_archive_bytes: int
    max_member_bytes: int


@dataclass(frozen=True)
class DesktopTargetPolicy:
    """Complete collection of desktop targets."""

    schema_version: int
    policy_path: Path
    targets: dict[str, DesktopTargetSpec]


@dataclass(frozen=True)
class FrontendAssetLock:
    """Immutable lock entry for a single frontend asset."""

    name: str
    route: str
    source: str
    content_type: str
    source_sha256: str
    source_size: int
    transformed_sha256: str
    transformed_size: int
    transform: str | None
    license_id: str


@dataclass(frozen=True)
class FrontendLicense:
    """License and copyright notice for a bundled frontend dependency."""

    id: str
    name: str
    spdx_expression: str
    upstream_component: str | None
    upstream_version: str | None
    copyright: str
    notice: str


def _resolve_relative_path(base_dir: Path, raw_path: str, field_name: str) -> Path:
    if "\\" in raw_path or raw_path.startswith(("/", "\\")):
        raise DesktopPolicyValidationError(
            f"{field_name} must be a relative POSIX-style path: {raw_path!r}"
        )
    pure = PurePosixPath(raw_path)
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise DesktopPolicyValidationError(
            f"{field_name} must not contain empty or traversal parts: {raw_path!r}"
        )
    resolved = (base_dir / Path(pure)).resolve()
    base_resolved = base_dir.resolve()
    if not (resolved == base_resolved or base_resolved in resolved.parents):
        raise DesktopPolicyValidationError(
            f"{field_name} traverses outside policy directory: {raw_path!r}"
        )
    return resolved


def load_desktop_target_policy(path: Path | None = None) -> DesktopTargetPolicy:
    """Load and validate the desktop target policy file."""
    if path is None:
        path = (
            Path(__file__).resolve().parents[2]
            / "packaging"
            / "desktop_shell"
            / "target-policy.json"
        )
    if not path.is_file():
        raise DesktopPolicyValidationError(f"Target policy file not found: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise DesktopPolicyValidationError(f"Malformed JSON in {path}: {err}") from err

    if not isinstance(raw, dict):
        raise DesktopPolicyValidationError("Target policy must be a JSON object")

    schema_version = raw.get("schema_version")
    if schema_version != _SCHEMA_VERSION:
        raise DesktopPolicyValidationError(
            f"Unsupported schema_version {schema_version!r}, expected {_SCHEMA_VERSION}"
        )

    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, dict) or not targets_raw:
        raise DesktopPolicyValidationError("'targets' must be a non-empty mapping")

    base_dir = path.parent
    targets: dict[str, DesktopTargetSpec] = {}

    for name, target_data in targets_raw.items():
        if not isinstance(name, str) or not _TARGET_NAME_RE.match(name):
            raise DesktopPolicyValidationError(f"Invalid target name: {name!r}")
        if name not in _TARGET_IDENTITIES:
            raise DesktopPolicyValidationError(f"Unknown target name: {name!r}")
        if not isinstance(target_data, dict):
            raise DesktopPolicyValidationError(f"Target {name!r} must be an object")

        unknown_fields = set(target_data) - _TARGET_FIELDS
        if unknown_fields:
            raise DesktopPolicyValidationError(
                f"Target {name!r} has unknown fields: {sorted(unknown_fields)}"
            )

        expected_plat, expected_arch, expected_fmt, expected_lock, expected_macos = (
            _TARGET_IDENTITIES[name]
        )

        platform = target_data.get("platform")
        if platform != expected_plat:
            raise DesktopPolicyValidationError(
                f"Target {name!r} platform must be {expected_plat!r}, got {platform!r}"
            )

        arch = target_data.get("architecture")
        if arch != expected_arch:
            raise DesktopPolicyValidationError(
                f"Target {name!r} architecture must be {expected_arch!r}, got {arch!r}"
            )

        python_ver = target_data.get("python_version")
        if python_ver != "3.12":
            raise DesktopPolicyValidationError(
                f"Target {name!r} python_version must be '3.12', got {python_ver!r}"
            )

        raw_lock = target_data.get("requirements_lock")
        if not isinstance(raw_lock, str) or raw_lock != expected_lock:
            raise DesktopPolicyValidationError(
                f"Target {name!r} requirements_lock must be {expected_lock!r}"
            )
        lock_path = _resolve_relative_path(base_dir, raw_lock, "requirements_lock")

        archive_raw = target_data.get("archive")
        if not isinstance(archive_raw, dict):
            raise DesktopPolicyValidationError(
                f"Target {name!r} archive must be an object"
            )
        unknown_archive = set(archive_raw) - _ARCHIVE_FIELDS
        if unknown_archive:
            raise DesktopPolicyValidationError(
                f"Target {name!r} archive has unknown fields: {sorted(unknown_archive)}"
            )
        archive_fmt = archive_raw.get("format")
        archive_ext = archive_raw.get("extension")
        if archive_fmt != expected_fmt or archive_ext != expected_fmt:
            raise DesktopPolicyValidationError(
                f"Target {name!r} archive format/ext must be {expected_fmt!r}"
            )
        template = archive_raw.get("name_template")
        if not isinstance(template, str) or "{product_version}" not in template:
            raise DesktopPolicyValidationError(
                f"Target {name!r} name_template must contain '{{product_version}}'"
            )

        forbidden_modules = target_data.get("forbidden_modules")
        if not isinstance(forbidden_modules, list) or not all(
            isinstance(m, str) and _MODULE_RE.match(m) for m in forbidden_modules
        ):
            raise DesktopPolicyValidationError(
                f"Target {name!r} forbidden_modules must be a list of module names"
            )

        forbidden_patterns = target_data.get("forbidden_path_patterns")
        if not isinstance(forbidden_patterns, list) or not all(
            isinstance(p, str) for p in forbidden_patterns
        ):
            raise DesktopPolicyValidationError(
                f"Target {name!r} forbidden_path_patterns must be a list of glob strings"
            )

        voice_bundle_paths = target_data.get("voice_bundle_paths")
        if (
            not isinstance(voice_bundle_paths, list)
            or not all(isinstance(path, str) for path in voice_bundle_paths)
            or sorted(voice_bundle_paths) != sorted(_voice_bundle_paths(expected_plat))
        ):
            raise DesktopPolicyValidationError(
                f"Target {name!r} voice_bundle_paths must list exactly the "
                "managed voice runtime inputs"
            )

        assets_lock_raw = target_data.get("frontend_assets_lock")
        if not isinstance(assets_lock_raw, str):
            raise DesktopPolicyValidationError(
                f"Target {name!r} frontend_assets_lock must be a string path"
            )
        assets_lock_path = _resolve_relative_path(
            base_dir, assets_lock_raw, "frontend_assets_lock"
        )

        licenses_raw = target_data.get("frontend_licenses")
        if not isinstance(licenses_raw, str):
            raise DesktopPolicyValidationError(
                f"Target {name!r} frontend_licenses must be a string path"
            )
        licenses_path = _resolve_relative_path(
            base_dir, licenses_raw, "frontend_licenses"
        )

        size_baselines_raw = target_data.get("size_baselines")
        if not isinstance(size_baselines_raw, str):
            raise DesktopPolicyValidationError(
                f"Target {name!r} size_baselines must be a string path"
            )
        size_baselines_path = _resolve_relative_path(
            base_dir, size_baselines_raw, "size_baselines"
        )

        macos_ver = target_data.get("macos_minimum_version")
        if macos_ver != expected_macos:
            raise DesktopPolicyValidationError(
                f"Target {name!r} macos_minimum_version must be {expected_macos!r}"
            )

        linux_abi_spec: LinuxAbiSpec | None = None
        if name.startswith("linux-"):
            abi_data = target_data.get("linux_abi")
            if not isinstance(abi_data, dict):
                raise DesktopPolicyValidationError(
                    f"Linux target {name!r} requires a 'linux_abi' object"
                )
            unknown_abi = set(abi_data) - _LINUX_ABI_FIELDS
            if unknown_abi:
                raise DesktopPolicyValidationError(
                    f"Target {name!r} linux_abi has unknown fields: {sorted(unknown_abi)}"
                )
            linux_abi_spec = LinuxAbiSpec(
                python_version=abi_data["python_version"],
                pygobject_version=abi_data["pygobject_version"],
                pycairo_version=abi_data["pycairo_version"],
                glib_floor=abi_data["glib_floor"],
                gtk_version=abi_data["gtk_version"],
                webkit_api=abi_data["webkit_api"],
                build_platform=abi_data["build_platform"],
                qualification_platforms=tuple(abi_data["qualification_platforms"]),
                prohibited_copied_distro_modules=tuple(
                    abi_data["prohibited_copied_distro_modules"]
                ),
                prohibited_bundled_closures=tuple(
                    abi_data["prohibited_bundled_closures"]
                ),
            )
        elif "linux_abi" in target_data and target_data["linux_abi"] is not None:
            raise DesktopPolicyValidationError(
                f"Non-Linux target {name!r} must not define 'linux_abi'"
            )

        targets[name] = DesktopTargetSpec(
            name=name,
            policy_path=path,
            platform=platform,
            architecture=arch,
            python_version=python_ver,
            requirements_lock=lock_path,
            archive_format=archive_fmt,
            archive_extension=archive_ext,
            artifact_name_template=template,
            forbidden_modules=tuple(forbidden_modules),
            forbidden_path_patterns=tuple(forbidden_patterns),
            voice_bundle_paths=tuple(voice_bundle_paths),
            frontend_assets_lock=assets_lock_path,
            frontend_licenses=licenses_path,
            size_baselines=size_baselines_path,
            macos_minimum_version=macos_ver,
            linux_abi=linux_abi_spec,
        )

    return DesktopTargetPolicy(
        schema_version=schema_version,
        policy_path=path,
        targets=targets,
    )


def load_desktop_target_spec(
    target_or_policy: str | Path,
    policy_or_target: Path | str | None = None,
) -> DesktopTargetSpec:
    """Load a single desktop target specification by name."""
    if isinstance(target_or_policy, Path) or (
        isinstance(policy_or_target, str) and not isinstance(target_or_policy, str)
    ):
        policy_path = target_or_policy if isinstance(target_or_policy, Path) else None
        target_name = str(policy_or_target)
    elif isinstance(policy_or_target, str) and policy_or_target in _TARGET_IDENTITIES:
        policy_path = target_or_policy if isinstance(target_or_policy, Path) else None
        target_name = policy_or_target
    else:
        target_name = str(target_or_policy)
        policy_path = policy_or_target if isinstance(policy_or_target, Path) else None

    policy = load_desktop_target_policy(policy_path)
    if target_name not in policy.targets:
        raise DesktopPolicyValidationError(
            f"Target {target_name!r} not defined in policy. Available: {sorted(policy.targets)}"
        )
    return policy.targets[target_name]


def load_size_baseline(path: Path, target_name: str) -> DesktopSizeBaseline:
    """Load the reviewed payload size ceiling for one desktop target."""
    raw = _load_json_object(path, "size baselines")
    baselines = raw.get("baselines")
    if raw.get("schema_version") != _SCHEMA_VERSION or not isinstance(baselines, dict):
        raise DesktopPolicyValidationError("size baselines have an unsupported format")
    entry = baselines.get(target_name)
    if (
        not isinstance(entry, dict)
        or set(entry) != _SIZE_BASELINE_FIELDS
        or entry["target"] != target_name
        or any(
            type(entry[field]) is not int or entry[field] <= 0
            for field in ("max_expanded_bytes", "max_regular_file_count")
        )
    ):
        raise DesktopPolicyValidationError(
            f"size baseline for {target_name!r} is missing or invalid"
        )
    return DesktopSizeBaseline(
        max_expanded_bytes=entry["max_expanded_bytes"],
        max_regular_file_count=entry["max_regular_file_count"],
    )


def load_desktop_build_policy(path: Path | None = None) -> DesktopBuildPolicy:
    """Load the bounded timeouts and limits used to build and inspect payloads."""
    raw = _load_json_object(path or _BUILD_POLICY_PATH, "build policy")
    if raw.get("schema_version") != _SCHEMA_VERSION or set(raw) != {
        "schema_version",
        *_BUILD_POLICY_BOUNDS,
    }:
        raise DesktopPolicyValidationError(
            "build policy has unsupported or missing fields"
        )
    for field, (minimum, maximum) in _BUILD_POLICY_BOUNDS.items():
        value = raw[field]
        if type(value) is not int or not minimum <= value <= maximum:
            raise DesktopPolicyValidationError(f"build policy {field} is out of bounds")
    return DesktopBuildPolicy(**{field: raw[field] for field in _BUILD_POLICY_BOUNDS})


def uv_executable_name(platform: str) -> str:
    """Return the file name of the uv executable on a desktop platform."""
    return _UV_EXECUTABLES[platform][0]


def _voice_bundle_paths(platform: str) -> tuple[str, ...]:
    return tuple(
        f"{VOICE_PAYLOAD_DIRECTORY}/{name}"
        for name in (
            uv_executable_name(platform),
            VOICE_WHEEL_PATTERN,
            VOICE_REQUIREMENTS_NAME,
            VOICE_MANIFEST_NAME,
        )
    )


def voice_wheel_platforms(target: DesktopTargetSpec) -> tuple[str, ...]:
    """Return the pip ``--platform`` tags a target's voice runtime accepts."""
    if target.platform == "win32":
        return ("win_amd64",)
    if target.platform == "darwin":
        if target.macos_minimum_version is None:
            raise DesktopPolicyValidationError("macOS target has no minimum version")
        floor = target.macos_minimum_version.replace(".", "_")
        # pip expands a macOS tag to every older compatible release.
        return (f"macosx_{floor}_{target.architecture}",)
    return (
        *(f"manylinux_2_{minor}_x86_64" for minor in _LINUX_GLIBC_MINORS),
        "manylinux2014_x86_64",
    )


def voice_release_cutoff(minimum_age_days: int, now: datetime | None = None) -> str:
    """Return the newest upload time a pin may have under the cooldown.

    That is the start (UTC) of the day ``minimum_age_days`` before ``now``.
    """
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    day = (moment - timedelta(days=minimum_age_days)).date()
    return f"{day.isoformat()}T00:00:00Z"


def voice_lock_path(target_name: str) -> Path:
    """Return the hash-locked voice runtime requirements for a desktop target."""
    if target_name not in _TARGET_IDENTITIES:
        raise DesktopPolicyValidationError(f"Unknown target name: {target_name!r}")
    return _VOICE_REQUIREMENTS_DIR / f"voice-{target_name}.txt"


def load_voice_runtime_policy(path: Path | None = None) -> VoiceRuntimePolicy:
    """Load the pinned uv, Python and bounds of the managed voice runtime."""
    policy_path = path or _VOICE_RUNTIME_POLICY_PATH
    raw = _load_json_object(policy_path, "voice runtime policy")
    if raw.get("schema_version") != _SCHEMA_VERSION or set(raw) != _VOICE_RUNTIME_FIELDS:
        raise DesktopPolicyValidationError(
            "voice runtime policy has unsupported or missing fields"
        )
    if not isinstance(raw["$comment"], str) or not raw["$comment"].strip():
        raise DesktopPolicyValidationError(
            "voice runtime policy must state its pinning rule in $comment"
        )
    python_version = raw["python_version"]
    if not isinstance(python_version, str) or not _EXACT_PYTHON_RE.fullmatch(
        python_version
    ):
        raise DesktopPolicyValidationError(
            "voice runtime python_version must be an exact 3.12 patch release"
        )
    bounded = _bounded_integers(raw, _VOICE_POLICY_BOUNDS, "voice runtime")
    if not (
        bounded["stall_timeout_seconds"]
        <= bounded["uv_command_timeout_seconds"]
        <= bounded["provision_timeout_seconds"]
    ):
        raise DesktopPolicyValidationError(
            "voice runtime timeouts must satisfy stall <= uv command <= provision"
        )
    download_raw = raw["build_download"]
    if not isinstance(download_raw, dict) or set(download_raw) != set(
        _VOICE_DOWNLOAD_BOUNDS
    ):
        raise DesktopPolicyValidationError(
            "voice runtime build_download has unsupported or missing fields"
        )
    download = _bounded_integers(download_raw, _VOICE_DOWNLOAD_BOUNDS, "build_download")
    if download["socket_timeout_seconds"] > download["timeout_seconds"]:
        raise DesktopPolicyValidationError(
            "build_download socket_timeout_seconds must not exceed timeout_seconds"
        )
    uv = _load_uv(raw["uv"])
    return VoiceRuntimePolicy(
        policy_path=policy_path,
        minimum_release_age_days=bounded["minimum_release_age_days"],
        python_version=python_version,
        uv_version=uv.version,
        uv_origin_host=uv.origin_host,
        uv_redirect_hosts=uv.redirect_hosts,
        uv_archives=uv.archives,
        uv_command_timeout_seconds=bounded["uv_command_timeout_seconds"],
        stall_timeout_seconds=bounded["stall_timeout_seconds"],
        provision_timeout_seconds=bounded["provision_timeout_seconds"],
        download_timeout_seconds=download["timeout_seconds"],
        socket_timeout_seconds=download["socket_timeout_seconds"],
        max_archive_bytes=download["max_archive_bytes"],
        max_member_bytes=download["max_member_bytes"],
    )


def _bounded_integers(
    raw: dict[str, object], bounds: dict[str, tuple[int, int]], label: str
) -> dict[str, int]:
    values: dict[str, int] = {}
    for field, (minimum, maximum) in bounds.items():
        value = raw[field]
        if type(value) is not int or not minimum <= value <= maximum:
            raise DesktopPolicyValidationError(f"{label} {field} is out of bounds")
        values[field] = value
    return values


@dataclass(frozen=True)
class _UvPins:
    version: str
    origin_host: str
    redirect_hosts: frozenset[str]
    archives: dict[str, UvArchiveSpec]


def _load_uv(raw: object) -> _UvPins:
    if not isinstance(raw, dict) or set(raw) != _UV_FIELDS:
        raise DesktopPolicyValidationError(
            "voice runtime uv must define version, hosts and targets"
        )
    version = raw["version"]
    if not isinstance(version, str) or not _UV_VERSION_RE.fullmatch(version):
        raise DesktopPolicyValidationError("voice runtime uv version must be exact")
    origin, redirects = raw["origin_host"], raw["redirect_hosts"]
    if (
        not isinstance(origin, str)
        or not _HOSTNAME_RE.fullmatch(origin)
        or not isinstance(redirects, list)
        or not 1 <= len(redirects) <= 8
        or len(set(redirects)) != len(redirects)
        or any(
            not isinstance(host, str) or not _HOSTNAME_RE.fullmatch(host)
            for host in redirects
        )
    ):
        raise DesktopPolicyValidationError("voice runtime uv download hosts are invalid")
    targets = raw["targets"]
    if not isinstance(targets, dict) or set(targets) != DESKTOP_TARGET_NAMES:
        raise DesktopPolicyValidationError(
            "voice runtime uv must pin exactly one archive per desktop target"
        )
    archives = {
        name: _load_uv_archive(name, entry, version, origin)
        for name, entry in targets.items()
    }
    return _UvPins(version, origin, frozenset(redirects), archives)


def _load_uv_archive(
    target_name: str, raw: object, version: str, origin_host: str
) -> UvArchiveSpec:
    if not isinstance(raw, dict) or set(raw) != _UV_ARCHIVE_FIELDS:
        raise DesktopPolicyValidationError(
            f"uv archive for {target_name!r} must define url, sha256 and member"
        )
    platform = _TARGET_IDENTITIES[target_name][0]
    executable, archive_format = _UV_EXECUTABLES[platform]
    url, sha256, member = raw["url"], raw["sha256"], raw["member"]
    # The URL must name the pinned release on the pinned origin, so neither the
    # version nor the host can drift from the archive.
    if not _is_release_url(url, origin_host, version, archive_format):
        raise DesktopPolicyValidationError(
            f"uv archive URL for {target_name!r} must be an https {archive_format} "
            f"of release {version} on {origin_host}"
        )
    if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256):
        raise DesktopPolicyValidationError(
            f"uv archive sha256 for {target_name!r} is invalid"
        )
    if (
        not isinstance(member, str)
        or not _ARCHIVE_MEMBER_RE.fullmatch(member)
        or any(part in {".", ".."} for part in member.split("/"))
        or PurePosixPath(member).name != executable
    ):
        raise DesktopPolicyValidationError(
            f"uv archive member for {target_name!r} must be a relative path to {executable}"
        )
    return UvArchiveSpec(
        url=url,
        sha256=sha256,
        member=PurePosixPath(member),
        archive_format=archive_format,
        executable_name=executable,
    )


def _is_release_url(url: object, host: str, version: str, archive_format: str) -> bool:
    if not isinstance(url, str) or any(character.isspace() for character in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and parts.hostname == host
        and parts.username is None
        and parts.password is None
        and port is None
        and not parts.query
        and not parts.fragment
        and f"/{version}/" in parts.path
        and parts.path.endswith(f".{archive_format}")
    )


def executable_toc_directory(build_metadata_dir: Path, role: str) -> Path:
    """Return the per-executable root holding that executable's PyInstaller TOCs."""
    if role not in EXECUTABLE_ROLES:
        raise DesktopPolicyValidationError(f"unknown executable role: {role!r}")
    return build_metadata_dir / "executables" / role


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DesktopPolicyValidationError(f"{label} could not be read") from error
    if not isinstance(raw, dict):
        raise DesktopPolicyValidationError(f"{label} must be a JSON object")
    return raw


def load_assets_lock(lock_path: Path | None = None) -> dict[str, FrontendAssetLock]:
    """Load and validate the frontend assets lock manifest."""
    if lock_path is None:
        lock_path = (
            Path(__file__).resolve().parents[2]
            / "packaging"
            / "desktop_shell"
            / "frontend"
            / "assets.lock.json"
        )
    if not lock_path.is_file():
        raise DesktopPolicyValidationError(f"Assets lock file not found: {lock_path}")

    try:
        raw = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise DesktopPolicyValidationError(
            f"Malformed JSON in {lock_path}: {err}"
        ) from err

    if not isinstance(raw, dict):
        raise DesktopPolicyValidationError("Assets lock must be a JSON object")

    if raw.get("schema_version") != _SCHEMA_VERSION:
        raise DesktopPolicyValidationError(
            f"Unsupported schema_version {raw.get('schema_version')!r}"
        )

    assets_raw = raw.get("assets")
    if not isinstance(assets_raw, dict) or not assets_raw:
        raise DesktopPolicyValidationError("'assets' must be a non-empty mapping")

    locks: dict[str, FrontendAssetLock] = {}
    routes_seen: set[str] = set()

    for name, item in assets_raw.items():
        if not isinstance(name, str) or not name:
            raise DesktopPolicyValidationError(f"Invalid asset name: {name!r}")
        if not isinstance(item, dict):
            raise DesktopPolicyValidationError(f"Asset {name!r} must be an object")

        unknown = set(item) - _ASSET_FIELDS
        if unknown:
            raise DesktopPolicyValidationError(
                f"Asset {name!r} has unknown fields: {sorted(unknown)}"
            )

        route = item.get("route")
        if not isinstance(route, str) or not route.startswith("/"):
            raise DesktopPolicyValidationError(
                f"Asset {name!r} route must start with '/'"
            )
        if route in routes_seen:
            raise DesktopPolicyValidationError(
                f"Duplicate route {route!r} in assets lock"
            )
        routes_seen.add(route)

        source_sha = item.get("source_sha256")
        trans_sha = item.get("transformed_sha256")
        if not isinstance(source_sha, str) or not _SHA256_RE.match(source_sha):
            raise DesktopPolicyValidationError(
                f"Asset {name!r} has invalid source_sha256: {source_sha!r}"
            )
        if not isinstance(trans_sha, str) or not _SHA256_RE.match(trans_sha):
            raise DesktopPolicyValidationError(
                f"Asset {name!r} has invalid transformed_sha256: {trans_sha!r}"
            )

        source_size = item.get("source_size")
        trans_size = item.get("transformed_size")
        if not isinstance(source_size, int) or source_size < 0:
            raise DesktopPolicyValidationError(
                f"Asset {name!r} has invalid source_size: {source_size!r}"
            )
        if not isinstance(trans_size, int) or trans_size < 0:
            raise DesktopPolicyValidationError(
                f"Asset {name!r} has invalid transformed_size: {trans_size!r}"
            )

        content_type = item.get("content_type")
        if not isinstance(content_type, str) or "/" not in content_type:
            raise DesktopPolicyValidationError(
                f"Asset {name!r} has invalid content_type: {content_type!r}"
            )

        license_id = item.get("license")
        if not isinstance(license_id, str) or not license_id:
            raise DesktopPolicyValidationError(
                f"Asset {name!r} missing or invalid license identifier"
            )

        transform = item.get("transform")
        if transform is not None and not isinstance(transform, str):
            raise DesktopPolicyValidationError(
                f"Asset {name!r} transform must be string or null"
            )

        locks[name] = FrontendAssetLock(
            name=name,
            route=route,
            source=item["source"],
            content_type=content_type,
            source_sha256=source_sha,
            source_size=source_size,
            transformed_sha256=trans_sha,
            transformed_size=trans_size,
            transform=transform,
            license_id=license_id,
        )

    return locks


def load_frontend_licenses(
    licenses_path: Path | None = None,
) -> dict[str, FrontendLicense]:
    """Load and validate the frontend licenses inventory."""
    if licenses_path is None:
        licenses_path = (
            Path(__file__).resolve().parents[2]
            / "packaging"
            / "desktop_shell"
            / "frontend"
            / "licenses.json"
        )
    if not licenses_path.is_file():
        raise DesktopPolicyValidationError(f"Licenses file not found: {licenses_path}")

    try:
        raw = json.loads(licenses_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise DesktopPolicyValidationError(
            f"Malformed JSON in {licenses_path}: {err}"
        ) from err

    if not isinstance(raw, dict):
        raise DesktopPolicyValidationError("Licenses file must be a JSON object")

    if raw.get("schema_version") != _SCHEMA_VERSION:
        raise DesktopPolicyValidationError(
            f"Unsupported schema_version {raw.get('schema_version')!r}"
        )

    licenses_raw = raw.get("licenses")
    if not isinstance(licenses_raw, dict) or not licenses_raw:
        raise DesktopPolicyValidationError("'licenses' must be a non-empty mapping")

    licenses: dict[str, FrontendLicense] = {}
    for lid, item in licenses_raw.items():
        if not isinstance(lid, str) or not lid:
            raise DesktopPolicyValidationError(f"Invalid license ID: {lid!r}")
        if not isinstance(item, dict):
            raise DesktopPolicyValidationError(f"License {lid!r} must be an object")

        unknown = set(item) - _LICENSE_FIELDS
        if unknown:
            raise DesktopPolicyValidationError(
                f"License {lid!r} has unknown fields: {sorted(unknown)}"
            )

        name = item.get("name")
        spdx = item.get("spdx_expression")
        copyright_text = item.get("copyright")
        notice = item.get("notice")

        if not isinstance(name, str) or not name:
            raise DesktopPolicyValidationError(f"License {lid!r} missing 'name'")
        if not isinstance(spdx, str) or not spdx:
            raise DesktopPolicyValidationError(
                f"License {lid!r} missing 'spdx_expression'"
            )
        if not isinstance(copyright_text, str) or not copyright_text:
            raise DesktopPolicyValidationError(f"License {lid!r} missing 'copyright'")
        if not isinstance(notice, str) or not notice:
            raise DesktopPolicyValidationError(f"License {lid!r} missing 'notice'")

        licenses[lid] = FrontendLicense(
            id=lid,
            name=name,
            spdx_expression=spdx,
            upstream_component=item.get("upstream_component"),
            upstream_version=item.get("upstream_version"),
            copyright=copyright_text,
            notice=notice,
        )

    return licenses


@dataclass(frozen=True)
class DesktopBuildRequest:
    """All explicit inputs needed to build one internal desktop artifact."""

    wheel: Path
    target: DesktopTargetSpec
    product_version: str
    build_revision: str
    source_commit: str
    output_dir: Path
    # Written into the runtime marker for the update check. Builds cut without
    # release inputs are development builds with the development identity.
    release_identity: ReleaseIdentity = DEVELOPMENT_IDENTITY


@dataclass(frozen=True)
class DesktopBuildResult:
    """Persistent paths produced by a successful desktop build."""

    payload_root: Path
    gui_executable: Path
    child_executable: Path
    console_executable: Path
    marker: Path
    pyinstaller_warning_file: Path
    build_metadata_dir: Path
    frontend_dir: Path


def _wheel_product_version(wheel: Path) -> str:
    """Read and validate the Servonaut identity from a built wheel."""
    try:
        with zipfile.ZipFile(wheel) as archive:
            metadata_names = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise DesktopPolicyValidationError(
                    "wheel must contain exactly one METADATA file"
                )
            metadata = BytesParser(policy=default).parsebytes(
                archive.read(metadata_names[0])
            )
            name = metadata.get("Name")
            version = metadata.get("Version")
            normalised_name = re.sub(r"[-_.]+", "-", name).casefold() if name else ""
            if normalised_name != "servonaut":
                raise DesktopPolicyValidationError(
                    "wheel is not the servonaut distribution"
                )
            if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
                raise DesktopPolicyValidationError(
                    "wheel has an invalid product version"
                )
            for direct_url_name in (
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/direct_url.json")
            ):
                direct_url = json.loads(archive.read(direct_url_name).decode("utf-8"))
                if isinstance(direct_url, dict) and isinstance(
                    direct_url.get("dir_info"), dict
                ):
                    raise DesktopPolicyValidationError(
                        "editable wheels are not valid build input"
                    )
            return version
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
        RecursionError,
    ) as error:
        raise DesktopPolicyValidationError(
            "wheel metadata could not be read"
        ) from error


def validate_desktop_build_request(request: DesktopBuildRequest) -> None:
    """Validate all build request parameters before invoking PyInstaller."""
    if not isinstance(request, DesktopBuildRequest):
        raise TypeError("request must be a DesktopBuildRequest")
    if not isinstance(request.wheel, Path):
        raise TypeError("wheel must be a Path")
    if not request.wheel.is_file():
        raise DesktopPolicyValidationError(f"wheel file not found: {request.wheel}")

    wheel_version = _wheel_product_version(request.wheel)
    if wheel_version != request.product_version:
        raise DesktopPolicyValidationError(
            f"wheel version {wheel_version!r} does not match product version {request.product_version!r}"
        )

    if not isinstance(request.target, DesktopTargetSpec):
        raise TypeError("target must be a DesktopTargetSpec")
    if not isinstance(request.product_version, str) or not _VERSION_RE.fullmatch(
        request.product_version
    ):
        raise DesktopPolicyValidationError("invalid product_version format")
    if (
        not isinstance(request.build_revision, str)
        or not request.build_revision.strip()
    ):
        raise DesktopPolicyValidationError("build_revision must be a non-empty string")
    if not isinstance(request.source_commit, str) or not request.source_commit.strip():
        raise DesktopPolicyValidationError("source_commit must be a non-empty string")
    if not isinstance(request.output_dir, Path):
        raise TypeError("output_dir must be a Path")
    if not request.output_dir.is_absolute():
        raise DesktopPolicyValidationError("output_dir must be an absolute path")
    if not isinstance(request.release_identity, ReleaseIdentity):
        raise TypeError("release_identity must be a ReleaseIdentity")

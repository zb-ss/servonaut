"""Strict data-only models for desktop shell target policy, assets, and ABI."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

_SCHEMA_VERSION = 1
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
        "frontend_assets_lock",
        "frontend_licenses",
        "macos_minimum_version",
        "linux_abi",
    }
)
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
    frontend_assets_lock: Path
    frontend_licenses: Path
    macos_minimum_version: str | None
    linux_abi: LinuxAbiSpec | None


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
            frontend_assets_lock=assets_lock_path,
            frontend_licenses=licenses_path,
            macos_minimum_version=macos_ver,
            linux_abi=linux_abi_spec,
        )

    return DesktopTargetPolicy(
        schema_version=schema_version,
        policy_path=path,
        targets=targets,
    )


def load_desktop_target_spec(
    target_name: str, policy_path: Path | None = None
) -> DesktopTargetSpec:
    """Load a single desktop target specification by name."""
    policy = load_desktop_target_policy(policy_path)
    if target_name not in policy.targets:
        raise DesktopPolicyValidationError(
            f"Target {target_name!r} not defined in policy. Available: {sorted(policy.targets)}"
        )
    return policy.targets[target_name]


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

"""Strict, data-only policy models for standalone CLI builds."""

from __future__ import annotations

import json
import re
import string
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import Literal

_SCHEMA_VERSION = 1
_POLICY_FIELDS = frozenset(
    {"schema_version", "build_command_timeout_seconds", "targets"}
)
_MAX_BUILD_COMMAND_TIMEOUT_SECONDS = 6 * 60 * 60
_TARGET_FIELDS = frozenset(
    {
        "platform",
        "architecture",
        "python_version",
        "requirements_lock",
        "archive",
        "forbidden_modules",
        "forbidden_path_patterns",
        "warning_allowlist",
        "size_baselines",
        "size_baseline_id",
        "macos_minimum_version",
    }
)
_ARCHIVE_FIELDS = frozenset({"format", "extension", "name_template"})
_TARGET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_SCALAR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PRODUCT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_TARGET_IDENTITIES = {
    "windows-x64": ("win32", "x86_64", "zip", "requirements/windows-x64.txt", None),
    "macos-x64": ("darwin", "x86_64", "tar.gz", "requirements/macos-x64.txt", "13.0"),
    "macos-arm64": ("darwin", "arm64", "tar.gz", "requirements/macos-arm64.txt", "13.0"),
    "linux-x64-ubuntu-22.04": (
        "linux",
        "x86_64",
        "tar.gz",
        "requirements/linux-x64-ubuntu-22.04.txt",
        None,
    ),
}
_ARTIFACT_TEMPLATE = "servonaut-{product_version}-{target}.{extension}"
_WARNING_ALLOWLIST = "warnings-allowlist.json"
_SIZE_BASELINES = "size-baselines.json"


class BuildValidationError(ValueError):
    """Raised when standalone build input is malformed or unsafe."""


@dataclass(frozen=True)
class TargetSpec:
    """Validated platform-specific standalone build policy."""

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
    warning_allowlist: Path
    size_baselines: Path
    size_baseline_id: str
    macos_minimum_version: str | None
    build_command_timeout_seconds: int


@dataclass(frozen=True)
class BuildRequest:
    """All explicit inputs needed to build one standalone artifact."""

    wheel: Path
    target: TargetSpec
    product_version: str
    build_revision: str
    source_commit: str
    output_dir: Path
    require_artifact_selftest: bool


@dataclass(frozen=True)
class BuildResult:
    """Persistent paths produced by a successful standalone build."""

    payload_root: Path
    executable: Path
    marker: Path
    pyinstaller_warning_file: Path
    build_metadata_dir: Path
    archive: Path | None


def load_target_spec(policy_path: Path, target_name: str) -> TargetSpec:
    """Load one target from a strict, repository-contained JSON policy."""
    if not isinstance(target_name, str) or not _TARGET_NAME_RE.fullmatch(target_name):
        raise BuildValidationError("target name is invalid")
    resolved_policy = _require_regular_file(policy_path, "target policy")
    try:
        raw = json.loads(
            resolved_policy.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise BuildValidationError("target policy must be valid UTF-8 JSON") from error
    if not isinstance(raw, dict) or set(raw) != _POLICY_FIELDS:
        raise BuildValidationError("target policy has unsupported or missing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != _SCHEMA_VERSION:
        raise BuildValidationError("target policy has an unsupported schema version")
    command_timeout = raw["build_command_timeout_seconds"]
    if (
        type(command_timeout) is not int
        or not 1 <= command_timeout <= _MAX_BUILD_COMMAND_TIMEOUT_SECONDS
    ):
        raise BuildValidationError("target policy build command timeout is invalid")
    targets = raw["targets"]
    if not isinstance(targets, dict) or set(targets) != set(_TARGET_IDENTITIES):
        raise BuildValidationError("target policy must define exactly the supported targets")
    if target_name not in targets:
        raise BuildValidationError(f"target {target_name!r} is not defined by the policy")
    parsed_targets: dict[str, TargetSpec] = {}
    for name, target in targets.items():
        if not isinstance(name, str) or not _TARGET_NAME_RE.fullmatch(name):
            raise BuildValidationError("target policy contains an invalid target name")
        if not isinstance(target, dict) or set(target) != _TARGET_FIELDS:
            raise BuildValidationError("target has unsupported or missing fields")
        parsed_targets[name] = _parse_target(
            name, target, resolved_policy, command_timeout
        )
    for name, target in parsed_targets.items():
        _validate_target_identity(target, resolved_policy, _TARGET_IDENTITIES[name])
    return parsed_targets[target_name]


def validate_build_request(request: BuildRequest) -> None:
    """Fail before subprocesses for unsafe wheel or diagnostic input."""
    if not isinstance(request, BuildRequest):
        raise TypeError("request must be a BuildRequest")
    wheel = _require_regular_file(request.wheel, "wheel")
    if wheel.suffix != ".whl":
        raise BuildValidationError("wheel must have a .whl extension")
    if not _PRODUCT_VERSION_RE.fullmatch(request.product_version):
        raise BuildValidationError("product version must use X.Y.Z form")
    if _wheel_product_version(wheel) != request.product_version:
        raise BuildValidationError("wheel version does not match product version")
    _validate_scalar(request.build_revision, "build revision")
    _validate_scalar(request.source_commit, "source commit")
    if not isinstance(request.require_artifact_selftest, bool):
        raise BuildValidationError("require_artifact_selftest must be a boolean")
    if not isinstance(request.output_dir, Path):
        raise TypeError("output_dir must be a Path")
    if not isinstance(request.target, TargetSpec):
        raise TypeError("target must be a TargetSpec")
    canonical_target = load_target_spec(request.target.policy_path, request.target.name)
    if request.target != canonical_target:
        raise BuildValidationError("target does not match its validated policy")


def _parse_target(
    name: str,
    raw: dict[str, object],
    policy_path: Path,
    build_command_timeout_seconds: int,
) -> TargetSpec:
    policy_root = policy_path.parent
    platform = _literal(raw["platform"], {"win32", "darwin", "linux"}, "platform")
    architecture = _literal(raw["architecture"], {"x86_64", "arm64"}, "architecture")
    python_version = raw["python_version"]
    if python_version != "3.12":
        raise BuildValidationError("target python_version must be 3.12")
    archive = raw["archive"]
    if not isinstance(archive, dict) or set(archive) != _ARCHIVE_FIELDS:
        raise BuildValidationError("archive has unsupported or missing fields")
    archive_format = _literal(archive["format"], {"zip", "tar.gz"}, "archive format")
    archive_extension = _literal(
        archive["extension"], {"zip", "tar.gz"}, "archive extension"
    )
    if archive_format != archive_extension:
        raise BuildValidationError("archive format and extension must match")
    template = archive["name_template"]
    if not isinstance(template, str):
        raise BuildValidationError("archive name template must be a string")
    _validate_artifact_template(template)
    forbidden_modules = _string_tuple(raw["forbidden_modules"], "forbidden modules")
    if any(not _MODULE_RE.fullmatch(module) for module in forbidden_modules):
        raise BuildValidationError("forbidden modules must be Python module names")
    forbidden_paths = _string_tuple(
        raw["forbidden_path_patterns"], "forbidden path patterns"
    )
    if any(not _is_safe_relative_pattern(pattern) for pattern in forbidden_paths):
        raise BuildValidationError("forbidden path patterns must be normalised relative paths")
    size_baseline_id = raw["size_baseline_id"]
    _validate_scalar(size_baseline_id, "size baseline id")
    macos_minimum_version = raw["macos_minimum_version"]
    if platform == "darwin":
        if macos_minimum_version != "13.0":
            raise BuildValidationError("macOS targets must set macos_minimum_version to 13.0")
    elif macos_minimum_version is not None:
        raise BuildValidationError("only macOS targets may set macos_minimum_version")
    return TargetSpec(
        name=name,
        policy_path=policy_path,
        platform=platform,  # type: ignore[arg-type]
        architecture=architecture,  # type: ignore[arg-type]
        python_version=python_version,
        requirements_lock=_policy_file(
            policy_root, raw["requirements_lock"], "requirements lock", required=True
        ),
        archive_format=archive_format,  # type: ignore[arg-type]
        archive_extension=archive_extension,  # type: ignore[arg-type]
        artifact_name_template=template,
        forbidden_modules=forbidden_modules,
        forbidden_path_patterns=forbidden_paths,
        warning_allowlist=_policy_file(
            policy_root, raw["warning_allowlist"], "warning allowlist", required=False
        ),
        size_baselines=_policy_file(
            policy_root, raw["size_baselines"], "size baselines", required=False
        ),
        size_baseline_id=size_baseline_id,
        macos_minimum_version=macos_minimum_version,
        build_command_timeout_seconds=build_command_timeout_seconds,
    )


def _policy_file(
    policy_root: Path, value: object, label: str, *, required: bool
) -> Path:
    if not isinstance(value, str) or not _is_safe_relative_pattern(value):
        raise BuildValidationError(f"{label} must be a safe relative path")
    candidate = (policy_root / PurePosixPath(value)).resolve()
    try:
        candidate.relative_to(policy_root.resolve())
    except ValueError as error:
        raise BuildValidationError(f"{label} escapes the policy directory") from error
    if required:
        return _require_regular_file(candidate, label)
    return candidate


def _require_regular_file(path: Path, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} must be a Path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise BuildValidationError(f"{label} does not exist") from error
    if not resolved.is_file():
        raise BuildValidationError(f"{label} must be a regular file")
    return resolved


def _literal(value: object, allowed: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise BuildValidationError(f"{label} is invalid")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise BuildValidationError(f"{label} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise BuildValidationError(f"{label} must not contain duplicates")
    return tuple(value)


def _is_safe_relative_pattern(value: str) -> bool:
    if (
        not value
        or len(value) > 255
        or "\x00" in value
        or "\r" in value
        or "\n" in value
        or "\\" in value
    ):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and not ({".", ".."} & set(value.split("/")))


def _validate_artifact_template(template: str) -> None:
    if not template or len(template) > 256 or "/" in template or "\\" in template:
        raise BuildValidationError("archive name template is unsafe")
    fields: set[str] = set()
    try:
        for _, field_name, format_spec, conversion in string.Formatter().parse(template):
            if field_name is None:
                continue
            if field_name not in {"product_version", "target", "extension"}:
                raise BuildValidationError("archive name template uses an unsupported field")
            if format_spec or conversion:
                raise BuildValidationError("archive name template cannot format fields")
            fields.add(field_name)
        rendered = template.format(product_version="1.2.3", target="linux-x64", extension="tar.gz")
    except (ValueError, KeyError) as error:
        raise BuildValidationError("archive name template is invalid") from error
    if fields != {"product_version", "target", "extension"} or ".." in rendered:
        raise BuildValidationError("archive name template is unsafe")


def _validate_target_identity(
    target: TargetSpec,
    policy_path: Path,
    expected: tuple[str, str, str, str, str | None],
) -> None:
    """Pin target names to their reviewed native build identities."""
    policy_root = policy_path.parent
    platform, architecture, archive_format, lock_path, macos_minimum = expected
    if (
        target.policy_path != policy_path
        or target.platform != platform
        or target.architecture != architecture
        or target.archive_format != archive_format
        or target.archive_extension != archive_format
        or target.macos_minimum_version != macos_minimum
        or target.artifact_name_template != _ARTIFACT_TEMPLATE
        or target.requirements_lock != (policy_root / lock_path).resolve()
        or target.warning_allowlist != (policy_root / _WARNING_ALLOWLIST).resolve()
        or target.size_baselines != (policy_root / _SIZE_BASELINES).resolve()
    ):
        raise BuildValidationError("target policy does not match the supported target identity")


def _validate_scalar(value: object, label: str) -> None:
    if not isinstance(value, str) or not _SCALAR_RE.fullmatch(value):
        raise BuildValidationError(f"{label} is invalid")


def _wheel_product_version(wheel: Path) -> str:
    """Read and validate the Servonaut identity from a built wheel."""
    try:
        with zipfile.ZipFile(wheel) as archive:
            metadata_names = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise BuildValidationError("wheel must contain exactly one METADATA file")
            metadata = BytesParser(policy=default).parsebytes(archive.read(metadata_names[0]))
            name = metadata.get("Name")
            version = metadata.get("Version")
            normalised_name = re.sub(r"[-_.]+", "-", name).casefold() if name else ""
            if normalised_name != "servonaut":
                raise BuildValidationError("wheel is not the servonaut distribution")
            if not isinstance(version, str) or not _PRODUCT_VERSION_RE.fullmatch(version):
                raise BuildValidationError("wheel has an invalid product version")
            for direct_url_name in (
                name for name in archive.namelist() if name.endswith(".dist-info/direct_url.json")
            ):
                direct_url = json.loads(archive.read(direct_url_name).decode("utf-8"))
                if isinstance(direct_url, dict) and isinstance(direct_url.get("dir_info"), dict):
                    raise BuildValidationError("editable wheels are not valid build input")
            return version
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
        RecursionError,
    ) as error:
        raise BuildValidationError("wheel metadata could not be read") from error


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Decode JSON objects while rejecting duplicate keys at every depth."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BuildValidationError(f"target policy duplicates key {key!r}")
        result[key] = value
    return result

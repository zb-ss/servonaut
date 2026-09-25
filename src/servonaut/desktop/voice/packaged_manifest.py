"""Strict loader for the voice-runtime manifest bundled with a desktop build.

The desktop build places the pinned ``uv`` executable, the matching Servonaut
wheel, the hash-locked voice requirements and this manifest in the ``voice``
directory of its resources. The manifest pins every input by SHA-256 and
carries the provisioning time limits, so nothing about the managed voice
runtime is resolved from the network or the user's environment.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

PACKAGED_VOICE_DIRNAME: Final = "voice"
PACKAGED_MANIFEST_FILENAME: Final = "voice-runtime.json"
REQUIREMENTS_FILENAME: Final = "voice-requirements.txt"

_SCHEMA_VERSION: Final = 1
# The manifest is a small, fixed build-time document. This protocol bound keeps
# a damaged or substituted file from consuming unbounded memory.
_MAX_MANIFEST_BYTES: Final = 64 * 1024
# Upper bound for any single time limit. It rejects nonsensical values rather
# than expressing a policy; the actual limits come from the manifest.
_MAX_TIMEOUT_SECONDS: Final = 24 * 60 * 60

_ROOT_KEYS: Final = frozenset(
    {
        "schema_version",
        "target",
        "python_version",
        "uv",
        "wheel",
        "requirements",
        "timeouts",
    }
)
_FILE_KEYS: Final = frozenset({"filename", "sha256"})
_TIMEOUT_KEYS: Final = frozenset(
    {"uv_command_seconds", "stall_seconds", "provision_seconds"}
)

_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_TARGET_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_FILENAME_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
_PYTHON_VERSION_PATTERN: Final = re.compile(r"3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


class PackagedVoiceManifestError(ValueError):
    """Raised when the bundled voice-runtime manifest is missing or invalid."""


@dataclass(frozen=True)
class BundledFile:
    """A file shipped next to the manifest, pinned by its SHA-256 digest."""

    filename: str
    sha256: str


@dataclass(frozen=True)
class ProvisionTimeouts:
    """Time limits for provisioning, in seconds."""

    uv_command_seconds: int
    stall_seconds: int
    provision_seconds: int


@dataclass(frozen=True)
class PackagedVoiceManifest:
    """Validated contents of the bundled voice-runtime manifest."""

    schema_version: int
    target: str
    python_version: str
    uv: BundledFile
    wheel: BundledFile
    requirements: BundledFile
    timeouts: ProvisionTimeouts


def load_packaged_manifest(path: Path) -> PackagedVoiceManifest:
    """Read and validate the manifest at ``path``.

    Raises:
        PackagedVoiceManifestError: If the file cannot be read, is larger than
            the protocol bound, or does not match the schema exactly.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_MANIFEST_BYTES + 1)
    except OSError as error:
        raise PackagedVoiceManifestError(
            f"The voice runtime manifest could not be read: {error.strerror or error}"
        ) from error
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise PackagedVoiceManifestError("The voice runtime manifest is too large.")
    return parse_packaged_manifest(raw)


def parse_packaged_manifest(raw: bytes) -> PackagedVoiceManifest:
    """Validate manifest bytes against the exact schema."""
    document = _require_object(_decode_document(raw), _ROOT_KEYS, "manifest")
    schema_version = _require_int(document["schema_version"], "schema_version")
    if schema_version != _SCHEMA_VERSION:
        raise PackagedVoiceManifestError(
            f"Unsupported voice runtime manifest schema_version {schema_version}."
        )
    requirements = _bundled_file(document["requirements"], "requirements")
    if requirements.filename != REQUIREMENTS_FILENAME:
        raise PackagedVoiceManifestError(
            f"requirements.filename must be {REQUIREMENTS_FILENAME!r}."
        )
    wheel = _bundled_file(document["wheel"], "wheel")
    if not wheel.filename.endswith(".whl"):
        raise PackagedVoiceManifestError("wheel.filename must name a .whl file.")
    return PackagedVoiceManifest(
        schema_version=schema_version,
        target=_require_match(document["target"], _TARGET_PATTERN, "target"),
        python_version=_require_match(
            document["python_version"], _PYTHON_VERSION_PATTERN, "python_version"
        ),
        uv=_bundled_file(document["uv"], "uv"),
        wheel=wheel,
        requirements=requirements,
        timeouts=_timeouts(document["timeouts"]),
    )


def _decode_document(raw: bytes) -> object:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise PackagedVoiceManifestError(
            f"The voice runtime manifest is not valid JSON: {error}"
        ) from None
    return document


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackagedVoiceManifestError(f"Duplicate manifest key {key!r}.")
        result[key] = value
    return result


def _reject_constant(constant: str) -> None:
    raise PackagedVoiceManifestError(f"Unsupported JSON constant {constant}.")


def _require_object(
    value: object, expected: frozenset[str], field: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PackagedVoiceManifestError(f"{field} must be an object.")
    keys = set(value)
    if keys != expected:
        missing = sorted(expected - keys)
        unknown = sorted(keys - expected)
        raise PackagedVoiceManifestError(
            f"{field} has missing keys {missing} or unknown keys {unknown}."
        )
    return value


def _require_int(value: object, field: str) -> int:
    if type(value) is not int:
        raise PackagedVoiceManifestError(f"{field} must be an integer.")
    return value


def _require_match(value: object, pattern: re.Pattern[str], field: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise PackagedVoiceManifestError(f"{field} is malformed.")
    return value


def _bundled_file(value: object, field: str) -> BundledFile:
    entry = _require_object(value, _FILE_KEYS, field)
    return BundledFile(
        filename=_require_match(entry["filename"], _FILENAME_PATTERN, f"{field}.filename"),
        sha256=_require_match(entry["sha256"], _SHA256_PATTERN, f"{field}.sha256"),
    )


def _timeouts(value: object) -> ProvisionTimeouts:
    entry = _require_object(value, _TIMEOUT_KEYS, "timeouts")
    seconds = {key: _timeout_value(entry[key], f"timeouts.{key}") for key in _TIMEOUT_KEYS}
    timeouts = ProvisionTimeouts(**seconds)
    if not (
        timeouts.stall_seconds
        <= timeouts.uv_command_seconds
        <= timeouts.provision_seconds
    ):
        raise PackagedVoiceManifestError(
            "timeouts must satisfy stall_seconds <= uv_command_seconds <= provision_seconds."
        )
    return timeouts


def _timeout_value(value: object, field: str) -> int:
    seconds = _require_int(value, field)
    if not 0 < seconds <= _MAX_TIMEOUT_SECONDS:
        raise PackagedVoiceManifestError(
            f"{field} must be between 1 and {_MAX_TIMEOUT_SECONDS} seconds."
        )
    return seconds

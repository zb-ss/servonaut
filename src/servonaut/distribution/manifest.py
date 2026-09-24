"""Data models, schema validation, and canonicalization for Servonaut release manifests."""

from __future__ import annotations

import json
import re
import reprlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Optional, Sequence

from servonaut.runtime import DistributionKind

_NUMERIC_IDENTIFIER = r"0|[1-9][0-9]*"
_PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_BUILD_IDENTIFIER = r"[0-9A-Za-z-]+"
# Semantic Versioning 2.0.0, matched with fullmatch so no trailing newline or
# non-ASCII digit can slip through.
_SEMVER_REGEX = re.compile(
    rf"({_NUMERIC_IDENTIFIER})\.({_NUMERIC_IDENTIFIER})\.({_NUMERIC_IDENTIFIER})"
    rf"(?:-({_PRERELEASE_IDENTIFIER}(?:\.{_PRERELEASE_IDENTIFIER})*))?"
    rf"(?:\+({_BUILD_IDENTIFIER}(?:\.{_BUILD_IDENTIFIER})*))?"
)
_HEX_64_REGEX = re.compile(r"[0-9a-fA-F]{64}")
_HEX_SIGNATURE_REGEX = re.compile(r"[0-9a-fA-F]{128}")
# On platforms whose host version can be read, min_os is a dotted decimal
# operating-system version such as "13.0" and is enforced by clients.
_OS_VERSION_REGEX = re.compile(r"[0-9]+(?:\.[0-9]+){0,3}")
_VERSIONED_OS_PLATFORMS = frozenset({"darwin", "windows"})
_SUPPORTED_SCHEMA_VERSIONS = {1}
_SUPPORTED_PLATFORMS = {"linux", "darwin", "windows"}
_SUPPORTED_ARCHITECTURES = {"x86_64", "arm64"}

# Manifest content is untrusted until verified, so values echoed into error
# messages are escaped and truncated rather than interpolated verbatim.
_UNTRUSTED_REPR = reprlib.Repr()
_UNTRUSTED_REPR.maxstring = 80
_UNTRUSTED_REPR.maxother = 80
_UNTRUSTED_REPR.maxlist = 4
_UNTRUSTED_REPR.maxdict = 4
_UNTRUSTED_REPR.maxlevel = 2


class ArtifactKind(str, Enum):
    """The type of distribution artifact."""

    STANDALONE_CLI = "standalone_cli"
    MACOS_DMG = "macos_dmg"
    WINDOWS_MSI = "windows_msi"
    UBUNTU_DEB = "ubuntu_deb"


class ReleaseChannel(str, Enum):
    """The distribution update release channel."""

    STABLE = "stable"
    PREVIEW = "preview"
    NIGHTLY = "nightly"


class ManifestError(Exception):
    """Base exception for release manifest errors."""


class ManifestSchemaError(ManifestError):
    """Raised when a release manifest or artifact violates schema rules."""


def bounded_repr(value: object) -> str:
    """Return an escaped, length-bounded representation of an untrusted value."""
    return _UNTRUSTED_REPR.repr(value)


@dataclass(frozen=True, slots=True)
class SemVer:
    """A parsed Semantic Versioning 2.0.0 version."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @property
    def precedence(self) -> tuple[object, ...]:
        """Sort key implementing SemVer 2.0.0 section 11 precedence.

        Build metadata is ignored. A release outranks any of its prereleases;
        numeric prerelease identifiers compare numerically, sort below
        alphanumeric ones, and a longer identifier list wins a shared prefix.
        """
        if not self.prerelease:
            return (self.major, self.minor, self.patch, (1,))
        identifiers = tuple(
            (0, int(part), "") if part.isdigit() else (1, 0, part)
            for part in self.prerelease
        )
        return (self.major, self.minor, self.patch, (0, identifiers))


def parse_semver(version: object) -> SemVer:
    """Parse a Semantic Versioning 2.0.0 string.

    Raises:
        ManifestSchemaError: If the value is not a valid semantic version.
    """
    match = _SEMVER_REGEX.fullmatch(version) if isinstance(version, str) else None
    if match is None:
        raise ManifestSchemaError(
            f"Invalid semantic version string: {bounded_repr(version)}"
        )
    major, minor, patch, prerelease, build = match.groups()
    return SemVer(
        major=int(major),
        minor=int(minor),
        patch=int(patch),
        prerelease=tuple(prerelease.split(".")) if prerelease else (),
        build=tuple(build.split(".")) if build else (),
    )


def parse_timestamp(value: object) -> datetime:
    """Parse an ISO 8601 manifest timestamp into an aware UTC-based datetime.

    A trailing ``Z`` is accepted on every supported Python version, and a
    timestamp without an offset is taken to be UTC.

    Raises:
        ManifestSchemaError: If the value is not a parseable timestamp.
    """
    if not isinstance(value, str) or not value:
        raise ManifestSchemaError(f"Invalid ISO 8601 timestamp: {bounded_repr(value)}")
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise ManifestSchemaError(
            f"Invalid ISO 8601 timestamp: {bounded_repr(value)}"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True, slots=True)
class ReleaseArtifact:
    """A downloadable distribution artifact described within a release manifest.

    ``filename`` is a bare file name. For macOS and Windows artifacts
    ``min_os`` is the minimum operating-system version as dot-separated
    integers, such as ``"13.0"`` for macOS 13 or ``"10.0.17763"`` for Windows,
    and clients refuse the artifact on an older host. On other platforms it is
    a free-form, informational label such as ``"Ubuntu 22.04"``.
    """

    artifact_id: str
    kind: ArtifactKind
    distribution: DistributionKind
    platform: str
    arch: str
    filename: str
    download_url: str
    byte_size: int
    sha256: str
    min_os: Optional[str] = None
    sbom_sha256: Optional[str] = None
    attestation_url: Optional[str] = None
    signature: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_id, str) or not self.artifact_id:
            raise ManifestSchemaError("Artifact ID must be a non-empty string.")
        if not isinstance(self.kind, ArtifactKind):
            raise ManifestSchemaError(f"Invalid artifact kind: {bounded_repr(self.kind)}")
        if not isinstance(self.distribution, DistributionKind):
            raise ManifestSchemaError(
                f"Invalid distribution kind: {bounded_repr(self.distribution)}"
            )
        _require_member(self.platform, _SUPPORTED_PLATFORMS, "Platform")
        _require_member(self.arch, _SUPPORTED_ARCHITECTURES, "Architecture")
        _require_bare_filename(self.filename)
        if not isinstance(self.download_url, str) or not self.download_url:
            raise ManifestSchemaError("Download URL must be a non-empty string.")
        if not isinstance(self.byte_size, int) or isinstance(self.byte_size, bool) or self.byte_size <= 0:
            raise ManifestSchemaError("Byte size must be a positive integer.")
        _require_pattern(
            self.sha256, _HEX_64_REGEX, "SHA-256 digest must be a 64-character hex string."
        )
        self._validate_optional_fields()

    def _validate_optional_fields(self) -> None:
        if self.min_os is not None:
            if not isinstance(self.min_os, str) or not self.min_os:
                raise ManifestSchemaError("min_os must be a non-empty string when provided.")
            if self.platform in _VERSIONED_OS_PLATFORMS:
                _require_pattern(
                    self.min_os,
                    _OS_VERSION_REGEX,
                    f"min_os for {self.platform} must be a dotted decimal version such as '13.0'.",
                )
        if self.sbom_sha256 is not None:
            _require_pattern(
                self.sbom_sha256,
                _HEX_64_REGEX,
                "SBOM SHA-256 digest must be a 64-character hex string.",
            )
        if self.attestation_url is not None and (
            not isinstance(self.attestation_url, str) or not self.attestation_url
        ):
            raise ManifestSchemaError("Attestation URL must be a non-empty string when provided.")
        if self.signature is not None:
            _require_pattern(
                self.signature,
                _HEX_SIGNATURE_REGEX,
                "Artifact signature must be a 128-character hex Ed25519 signature.",
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert artifact to a JSON-serializable dictionary."""
        data: dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "kind": self.kind.value,
            "distribution": self.distribution.value,
            "platform": self.platform,
            "arch": self.arch,
            "filename": self.filename,
            "download_url": self.download_url,
            "byte_size": self.byte_size,
            "sha256": self.sha256.lower(),
        }
        if self.min_os is not None:
            data["min_os"] = self.min_os
        if self.sbom_sha256 is not None:
            data["sbom_sha256"] = self.sbom_sha256.lower()
        if self.attestation_url is not None:
            data["attestation_url"] = self.attestation_url
        if self.signature is not None:
            data["signature"] = self.signature
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReleaseArtifact:
        """Construct a ReleaseArtifact from a dictionary."""
        if not isinstance(data, Mapping):
            raise ManifestSchemaError("Artifact payload must be a mapping.")

        required_fields = {
            "artifact_id",
            "kind",
            "distribution",
            "platform",
            "arch",
            "filename",
            "download_url",
            "byte_size",
            "sha256",
        }
        missing = required_fields - set(data.keys())
        if missing:
            raise ManifestSchemaError(f"Artifact missing required fields: {sorted(missing)}")

        try:
            kind = ArtifactKind(data["kind"])
        except ValueError as err:
            raise ManifestSchemaError(
                f"Unknown artifact kind: {bounded_repr(data['kind'])}"
            ) from err

        try:
            distribution = DistributionKind(data["distribution"])
        except ValueError as err:
            raise ManifestSchemaError(
                f"Unknown distribution kind: {bounded_repr(data['distribution'])}"
            ) from err

        return cls(
            artifact_id=data["artifact_id"],
            kind=kind,
            distribution=distribution,
            platform=data["platform"],
            arch=data["arch"],
            filename=data["filename"],
            download_url=data["download_url"],
            byte_size=data["byte_size"],
            sha256=data["sha256"],
            min_os=data.get("min_os"),
            sbom_sha256=data.get("sbom_sha256"),
            attestation_url=data.get("attestation_url"),
            signature=data.get("signature"),
        )


@dataclass(frozen=True, slots=True)
class ManifestSignature:
    """A cryptographic signature over the canonical release manifest bytes."""

    key_id: str
    algorithm: str
    signature: str
    signed_at: str

    def __post_init__(self) -> None:
        if not self.key_id or not isinstance(self.key_id, str):
            raise ManifestSchemaError("Signature key_id must be a non-empty string.")
        if not self.algorithm or not isinstance(self.algorithm, str):
            raise ManifestSchemaError("Signature algorithm must be a non-empty string.")
        if self.algorithm.lower() != "ed25519":
            raise ManifestSchemaError(
                f"Unsupported signature algorithm {bounded_repr(self.algorithm)}. Must be 'ed25519'."
            )
        if not self.signature or not isinstance(self.signature, str):
            raise ManifestSchemaError("Signature bytes must be a non-empty string.")
        if not self.signed_at or not isinstance(self.signed_at, str):
            raise ManifestSchemaError("Signature signed_at must be a non-empty ISO 8601 string.")

    def to_dict(self) -> dict[str, Any]:
        """Convert signature to a JSON-serializable dictionary."""
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm.lower(),
            "signature": self.signature,
            "signed_at": self.signed_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ManifestSignature:
        """Construct a ManifestSignature from a dictionary."""
        if not isinstance(data, Mapping):
            raise ManifestSchemaError("Signature payload must be a mapping.")

        required_fields = {"key_id", "algorithm", "signature", "signed_at"}
        missing = required_fields - set(data.keys())
        if missing:
            raise ManifestSchemaError(f"Signature missing required fields: {sorted(missing)}")

        return cls(
            key_id=data["key_id"],
            algorithm=data["algorithm"],
            signature=data["signature"],
            signed_at=data["signed_at"],
        )


@dataclass(frozen=True, slots=True)
class ReleaseManifest:
    """A canonical signed release manifest declaring available artifacts."""

    schema_version: int
    channel: ReleaseChannel
    product_version: str
    published_at: str
    artifacts: tuple[ReleaseArtifact, ...]
    signatures: tuple[ManifestSignature, ...]
    packaging_revision: Optional[int] = None
    expires_at: Optional[str] = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.schema_version, int)
            or isinstance(self.schema_version, bool)
            or self.schema_version not in _SUPPORTED_SCHEMA_VERSIONS
        ):
            raise ManifestSchemaError(
                f"Unsupported manifest schema_version: {bounded_repr(self.schema_version)}"
            )
        if not isinstance(self.channel, ReleaseChannel):
            raise ManifestSchemaError(f"Invalid release channel: {bounded_repr(self.channel)}")
        try:
            parse_semver(self.product_version)
        except ManifestSchemaError:
            raise ManifestSchemaError(
                f"Product version {bounded_repr(self.product_version)} "
                "is not a valid Semantic Version (X.Y.Z)."
            ) from None
        if not self.published_at or not isinstance(self.published_at, str):
            raise ManifestSchemaError("published_at must be a non-empty ISO 8601 string.")
        if self.packaging_revision is not None:
            if (
                not isinstance(self.packaging_revision, int)
                or isinstance(self.packaging_revision, bool)
                or self.packaging_revision < 1
            ):
                raise ManifestSchemaError("packaging_revision must be a positive integer (>= 1).")
        if self.expires_at is not None and (not isinstance(self.expires_at, str) or not self.expires_at):
            raise ManifestSchemaError("expires_at must be a non-empty string when provided.")
        if not isinstance(self.artifacts, tuple) or not self.artifacts:
            raise ManifestSchemaError("Release manifest must declare at least one artifact.")
        for artifact in self.artifacts:
            if not isinstance(artifact, ReleaseArtifact):
                raise ManifestSchemaError("Artifacts must be instances of ReleaseArtifact.")
        if not isinstance(self.signatures, tuple):
            raise ManifestSchemaError("Signatures must be a tuple of ManifestSignature instances.")
        for sig in self.signatures:
            if not isinstance(sig, ManifestSignature):
                raise ManifestSchemaError("Signatures must be instances of ManifestSignature.")

    def canonical_bytes(self) -> bytes:
        """Generate canonical bytes for cryptographic signing and verification.

        The canonical payload omits the ``signatures`` field and serializes the
        manifest in deterministic sorted compact JSON (RFC 8785).
        """
        payload = self.to_dict()
        payload.pop("signatures", None)
        return canonicalize_json(payload)

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to a JSON-serializable dictionary."""
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "channel": self.channel.value,
            "product_version": self.product_version,
            "published_at": self.published_at,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "signatures": [sig.to_dict() for sig in self.signatures],
        }
        if self.packaging_revision is not None:
            data["packaging_revision"] = self.packaging_revision
        if self.expires_at is not None:
            data["expires_at"] = self.expires_at
        return data

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        """Serialize manifest to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReleaseManifest:
        """Construct a ReleaseManifest from a dictionary."""
        if not isinstance(data, Mapping):
            raise ManifestSchemaError("Manifest payload must be a mapping.")

        required_fields = {
            "schema_version",
            "channel",
            "product_version",
            "published_at",
            "artifacts",
        }
        missing = required_fields - set(data.keys())
        if missing:
            raise ManifestSchemaError(f"Manifest missing required fields: {sorted(missing)}")

        try:
            channel = ReleaseChannel(data["channel"])
        except ValueError as err:
            raise ManifestSchemaError(
                f"Unknown release channel: {bounded_repr(data['channel'])}"
            ) from err

        raw_artifacts = data["artifacts"]
        if not isinstance(raw_artifacts, Sequence) or isinstance(raw_artifacts, (str, bytes)):
            raise ManifestSchemaError("Artifacts must be a sequence of artifact mappings.")
        artifacts = tuple(ReleaseArtifact.from_dict(item) for item in raw_artifacts)

        raw_signatures = data.get("signatures", [])
        if not isinstance(raw_signatures, Sequence) or isinstance(raw_signatures, (str, bytes)):
            raise ManifestSchemaError("Signatures must be a sequence of signature mappings.")
        signatures = tuple(ManifestSignature.from_dict(item) for item in raw_signatures)

        return cls(
            schema_version=data["schema_version"],
            channel=channel,
            product_version=data["product_version"],
            published_at=data["published_at"],
            artifacts=artifacts,
            signatures=signatures,
            packaging_revision=data.get("packaging_revision"),
            expires_at=data.get("expires_at"),
        )

    @classmethod
    def from_json(cls, raw_json: str | bytes) -> ReleaseManifest:
        """Parse a ReleaseManifest from raw JSON bytes or string."""
        try:
            data = json.loads(raw_json)
        except Exception as err:
            raise ManifestSchemaError(f"Failed to decode manifest JSON: {err}") from err
        return cls.from_dict(data)


def canonicalize_json(data: Any) -> bytes:
    """Deterministically serialize data to UTF-8 canonical JSON (RFC 8785 subset).

    - Dictionary keys are recursively sorted.
    - Compact separators (',', ':') with no extraneous whitespace.
    - Strict UTF-8 encoding.
    """
    def _normalize(val: Any) -> Any:
        if isinstance(val, Mapping):
            return {k: _normalize(val[k]) for k in sorted(val.keys())}
        if isinstance(val, (list, tuple)):
            return [_normalize(item) for item in val]
        if isinstance(val, Enum):
            return val.value
        return val

    normalized = _normalize(data)
    serialized = json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    try:
        return serialized.encode("utf-8")
    except UnicodeEncodeError:
        raise ManifestSchemaError(
            "Manifest contains text that is not valid Unicode (for example a lone surrogate)."
        ) from None


def _require_member(value: object, allowed: frozenset[str] | set[str], label: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ManifestSchemaError(
            f"{label} {bounded_repr(value)} is not supported. Must be one of {sorted(allowed)}."
        )


def _require_pattern(value: object, pattern: re.Pattern[str], message: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ManifestSchemaError(message)


def _require_bare_filename(filename: object) -> None:
    """Require a bare file name so a download can never leave its directory."""
    if not isinstance(filename, str) or not filename:
        raise ManifestSchemaError("Filename must be a non-empty string.")
    if (
        filename in {".", ".."}
        or PurePosixPath(filename).name != filename
        or PureWindowsPath(filename).name != filename
        or any(ord(char) < 0x20 or char == "\x7f" for char in filename)
    ):
        raise ManifestSchemaError(
            f"Filename {bounded_repr(filename)} must be a bare file name without directories."
        )

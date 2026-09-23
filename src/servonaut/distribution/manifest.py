"""Data models, schema validation, and canonicalization for Servonaut release manifests."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Sequence

from servonaut.runtime import DistributionKind

_SEMVER_REGEX = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_HEX_64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
_SUPPORTED_SCHEMA_VERSIONS = {1}
_SUPPORTED_PLATFORMS = {"linux", "darwin", "windows"}
_SUPPORTED_ARCHITECTURES = {"x86_64", "arm64"}


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


@dataclass(frozen=True, slots=True)
class ReleaseArtifact:
    """A downloadable distribution artifact described within a release manifest."""

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
        if not self.artifact_id or not isinstance(self.artifact_id, str):
            raise ManifestSchemaError("Artifact ID must be a non-empty string.")
        if not isinstance(self.kind, ArtifactKind):
            raise ManifestSchemaError(f"Invalid artifact kind: {self.kind}")
        if not isinstance(self.distribution, DistributionKind):
            raise ManifestSchemaError(f"Invalid distribution kind: {self.distribution}")
        if self.platform not in _SUPPORTED_PLATFORMS:
            raise ManifestSchemaError(
                f"Platform '{self.platform}' is not supported. Must be one of {_SUPPORTED_PLATFORMS}."
            )
        if self.arch not in _SUPPORTED_ARCHITECTURES:
            raise ManifestSchemaError(
                f"Architecture '{self.arch}' is not supported. Must be one of {_SUPPORTED_ARCHITECTURES}."
            )
        if not self.filename or not isinstance(self.filename, str):
            raise ManifestSchemaError("Filename must be a non-empty string.")
        if not self.download_url or not isinstance(self.download_url, str):
            raise ManifestSchemaError("Download URL must be a non-empty string.")
        if not isinstance(self.byte_size, int) or isinstance(self.byte_size, bool) or self.byte_size <= 0:
            raise ManifestSchemaError("Byte size must be a positive integer.")
        if not isinstance(self.sha256, str) or not _HEX_64_REGEX.match(self.sha256):
            raise ManifestSchemaError("SHA-256 digest must be a 64-character hex string.")
        if self.sbom_sha256 is not None:
            if not isinstance(self.sbom_sha256, str) or not _HEX_64_REGEX.match(self.sbom_sha256):
                raise ManifestSchemaError("SBOM SHA-256 digest must be a 64-character hex string.")

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
            raise ManifestSchemaError(f"Unknown artifact kind: {data['kind']}") from err

        try:
            distribution = DistributionKind(data["distribution"])
        except ValueError as err:
            raise ManifestSchemaError(f"Unknown distribution kind: {data['distribution']}") from err

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
            raise ManifestSchemaError(f"Unsupported signature algorithm '{self.algorithm}'. Must be 'ed25519'.")
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
            raise ManifestSchemaError(f"Unsupported manifest schema_version: {self.schema_version}")
        if not isinstance(self.channel, ReleaseChannel):
            raise ManifestSchemaError(f"Invalid release channel: {self.channel}")
        if not isinstance(self.product_version, str) or not _SEMVER_REGEX.match(self.product_version):
            raise ManifestSchemaError(
                f"Product version '{self.product_version}' is not a valid Semantic Version (X.Y.Z)."
            )
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
            raise ManifestSchemaError(f"Unknown release channel: {data['channel']}") from err

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
    return json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

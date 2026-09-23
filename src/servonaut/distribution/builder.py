"""Builder for assembling, sizing, hashing, and signing release manifests."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
from typing import Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution.manifest import (
    ArtifactKind,
    ManifestError,
    ManifestSchemaError,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    _SEMVER_REGEX,
)
from servonaut.distribution.trust import sign_manifest
from servonaut.runtime import DistributionKind


class ManifestBuilderError(ManifestError):
    """Raised when release manifest assembly fails validation."""


class ManifestBuilder:
    """Fluent, type-safe builder to construct and validate ReleaseManifest instances."""

    def __init__(
        self,
        product_version: str,
        *,
        channel: ReleaseChannel = ReleaseChannel.STABLE,
        packaging_revision: Optional[int] = None,
        published_at: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> None:
        if not isinstance(product_version, str) or not _SEMVER_REGEX.match(product_version):
            raise ManifestSchemaError(
                f"Product version '{product_version}' is not a valid Semantic Version (X.Y.Z)."
            )
        if not isinstance(channel, ReleaseChannel):
            raise ManifestSchemaError(f"Invalid release channel: {channel}")
        if packaging_revision is not None and (
            not isinstance(packaging_revision, int) or isinstance(packaging_revision, bool) or packaging_revision < 0
        ):
            raise ManifestSchemaError("packaging_revision must be a non-negative integer.")

        self._product_version = product_version
        self._channel = channel
        self._packaging_revision = packaging_revision
        self._published_at = published_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._expires_at = expires_at
        self._artifacts: dict[str, ReleaseArtifact] = {}

    @property
    def product_version(self) -> str:
        """Target semantic product version."""
        return self._product_version

    @property
    def channel(self) -> ReleaseChannel:
        """Release channel."""
        return self._channel

    @property
    def packaging_revision(self) -> Optional[int]:
        """Packaging revision."""
        return self._packaging_revision

    @property
    def published_at(self) -> str:
        """Publication timestamp."""
        return self._published_at

    @property
    def expires_at(self) -> Optional[str]:
        """Expiration timestamp."""
        return self._expires_at

    @property
    def artifacts(self) -> tuple[ReleaseArtifact, ...]:
        """Declared release artifacts."""
        return tuple(self._artifacts.values())

    def add_artifact(self, artifact: ReleaseArtifact) -> ManifestBuilder:
        """Register a pre-constructed ReleaseArtifact."""
        if artifact.artifact_id in self._artifacts:
            raise ManifestBuilderError(f"Artifact with ID '{artifact.artifact_id}' already added.")
        self._artifacts[artifact.artifact_id] = artifact
        return self

    def add_artifact_file(
        self,
        file_path: Path | str,
        *,
        kind: ArtifactKind,
        distribution: DistributionKind,
        platform: str,
        arch: str,
        download_url: str,
        artifact_id: Optional[str] = None,
        min_os: Optional[str] = None,
        sbom_file: Optional[Path | str] = None,
        attestation_url: Optional[str] = None,
        signature: Optional[str] = None,
    ) -> ReleaseArtifact:
        """Inspect a local file on disk, compute SHA-256 and byte size, and register it."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Artifact file not found: {path}")

        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)
        sha256 = hasher.hexdigest().lower()
        byte_size = path.stat().st_size

        sbom_sha256: Optional[str] = None
        if sbom_file is not None:
            sbom_path = Path(sbom_file).resolve()
            if not sbom_path.is_file():
                raise FileNotFoundError(f"SBOM file not found: {sbom_path}")
            sbom_hasher = hashlib.sha256()
            with open(sbom_path, "rb") as f:
                while chunk := f.read(64 * 1024):
                    sbom_hasher.update(chunk)
            sbom_sha256 = sbom_hasher.hexdigest().lower()

        resolved_id = artifact_id or f"{kind.value}-{platform}-{arch}"
        artifact = ReleaseArtifact(
            artifact_id=resolved_id,
            kind=kind,
            distribution=distribution,
            platform=platform,
            arch=arch,
            filename=path.name,
            download_url=download_url,
            byte_size=byte_size,
            sha256=sha256,
            min_os=min_os,
            sbom_sha256=sbom_sha256,
            attestation_url=attestation_url,
            signature=signature,
        )
        self.add_artifact(artifact)
        return artifact

    def sign_artifact(
        self,
        artifact_id: str,
        private_key: Ed25519PrivateKey,
    ) -> ManifestBuilder:
        """Sign an individual artifact's SHA-256 digest using Ed25519 and record its signature."""
        if artifact_id not in self._artifacts:
            raise ManifestBuilderError(f"Cannot sign unknown artifact ID '{artifact_id}'.")

        old_art = self._artifacts[artifact_id]
        raw_sig = private_key.sign(old_art.sha256.encode("ascii"))
        sig_hex = raw_sig.hex()

        updated_art = ReleaseArtifact(
            artifact_id=old_art.artifact_id,
            kind=old_art.kind,
            distribution=old_art.distribution,
            platform=old_art.platform,
            arch=old_art.arch,
            filename=old_art.filename,
            download_url=old_art.download_url,
            byte_size=old_art.byte_size,
            sha256=old_art.sha256,
            min_os=old_art.min_os,
            sbom_sha256=old_art.sbom_sha256,
            attestation_url=old_art.attestation_url,
            signature=sig_hex,
        )
        self._artifacts[artifact_id] = updated_art
        return self

    def build(self) -> ReleaseManifest:
        """Construct the canonical ReleaseManifest."""
        if not self._artifacts:
            raise ManifestBuilderError("Cannot build an empty release manifest; register at least one artifact.")

        return ReleaseManifest(
            schema_version=1,
            channel=self._channel,
            product_version=self._product_version,
            published_at=self._published_at,
            packaging_revision=self._packaging_revision,
            expires_at=self._expires_at,
            artifacts=tuple(self._artifacts.values()),
            signatures=(),
        )

    def build_signed(
        self,
        private_key: Ed25519PrivateKey,
        key_id: str,
    ) -> ReleaseManifest:
        """Build the manifest and sign it with an Ed25519 private key."""
        unsigned = self.build()
        return sign_manifest(unsigned, private_key, key_id)

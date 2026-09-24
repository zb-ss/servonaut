"""Unit tests for ManifestBuilder."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from servonaut.distribution.builder import ManifestBuilder, ManifestBuilderError
from servonaut.distribution.manifest import (
    ArtifactKind,
    ManifestSchemaError,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
)
from servonaut.distribution.trust import TrustPolicy, verify_manifest
from servonaut.runtime import DistributionKind

_EXPIRES_AT = "2099-01-01T00:00:00Z"


class TestManifestBuilder:
    def test_init_validation(self) -> None:
        builder = ManifestBuilder(
            "2.27.0", channel=ReleaseChannel.STABLE, packaging_revision=1, expires_at=_EXPIRES_AT
        )
        assert builder.product_version == "2.27.0"
        assert builder.channel == ReleaseChannel.STABLE
        assert builder.packaging_revision == 1
        assert builder.published_at is not None

        # Invalid semver
        with pytest.raises(ManifestSchemaError, match="not a valid Semantic Version"):
            ManifestBuilder("invalid-semver", expires_at=_EXPIRES_AT)

        # Negative revision
        with pytest.raises(ManifestSchemaError, match="non-negative integer"):
            ManifestBuilder("2.27.0", packaging_revision=-1, expires_at=_EXPIRES_AT)

    def test_add_artifact(self) -> None:
        builder = ManifestBuilder("2.27.0", expires_at=_EXPIRES_AT)
        artifact = ReleaseArtifact(
            artifact_id="cli-linux-x64",
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            filename="cli.tar.gz",
            download_url="https://releases.servonaut.dev/cli.tar.gz",
            byte_size=1024,
            sha256="a" * 64,
        )
        builder.add_artifact(artifact)
        assert len(builder.artifacts) == 1

        # Duplicate artifact ID
        with pytest.raises(ManifestBuilderError, match="already added"):
            builder.add_artifact(artifact)

    def test_add_artifact_file(self, tmp_path: Path) -> None:
        builder = ManifestBuilder("2.27.0", expires_at=_EXPIRES_AT)

        dummy_file = tmp_path / "servonaut-linux-x64.tar.gz"
        content = b"DUMMY_BINARY_PAYLOAD_FOR_TESTS"
        dummy_file.write_bytes(content)
        expected_sha256 = hashlib.sha256(content).hexdigest()

        sbom_file = tmp_path / "sbom.json"
        sbom_content = b'{"sbom": "content"}'
        sbom_file.write_bytes(sbom_content)
        expected_sbom_sha256 = hashlib.sha256(sbom_content).hexdigest()

        art = builder.add_artifact_file(
            dummy_file,
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            download_url="https://releases.servonaut.dev/servonaut-linux-x64.tar.gz",
            sbom_file=sbom_file,
        )

        assert art.filename == "servonaut-linux-x64.tar.gz"
        assert art.byte_size == len(content)
        assert art.sha256 == expected_sha256
        assert art.sbom_sha256 == expected_sbom_sha256
        assert art.artifact_id == "standalone_cli-linux-x86_64"

    def test_add_artifact_file_missing_raises(self, tmp_path: Path) -> None:
        builder = ManifestBuilder("2.27.0", expires_at=_EXPIRES_AT)
        with pytest.raises(FileNotFoundError):
            builder.add_artifact_file(
                tmp_path / "nonexistent.tar.gz",
                kind=ArtifactKind.STANDALONE_CLI,
                distribution=DistributionKind.FROZEN_CLI,
                platform="linux",
                arch="x86_64",
                download_url="https://releases.servonaut.dev/file.tar.gz",
            )

    def test_sign_artifact(self, tmp_path: Path) -> None:
        builder = ManifestBuilder("2.27.0", expires_at=_EXPIRES_AT)
        dummy_file = tmp_path / "cli.tar.gz"
        dummy_file.write_bytes(b"HELLO")
        builder.add_artifact_file(
            dummy_file,
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            download_url="https://releases.servonaut.dev/cli.tar.gz",
            artifact_id="cli-linux",
        )

        priv_key = Ed25519PrivateKey.generate()
        builder.sign_artifact("cli-linux", priv_key)

        signed_art = builder.artifacts[0]
        assert signed_art.signature is not None
        sig_bytes = bytes.fromhex(signed_art.signature)
        priv_key.public_key().verify(sig_bytes, signed_art.sha256.encode("ascii"))

    def test_sign_nonexistent_artifact_raises(self) -> None:
        builder = ManifestBuilder("2.27.0", expires_at=_EXPIRES_AT)
        priv_key = Ed25519PrivateKey.generate()
        with pytest.raises(ManifestBuilderError, match="Cannot sign unknown artifact ID"):
            builder.sign_artifact("missing-id", priv_key)

    def test_build_empty_raises(self) -> None:
        builder = ManifestBuilder("2.27.0", expires_at=_EXPIRES_AT)
        with pytest.raises(ManifestBuilderError, match="Cannot build an empty release manifest"):
            builder.build()

    def test_build_signed_and_verify(self, tmp_path: Path) -> None:
        builder = ManifestBuilder("2.27.0", packaging_revision=2, expires_at=_EXPIRES_AT)
        dummy_file = tmp_path / "servonaut-cli.tar.gz"
        dummy_file.write_bytes(b"PAYLOAD")

        builder.add_artifact_file(
            dummy_file,
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            download_url="https://releases.servonaut.dev/servonaut-cli.tar.gz",
        )

        priv_key = Ed25519PrivateKey.generate()
        key_id = "release-key-2026"
        manifest = builder.build_signed(priv_key, key_id)

        assert manifest.product_version == "2.27.0"
        assert manifest.packaging_revision == 2
        assert len(manifest.signatures) == 1
        assert manifest.signatures[0].key_id == key_id

        # Trust policy verification
        policy = TrustPolicy(
            trusted_public_keys={key_id: priv_key.public_key()},
            minimum_signatures=1,
            allowed_origin_prefixes=("https://releases.servonaut.dev/",),
        )
        # Verify manifest does not raise
        verify_manifest(manifest, policy)

        # Roundtrip JSON
        raw_json = manifest.to_json()
        restored = ReleaseManifest.from_json(raw_json)
        assert restored.product_version == manifest.product_version
        assert restored.artifacts[0].sha256 == manifest.artifacts[0].sha256
        assert restored.expires_at == _EXPIRES_AT

    def test_expires_at_is_required(self) -> None:
        with pytest.raises(TypeError, match="expires_at"):
            ManifestBuilder("2.27.0")  # type: ignore[call-arg]

    def test_unparseable_expires_at_is_rejected(self) -> None:
        with pytest.raises(ManifestSchemaError, match="Invalid ISO 8601 timestamp"):
            ManifestBuilder("2.27.0", expires_at="next tuesday")

    @pytest.mark.parametrize("expires_at", ["2026-09-23T12:00:00Z", "2026-09-22T12:00:00+00:00"])
    def test_expires_at_must_follow_published_at(self, expires_at: str) -> None:
        with pytest.raises(ManifestBuilderError, match="later than published_at"):
            ManifestBuilder(
                "2.27.0", published_at="2026-09-23T12:00:00Z", expires_at=expires_at
            )

    def test_unparseable_published_at_is_rejected(self) -> None:
        with pytest.raises(ManifestSchemaError, match="Invalid ISO 8601 timestamp"):
            ManifestBuilder("2.27.0", published_at="yesterday", expires_at=_EXPIRES_AT)

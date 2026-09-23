"""Unit tests for release artifact and manifest verification utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from servonaut.distribution.builder import ManifestBuilder
from servonaut.distribution.manifest import (
    ArtifactKind,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
)
from servonaut.distribution.trust import TrustPolicy
from servonaut.distribution.verify import (
    verify_artifact_signature,
    verify_file_sha256,
    verify_release_file,
)
from servonaut.runtime import DistributionKind


class TestVerification:
    def test_verify_file_sha256(self, tmp_path: Path) -> None:
        file = tmp_path / "test.bin"
        data = b"INTEGRITY_CHECK_SAMPLE_DATA"
        file.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()

        assert verify_file_sha256(file, digest) is True
        assert verify_file_sha256(file, digest.upper()) is True
        assert verify_file_sha256(file, "0" * 64) is False
        assert verify_file_sha256(tmp_path / "absent.bin", digest) is False

    def test_verify_artifact_signature(self) -> None:
        priv_key = Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        wrong_key = Ed25519PrivateKey.generate().public_key()

        sha256 = "a" * 64
        sig = priv_key.sign(sha256.encode("ascii")).hex()

        art = ReleaseArtifact(
            artifact_id="art-1",
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            filename="art-1.tar.gz",
            download_url="https://releases.servonaut.dev/art-1.tar.gz",
            byte_size=100,
            sha256=sha256,
            signature=sig,
        )

        assert verify_artifact_signature(art, pub_key) is True
        assert verify_artifact_signature(art, wrong_key) is False

        # No signature
        art_no_sig = ReleaseArtifact(
            artifact_id="art-2",
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            filename="art-2.tar.gz",
            download_url="https://releases.servonaut.dev/art-2.tar.gz",
            byte_size=100,
            sha256=sha256,
        )
        assert verify_artifact_signature(art_no_sig, pub_key) is False

    def test_verify_release_file_happy_path(self, tmp_path: Path) -> None:
        priv_key = Ed25519PrivateKey.generate()
        key_id = "test-key-1"

        target_file = tmp_path / "servonaut-cli.tar.gz"
        payload = b"VALID_BINARY_PAYLOAD"
        target_file.write_bytes(payload)

        builder = ManifestBuilder("2.27.0")
        builder.add_artifact_file(
            target_file,
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            download_url="https://releases.servonaut.dev/servonaut-cli.tar.gz",
            artifact_id="cli",
        )
        builder.sign_artifact("cli", priv_key)
        manifest = builder.build_signed(priv_key, key_id)

        policy = TrustPolicy(
            trusted_public_keys={key_id: priv_key.public_key()},
            minimum_signatures=1,
            allowed_origin_prefixes=("https://releases.servonaut.dev/",),
        )

        ok, msg = verify_release_file(manifest, target_file, trust_policy=policy)
        assert ok is True
        assert "successfully verified" in msg

    def test_verify_release_file_tampered_payload(self, tmp_path: Path) -> None:
        target_file = tmp_path / "servonaut-cli.tar.gz"
        target_file.write_bytes(b"INITIAL_PAYLOAD")

        builder = ManifestBuilder("2.27.0")
        builder.add_artifact_file(
            target_file,
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            download_url="https://releases.servonaut.dev/servonaut-cli.tar.gz",
        )
        manifest = builder.build()

        # Modify file on disk
        target_file.write_bytes(b"TAMPERED_PAYLOAD")

        ok, msg = verify_release_file(manifest, target_file)
        assert ok is False
        assert "Size mismatch" in msg or "integrity verification failed" in msg

    def test_verify_release_file_unregistered_file(self, tmp_path: Path) -> None:
        f1 = tmp_path / "registered.tar.gz"
        f1.write_bytes(b"1")
        f2 = tmp_path / "unregistered.tar.gz"
        f2.write_bytes(b"2")

        builder = ManifestBuilder("2.27.0")
        builder.add_artifact_file(
            f1,
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            download_url="https://releases.servonaut.dev/registered.tar.gz",
        )
        manifest = builder.build()

        ok, msg = verify_release_file(manifest, f2)
        assert ok is False
        assert "not registered in the release manifest" in msg

    def test_verify_release_file_nonexistent_file(self, tmp_path: Path) -> None:
        builder = ManifestBuilder("2.27.0")
        dummy = tmp_path / "dummy.tar.gz"
        dummy.write_bytes(b"A")
        builder.add_artifact_file(
            dummy,
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            download_url="https://releases.servonaut.dev/dummy.tar.gz",
        )
        manifest = builder.build()

        ok, msg = verify_release_file(manifest, tmp_path / "missing.tar.gz")
        assert ok is False
        assert "does not exist" in msg

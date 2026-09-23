"""Tests for cryptographic trust policy, Ed25519 verification, downgrade checks, and target resolution."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution.manifest import (
    ArtifactKind,
    ManifestSchemaError,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
)
from servonaut.distribution.trust import (
    AmbiguousArtifactError,
    ManifestDowngradeError,
    ManifestExpiredError,
    ManifestOriginError,
    ManifestSignatureError,
    ManifestTargetError,
    NoCompatibleArtifactError,
    TrustPolicy,
    check_downgrade,
    decode_signature_bytes,
    encode_signature_bytes,
    load_ed25519_public_key,
    normalize_arch,
    normalize_platform,
    parse_semver,
    resolve_target_artifact,
    sign_manifest,
    verify_manifest,
)
from servonaut.runtime import DistributionKind, RuntimeLayout

VALID_SHA256 = "c" * 64


def make_test_artifact(
    *,
    artifact_id: str = "cli-linux-x64",
    kind: ArtifactKind = ArtifactKind.STANDALONE_CLI,
    distribution: DistributionKind = DistributionKind.FROZEN_CLI,
    platform: str = "linux",
    arch: str = "x86_64",
    download_url: str = "https://github.com/zb-ss/servonaut/releases/download/v2.26.3/cli-linux.tar.gz",
) -> ReleaseArtifact:
    return ReleaseArtifact(
        artifact_id=artifact_id,
        kind=kind,
        distribution=distribution,
        platform=platform,
        arch=arch,
        filename="cli-linux.tar.gz",
        download_url=download_url,
        byte_size=12_000_000,
        sha256=VALID_SHA256,
    )


def make_test_manifest(
    *,
    product_version: str = "2.26.3",
    packaging_revision: int | None = None,
    channel: ReleaseChannel = ReleaseChannel.STABLE,
    artifacts: tuple[ReleaseArtifact, ...] | None = None,
    expires_at: str | None = None,
) -> ReleaseManifest:
    return ReleaseManifest(
        schema_version=1,
        channel=channel,
        product_version=product_version,
        published_at="2026-09-23T12:00:00Z",
        artifacts=artifacts if artifacts is not None else (make_test_artifact(),),
        signatures=(),
        packaging_revision=packaging_revision,
        expires_at=expires_at,
    )


class TestSemVerAndDowngrade:
    def test_parse_semver(self) -> None:
        assert parse_semver("2.26.3") == (2, 26, 3, 1, "")
        assert parse_semver("2.26.4-preview.1") == (2, 26, 4, 0, "preview.1")
        assert parse_semver("3.0.0+build123") == (3, 0, 0, 1, "")

    def test_parse_semver_invalid(self) -> None:
        with pytest.raises(ManifestSchemaError, match="Invalid semantic version string"):
            parse_semver("not_a_version")

    def test_check_downgrade_rejection(self) -> None:
        # Older version
        manifest = make_test_manifest(product_version="2.26.2")
        with pytest.raises(ManifestDowngradeError, match="Refusing downgrade"):
            check_downgrade(manifest, current_version="2.26.3")

        # Same version, same revision
        manifest = make_test_manifest(product_version="2.26.3")
        with pytest.raises(ManifestDowngradeError, match="No update available"):
            check_downgrade(manifest, current_version="2.26.3")

        # Same version, lower revision
        manifest = make_test_manifest(product_version="2.26.3", packaging_revision=1)
        with pytest.raises(ManifestDowngradeError, match="Refusing downgrade"):
            check_downgrade(manifest, current_version="2.26.3", current_packaging_revision=2)

    def test_check_downgrade_allowed_updates(self) -> None:
        # Newer patch
        manifest = make_test_manifest(product_version="2.26.4")
        check_downgrade(manifest, current_version="2.26.3")  # Does not raise

        # Newer minor
        manifest = make_test_manifest(product_version="2.27.0")
        check_downgrade(manifest, current_version="2.26.3")  # Does not raise

        # Same version, higher packaging revision
        manifest = make_test_manifest(product_version="2.26.3", packaging_revision=2)
        check_downgrade(manifest, current_version="2.26.3", current_packaging_revision=1)  # Does not raise


class TestEd25519TrustVerification:
    @pytest.fixture
    def keypair(self) -> tuple[Ed25519PrivateKey, str]:
        priv = Ed25519PrivateKey.generate()
        key_id = "test-key-primary"
        return priv, key_id

    def test_sign_and_verify_success(self, keypair: tuple[Ed25519PrivateKey, str]) -> None:
        priv_key, key_id = keypair
        manifest = make_test_manifest()
        signed_manifest = sign_manifest(manifest, priv_key, key_id)

        assert len(signed_manifest.signatures) == 1
        sig = signed_manifest.signatures[0]
        assert sig.key_id == key_id
        assert sig.algorithm == "ed25519"

        policy = TrustPolicy(
            trusted_public_keys={key_id: priv_key.public_key()},
            minimum_signatures=1,
        )
        verify_manifest(signed_manifest, policy)

    def test_tampered_manifest_fails_verification(self, keypair: tuple[Ed25519PrivateKey, str]) -> None:
        priv_key, key_id = keypair
        manifest = make_test_manifest()
        signed_manifest = sign_manifest(manifest, priv_key, key_id)

        policy = TrustPolicy(
            trusted_public_keys={key_id: priv_key.public_key()},
            minimum_signatures=1,
        )

        # Tamper with an artifact SHA256 in the manifest
        tampered_artifact = make_test_artifact(download_url="https://github.com/zb-ss/servonaut/releases/download/v2.26.3/tampered.tar.gz")
        tampered_manifest = ReleaseManifest(
            schema_version=signed_manifest.schema_version,
            channel=signed_manifest.channel,
            product_version=signed_manifest.product_version,
            published_at=signed_manifest.published_at,
            artifacts=(tampered_artifact,),
            signatures=signed_manifest.signatures,
        )

        with pytest.raises(ManifestSignatureError, match="Cryptographic signature verification failed"):
            verify_manifest(tampered_manifest, policy)

    def test_corrupted_signature_fails_verification(self, keypair: tuple[Ed25519PrivateKey, str]) -> None:
        priv_key, key_id = keypair
        manifest = make_test_manifest()
        signed_manifest = sign_manifest(manifest, priv_key, key_id)

        policy = TrustPolicy(
            trusted_public_keys={key_id: priv_key.public_key()},
            minimum_signatures=1,
        )

        sig = signed_manifest.signatures[0]
        raw_sig = bytearray(decode_signature_bytes(sig.signature))
        raw_sig[0] ^= 0xFF  # Flip bits
        corrupted_sig = encode_signature_bytes(bytes(raw_sig))

        corrupted_manifest = ReleaseManifest(
            schema_version=signed_manifest.schema_version,
            channel=signed_manifest.channel,
            product_version=signed_manifest.product_version,
            published_at=signed_manifest.published_at,
            artifacts=signed_manifest.artifacts,
            signatures=(
                signed_manifest.signatures[0].__class__(
                    key_id=sig.key_id,
                    algorithm=sig.algorithm,
                    signature=corrupted_sig,
                    signed_at=sig.signed_at,
                ),
            ),
        )

        with pytest.raises(ManifestSignatureError, match="Cryptographic signature verification failed"):
            verify_manifest(corrupted_manifest, policy)

    def test_untrusted_key_fails_minimum_signatures(self, keypair: tuple[Ed25519PrivateKey, str]) -> None:
        priv_key, _ = keypair
        manifest = make_test_manifest()
        signed_manifest = sign_manifest(manifest, priv_key, "unknown-key-id")

        another_key = Ed25519PrivateKey.generate().public_key()
        policy = TrustPolicy(
            trusted_public_keys={"authorized-key-id": another_key},
            minimum_signatures=1,
        )
        with pytest.raises(ManifestSignatureError, match="requires at least 1 trusted signature"):
            verify_manifest(signed_manifest, policy)

    def test_multi_signature_threshold(self) -> None:
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()

        manifest = make_test_manifest()
        signed = sign_manifest(manifest, priv1, "key-1")
        signed_both = sign_manifest(signed, priv2, "key-2")

        policy_two = TrustPolicy(
            trusted_public_keys={
                "key-1": priv1.public_key(),
                "key-2": priv2.public_key(),
            },
            minimum_signatures=2,
        )
        verify_manifest(signed_both, policy_two)

        # Fails if only 1 valid signature is present when 2 are required
        policy_needs_two = TrustPolicy(
            trusted_public_keys={"key-1": priv1.public_key()},
            minimum_signatures=2,
        )
        with pytest.raises(ManifestSignatureError, match="requires at least 2 trusted signature"):
            verify_manifest(signed_both, policy_needs_two)


class TestOriginAndFreshness:
    def test_disallowed_channel(self) -> None:
        manifest = make_test_manifest(channel=ReleaseChannel.NIGHTLY)
        policy = TrustPolicy(
            trusted_public_keys={},
            allowed_channels=(ReleaseChannel.STABLE,),
        )
        with pytest.raises(ManifestSchemaError, match="Release channel 'nightly' is not permitted"):
            verify_manifest(manifest, policy)

    def test_enforce_https(self) -> None:
        artifact = make_test_artifact(download_url="http://github.com/zb-ss/servonaut/releases/download/v1.0/file.tar.gz")
        manifest = make_test_manifest(artifacts=(artifact,))
        policy = TrustPolicy(
            trusted_public_keys={},
            enforce_https=True,
        )
        with pytest.raises(ManifestOriginError, match="must use HTTPS"):
            verify_manifest(manifest, policy)

    def test_disallowed_origin_prefix(self) -> None:
        artifact = make_test_artifact(download_url="https://untrusted-domain.com/downloads/file.tar.gz")
        manifest = make_test_manifest(artifacts=(artifact,))
        policy = TrustPolicy(
            trusted_public_keys={},
            allowed_origin_prefixes=("https://github.com/zb-ss/servonaut/releases/download/",),
        )
        with pytest.raises(ManifestOriginError, match="is not in allowed origins"):
            verify_manifest(manifest, policy)

    def test_expired_manifest(self) -> None:
        now = datetime.now(timezone.utc)
        expired_time = (now - timedelta(hours=1)).isoformat()
        manifest = make_test_manifest(expires_at=expired_time)
        policy = TrustPolicy(
            trusted_public_keys={},
            require_freshness=True,
            clock_skew_tolerance_seconds=60,
        )
        with pytest.raises(ManifestExpiredError, match="Release manifest expired"):
            verify_manifest(manifest, policy, now=now)

    def test_unexpired_manifest_passes(self) -> None:
        now = datetime.now(timezone.utc)
        future_time = (now + timedelta(hours=24)).isoformat()
        manifest = make_test_manifest(expires_at=future_time)
        policy = TrustPolicy(
            trusted_public_keys={},
            require_freshness=True,
            minimum_signatures=0,  # Only testing freshness
        )
        verify_manifest(manifest, policy, now=now)


class TestTargetResolution:
    def test_normalize_platform(self) -> None:
        assert normalize_platform("linux") == "linux"
        assert normalize_platform("linux-gnu") == "linux"
        assert normalize_platform("darwin") == "darwin"
        assert normalize_platform("macos") == "darwin"
        assert normalize_platform("win32") == "windows"
        assert normalize_platform("windows") == "windows"

        with pytest.raises(ManifestTargetError, match="Unsupported operating system"):
            normalize_platform("freebsd")

    def test_normalize_arch(self) -> None:
        assert normalize_arch("x86_64") == "x86_64"
        assert normalize_arch("amd64") == "x86_64"
        assert normalize_arch("x64") == "x86_64"
        assert normalize_arch("arm64") == "arm64"
        assert normalize_arch("aarch64") == "arm64"

        with pytest.raises(ManifestTargetError, match="Unsupported machine architecture"):
            normalize_arch("riscv64")

    def test_resolve_target_artifact_success(self) -> None:
        cli_linux = make_test_artifact(
            artifact_id="cli-linux-x64",
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
        )
        cli_macos = make_test_artifact(
            artifact_id="cli-macos-arm64",
            distribution=DistributionKind.FROZEN_CLI,
            platform="darwin",
            arch="arm64",
        )
        desktop_deb = make_test_artifact(
            artifact_id="desktop-ubuntu-deb",
            kind=ArtifactKind.UBUNTU_DEB,
            distribution=DistributionKind.PACKAGED_DESKTOP,
            platform="linux",
            arch="x86_64",
        )
        manifest = make_test_manifest(artifacts=(cli_linux, cli_macos, desktop_deb))

        # Test CLI resolution with DistributionKind directly
        resolved_cli = resolve_target_artifact(
            manifest,
            DistributionKind.FROZEN_CLI,
            platform_name="linux",
            machine_arch="x86_64",
        )
        assert resolved_cli.artifact_id == "cli-linux-x64"

        # Test Desktop resolution with DistributionKind directly
        resolved_desktop = resolve_target_artifact(
            manifest,
            DistributionKind.PACKAGED_DESKTOP,
            platform_name="linux",
            machine_arch="x86_64",
        )
        assert resolved_desktop.artifact_id == "desktop-ubuntu-deb"

    def test_resolve_target_artifact_with_runtime_layout_instance(self, tmp_path: Path) -> None:
        from servonaut.runtime import PackageManagementCapability, PackageManagementKind

        cli_linux = make_test_artifact(
            artifact_id="cli-linux-x64",
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
        )
        manifest = make_test_manifest(artifacts=(cli_linux,))

        runtime = RuntimeLayout(
            kind=DistributionKind.FROZEN_CLI,
            product_version="2.26.3",
            build_revision=None,
            resource_root=tmp_path / "resources",
            executable_root=tmp_path / "bin",
            data_root=tmp_path / "data",
            executable=tmp_path / "bin" / "servonaut",
            python_executable=Path("/usr/bin/python3"),
            path_console=None,
            console_helper=tmp_path / "bin" / "servonaut",
            desktop_child=None,
            package_management=PackageManagementCapability(
                kind=PackageManagementKind.UNSUPPORTED,
                argv_prefix=(),
                allows_automatic_mutation=False,
            ),
            is_frozen=True,
        )

        resolved = resolve_target_artifact(
            manifest,
            runtime,
            platform_name="linux",
            machine_arch="x86_64",
        )
        assert resolved.artifact_id == "cli-linux-x64"

    def test_resolve_target_artifact_not_found(self) -> None:
        cli_linux = make_test_artifact(
            artifact_id="cli-linux-x64",
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
        )
        manifest = make_test_manifest(artifacts=(cli_linux,))
        with pytest.raises(NoCompatibleArtifactError, match="No compatible artifact found"):
            resolve_target_artifact(
                manifest,
                DistributionKind.FROZEN_CLI,
                platform_name="darwin",
                machine_arch="arm64",
            )

    def test_resolve_target_artifact_ambiguous(self) -> None:
        art1 = make_test_artifact(
            artifact_id="cli-linux-1",
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
        )
        art2 = make_test_artifact(
            artifact_id="cli-linux-2",
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
        )
        manifest = make_test_manifest(artifacts=(art1, art2))
        with pytest.raises(AmbiguousArtifactError, match="Ambiguous artifact resolution"):
            resolve_target_artifact(
                manifest,
                DistributionKind.FROZEN_CLI,
                platform_name="linux",
                machine_arch="x86_64",
            )



class TestKeyHelpers:
    def test_load_ed25519_public_key_formats(self) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        raw = pub.public_bytes_raw()

        # From raw bytes
        loaded1 = load_ed25519_public_key(raw)
        assert loaded1.public_bytes_raw() == raw

        # From hex
        loaded2 = load_ed25519_public_key(raw.hex())
        assert loaded2.public_bytes_raw() == raw

        # From base64
        b64 = encode_signature_bytes(raw)
        loaded3 = load_ed25519_public_key(b64)
        assert loaded3.public_bytes_raw() == raw

    def test_load_ed25519_public_key_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="must be 32 bytes"):
            load_ed25519_public_key(b"short_bytes")

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
from servonaut.distribution import manifest as manifest_module
from servonaut.distribution import trust as trust_module
from servonaut.distribution import trust_root
from servonaut.distribution.trust import (
    AmbiguousArtifactError,
    ManifestDowngradeError,
    ManifestExpiredError,
    ManifestOriginError,
    ManifestSignatureError,
    ManifestTargetError,
    NoCompatibleArtifactError,
    OperatingSystemTooOldError,
    TrustPolicy,
    channels_accepted_by,
    check_downgrade,
    decode_signature_bytes,
    encode_signature_bytes,
    host_os_version,
    load_ed25519_public_key,
    normalize_arch,
    normalize_platform,
    parse_semver,
    release_trust_policy,
    resolve_target_artifact,
    sign_manifest,
    verify_manifest,
)
from servonaut.runtime import DistributionKind, RuntimeLayout

VALID_SHA256 = "c" * 64
FUTURE_EXPIRY = "2099-01-01T00:00:00Z"
RELEASES_PREFIX = "https://github.com/zb-ss/servonaut/releases/download/"


def make_test_artifact(
    *,
    artifact_id: str = "cli-linux-x64",
    kind: ArtifactKind = ArtifactKind.STANDALONE_CLI,
    distribution: DistributionKind = DistributionKind.FROZEN_CLI,
    platform: str = "linux",
    arch: str = "x86_64",
    download_url: str = "https://github.com/zb-ss/servonaut/releases/download/v2.26.3/cli-linux.tar.gz",
    min_os: str | None = None,
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
        min_os=min_os,
    )


def make_test_manifest(
    *,
    product_version: str = "2.26.3",
    packaging_revision: int | None = None,
    channel: ReleaseChannel = ReleaseChannel.STABLE,
    artifacts: tuple[ReleaseArtifact, ...] | None = None,
    expires_at: str | None = FUTURE_EXPIRY,
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


def signed_with_policy(
    manifest: ReleaseManifest, **policy_overrides: object
) -> tuple[ReleaseManifest, TrustPolicy]:
    """Sign ``manifest`` with a fresh key and return a policy trusting that key."""
    key = Ed25519PrivateKey.generate()
    policy = TrustPolicy(trusted_public_keys={"k": key.public_key()}, **policy_overrides)  # type: ignore[arg-type]
    return sign_manifest(manifest, key, "k"), policy


class TestSemVerAndDowngrade:
    def test_parse_semver(self) -> None:
        stable = parse_semver("2.26.3")
        assert (stable.major, stable.minor, stable.patch, stable.prerelease) == (2, 26, 3, ())
        assert parse_semver("2.26.4-preview.1").prerelease == ("preview", "1")
        assert parse_semver("3.0.0+build123").build == ("build123",)

    def test_manifest_and_trust_share_one_parser(self) -> None:
        assert trust_module.parse_semver is manifest_module.parse_semver

    def test_precedence_follows_semver_section_11(self) -> None:
        ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
        ]
        keys = [parse_semver(version).precedence for version in ordered]
        assert keys == sorted(keys)
        assert len(set(keys)) == len(keys)

    def test_build_metadata_does_not_affect_precedence(self) -> None:
        assert parse_semver("2.27.0+a").precedence == parse_semver("2.27.0+b").precedence

    @pytest.mark.parametrize("version", ["2.27.0\n", "2.27.0-01", "2.27", "v2.27.0", "2.27.0-", 27])
    def test_parse_semver_rejects_non_semver(self, version: object) -> None:
        with pytest.raises(ManifestSchemaError, match="Invalid semantic version string"):
            parse_semver(version)

    def test_newer_prerelease_is_an_update(self) -> None:
        check_downgrade(make_test_manifest(product_version="2.28.0-rc.2"), current_version="2.28.0-rc.1")
        check_downgrade(make_test_manifest(product_version="2.28.0-rc.10"), current_version="2.28.0-rc.9")
        check_downgrade(make_test_manifest(product_version="2.28.0"), current_version="2.28.0-rc.9")

    def test_older_prerelease_is_a_downgrade(self) -> None:
        with pytest.raises(ManifestDowngradeError, match="Refusing downgrade"):
            check_downgrade(make_test_manifest(product_version="2.28.0-rc.1"), current_version="2.28.0-rc.2")
        with pytest.raises(ManifestDowngradeError, match="Refusing downgrade"):
            check_downgrade(make_test_manifest(product_version="2.28.0-rc.9"), current_version="2.28.0")

    def test_non_semver_current_version_raises_schema_error(self) -> None:
        with pytest.raises(ManifestSchemaError):
            check_downgrade(make_test_manifest(product_version="2.28.0"), current_version="2.28.0.dev0")

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
            expires_at=signed_manifest.expires_at,
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
            expires_at=signed_manifest.expires_at,
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
        with pytest.raises(ManifestSignatureError, match="requires at least 2 trusted signature"):
            verify_manifest(signed, policy_two)


class TestTrustPolicyValidation:
    @pytest.fixture
    def one_key(self) -> dict[str, object]:
        return {"k": Ed25519PrivateKey.generate().public_key()}

    @pytest.mark.parametrize("minimum", [0, -5, True, 2, 1.0])
    def test_minimum_signatures_must_fit_the_trusted_keys(
        self, one_key: dict[str, object], minimum: object
    ) -> None:
        with pytest.raises(ValueError, match="minimum_signatures"):
            TrustPolicy(trusted_public_keys=one_key, minimum_signatures=minimum)  # type: ignore[arg-type]

    def test_a_policy_without_keys_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="minimum_signatures"):
            TrustPolicy(trusted_public_keys={})

    @pytest.mark.parametrize(
        "prefix",
        [
            "https://github.com/zb-ss/servonaut",
            "http://github.com/zb-ss/servonaut/releases/download/",
            "https://user@github.com/zb-ss/",  # leak-guard:allow
            "https://github.com:8443/zb-ss/",
            "https://github.com/zb-ss/../",
        ],
    )
    def test_origin_prefixes_are_validated(self, one_key: dict[str, object], prefix: str) -> None:
        with pytest.raises(ValueError):
            TrustPolicy(trusted_public_keys=one_key, allowed_origin_prefixes=(prefix,))  # type: ignore[arg-type]

    def test_defaults_come_from_the_trust_root(self, one_key: dict[str, object]) -> None:
        policy = TrustPolicy(trusted_public_keys=one_key)  # type: ignore[arg-type]
        assert tuple(policy.allowed_origin_prefixes) == trust_root.ALLOWED_ARTIFACT_ORIGINS
        assert tuple(policy.allowed_channels) == (ReleaseChannel.STABLE,)


class TestReleaseChannels:
    def test_stable_builds_accept_only_stable(self) -> None:
        assert channels_accepted_by(ReleaseChannel.STABLE) == (ReleaseChannel.STABLE,)

    def test_preview_builds_accept_preview_and_stable(self) -> None:
        assert set(channels_accepted_by(ReleaseChannel.PREVIEW)) == {
            ReleaseChannel.PREVIEW,
            ReleaseChannel.STABLE,
        }

    def test_builds_cannot_follow_nightly(self) -> None:
        with pytest.raises(ValueError):
            channels_accepted_by(ReleaseChannel.NIGHTLY)

    def test_default_policy_rejects_a_signed_preview_manifest(self) -> None:
        manifest, policy = signed_with_policy(make_test_manifest(channel=ReleaseChannel.PREVIEW))
        with pytest.raises(ManifestSchemaError, match="'preview' is not permitted"):
            verify_manifest(manifest, policy)


class TestPinnedTrustRoot:
    def test_no_pinned_keys_means_no_policy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(trust_root, "PINNED_RELEASE_KEYS", {})
        assert release_trust_policy(ReleaseChannel.STABLE) is None

    def test_policy_is_built_from_pinned_keys_and_build_channel(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        key = Ed25519PrivateKey.generate()
        monkeypatch.setattr(
            trust_root, "PINNED_RELEASE_KEYS", {"release-1": key.public_key().public_bytes_raw().hex()}
        )
        policy = release_trust_policy(ReleaseChannel.PREVIEW)

        assert policy is not None
        assert set(policy.trusted_public_keys) == {"release-1"}
        assert tuple(policy.allowed_origin_prefixes) == trust_root.ALLOWED_ARTIFACT_ORIGINS
        assert tuple(policy.allowed_channels) == channels_accepted_by(ReleaseChannel.PREVIEW)

    def test_shipped_pinned_keys_are_loadable(self) -> None:
        for encoded in trust_root.PINNED_RELEASE_KEYS.values():
            load_ed25519_public_key(encoded)


class TestOriginAndFreshness:
    def test_disallowed_channel(self) -> None:
        manifest, policy = signed_with_policy(
            make_test_manifest(channel=ReleaseChannel.NIGHTLY),
            allowed_channels=(ReleaseChannel.STABLE,),
        )
        with pytest.raises(ManifestSchemaError, match="Release channel 'nightly' is not permitted"):
            verify_manifest(manifest, policy)

    def test_enforce_https(self) -> None:
        artifact = make_test_artifact(download_url="http://github.com/zb-ss/servonaut/releases/download/v1.0/file.tar.gz")
        manifest, policy = signed_with_policy(make_test_manifest(artifacts=(artifact,)), enforce_https=True)
        with pytest.raises(ManifestOriginError, match="must use HTTPS"):
            verify_manifest(manifest, policy)

    def test_disallowed_origin_prefix(self) -> None:
        artifact = make_test_artifact(download_url="https://untrusted-domain.com/downloads/file.tar.gz")
        manifest, policy = signed_with_policy(
            make_test_manifest(artifacts=(artifact,)),
            allowed_origin_prefixes=(RELEASES_PREFIX,),
        )
        with pytest.raises(ManifestOriginError, match="is not in allowed origins"):
            verify_manifest(manifest, policy)

    @pytest.mark.parametrize(
        "url",
        [
            RELEASES_PREFIX + "../../../../evil/x/releases/download/v1/s.tgz",
            RELEASES_PREFIX + "v1/./s.tgz",
            RELEASES_PREFIX + "%2e%2e/%2E%2E/evil/s.tgz",
            RELEASES_PREFIX + "..%2f..%2fevil/s.tgz",
            RELEASES_PREFIX + "v1\\..\\s.tgz",
            "https://user:secret@github.com/zb-ss/servonaut/releases/download/v1/s.tgz",  # leak-guard:allow
            "https://github.com:443/zb-ss/servonaut/releases/download/v1/s.tgz",
            "https://github.com:/zb-ss/servonaut/releases/download/v1/s.tgz",
            RELEASES_PREFIX + "v1/s.tgz\n",
            RELEASES_PREFIX + "v1/s.tgz?x=1 2",
        ],
    )
    def test_prefix_bypass_forms_are_rejected(self, url: str) -> None:
        manifest, policy = signed_with_policy(
            make_test_manifest(artifacts=(make_test_artifact(download_url=url),)),
            allowed_origin_prefixes=(RELEASES_PREFIX,),
        )
        with pytest.raises(ManifestOriginError):
            verify_manifest(manifest, policy)

    def test_normalised_host_case_still_matches(self) -> None:
        url = "https://GitHub.com/zb-ss/servonaut/releases/download/v1/s.tgz"
        manifest, policy = signed_with_policy(
            make_test_manifest(artifacts=(make_test_artifact(download_url=url),)),
            allowed_origin_prefixes=(RELEASES_PREFIX,),
        )
        verify_manifest(manifest, policy)

    def test_origin_errors_escape_and_bound_the_url(self) -> None:
        url = RELEASES_PREFIX + "\x1b[2J" + "a" * 50_000
        manifest, policy = signed_with_policy(
            make_test_manifest(artifacts=(make_test_artifact(download_url=url),))
        )
        with pytest.raises(ManifestOriginError) as raised:
            verify_manifest(manifest, policy)
        assert "\x1b" not in str(raised.value)
        assert len(str(raised.value)) < 400

    def test_expired_manifest(self) -> None:
        now = datetime.now(timezone.utc)
        expired_time = (now - timedelta(hours=1)).isoformat()
        manifest, policy = signed_with_policy(
            make_test_manifest(expires_at=expired_time),
            require_freshness=True,
            clock_skew_tolerance_seconds=60,
        )
        with pytest.raises(ManifestExpiredError, match="Release manifest expired"):
            verify_manifest(manifest, policy, now=now)

    def test_unexpired_manifest_passes(self) -> None:
        now = datetime.now(timezone.utc)
        future_time = (now + timedelta(hours=24)).isoformat()
        manifest, policy = signed_with_policy(
            make_test_manifest(expires_at=future_time), require_freshness=True
        )
        verify_manifest(manifest, policy, now=now)

    def test_missing_expiry_is_refused_when_freshness_is_required(self) -> None:
        manifest, policy = signed_with_policy(
            make_test_manifest(expires_at=None), require_freshness=True
        )
        with pytest.raises(ManifestExpiredError, match="declares no expires_at"):
            verify_manifest(manifest, policy, now=datetime(2030, 1, 1, tzinfo=timezone.utc))

    def test_missing_expiry_is_allowed_when_freshness_is_not_required(self) -> None:
        manifest, policy = signed_with_policy(
            make_test_manifest(expires_at=None), require_freshness=False
        )
        verify_manifest(manifest, policy)

    def test_zulu_expiry_is_accepted(self) -> None:
        manifest, policy = signed_with_policy(make_test_manifest(expires_at="2026-10-01T00:00:00Z"))
        verify_manifest(manifest, policy, now=datetime(2026, 9, 24, tzinfo=timezone.utc))

    def test_malformed_expiry_is_a_schema_error_with_a_bounded_message(self) -> None:
        manifest, policy = signed_with_policy(make_test_manifest(expires_at="x" * 10_000))
        with pytest.raises(ManifestSchemaError, match="Invalid ISO 8601 timestamp") as raised:
            verify_manifest(manifest, policy)
        assert len(str(raised.value)) < 200

    def test_unsigned_manifest_is_rejected(self) -> None:
        _signed, policy = signed_with_policy(make_test_manifest())
        with pytest.raises(ManifestSignatureError, match="requires at least 1 trusted signature"):
            verify_manifest(make_test_manifest(), policy)


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


class TestMinimumOperatingSystem:
    def _darwin_manifest(self, *min_os_values: str) -> ReleaseManifest:
        artifacts = tuple(
            make_test_artifact(
                artifact_id=f"cli-macos-{index}", platform="darwin", arch="arm64", min_os=value
            )
            for index, value in enumerate(min_os_values)
        )
        return make_test_manifest(artifacts=artifacts)

    def _resolve(self, manifest: ReleaseManifest, os_version: str | None) -> ReleaseArtifact:
        return resolve_target_artifact(
            manifest,
            DistributionKind.FROZEN_CLI,
            platform_name="darwin",
            machine_arch="arm64",
            os_version=os_version,
        )

    def test_host_older_than_min_os_is_refused(self) -> None:
        with pytest.raises(OperatingSystemTooOldError, match="requires darwin 14.0 or later"):
            self._resolve(self._darwin_manifest("14.0"), "13.6.1")

    @pytest.mark.parametrize("os_version", ["14", "14.0", "14.0.0", "15.1"])
    def test_host_at_or_above_min_os_resolves(self, os_version: str) -> None:
        assert self._resolve(self._darwin_manifest("14.0"), os_version).min_os == "14.0"

    @pytest.mark.parametrize("os_version", [None, "unknown"])
    def test_unknown_host_version_is_not_enforced(self, os_version: str | None) -> None:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(trust_module, "host_os_version", lambda _platform: None)
            assert self._resolve(self._darwin_manifest("14.0"), os_version).min_os == "14.0"

    def test_min_os_filters_before_ambiguity(self) -> None:
        manifest = self._darwin_manifest("11.0", "14.0")
        assert self._resolve(manifest, "12.7").min_os == "11.0"
        with pytest.raises(AmbiguousArtifactError):
            self._resolve(manifest, "14.2")

    def test_host_version_is_read_on_macos(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(trust_module.sys, "platform", "darwin")
        monkeypatch.setattr(trust_module.platform, "mac_ver", lambda: ("13.6.1", ("", "", ""), "arm64"))
        assert host_os_version("darwin") == "13.6.1"

    def test_host_version_is_read_on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(trust_module.sys, "platform", "win32")
        monkeypatch.setattr(trust_module.platform, "version", lambda: "10.0.19045")
        assert host_os_version("windows") == "10.0.19045"

    def test_host_version_is_unknown_for_another_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(trust_module.sys, "platform", "linux")
        assert host_os_version("darwin") is None
        assert host_os_version("linux") is None

    def test_resolution_uses_the_detected_host_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(trust_module, "host_os_version", lambda _platform: "12.0")
        with pytest.raises(OperatingSystemTooOldError):
            self._resolve(self._darwin_manifest("13.0"), None)


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

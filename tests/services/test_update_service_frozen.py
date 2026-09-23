"""Tests for UpdateService frozen distribution update checks and verified downloads."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution import (
    ArtifactKind,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    TrustPolicy,
    sign_manifest,
)
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeCapabilityError,
    RuntimeLayout,
)
from servonaut.services.update_service import UpdateService

_TEST_MANIFEST_URL = "https://releases.servonaut.dev/manifest.json"


def _make_frozen_runtime(
    tmp_path: Path,
    *,
    kind: DistributionKind = DistributionKind.FROZEN_CLI,
    version: str = "2.26.3",
    revision: str | None = None,
) -> RuntimeLayout:
    return RuntimeLayout(
        kind=kind,
        product_version=version,
        build_revision=revision,
        resource_root=tmp_path / "resources",
        executable_root=tmp_path / "bin",
        data_root=tmp_path / "data",
        executable=tmp_path / "bin" / "servonaut",
        python_executable=None,
        path_console=None,
        console_helper=tmp_path / "bin" / "servonaut",
        desktop_child=tmp_path / "bin" / "servonaut-child" if kind == DistributionKind.PACKAGED_DESKTOP else None,
        package_management=PackageManagementCapability(
            kind=PackageManagementKind.UNSUPPORTED,
            argv_prefix=(),
            allows_automatic_mutation=False,
        ),
        is_frozen=True,
    )


def _make_manifest_with_signature(
    priv_key: Ed25519PrivateKey,
    key_id: str,
    *,
    version: str = "2.27.0",
    revision: int | None = None,
    channel: ReleaseChannel = ReleaseChannel.STABLE,
    artifacts: tuple[ReleaseArtifact, ...] | None = None,
) -> ReleaseManifest:
    if artifacts is None:
        payload_bytes = b"fake binary payload content"
        sha256 = hashlib.sha256(payload_bytes).hexdigest()
        artifacts = (
            ReleaseArtifact(
                artifact_id="cli-linux-x64",
                kind=ArtifactKind.STANDALONE_CLI,
                distribution=DistributionKind.FROZEN_CLI,
                platform="linux",
                arch="x86_64",
                filename="servonaut-cli-linux-x64.tar.gz",
                download_url=f"https://github.com/zb-ss/servonaut/releases/download/v{version}/servonaut-cli-linux-x64.tar.gz",
                byte_size=len(payload_bytes),
                sha256=sha256,
            ),
            ReleaseArtifact(
                artifact_id="desktop-ubuntu-deb",
                kind=ArtifactKind.UBUNTU_DEB,
                distribution=DistributionKind.PACKAGED_DESKTOP,
                platform="linux",
                arch="x86_64",
                filename="servonaut-desktop.deb",
                download_url=f"https://github.com/zb-ss/servonaut/releases/download/v{version}/servonaut-desktop.deb",
                byte_size=len(payload_bytes),
                sha256=sha256,
            ),
        )

    base = ReleaseManifest(
        schema_version=1,
        channel=channel,
        product_version=version,
        published_at="2026-09-23T12:00:00Z",
        artifacts=artifacts,
        signatures=(),
        packaging_revision=revision,
    )
    return sign_manifest(base, priv_key, key_id)


class _MockResponse:
    def __init__(self, data: bytes) -> None:
        self._bio = io.BytesIO(data)

    def read(self, size: int = -1) -> bytes:
        return self._bio.read(size)

    def __enter__(self) -> _MockResponse:
        return self

    def __exit__(self, *args) -> None:
        pass


class TestUpdateServiceFrozen:
    @pytest.fixture
    def trust_setup(self) -> tuple[Ed25519PrivateKey, str, TrustPolicy]:
        priv_key = Ed25519PrivateKey.generate()
        key_id = "prod-key-1"
        policy = TrustPolicy(
            trusted_public_keys={key_id: priv_key.public_key()},
            minimum_signatures=1,
            allowed_origin_prefixes=("https://github.com/zb-ss/servonaut/releases/download/",),
        )
        return priv_key, key_id, policy

    def test_check_for_update_frozen_happy_path(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        priv_key, key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path, version="2.26.3")
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0")
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(
            runtime=runtime,
            manifest_url=_TEST_MANIFEST_URL,
            trust_policy=policy,
        )

        with patch("urllib.request.urlopen", return_value=_MockResponse(raw_manifest)), \
             patch("servonaut.distribution.trust.normalize_platform", return_value="linux"), \
             patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"):
            result = service.check_for_update()

        assert result == "2.27.0"
        assert service.latest_version == "2.27.0"
        assert service.target_artifact is not None
        assert service.target_artifact.artifact_id == "cli-linux-x64"
        assert "Update available" in service.update_status

    def test_check_for_update_offline_graceful_degradation(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        _priv, _key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path)
        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network is unreachable")):
            result = service.check_for_update()

        assert result is None
        assert "offline" in service.update_status.lower()

    def test_check_for_update_signature_verification_failure(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        _priv, _key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path)

        # Sign with an unauthorized key
        unauthorized_key = Ed25519PrivateKey.generate()
        manifest = _make_manifest_with_signature(unauthorized_key, "untrusted-key", version="2.27.0")
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", return_value=_MockResponse(raw_manifest)):
            result = service.check_for_update()

        assert result is None
        assert "verification failed" in service.update_status.lower()

    def test_check_for_update_downgrade_prevention(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        priv_key, key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path, version="2.26.3")

        # Manifest with older version 2.26.2
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.26.2")
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", return_value=_MockResponse(raw_manifest)):
            result = service.check_for_update()

        assert result is None
        assert "latest version" in service.update_status.lower()

    def test_check_for_update_unapproved_origin(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        priv_key, key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path, version="2.26.3")

        # Create artifact with unapproved download URL
        unapproved_artifact = ReleaseArtifact(
            artifact_id="cli-linux-x64",
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            filename="cli.tar.gz",
            download_url="https://untrusted-host.com/cli.tar.gz",
            byte_size=100,
            sha256="d" * 64,
        )
        manifest = _make_manifest_with_signature(
            priv_key, key_id, version="2.27.0", artifacts=(unapproved_artifact,)
        )
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", return_value=_MockResponse(raw_manifest)):
            result = service.check_for_update()

        assert result is None
        assert "verification failed" in service.update_status.lower()

    def test_download_update_verified_stream(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        priv_key, key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path, version="2.26.3")

        payload = b"VALID_BINARY_PAYLOAD_CHUNKS" * 1024
        sha256 = hashlib.sha256(payload).hexdigest()
        artifact = ReleaseArtifact(
            artifact_id="cli-linux-x64",
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            filename="servonaut-update.tar.gz",
            download_url="https://github.com/zb-ss/servonaut/releases/download/v2.27.0/servonaut-update.tar.gz",
            byte_size=len(payload),
            sha256=sha256,
        )
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0", artifacts=(artifact,))
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", return_value=_MockResponse(raw_manifest)), \
             patch("servonaut.distribution.trust.normalize_platform", return_value="linux"), \
             patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"):
            assert service.check_for_update() == "2.27.0"

        # Now download
        dest_dir = tmp_path / "downloads"
        progress_calls: list[tuple[int, int]] = []

        with patch("urllib.request.urlopen", return_value=_MockResponse(payload)):
            downloaded = service.download_update(
                destination_dir=dest_dir,
                progress_callback=lambda d, t: progress_calls.append((d, t)),
            )

        assert downloaded.is_file()
        assert downloaded.name == "servonaut-update.tar.gz"
        assert downloaded.read_bytes() == payload
        assert len(progress_calls) > 0
        assert not (dest_dir / "servonaut-update.tar.gz.part").exists()

    def test_download_update_hash_mismatch_raises_and_cleans_up(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        priv_key, key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path, version="2.26.3")

        expected_payload = b"EXPECTED_PAYLOAD"
        actual_payload = b"CORRUPTED_PAYLOAD"
        sha256 = hashlib.sha256(expected_payload).hexdigest()

        artifact = ReleaseArtifact(
            artifact_id="cli-linux-x64",
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            filename="servonaut-corrupt.tar.gz",
            download_url="https://github.com/zb-ss/servonaut/releases/download/v2.27.0/servonaut-corrupt.tar.gz",
            byte_size=len(expected_payload),
            sha256=sha256,
        )
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0", artifacts=(artifact,))
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", return_value=_MockResponse(raw_manifest)), \
             patch("servonaut.distribution.trust.normalize_platform", return_value="linux"), \
             patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"):
            service.check_for_update()

        dest_dir = tmp_path / "downloads"
        with patch("urllib.request.urlopen", return_value=_MockResponse(actual_payload)):
            with pytest.raises(ValueError, match="Integrity check failed"):
                service.download_update(destination_dir=dest_dir)

        # Ensure temp part file is unlinked and target file does not exist
        assert not (dest_dir / "servonaut-corrupt.tar.gz").exists()
        assert not (dest_dir / "servonaut-corrupt.tar.gz.part").exists()

    def test_run_upgrade_frozen_guidance_for_cli(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        priv_key, key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path, version="2.26.3")

        payload = b"CLI_BINARY"
        sha256 = hashlib.sha256(payload).hexdigest()
        artifact = ReleaseArtifact(
            artifact_id="cli-linux-x64",
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            filename="cli.tar.gz",
            download_url="https://github.com/zb-ss/servonaut/releases/download/v2.27.0/cli.tar.gz",
            byte_size=len(payload),
            sha256=sha256,
        )
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0", artifacts=(artifact,))
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", side_effect=[_MockResponse(raw_manifest), _MockResponse(payload)]), \
             patch("servonaut.distribution.trust.normalize_platform", return_value="linux"), \
             patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"):
            ok, msg = asyncio.run(service.run_upgrade())

        assert ok is True
        assert "Downloaded verified update" in msg
        assert "Extract the archive and replace" in msg

    @pytest.mark.parametrize(
        "kind,expected_keyword",
        [
            (ArtifactKind.MACOS_DMG, "Open the DMG disk image"),
            (ArtifactKind.WINDOWS_MSI, "Run the installer"),
            (ArtifactKind.UBUNTU_DEB, "sudo apt install"),
        ],
    )
    def test_run_upgrade_guidance_installers(
        self,
        tmp_path: Path,
        trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy],
        kind: ArtifactKind,
        expected_keyword: str,
    ) -> None:
        priv_key, key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path, kind=DistributionKind.PACKAGED_DESKTOP)

        payload = b"INSTALLER_BYTES"
        sha256 = hashlib.sha256(payload).hexdigest()
        artifact = ReleaseArtifact(
            artifact_id="installer-1",
            kind=kind,
            distribution=DistributionKind.PACKAGED_DESKTOP,
            platform="linux" if kind == ArtifactKind.UBUNTU_DEB else ("darwin" if kind == ArtifactKind.MACOS_DMG else "windows"),
            arch="x86_64",
            filename="servonaut-installer",
            download_url="https://github.com/zb-ss/servonaut/releases/download/v2.27.0/servonaut-installer",
            byte_size=len(payload),
            sha256=sha256,
        )
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0", artifacts=(artifact,))
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", side_effect=[_MockResponse(raw_manifest), _MockResponse(payload)]), \
             patch("servonaut.distribution.trust.normalize_platform", return_value=artifact.platform), \
             patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"):
            ok, msg = asyncio.run(service.run_upgrade())

        assert ok is True
        assert expected_keyword in msg

    def test_run_upgrade_already_latest(
        self, tmp_path: Path, trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy]
    ) -> None:
        priv_key, key_id, policy = trust_setup
        runtime = _make_frozen_runtime(tmp_path, version="2.27.0")

        # Manifest also at 2.27.0
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0")
        raw_manifest = json.dumps(manifest.to_dict()).encode("utf-8")

        service = UpdateService(runtime=runtime, manifest_url=_TEST_MANIFEST_URL, trust_policy=policy)

        with patch("urllib.request.urlopen", return_value=_MockResponse(raw_manifest)):
            ok, msg = asyncio.run(service.run_upgrade())

        assert ok is True
        assert "Already on the latest version" in msg

    def test_check_for_update_unconfigured_frozen_guidance(self, tmp_path: Path) -> None:
        from unittest.mock import AsyncMock
        runtime = _make_frozen_runtime(tmp_path)
        service = UpdateService(runtime=runtime)
        with patch("urllib.request.urlopen") as request, patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as spawn:
            assert service.check_for_update() is None
            ok, message = asyncio.run(service.run_upgrade())
        assert ok is False
        assert "signed build" in message
        assert service.update_status == message
        request.assert_not_called()
        spawn.assert_not_called()


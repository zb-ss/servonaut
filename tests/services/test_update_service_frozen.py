"""Tests for UpdateService frozen distribution update checks and verified downloads."""

from __future__ import annotations

import asyncio
import hashlib
import http.server
import io
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution import (
    ArtifactKind,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    TrustPolicy,
    sign_manifest,
    trust_root,
)
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.services import update_service as update_module
from servonaut.services.update_service import (
    HttpsOnlyRedirectHandler,
    UpdateCheckResult,
    UpdateInProgressError,
    UpdateIntegrityError,
    UpdateService,
    build_https_opener,
)

_TEST_MANIFEST_URL = "https://releases.servonaut.dev/manifest.json"
_RELEASES = "https://github.com/zb-ss/servonaut/releases/download"
_FUTURE_EXPIRY = "2099-01-01T00:00:00Z"


def _make_frozen_runtime(
    tmp_path: Path,
    *,
    kind: DistributionKind = DistributionKind.FROZEN_CLI,
    version: str = "2.26.3",
    revision: str | None = None,
    channel: str = "stable",
    packaging_revision: int | None = None,
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
        release_channel=channel,
        packaging_revision=packaging_revision,
    )


def _cli_artifact(
    payload: bytes, *, filename: str = "servonaut-cli-linux-x64.tar.gz", version: str = "2.27.0"
) -> ReleaseArtifact:
    return ReleaseArtifact(
        artifact_id="cli-linux-x64",
        kind=ArtifactKind.STANDALONE_CLI,
        distribution=DistributionKind.FROZEN_CLI,
        platform="linux",
        arch="x86_64",
        filename=filename,
        download_url=f"{_RELEASES}/v{version}/{filename}",
        byte_size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _make_manifest_with_signature(
    priv_key: Ed25519PrivateKey,
    key_id: str,
    *,
    version: str = "2.27.0",
    revision: int | None = None,
    channel: ReleaseChannel = ReleaseChannel.STABLE,
    artifacts: tuple[ReleaseArtifact, ...] | None = None,
    expires_at: str | None = _FUTURE_EXPIRY,
) -> ReleaseManifest:
    if artifacts is None:
        payload_bytes = b"fake binary payload content"
        artifacts = (
            _cli_artifact(payload_bytes, version=version),
            ReleaseArtifact(
                artifact_id="desktop-ubuntu-deb",
                kind=ArtifactKind.UBUNTU_DEB,
                distribution=DistributionKind.PACKAGED_DESKTOP,
                platform="linux",
                arch="x86_64",
                filename="servonaut-desktop.deb",
                download_url=f"{_RELEASES}/v{version}/servonaut-desktop.deb",
                byte_size=len(payload_bytes),
                sha256=hashlib.sha256(payload_bytes).hexdigest(),
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
        expires_at=expires_at,
    )
    return sign_manifest(base, priv_key, key_id)


def _raw(manifest: ReleaseManifest) -> bytes:
    return json.dumps(manifest.to_dict()).encode("utf-8")


class _MockResponse:
    def __init__(self, data: bytes, headers: dict[str, str] | None = None) -> None:
        self._bio = io.BytesIO(data)
        self.headers = headers or {}
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._bio.read(size)
        self.bytes_read += len(chunk)
        return chunk

    def __enter__(self) -> _MockResponse:
        return self

    def __exit__(self, *args) -> None:
        pass


class _EndlessResponse(_MockResponse):
    """A response body that never ends, as a hostile server might send."""

    def __init__(self) -> None:
        super().__init__(b"")

    def read(self, size: int = -1) -> bytes:
        self.bytes_read += size
        return b"A" * size


class _SlowEndlessResponse(_EndlessResponse):
    """An endless body trickled slowly enough to outlast a short deadline."""

    def read(self, size: int = -1) -> bytes:
        time.sleep(0.03)
        return super().read(size)


class _FakeOpener:
    def __init__(self, *responses: object) -> None:
        self._responses = list(responses)
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float | None = None) -> object:
        self.requests.append(request)
        response = self._responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


@pytest.fixture
def linux_x64() -> Iterator[None]:
    with patch("servonaut.distribution.trust.normalize_platform", return_value="linux"), \
         patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"):
        yield


@pytest.fixture
def trust_setup() -> tuple[Ed25519PrivateKey, str, TrustPolicy]:
    priv_key = Ed25519PrivateKey.generate()
    key_id = "prod-key-1"
    policy = TrustPolicy(
        trusted_public_keys={key_id: priv_key.public_key()},
        minimum_signatures=1,
        allowed_origin_prefixes=(f"{_RELEASES}/",),
    )
    return priv_key, key_id, policy


def _service(
    tmp_path: Path,
    policy: TrustPolicy,
    *responses: object,
    service_kwargs: dict[str, object] | None = None,
    **runtime_kwargs: object,
) -> UpdateService:
    return UpdateService(
        runtime=_make_frozen_runtime(tmp_path, **runtime_kwargs),  # type: ignore[arg-type]
        manifest_url=_TEST_MANIFEST_URL,
        trust_policy=policy,
        opener=_FakeOpener(*responses),  # type: ignore[arg-type]
        **(service_kwargs or {}),  # type: ignore[arg-type]
    )


def _ready_to_download(
    tmp_path: Path,
    trust_setup: tuple[Ed25519PrivateKey, str, TrustPolicy],
    payload: bytes,
    *download_responses: object,
    service_kwargs: dict[str, object] | None = None,
) -> UpdateService:
    """A service whose check already resolved a CLI artifact for ``payload``."""
    priv_key, key_id, policy = trust_setup
    manifest = _make_manifest_with_signature(priv_key, key_id, artifacts=(_cli_artifact(payload),))
    service = _service(
        tmp_path, policy, _MockResponse(_raw(manifest)), *download_responses, service_kwargs=service_kwargs
    )
    with patch("servonaut.distribution.trust.normalize_platform", return_value="linux"), \
         patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"):
        assert service.check_for_update() == "2.27.0"
    return service


class TestUpdateServiceFrozen:
    def test_check_for_update_frozen_happy_path(self, tmp_path, trust_setup, linux_x64) -> None:
        priv_key, key_id, policy = trust_setup
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0")
        service = _service(tmp_path, policy, _MockResponse(_raw(manifest)))

        result = service.check_for_update()

        assert result == "2.27.0"
        assert service.latest_version == "2.27.0"
        assert service.target_artifact is not None
        assert service.target_artifact.artifact_id == "cli-linux-x64"
        assert "Update available" in service.update_status
        assert service.last_check_result is UpdateCheckResult.UPDATE_AVAILABLE

    def test_check_for_update_offline_graceful_degradation(self, tmp_path, trust_setup) -> None:
        _priv, _key_id, policy = trust_setup
        service = _service(tmp_path, policy, urllib.error.URLError("Network is unreachable"))

        assert service.check_for_update() is None
        assert "offline" in service.update_status.lower()
        assert service.last_check_result is UpdateCheckResult.OFFLINE

    def test_check_for_update_signature_verification_failure(self, tmp_path, trust_setup) -> None:
        _priv, _key_id, policy = trust_setup
        unauthorized_key = Ed25519PrivateKey.generate()
        manifest = _make_manifest_with_signature(unauthorized_key, "untrusted-key", version="2.27.0")
        service = _service(tmp_path, policy, _MockResponse(_raw(manifest)))

        assert service.check_for_update() is None
        assert "verification failed" in service.update_status.lower()
        assert service.last_check_result is UpdateCheckResult.VERIFICATION_FAILED

    def test_check_for_update_downgrade_prevention(self, tmp_path, trust_setup) -> None:
        priv_key, key_id, policy = trust_setup
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.26.2")
        service = _service(tmp_path, policy, _MockResponse(_raw(manifest)), version="2.26.3")

        assert service.check_for_update() is None
        assert "latest version" in service.update_status.lower()
        assert service.last_check_result is UpdateCheckResult.UP_TO_DATE

    def test_check_for_update_unapproved_origin(self, tmp_path, trust_setup) -> None:
        priv_key, key_id, policy = trust_setup
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
        manifest = _make_manifest_with_signature(priv_key, key_id, artifacts=(unapproved_artifact,))
        service = _service(tmp_path, policy, _MockResponse(_raw(manifest)))

        assert service.check_for_update() is None
        assert "verification failed" in service.update_status.lower()

    def test_download_update_verified_stream(self, tmp_path, trust_setup) -> None:
        payload = b"VALID_BINARY_PAYLOAD_CHUNKS" * 1024
        service = _ready_to_download(
            tmp_path, trust_setup, payload, _MockResponse(payload, {"Content-Length": str(len(payload))})
        )
        dest_dir = tmp_path / "downloads"
        progress_calls: list[tuple[int, int]] = []

        downloaded = service.download_update(
            destination_dir=dest_dir,
            progress_callback=lambda d, t: progress_calls.append((d, t)),
        )

        assert downloaded == dest_dir / "servonaut-cli-linux-x64.tar.gz"
        assert downloaded.read_bytes() == payload
        assert progress_calls[-1] == (len(payload), len(payload))
        assert [p.name for p in dest_dir.iterdir()] == ["servonaut-cli-linux-x64.tar.gz"]

    def test_download_update_hash_mismatch_raises_and_cleans_up(self, tmp_path, trust_setup) -> None:
        expected_payload = b"EXPECTED_PAYLOAD"
        service = _ready_to_download(
            tmp_path, trust_setup, expected_payload, _MockResponse(b"CORRUPTED_PAYLOA")
        )
        dest_dir = tmp_path / "downloads"

        with pytest.raises(ValueError, match="Integrity check failed"):
            service.download_update(destination_dir=dest_dir)

        assert list(dest_dir.iterdir()) == []

    def test_run_upgrade_frozen_guidance_for_cli(self, tmp_path, trust_setup, linux_x64) -> None:
        priv_key, key_id, policy = trust_setup
        payload = b"CLI_BINARY"
        artifact = _cli_artifact(payload, filename="cli.tar.gz")
        manifest = _make_manifest_with_signature(priv_key, key_id, artifacts=(artifact,))
        service = _service(tmp_path, policy, _MockResponse(_raw(manifest)), _MockResponse(payload))

        with patch.object(Path, "home", return_value=tmp_path):
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
    def test_run_upgrade_guidance_installers(self, tmp_path, trust_setup, kind, expected_keyword) -> None:
        priv_key, key_id, policy = trust_setup
        payload = b"INSTALLER_BYTES"
        artifact = ReleaseArtifact(
            artifact_id="installer-1",
            kind=kind,
            distribution=DistributionKind.PACKAGED_DESKTOP,
            platform="linux" if kind == ArtifactKind.UBUNTU_DEB else ("darwin" if kind == ArtifactKind.MACOS_DMG else "windows"),
            arch="x86_64",
            filename="servonaut-installer",
            download_url=f"{_RELEASES}/v2.27.0/servonaut-installer",
            byte_size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        manifest = _make_manifest_with_signature(priv_key, key_id, artifacts=(artifact,))
        service = _service(
            tmp_path,
            policy,
            _MockResponse(_raw(manifest)),
            _MockResponse(payload),
            kind=DistributionKind.PACKAGED_DESKTOP,
        )

        with patch("servonaut.distribution.trust.normalize_platform", return_value=artifact.platform), \
             patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"), \
             patch.object(Path, "home", return_value=tmp_path):
            ok, msg = asyncio.run(service.run_upgrade())

        assert ok is True
        assert expected_keyword in msg

    def test_run_upgrade_already_latest(self, tmp_path, trust_setup) -> None:
        priv_key, key_id, policy = trust_setup
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0")
        service = _service(tmp_path, policy, _MockResponse(_raw(manifest)), version="2.27.0")

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


class TestUntrustedManifestInput:
    """Unsigned or malformed manifest content is reported, never raised or echoed."""

    @pytest.mark.parametrize(
        "field,value", [("platform", ["linux"]), ("arch", {}), ("byte_size", "1")]
    )
    def test_malformed_field_types_are_reported_not_raised(self, tmp_path, trust_setup, field, value) -> None:
        priv_key, key_id, policy = trust_setup
        document = _make_manifest_with_signature(priv_key, key_id).to_dict()
        document["artifacts"][0][field] = value
        service = _service(tmp_path, policy, _MockResponse(json.dumps(document).encode()))

        assert service.check_for_update() is None
        assert service.last_check_result is UpdateCheckResult.INVALID_MANIFEST

    def test_lone_surrogate_is_reported_not_raised(self, tmp_path, trust_setup) -> None:
        priv_key, key_id, policy = trust_setup
        raw = _raw(_make_manifest_with_signature(priv_key, key_id)).replace(
            b'"2026-09-23T12:00:00Z"', b'"\\ud800"', 1
        )
        service = _service(tmp_path, policy, _MockResponse(raw))

        assert service.check_for_update() is None
        assert service.last_check_result is UpdateCheckResult.VERIFICATION_FAILED

    @pytest.mark.parametrize("current", ["2.27.0.dev0", "2.28.0rc1"])
    def test_non_semver_running_version_is_reported_not_raised(self, tmp_path, trust_setup, current) -> None:
        priv_key, key_id, policy = trust_setup
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0")
        service = _service(tmp_path, policy, _MockResponse(_raw(manifest)), version=current)

        assert service.check_for_update() is None
        assert service.last_check_result is UpdateCheckResult.VERSION_UNCOMPARABLE

    def test_status_is_a_fixed_message_without_manifest_text(self, tmp_path, trust_setup) -> None:
        _priv, _key_id, policy = trust_setup
        hostile = "\x1b]0;owned\x07" + "X" * 100_000
        raw = json.dumps({"schema_version": 1, "channel": hostile, "product_version": "9.9.9",
                          "published_at": "x", "artifacts": []}).encode()
        service = _service(tmp_path, policy, _MockResponse(raw))

        assert service.check_for_update() is None
        assert service.update_status == update_module._STATUS_MESSAGES[UpdateCheckResult.INVALID_MANIFEST]

    def test_status_text_cannot_fake_an_up_to_date_result(self, tmp_path, trust_setup) -> None:
        _priv, _key_id, policy = trust_setup
        raw = json.dumps({"schema_version": 1, "channel": "on the latest version",
                          "product_version": "9.9.9", "published_at": "x", "artifacts": []}).encode()
        service = _service(tmp_path, policy, _MockResponse(raw))

        ok, _message = asyncio.run(service.run_upgrade())

        assert ok is False
        assert service.last_check_result is UpdateCheckResult.INVALID_MANIFEST

    def test_manifest_without_expiry_is_refused(self, tmp_path, trust_setup) -> None:
        priv_key, key_id, policy = trust_setup
        manifest = _make_manifest_with_signature(priv_key, key_id, expires_at=None)
        service = _service(tmp_path, policy, _MockResponse(_raw(manifest)))

        assert service.check_for_update() is None
        assert service.last_check_result is UpdateCheckResult.VERIFICATION_FAILED

    def test_oversized_manifest_is_refused_after_a_bounded_read(self, tmp_path, trust_setup) -> None:
        _priv, _key_id, policy = trust_setup
        endless = _EndlessResponse()
        service = _service(tmp_path, policy, endless)

        assert service.check_for_update() is None
        assert service.last_check_result is UpdateCheckResult.INVALID_MANIFEST
        assert endless.bytes_read <= update_module._MAX_MANIFEST_BYTES + update_module._TRANSFER_CHUNK_BYTES

    def test_manifest_transfer_has_an_overall_deadline(self, tmp_path, trust_setup) -> None:
        _priv, _key_id, policy = trust_setup
        trickle = _SlowEndlessResponse()
        service = _service(
            tmp_path, policy, trickle, service_kwargs={"manifest_deadline_seconds": 0.05}
        )

        assert service.check_for_update() is None
        assert service.last_check_result is UpdateCheckResult.OFFLINE
        assert trickle.bytes_read < update_module._MAX_MANIFEST_BYTES


class TestReleaseChannelPolicy:
    @pytest.fixture
    def pinned_key(self, monkeypatch) -> Ed25519PrivateKey:
        key = Ed25519PrivateKey.generate()
        monkeypatch.setattr(
            trust_root, "PINNED_RELEASE_KEYS", {"release-1": key.public_key().public_bytes_raw().hex()}
        )
        return key

    def _check(self, tmp_path: Path, manifest: ReleaseManifest, channel: str) -> UpdateService:
        service = UpdateService(
            runtime=_make_frozen_runtime(tmp_path, channel=channel),
            manifest_url=_TEST_MANIFEST_URL,
            opener=_FakeOpener(_MockResponse(_raw(manifest))),  # type: ignore[arg-type]
        )
        service.check_for_update()
        return service

    def test_stable_build_refuses_a_signed_preview_manifest(self, tmp_path, pinned_key, linux_x64) -> None:
        manifest = _make_manifest_with_signature(pinned_key, "release-1", channel=ReleaseChannel.PREVIEW)
        service = self._check(tmp_path, manifest, "stable")

        assert service.last_check_result is UpdateCheckResult.VERIFICATION_FAILED
        assert service.target_artifact is None

    @pytest.mark.parametrize("manifest_channel", [ReleaseChannel.PREVIEW, ReleaseChannel.STABLE])
    def test_preview_build_accepts_preview_and_stable(
        self, tmp_path, pinned_key, linux_x64, manifest_channel
    ) -> None:
        manifest = _make_manifest_with_signature(pinned_key, "release-1", channel=manifest_channel)
        service = self._check(tmp_path, manifest, "preview")

        assert service.last_check_result is UpdateCheckResult.UPDATE_AVAILABLE

    def test_no_pinned_key_means_updates_are_not_configured(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(trust_root, "PINNED_RELEASE_KEYS", {})
        opener = _FakeOpener()
        service = UpdateService(
            runtime=_make_frozen_runtime(tmp_path),
            manifest_url=_TEST_MANIFEST_URL,
            opener=opener,  # type: ignore[arg-type]
        )

        assert service.check_for_update() is None
        assert service.last_check_result is UpdateCheckResult.NOT_CONFIGURED
        assert "not configured" in service.update_status
        assert opener.requests == []


class TestPackagingRevision:
    def test_same_version_and_revision_is_up_to_date(self, tmp_path, trust_setup, linux_x64) -> None:
        priv_key, key_id, policy = trust_setup
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0", revision=1)
        service = _service(
            tmp_path, policy, _MockResponse(_raw(manifest)),
            version="2.27.0", revision="ci-r1", packaging_revision=1,
        )

        assert service.check_for_update() is None
        assert service.last_check_result is UpdateCheckResult.UP_TO_DATE

    def test_higher_packaging_revision_is_an_update(self, tmp_path, trust_setup, linux_x64) -> None:
        priv_key, key_id, policy = trust_setup
        manifest = _make_manifest_with_signature(priv_key, key_id, version="2.27.0", revision=2)
        service = _service(
            tmp_path, policy, _MockResponse(_raw(manifest)),
            version="2.27.0", revision="ci-r1", packaging_revision=1,
        )

        assert service.check_for_update() == "2.27.0"


class TestBoundedDownload:
    def test_download_stops_once_it_exceeds_the_signed_size(self, tmp_path, trust_setup) -> None:
        payload = b"x" * (64 * 1024 * 8)
        endless = _EndlessResponse()
        service = _ready_to_download(tmp_path, trust_setup, payload, endless)
        progress: list[int] = []

        with pytest.raises(UpdateIntegrityError, match="exceeded"):
            service.download_update(tmp_path / "dl", lambda done, _total: progress.append(done))

        assert max(progress) <= len(payload)
        assert endless.bytes_read <= len(payload) + update_module._TRANSFER_CHUNK_BYTES
        assert list((tmp_path / "dl").iterdir()) == []

    def test_disagreeing_content_length_is_refused_before_reading(self, tmp_path, trust_setup) -> None:
        payload = b"PAYLOAD"
        response = _MockResponse(payload, {"Content-Length": "999999999"})
        service = _ready_to_download(tmp_path, trust_setup, payload, response)

        with pytest.raises(UpdateIntegrityError, match="announced"):
            service.download_update(tmp_path / "dl")

        assert response.bytes_read == 0
        assert list((tmp_path / "dl").iterdir()) == []

    def test_truncated_download_is_refused(self, tmp_path, trust_setup) -> None:
        payload = b"PAYLOAD-BYTES"
        service = _ready_to_download(tmp_path, trust_setup, payload, _MockResponse(payload[:4]))

        with pytest.raises(UpdateIntegrityError, match="Size mismatch"):
            service.download_update(tmp_path / "dl")

    def test_download_has_an_overall_deadline(self, tmp_path, trust_setup) -> None:
        payload = b"y" * (64 * 1024 * 64)
        trickle = _SlowEndlessResponse()
        service = _ready_to_download(
            tmp_path, trust_setup, payload, trickle, service_kwargs={"download_deadline_seconds": 0.05}
        )

        with pytest.raises(TimeoutError):
            service.download_update(tmp_path / "dl")

        assert trickle.bytes_read < len(payload)
        assert list((tmp_path / "dl").iterdir()) == []

    def test_run_upgrade_reports_a_fixed_message_for_a_rejected_download(self, tmp_path, trust_setup) -> None:
        payload = b"EXPECTED"
        service = _ready_to_download(tmp_path, trust_setup, payload, _MockResponse(b"\x1b[2JEVIL"))

        with patch.object(Path, "home", return_value=tmp_path):
            ok, message = asyncio.run(service.run_upgrade())

        assert ok is False
        assert message == update_module._DOWNLOAD_REJECTED_MESSAGE


class TestConcurrentDownloads:
    def test_second_download_is_refused_while_one_runs(self, tmp_path, trust_setup) -> None:
        payload = b"z" * (64 * 1024 * 2)
        started, release = threading.Event(), threading.Event()

        class _BlockingResponse(_MockResponse):
            def read(self, size: int = -1) -> bytes:
                started.set()
                release.wait(timeout=10)
                return super().read(size)

        service = _ready_to_download(tmp_path, trust_setup, payload, _BlockingResponse(payload))
        results: dict[str, Path] = {}
        worker = threading.Thread(
            target=lambda: results.setdefault("first", service.download_update(tmp_path / "dl"))
        )
        worker.start()
        assert started.wait(timeout=10)
        try:
            with pytest.raises(UpdateInProgressError):
                service.download_update(tmp_path / "dl")
        finally:
            release.set()
            worker.join(timeout=10)

        assert results["first"] == tmp_path / "dl" / "servonaut-cli-linux-x64.tar.gz"

    def test_download_never_touches_a_shared_partial_file(self, tmp_path, trust_setup) -> None:
        payload = b"PAYLOAD"
        service = _ready_to_download(tmp_path, trust_setup, payload, _MockResponse(payload))
        dest = tmp_path / "dl"
        dest.mkdir()
        foreign = dest / "servonaut-cli-linux-x64.tar.gz.part"
        foreign.write_bytes(b"another download in progress")

        downloaded = service.download_update(dest)

        assert downloaded.read_bytes() == payload
        assert foreign.read_bytes() == b"another download in progress"


class TestUpgradeCommand:
    def test_get_upgrade_command_has_no_side_effects_on_frozen_builds(self, tmp_path: Path) -> None:
        service = UpdateService(runtime=_make_frozen_runtime(tmp_path))

        assert service.get_upgrade_command() is None
        assert service.update_status is None


class TestHttpsOnlyRedirects:
    def test_handler_refuses_a_redirect_to_http(self) -> None:
        handler = HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://releases.servonaut.dev/a")
        with pytest.raises(urllib.error.HTTPError, match="non-HTTPS"):
            handler.redirect_request(request, None, 302, "Found", {}, "http://releases.servonaut.dev/b")

    def test_handler_follows_a_redirect_to_https(self) -> None:
        handler = HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://releases.servonaut.dev/a")
        redirected = handler.redirect_request(
            request, None, 302, "Found", {}, "https://objects.example.net/b"
        )
        assert redirected.full_url == "https://objects.example.net/b"

    def test_default_opener_refuses_a_real_http_redirect(self) -> None:
        class _Redirector(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - http.server API
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/next")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with pytest.raises(urllib.error.HTTPError, match="non-HTTPS"):
                build_https_opener().open(f"http://127.0.0.1:{server.server_port}/start", timeout=5)
        finally:
            server.shutdown()
            server.server_close()

    def test_service_uses_the_https_only_opener_by_default(self, tmp_path: Path) -> None:
        service = UpdateService(runtime=_make_frozen_runtime(tmp_path))
        assert any(isinstance(handler, HttpsOnlyRedirectHandler) for handler in service._opener.handlers)

"""A build's runtime marker carries the identity the update check orders by.

These tests follow the values from the builder that writes the marker, through
the runtime parser, into the signed-manifest comparison.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import scripts.desktop_shell.build as desktop_build
from scripts.desktop_shell.model import DesktopBuildRequest, load_desktop_target_spec
from scripts.standalone_cli.release_identity import DEVELOPMENT_IDENTITY, ReleaseIdentity
from servonaut import runtime
from servonaut.distribution import (
    ArtifactKind,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    TrustPolicy,
)
from servonaut.distribution.trust import sign_manifest
from servonaut.runtime import DistributionKind, RuntimeEvidence, RuntimeLayout, resolve_runtime
from servonaut.services.update_service import UpdateCheckResult, UpdateService

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"
_VERSION = "2.27.0"
_RELEASES = "https://github.com/zb-ss/servonaut/releases/download"
_MANIFEST_URL = "https://releases.servonaut.dev/manifest.json"
_KEY_ID = "release-test"


def _desktop_payload(tmp_path: Path, identity: ReleaseIdentity) -> Path:
    """Write the marker exactly as the desktop builder does for a payload."""
    payload = tmp_path / "servonaut-desktop"
    payload.mkdir()
    request = DesktopBuildRequest(
        wheel=tmp_path / f"servonaut-{_VERSION}-py3-none-any.whl",
        target=load_desktop_target_spec(_POLICY_PATH, "linux-x64-ubuntu-22.04"),
        product_version=_VERSION,
        # A free-form CI label; it must never decide update ordering.
        build_revision="ci-r1",
        source_commit="commit1",
        output_dir=tmp_path / "out",
        release_identity=identity,
    )
    desktop_build._write_runtime_marker(payload, request)
    return payload


def _runtime_from_payload(payload: Path) -> RuntimeLayout:
    return resolve_runtime(
        RuntimeEvidence(
            executable=payload / "servonaut-desktop",
            executable_root=payload,
            resource_root=payload / "_internal",
            home=payload.parent / "home",
            is_frozen=True,
            package_version=_VERSION,
            package_is_installed=False,
            source_install_path=None,
            path_console=None,
            pipx_executable=None,
            pipx_contains_servonaut=False,
            marker=runtime._read_build_marker(payload),
        )
    )


@pytest.mark.parametrize(
    "identity", [DEVELOPMENT_IDENTITY, ReleaseIdentity("preview", 7)]
)
def test_desktop_marker_round_trips_through_the_runtime_parser(
    tmp_path: Path, identity: ReleaseIdentity
) -> None:
    payload = _desktop_payload(tmp_path, identity)

    written = json.loads((payload / "servonaut-runtime.json").read_text("utf-8"))
    layout = _runtime_from_payload(payload)

    assert written["channel"] == identity.channel
    assert written["packaging_revision"] == identity.packaging_revision
    assert layout.kind is DistributionKind.PACKAGED_DESKTOP
    assert layout.build_revision == "ci-r1"
    assert layout.release_channel == identity.channel
    assert layout.packaging_revision == identity.packaging_revision


class _Response:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.headers: dict[str, str] = {}

    def read(self, size: int = -1) -> bytes:
        data, self._data = self._data, b""
        return data

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _Opener:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def open(self, _request: object, timeout: float | None = None) -> _Response:
        return _Response(self._body)


@pytest.fixture
def linux_x64() -> Iterator[None]:
    with patch("servonaut.distribution.trust.normalize_platform", return_value="linux"), \
         patch("servonaut.distribution.trust.normalize_arch", return_value="x86_64"):
        yield


def _signed_manifest(
    key: Ed25519PrivateKey, *, version: str, revision: int | None
) -> bytes:
    payload = b"desktop package"
    artifact = ReleaseArtifact(
        artifact_id="desktop-ubuntu-deb",
        kind=ArtifactKind.UBUNTU_DEB,
        distribution=DistributionKind.PACKAGED_DESKTOP,
        platform="linux",
        arch="x86_64",
        filename="servonaut-desktop.deb",
        download_url=f"{_RELEASES}/v{version}/servonaut-desktop.deb",
        byte_size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    manifest = ReleaseManifest(
        schema_version=1,
        channel=ReleaseChannel.STABLE,
        product_version=version,
        published_at="2026-09-23T12:00:00Z",
        artifacts=(artifact,),
        signatures=(),
        packaging_revision=revision,
        expires_at="2099-01-01T00:00:00Z",
    )
    signed = sign_manifest(manifest, key, _KEY_ID)
    return json.dumps(signed.to_dict()).encode("utf-8")


def _check(tmp_path: Path, manifest: bytes, key: Ed25519PrivateKey) -> UpdateService:
    service = UpdateService(
        runtime=_runtime_from_payload(_desktop_payload(tmp_path, DEVELOPMENT_IDENTITY)),
        manifest_url=_MANIFEST_URL,
        trust_policy=TrustPolicy(
            trusted_public_keys={_KEY_ID: key.public_key()},
            minimum_signatures=1,
            allowed_origin_prefixes=(f"{_RELEASES}/",),
        ),
        opener=_Opener(manifest),  # type: ignore[arg-type]
    )
    service.check_for_update()
    return service


@pytest.mark.usefixtures("linux_x64")
@pytest.mark.parametrize("manifest_revision", [1, None])
def test_same_version_and_revision_is_not_offered_as_an_update(
    tmp_path: Path, manifest_revision: int | None
) -> None:
    key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(key, version=_VERSION, revision=manifest_revision)

    service = _check(tmp_path, manifest, key)

    assert service.last_check_result is UpdateCheckResult.UP_TO_DATE
    assert service.latest_version is None


@pytest.mark.usefixtures("linux_x64")
@pytest.mark.parametrize(
    ("version", "revision"), [(_VERSION, 2), ("2.27.1", None), ("2.27.1", 1)]
)
def test_a_later_packaging_or_version_is_offered(
    tmp_path: Path, version: str, revision: int | None
) -> None:
    key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(key, version=version, revision=revision)

    service = _check(tmp_path, manifest, key)

    assert service.last_check_result is UpdateCheckResult.UPDATE_AVAILABLE
    assert service.latest_version == version

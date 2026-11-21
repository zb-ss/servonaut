"""Read-only qualification of a previously published, signed macOS release."""

from __future__ import annotations

import hashlib
import os
import platform
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import pytest

from servonaut.distribution.manifest import ArtifactKind, ReleaseChannel, ReleaseManifest, build_version_text
from servonaut.distribution.trust import release_trust_policy, verify_manifest
from servonaut.distribution.trust_root import DEFAULT_MANIFEST_URLS
from servonaut.updates.macos_native import (
    BUNDLE_ID, _require_notarization, _signed_team, copy_bundle, mounted_application,
    native_command, read_info, require_developer_id,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("SERVONAUT_CHECK_PUBLISHED_DMG") != "1",
    reason="Optional hosted macOS check of the public signed release",
)


def _published_dmg():
    architecture = platform.machine()
    for channel in (ReleaseChannel.PREVIEW, ReleaseChannel.STABLE):
        try:
            with urlopen(DEFAULT_MANIFEST_URLS[channel.value], timeout=20) as response:
                manifest = ReleaseManifest.from_json(response.read(1 << 20))
        except HTTPError as exc:
            if exc.code == 404:
                continue
            pytest.skip(f"The public release manifest responded with HTTP {exc.code}.")
        except (URLError, TimeoutError) as exc:
            pytest.skip(f"The public release manifest could not be reached ({type(exc).__name__}).")
        trust = release_trust_policy(channel)
        assert trust is not None
        verify_manifest(manifest, trust)
        for artifact in manifest.artifacts:
            if artifact.kind is ArtifactKind.MACOS_DMG and artifact.arch == architecture:
                return manifest, artifact
    pytest.skip(f"The current signed manifests offer no disk image for {architecture}.")


@pytest.mark.timeout(420)
def test_published_notarized_bundle_can_be_staged(tmp_path: Path) -> None:
    manifest, artifact = _published_dmg()
    root = tmp_path.resolve()
    image = root / "published.dmg"
    digest = hashlib.sha256()
    received = 0
    with urlopen(artifact.download_url, timeout=20) as response, image.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            assert received <= artifact.byte_size
            digest.update(chunk)
            output.write(chunk)
    assert received == artifact.byte_size
    assert digest.hexdigest() == artifact.sha256.lower()

    native_command("/usr/bin/xcrun", "stapler", "validate", image)
    copied = root / "copied.app"
    with mounted_application(image, root / "mount") as source:
        copy_bundle(source, copied, image=image)
    info = read_info(copied)
    assert info["CFBundleShortVersionString"] == build_version_text(manifest.product_version)
    native_command("/usr/bin/codesign", "--verify", "--deep", "--strict", copied)
    require_developer_id(copied, _signed_team(copied), BUNDLE_ID)
    native_command("/usr/bin/xcrun", "stapler", "validate", copied)
    _require_notarization(copied)

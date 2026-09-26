"""Reading the runtime marker back out of finished release artifacts."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.distribution.package_deb import REQUIRED_PAYLOAD_BINARIES, package_deb
from servonaut.distribution.artifact_marker import (
    ArtifactMarkerError,
    identity_mismatches,
    read_artifact_marker,
)
from servonaut.distribution.manifest import ArtifactKind, ReleaseArtifact
from servonaut.runtime import DistributionKind

_MARKER = {
    "schema_version": 1,
    "distribution": "packaged-desktop",
    "product_version": "2.27.0",
    "build_revision": "ci-r1",
    "channel": "stable",
    "packaging_revision": 2,
    "console_helper": "servonaut",
    "desktop_child": "servonaut-desktop-child",
}


def _artifact(path: Path, kind: ArtifactKind) -> ReleaseArtifact:
    distribution = (
        DistributionKind.FROZEN_CLI
        if kind is ArtifactKind.STANDALONE_CLI
        else DistributionKind.PACKAGED_DESKTOP
    )
    data = path.read_bytes() if path.is_file() else b"x"
    return ReleaseArtifact(
        artifact_id="artifact",
        kind=kind,
        distribution=distribution,
        platform="linux",
        arch="x86_64",
        filename=path.name,
        download_url=f"https://example.com/{path.name}",
        byte_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _tar(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def _marker_bytes(**overrides: object) -> bytes:
    return json.dumps({**_MARKER, **overrides}).encode("utf-8")


@pytest.mark.parametrize("name", ["servonaut-runtime.json", "./servonaut-runtime.json"])
def test_standalone_tar_marker_is_read_from_the_archive_root(
    tmp_path: Path, name: str
) -> None:
    path = _tar(
        tmp_path / "servonaut-2.27.0-linux.tar.gz",
        [("servonaut", b"binary"), (name, _marker_bytes())],
    )

    assert read_artifact_marker(_artifact(path, ArtifactKind.STANDALONE_CLI), path) == _MARKER


def test_standalone_zip_marker_is_read_from_the_archive_root(tmp_path: Path) -> None:
    path = tmp_path / "servonaut-2.27.0-windows-x64.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("servonaut.exe", b"binary")
        archive.writestr("servonaut-runtime.json", _marker_bytes())

    assert read_artifact_marker(_artifact(path, ArtifactKind.STANDALONE_CLI), path) == _MARKER


@pytest.mark.parametrize(
    "members",
    [
        [("servonaut", b"binary")],
        [("nested/servonaut-runtime.json", _marker_bytes())],
        [("servonaut-runtime.json", _marker_bytes()), ("servonaut-runtime.json", b"{}")],
        [("servonaut-runtime.json", b"x" * (256 * 1024 + 1))],
        [("servonaut-runtime.json", b"[]")],
        [("servonaut-runtime.json", b"not json")],
    ],
)
def test_standalone_archive_needs_exactly_one_small_marker_object(
    tmp_path: Path, members: list[tuple[str, bytes]]
) -> None:
    path = _tar(tmp_path / "servonaut.tar.gz", members)

    with pytest.raises(ArtifactMarkerError):
        read_artifact_marker(_artifact(path, ArtifactKind.STANDALONE_CLI), path)


def test_marker_link_is_not_followed(tmp_path: Path) -> None:
    path = tmp_path / "servonaut.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("servonaut-runtime.json")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        archive.addfile(info)

    with pytest.raises(ArtifactMarkerError):
        read_artifact_marker(_artifact(path, ArtifactKind.STANDALONE_CLI), path)


def test_debian_package_marker_is_read_from_the_install_prefix(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    for name in REQUIRED_PAYLOAD_BINARIES:
        (payload / name).write_bytes(b"\x7fELFbinary")
        (payload / name).chmod(0o755)
    (payload / "servonaut-runtime.json").write_bytes(_marker_bytes())
    deb, _sha256, _size = package_deb(
        payload_dir=payload,
        output_dir=tmp_path / "out",
        product_version="2.27.0",
        packaging_revision=2,
        maintainer="Package Maintainer <maintainer@example.org>",
    )

    assert read_artifact_marker(_artifact(deb, ArtifactKind.UBUNTU_DEB), deb) == _MARKER


def test_non_debian_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "servonaut.deb"
    path.write_bytes(b"not an ar archive")

    with pytest.raises(ArtifactMarkerError, match="ar archive"):
        read_artifact_marker(_artifact(path, ArtifactKind.UBUNTU_DEB), path)


@pytest.mark.parametrize("kind", [ArtifactKind.MACOS_DMG, ArtifactKind.WINDOWS_MSI])
def test_formats_without_a_reader_fail_closed(tmp_path: Path, kind: ArtifactKind) -> None:
    path = tmp_path / "servonaut.bin"
    path.write_bytes(b"image")

    with pytest.raises(ArtifactMarkerError, match="cannot be read"):
        read_artifact_marker(_artifact(path, kind), path)


def test_identity_mismatches_name_each_disagreeing_field(tmp_path: Path) -> None:
    path = tmp_path / "servonaut.deb"
    path.write_bytes(b"x")
    artifact = _artifact(path, ArtifactKind.UBUNTU_DEB)

    def mismatches(**overrides: object) -> tuple[str, ...]:
        return identity_mismatches(
            {**_MARKER, **overrides},
            artifact=artifact,
            product_version="2.27.0",
            channel="stable",
            packaging_revision=2,
        )

    assert mismatches() == ()
    assert mismatches(channel="preview") == ("channel",)
    assert mismatches(packaging_revision=1) == ("packaging_revision",)
    assert mismatches(packaging_revision="2") == ("packaging_revision",)
    assert mismatches(product_version="2.27.1") == ("product_version",)
    assert mismatches(distribution="frozen-cli") == ("distribution",)

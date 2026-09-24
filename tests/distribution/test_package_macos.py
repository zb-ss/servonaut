"""Contract tests for macOS App Bundle (.app) assembly, DMG creation, and manifest integration."""

from __future__ import annotations

import io
from pathlib import Path
import plistlib
import shutil
import stat
import tarfile
from typing import Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts.distribution.package_macos import (
    REQUIRED_PAYLOAD_FILES,
    MacosPackagingError,
    assemble_app_bundle,
    main,
    package_dmg,
    resolve_epoch,
)
from servonaut.distribution.builder import ManifestBuilder
from servonaut.distribution.manifest import (
    ArtifactKind,
    ReleaseChannel,
)
from servonaut.distribution.trust import TrustPolicy
from servonaut.distribution.verify import verify_release_file
from servonaut.runtime import DistributionKind


@pytest.fixture
def mock_payload(tmp_path: Path) -> Path:
    """Create a minimal valid onedir desktop payload."""
    payload_dir = tmp_path / "mock-payload"
    payload_dir.mkdir(parents=True)

    for binary_name in REQUIRED_PAYLOAD_FILES:
        target = payload_dir / binary_name
        if binary_name.endswith(".json"):
            target.write_text('{"distribution": "packaged-desktop"}', encoding="utf-8")
        else:
            target.write_bytes(b"\xcf\xfa\xed\xfefakemachoexecutable")
            target.chmod(0o755)

    # Subdirectory in _internal
    internal_dir = payload_dir / "_internal" / "lib"
    internal_dir.mkdir(parents=True)
    dylib = internal_dir / "libtest.dylib"
    dylib.write_bytes(b"\xcf\xfa\xed\xfefakedylib")
    dylib.chmod(0o755)

    return payload_dir


class TestAssembleAppBundle:
    """Tests covering assembly of Servonaut.app directory structure."""

    def test_assemble_app_bundle_structure_and_plist(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            packaging_revision=1,
            bundle_name="Servonaut.app",
        )

        assert app_path.is_dir()
        contents_dir = app_path / "Contents"
        assert contents_dir.is_dir()

        # PkgInfo check
        pkg_info = contents_dir / "PkgInfo"
        assert pkg_info.is_file()
        assert pkg_info.read_bytes() == b"APPL????"

        # Info.plist check
        plist_file = contents_dir / "Info.plist"
        assert plist_file.is_file()
        with open(plist_file, "rb") as fp:
            plist_data = plistlib.load(fp)

        assert plist_data["CFBundlePackageType"] == "APPL"
        assert plist_data["CFBundleName"] == "Servonaut"
        assert plist_data["CFBundleDisplayName"] == "Servonaut"
        assert plist_data["CFBundleIdentifier"] == "dev.servonaut.desktop"
        assert plist_data["CFBundleVersion"] == "2.26.3.1"
        assert plist_data["CFBundleShortVersionString"] == "2.26.3"
        assert plist_data["CFBundleExecutable"] == "servonaut-desktop"
        assert plist_data["CFBundleIconFile"] == "AppIcon"
        assert plist_data["LSMinimumSystemVersion"] == "13.0"
        assert plist_data["NSHighResolutionCapable"] is True
        assert "NSMicrophoneUsageDescription" in plist_data

        # Binaries inside Contents/MacOS/
        macos_dir = contents_dir / "MacOS"
        assert (macos_dir / "servonaut-desktop").is_file()
        assert (macos_dir / "servonaut-desktop-child").is_file()
        assert (macos_dir / "servonaut").is_file()
        assert (macos_dir / "servonaut-runtime.json").is_file()
        assert (macos_dir / "_internal" / "lib" / "libtest.dylib").is_file()

        # Modes
        assert bool(
            (macos_dir / "servonaut-desktop").stat().st_mode
            & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        )
        assert bool(
            (macos_dir / "servonaut").stat().st_mode
            & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        )
        assert not bool(
            (macos_dir / "servonaut-runtime.json").stat().st_mode
            & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        )

        # Resources / AppIcon.icns
        assert (contents_dir / "Resources" / "AppIcon.icns").is_file()

    def test_missing_required_payload_binary_raises(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        (mock_payload / "servonaut-desktop").unlink()
        out_dir = tmp_path / "out"

        with pytest.raises(FileNotFoundError, match="servonaut-desktop"):
            assemble_app_bundle(
                payload_dir=mock_payload,
                output_dir=out_dir,
                product_version="2.26.3",
            )


class TestPackageDmg:
    """Tests covering drag-to-Applications DMG disk image packaging."""

    def test_package_dmg_intel_and_arm64(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            packaging_revision=1,
        )

        # 1. Package Intel (macos-x64)
        dmg_intel, hash_intel, size_intel = package_dmg(
            app_bundle_path=app_path,
            output_dir=out_dir,
            product_version="2.26.3",
            target_arch="macos-x64",
            packaging_revision=1,
            source_epoch=1700000000,
        )
        assert dmg_intel.is_file()
        assert dmg_intel.name == "servonaut-desktop-2.26.3-macos-x64.dmg"
        assert len(hash_intel) == 64
        assert size_intel == dmg_intel.stat().st_size
        assert size_intel > 512

        # Verify UDIF koly trailer
        raw_intel = dmg_intel.read_bytes()
        assert b"koly" in raw_intel[-512:]

        # 2. Package Apple Silicon (macos-arm64)
        dmg_arm64, hash_arm64, size_arm64 = package_dmg(
            app_bundle_path=app_path,
            output_dir=out_dir,
            product_version="2.26.3",
            target_arch="macos-arm64",
            packaging_revision=1,
            source_epoch=1700000000,
        )
        assert dmg_arm64.is_file()
        assert dmg_arm64.name == "servonaut-desktop-2.26.3-macos-arm64.dmg"
        assert len(hash_arm64) == 64
        assert size_arm64 == dmg_arm64.stat().st_size

    def test_custom_filename_is_respected(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
        )
        dmg_path, _, _ = package_dmg(
            app_bundle_path=app_path,
            output_dir=out_dir,
            product_version="2.26.3",
            target_arch="x86_64",
            filename="Servonaut-Custom.dmg",
        )
        assert dmg_path.name == "Servonaut-Custom.dmg"

    def test_unsupported_target_arch_raises(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
        )
        with pytest.raises(MacosPackagingError, match="Unsupported macOS target architecture"):
            package_dmg(
                app_bundle_path=app_path,
                output_dir=out_dir,
                product_version="2.26.3",
                target_arch="linux-x64",
            )


class TestManifestIntegration:
    """Tests integrating macOS DMG artifacts with ManifestBuilder and verify_release_file."""

    def test_manifest_builder_with_macos_dmg(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            packaging_revision=1,
        )
        dmg_path, sha256_hex, byte_size = package_dmg(
            app_bundle_path=app_path,
            output_dir=out_dir,
            product_version="2.26.3",
            target_arch="macos-arm64",
            packaging_revision=1,
        )

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id = "test-macos-key"

        builder = ManifestBuilder(
            product_version="2.26.3",
            channel=ReleaseChannel.STABLE,
            packaging_revision=1,
            expires_at="2099-01-01T00:00:00Z",
        )
        builder.add_artifact_file(
            dmg_path,
            kind=ArtifactKind.MACOS_DMG,
            distribution=DistributionKind.PACKAGED_DESKTOP,
            platform="darwin",
            arch="arm64",
            download_url=f"https://github.com/zb-ss/servonaut/releases/download/v2.26.3/{dmg_path.name}",
            min_os="13.0",
            artifact_id="desktop-macos-arm64",
        )
        builder.sign_artifact("desktop-macos-arm64", private_key)

        manifest = builder.build_signed(private_key, key_id=key_id)
        assert len(manifest.artifacts) == 1
        art = manifest.artifacts[0]
        assert art.kind == ArtifactKind.MACOS_DMG
        assert art.distribution == DistributionKind.PACKAGED_DESKTOP
        assert art.platform == "darwin"
        assert art.arch == "arm64"
        assert art.min_os == "13.0"
        assert art.sha256 == sha256_hex
        assert art.byte_size == byte_size
        assert art.signature is not None

        policy = TrustPolicy(
            trusted_public_keys={key_id: public_key},
            allowed_origin_prefixes=("https://github.com/zb-ss/servonaut/releases/download/",),
        )

        valid, msg = verify_release_file(manifest, dmg_path, trust_policy=policy)
        assert valid is True
        assert "successfully verified" in msg


class TestCLIExecution:
    """Tests executing package_macos CLI entry point."""

    def test_cli_package_macos_success(
        self, mock_payload: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_dir = tmp_path / "out"
        ret = main([
            "--payload-dir",
            str(mock_payload),
            "--output-dir",
            str(out_dir),
            "--version",
            "2.26.3",
            "--arch",
            "macos-arm64",
            "--revision",
            "1",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "macOS DMG created:" in captured.out
        assert "SHA-256:" in captured.out

    def test_cli_package_macos_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main([
            "--payload-dir",
            str(tmp_path / "nonexistent"),
            "--output-dir",
            str(tmp_path / "out"),
            "--version",
            "2.26.3",
            "--arch",
            "macos-arm64",
        ])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err

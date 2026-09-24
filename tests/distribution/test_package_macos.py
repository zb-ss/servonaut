"""Contract tests for macOS App Bundle (.app) assembly, DMG creation, and manifest integration."""

from __future__ import annotations

import io
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import tarfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts.distribution import package_macos
from scripts.distribution.package_macos import (
    REQUIRED_PAYLOAD_FILES,
    MacosPackagingError,
    assemble_app_bundle,
    main,
    package_dmg,
)
from scripts.distribution.payload_tree import PayloadTreeError
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
            dry_run=True,
        )
        assert dmg_intel.is_file()
        assert dmg_intel.name == "servonaut-desktop-2.26.3-macos-x64.dmg.simulated"
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
            dry_run=True,
        )
        assert dmg_arm64.is_file()
        assert dmg_arm64.name == "servonaut-desktop-2.26.3-macos-arm64.dmg.simulated"
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
            dry_run=True,
        )
        assert dmg_path.name == "Servonaut-Custom.dmg.simulated"

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
            dry_run=True,
        )

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id = "test-macos-key"

        builder = ManifestBuilder(
            product_version="2.26.3",
            channel=ReleaseChannel.STABLE,
            packaging_revision=1,
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
            "--dry-run",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Simulated macOS DMG placeholder written:" in captured.out
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


def _add_payload_links(payload_dir: Path) -> None:
    os.symlink("lib/libtest.dylib", payload_dir / "_internal" / "libtest.dylib")
    os.symlink("lib", payload_dir / "_internal" / "lib-current")


def _simulated_image_members(image_path: Path) -> dict[str, tarfile.TarInfo]:
    raw = image_path.read_bytes()
    with tarfile.open(fileobj=io.BytesIO(raw[:-512]), mode="r") as tar:
        return {member.name: member for member in tar.getmembers()}


class TestPayloadLinks:
    """Payload symbolic links survive app assembly and the simulated image."""

    def test_assemble_keeps_symlinks_as_links(self, mock_payload: Path, tmp_path: Path) -> None:
        _add_payload_links(mock_payload)

        app_path = assemble_app_bundle(
            payload_dir=mock_payload,
            output_dir=tmp_path / "out",
            product_version="2.26.3",
        )

        internal = app_path / "Contents" / "MacOS" / "_internal"
        assert (internal / "libtest.dylib").is_symlink()
        assert os.readlink(internal / "libtest.dylib") == "lib/libtest.dylib"
        assert (internal / "lib-current").is_symlink()
        assert os.readlink(internal / "lib-current") == "lib"

    def test_assemble_rejects_link_leaving_the_payload(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        os.symlink("/etc/hostname", mock_payload / "_internal" / "escape")

        with pytest.raises(PayloadTreeError, match="Unsafe symbolic link"):
            assemble_app_bundle(
                payload_dir=mock_payload,
                output_dir=tmp_path / "out",
                product_version="2.26.3",
            )

    def test_simulated_image_keeps_directory_links(self, mock_payload: Path, tmp_path: Path) -> None:
        _add_payload_links(mock_payload)
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload, output_dir=out_dir, product_version="2.26.3"
        )

        image_path, _, _ = package_dmg(
            app_bundle_path=app_path,
            output_dir=out_dir,
            product_version="2.26.3",
            target_arch="macos-arm64",
            dry_run=True,
        )

        members = _simulated_image_members(image_path)
        link = members["Servonaut.app/Contents/MacOS/_internal/lib-current"]
        assert link.issym() and link.linkname == "lib"
        assert members["Applications"].issym()
        assert members["Applications"].linkname == "/Applications"


class TestDmgToolRequirements:
    """A real disk image needs hdiutil; placeholders exist only in dry-run mode."""

    @pytest.fixture
    def app_path(self, mock_payload: Path, tmp_path: Path) -> Path:
        return assemble_app_bundle(
            payload_dir=mock_payload, output_dir=tmp_path / "out", product_version="2.26.3"
        )

    def test_missing_hdiutil_raises_instead_of_writing_a_placeholder(
        self, app_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(package_macos.shutil, "which", lambda name: None)
        out_dir = tmp_path / "dmg"

        with pytest.raises(MacosPackagingError, match="hdiutil"):
            package_dmg(
                app_bundle_path=app_path,
                output_dir=out_dir,
                product_version="2.26.3",
                target_arch="macos-arm64",
            )
        assert list(out_dir.iterdir()) == []

    def test_dry_run_never_invokes_hdiutil(
        self, app_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(package_macos.shutil, "which", lambda name: f"/usr/bin/{name}")

        def fail_run(*args: object, **kwargs: object) -> None:
            raise AssertionError("dry run must not run a disk image tool")

        monkeypatch.setattr(package_macos.subprocess, "run", fail_run)
        out_dir = tmp_path / "dmg"

        image_path, _, _ = package_dmg(
            app_bundle_path=app_path,
            output_dir=out_dir,
            product_version="2.26.3",
            target_arch="macos-arm64",
            dry_run=True,
        )

        assert image_path.name == "servonaut-desktop-2.26.3-macos-arm64.dmg.simulated"
        assert [p.name for p in out_dir.iterdir()] == [image_path.name]

    def test_hdiutil_builds_the_release_image(
        self, app_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(package_macos.shutil, "which", lambda name: f"/usr/bin/{name}")
        commands: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            commands.append(cmd)
            Path(cmd[-1]).write_bytes(b"udif image")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(package_macos.subprocess, "run", fake_run)

        dmg_path, _, byte_size = package_dmg(
            app_bundle_path=app_path,
            output_dir=tmp_path / "dmg",
            product_version="2.26.3",
            target_arch="macos-arm64",
        )

        assert dmg_path.name == "servonaut-desktop-2.26.3-macos-arm64.dmg"
        assert byte_size == len(b"udif image")
        assert commands[0][:2] == ["/usr/bin/hdiutil", "create"]


class TestPackageExistingApp:
    """The CLI can package an existing, already signed .app without rebuilding it."""

    def test_cli_packages_existing_app_bundle_untouched(
        self, mock_payload: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload, output_dir=out_dir, product_version="2.26.3"
        )
        signature = app_path / "Contents" / "_CodeSignature" / "CodeResources"
        signature.parent.mkdir()
        signature.write_bytes(b"signed")

        ret = main([
            "--app-bundle",
            str(app_path),
            "--output-dir",
            str(out_dir),
            "--version",
            "2.26.3",
            "--arch",
            "macos-arm64",
            "--dry-run",
        ])

        assert ret == 0
        assert signature.read_bytes() == b"signed"
        image = out_dir / "servonaut-desktop-2.26.3-macos-arm64.dmg.simulated"
        assert "Servonaut.app/Contents/_CodeSignature/CodeResources" in _simulated_image_members(image)

    def test_cli_rejects_payload_dir_and_app_bundle_together(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main([
                "--payload-dir",
                str(mock_payload),
                "--app-bundle",
                str(tmp_path / "Servonaut.app"),
                "--output-dir",
                str(tmp_path / "out"),
                "--version",
                "2.26.3",
                "--arch",
                "macos-arm64",
            ])
        assert excinfo.value.code == 2

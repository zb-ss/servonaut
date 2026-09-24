"""Tests for Windows x64 MSI and WiX packaging, component harvesting, and manifest integration."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts.distribution.package_windows import (
    BUNDLE_UPGRADE_CODE,
    PRODUCT_UPGRADE_CODE,
    REQUIRED_PAYLOAD_FILES,
    WindowsPackagingError,
    deterministic_guid,
    format_msi_version,
    generate_wix_sources,
    main,
    package_windows,
)

from servonaut.distribution.builder import ManifestBuilder
from servonaut.distribution.manifest import ArtifactKind, ReleaseChannel
from servonaut.distribution.trust import TrustPolicy, resolve_target_artifact, verify_manifest
from servonaut.distribution.verify import verify_release_file

from servonaut.runtime import DistributionKind


@pytest.fixture
def mock_windows_payload(tmp_path: Path) -> Path:
    """Create a minimal valid Windows desktop onedir payload."""
    payload_dir = tmp_path / "mock-windows-payload"
    payload_dir.mkdir(parents=True)

    for binary_name in REQUIRED_PAYLOAD_FILES:
        target = payload_dir / binary_name
        if binary_name.endswith(".json"):
            target.write_text('{"distribution": "packaged-desktop"}', encoding="utf-8")
        else:
            target.write_bytes(b"MZfakepeexecutable")

    # Subdirectories with DLLs and assets
    internal_dir = payload_dir / "_internal" / "lib"
    internal_dir.mkdir(parents=True)
    (internal_dir / "sqlite3.dll").write_bytes(b"MZfakedll")
    (internal_dir / "_socket.pyd").write_bytes(b"MZfakepyd")

    assets_dir = payload_dir / "frontend"
    assets_dir.mkdir(parents=True)
    (assets_dir / "index.html").write_text("<html>Servonaut</html>", encoding="utf-8")

    return payload_dir


class TestGuidAndVersionFormatting:
    """Test deterministic GUID derivation and MSI version formatting."""

    def test_deterministic_guid_reproducibility(self) -> None:
        guid1 = deterministic_guid("lib/sqlite3.dll")
        guid2 = deterministic_guid("lib\\sqlite3.dll")
        guid3 = deterministic_guid("lib/SQLITE3.DLL")
        guid_diff = deterministic_guid("lib/other.dll")

        assert guid1 == guid2 == guid3
        assert len(guid1) == 36
        assert guid1 != guid_diff

    def test_format_msi_version_valid(self) -> None:
        assert format_msi_version("0.2.0") == "0.2.0"
        assert format_msi_version("1.26.4", 2) == "1.26.4.2"
        assert format_msi_version("2.0.0-rc1") == "2.0.0"

    def test_format_msi_version_out_of_bounds(self) -> None:
        with pytest.raises(WindowsPackagingError, match="exceeds MSI integer limits"):
            format_msi_version("256.0.0")

        with pytest.raises(WindowsPackagingError, match="exceeds MSI integer limits"):
            format_msi_version("1.0.70000")

    def test_format_msi_version_invalid_semver(self) -> None:
        with pytest.raises(WindowsPackagingError, match="not valid Semantic Versioning"):
            format_msi_version("invalid-ver")


class TestPayloadValidation:
    """Test validation of required Windows payload files."""

    def test_missing_payload_file_raises(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty-payload"
        empty_dir.mkdir()

        with pytest.raises(WindowsPackagingError, match="Required Windows payload file"):
            package_windows(
                payload_dir=empty_dir,
                output_dir=tmp_path / "out",
                product_version="0.2.0",
            )

    def test_missing_payload_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            package_windows(
                payload_dir=tmp_path / "nonexistent",
                output_dir=tmp_path / "out",
                product_version="0.2.0",
            )


class TestWiXSourceGeneration:
    """Test generation of valid WiX product and bundle source XML files."""

    def test_product_wxs_structure_and_components(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        wix_dir = tmp_path / "wix_out"
        product_wxs, bundle_wxs, comp_count = generate_wix_sources(
            payload_dir=mock_windows_payload,
            output_wix_dir=wix_dir,
            product_version="0.2.0",
            packaging_revision=1,
            install_scope="perMachine",
        )

        assert product_wxs.is_file()
        assert bundle_wxs.is_file()

        # Parse product XML
        tree = ET.parse(product_wxs)
        root = tree.getroot()
        assert root.tag.endswith("Wix")

        ns = {"wix": "http://schemas.microsoft.com/wix/2006/wi"}

        # Product element
        product = root.find("wix:Product", ns)
        assert product is not None
        assert product.attrib["Version"] == "0.2.0.1"
        assert product.attrib["UpgradeCode"] == PRODUCT_UPGRADE_CODE


        # Downgrade error element
        major_upgrade = product.find("wix:MajorUpgrade", ns)
        assert major_upgrade is not None
        assert "DowngradeErrorMessage" in major_upgrade.attrib

        # WebView2 registry searches
        props = {p.attrib["Id"]: p for p in product.findall("wix:Property", ns)}
        assert "WV2_REG_MACHINE" in props
        assert "WV2_REG_WOW6432" in props
        assert "WV2_REG_USER" in props

        # Start menu shortcut and AppUserModelID
        shortcut_found = False
        app_user_model_found = False
        for shortcut in root.findall(".//wix:Shortcut", ns):
            if shortcut.attrib.get("Id") == "ApplicationStartMenuShortcut":
                shortcut_found = True
                for prop in shortcut.findall("wix:ShortcutProperty", ns):
                    if prop.attrib.get("Key") == "System.AppUserModel.ID" and prop.attrib.get("Value") == "dev.servonaut.desktop":
                        app_user_model_found = True
        assert shortcut_found
        assert app_user_model_found

        # Environment PATH component
        env_found = False
        for env in root.findall(".//wix:Environment", ns):
            if env.attrib.get("Name") == "PATH" and env.attrib.get("Value") == "[INSTALLFOLDER]":
                env_found = True
                assert env.attrib.get("System") == "yes"
        assert env_found

        # User data safety: verify NO RemoveFile or RemoveFolder points to ~/.servonaut
        xml_text = product_wxs.read_text(encoding="utf-8")
        assert ".servonaut" not in [f.attrib.get("Name") for f in root.findall(".//wix:RemoveFolder", ns)]
        assert ".servonaut" not in [f.attrib.get("Name") for f in root.findall(".//wix:RemoveFile", ns)]

        # Verify harvested files exist in components
        files_in_wxs = [f.attrib.get("Name") for f in root.findall(".//wix:File", ns)]
        assert "servonaut-desktop.exe" in files_in_wxs
        assert "servonaut-desktop-child.exe" in files_in_wxs
        assert "servonaut.exe" in files_in_wxs
        assert "servonaut-runtime.json" in files_in_wxs
        assert "sqlite3.dll" in files_in_wxs
        assert "_socket.pyd" in files_in_wxs
        assert "index.html" in files_in_wxs

    def test_per_user_scope_configuration(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        wix_dir = tmp_path / "wix_user"
        product_wxs, _, _ = generate_wix_sources(
            payload_dir=mock_windows_payload,
            output_wix_dir=wix_dir,
            product_version="0.2.0",
            install_scope="perUser",
        )

        tree = ET.parse(product_wxs)
        root = tree.getroot()
        ns = {"wix": "http://schemas.microsoft.com/wix/2006/wi"}

        pkg = root.find(".//wix:Package", ns)
        assert pkg is not None
        assert pkg.attrib["InstallScope"] == "perUser"

        # User PATH environment
        for env in root.findall(".//wix:Environment", ns):
            if env.attrib.get("Name") == "PATH":
                assert env.attrib.get("System") == "no"

    def test_bundle_wxs_chains_webview2_and_msi(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        wix_dir = tmp_path / "wix_bundle"
        _, bundle_wxs, _ = generate_wix_sources(
            payload_dir=mock_windows_payload,
            output_wix_dir=wix_dir,
            product_version="0.2.0",
        )

        tree = ET.parse(bundle_wxs)
        root = tree.getroot()
        ns = {"wix": "http://schemas.microsoft.com/wix/2006/wi"}

        bundle = root.find("wix:Bundle", ns)
        assert bundle is not None
        assert bundle.attrib["UpgradeCode"] == BUNDLE_UPGRADE_CODE


        # Check chain packages
        exe_pkg = root.find(".//wix:ExePackage", ns)
        assert exe_pkg is not None
        assert exe_pkg.attrib["Id"] == "WebView2Runtime"
        assert "go.microsoft.com" in exe_pkg.attrib["DownloadUrl"]

        msi_pkg = root.find(".//wix:MsiPackage", ns)
        assert msi_pkg is not None
        assert msi_pkg.attrib["Id"] == "ServonautMsi"


class TestPackageWindowsEndToEnd:
    """Test full package_windows workflow and manifest builder integration."""

    def test_package_windows_outputs_valid_artifacts(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        out_dir = tmp_path / "dist"
        result = package_windows(
            payload_dir=mock_windows_payload,
            output_dir=out_dir,
            product_version="0.2.0",
            packaging_revision=1,
            dry_run=True,
        )

        assert result.msi_path.is_file()
        assert result.product_wxs_path.is_file()
        assert result.bundle_wxs_path.is_file()
        assert result.version == "0.2.0"
        assert result.packaging_revision == 1
        assert len(result.sha256) == 64
        assert result.byte_size > 0

    def test_manifest_builder_with_windows_msi(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        out_dir = tmp_path / "dist"
        result = package_windows(
            payload_dir=mock_windows_payload,
            output_dir=out_dir,
            product_version="0.2.0",
            packaging_revision=1,
            dry_run=True,
        )

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        builder = ManifestBuilder(
            product_version="0.2.0",
            channel=ReleaseChannel.STABLE,
            packaging_revision=1,
            expires_at="2099-01-01T00:00:00Z",
        )

        artifact = builder.add_artifact_file(
            result.msi_path,
            kind=ArtifactKind.WINDOWS_MSI,
            distribution=DistributionKind.PACKAGED_DESKTOP,
            platform="windows",
            arch="x86_64",
            download_url=f"https://github.com/zb-ss/servonaut/releases/download/v0.2.0/{result.msi_path.name}",
            min_os="10.0.19041",
            artifact_id="desktop-windows-x64",
        )
        builder.sign_artifact("desktop-windows-x64", private_key)
        manifest = builder.build_signed(private_key, key_id="key-windows-test")

        # Verify trust policy
        policy = TrustPolicy(
            trusted_public_keys={"key-windows-test": public_key},
            allowed_origin_prefixes=("https://github.com/zb-ss/servonaut/releases/download/",),
        )

        verify_manifest(manifest, policy)
        assert len(manifest.artifacts) == 1

        resolved_artifact = resolve_target_artifact(
            manifest,
            DistributionKind.PACKAGED_DESKTOP,
            platform_name="windows",
            machine_arch="x86_64",
        )
        assert resolved_artifact is not None
        assert resolved_artifact.kind == ArtifactKind.WINDOWS_MSI
        assert resolved_artifact.sha256 == result.sha256

        # Verify disk file against signed manifest
        valid, msg = verify_release_file(manifest, result.msi_path, trust_policy=policy)
        assert valid is True
        assert "successfully verified" in msg




class TestCLIExecution:
    """Test CLI execution of package_windows."""

    def test_cli_success(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        out_dir = tmp_path / "cli_out"
        rc = main(
            [
                "--payload-dir",
                str(mock_windows_payload),
                "--output-dir",
                str(out_dir),
                "--version",
                "0.2.0",
                "--revision",
                "2",
                "--dry-run",
            ]
        )
        assert rc == 0
        assert (out_dir / "servonaut-0.2.0-windows-x64.msi").is_file()

    def test_cli_failure_on_missing_dir(self, tmp_path: Path) -> None:
        rc = main(
            [
                "--payload-dir",
                str(tmp_path / "does-not-exist"),
                "--output-dir",
                str(tmp_path / "cli_out"),
                "--version",
                "0.2.0",
            ]
        )
        assert rc == 1

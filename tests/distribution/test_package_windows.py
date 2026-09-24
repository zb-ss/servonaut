"""Tests for Windows x64 MSI and WiX packaging, component harvesting, and manifest integration."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts.distribution import package_windows as package_windows_module
from scripts.distribution.package_windows import (
    BUNDLE_UPGRADE_CODE,
    PRODUCT_UPGRADE_CODE,
    REQUIRED_PAYLOAD_FILES,
    WindowsPackagingError,
    _validate_wix_ids,
    deterministic_guid,
    format_msi_version,
    generate_wix_sources,
    main,
    package_windows,
)
from scripts.distribution.payload_tree import PayloadTreeError
from scripts.distribution.webview2_detect import (
    MINIMUM_WEBVIEW2_VERSION,
    WEBVIEW2_BOOTSTRAPPER_URL,
    WEBVIEW2_CLIENT_GUID,
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
        assert (out_dir / "servonaut-0.2.0-windows-x64.msi.simulated").is_file()
        assert not (out_dir / "servonaut-0.2.0-windows-x64.msi").exists()

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


_WIX_NS = {"wix": "http://schemas.microsoft.com/wix/2006/wi"}
# Long service names so every nested path overflows a plain truncated identifier.
_LONG_SERVICE_NAMES = (
    "bedrock-agent-runtime-evaluation-jobs-service-alpha",
    "bedrock-agent-runtime-evaluation-jobs-service-bravo",
    "bedrock-agent-runtime-evaluation-jobs-service-charlie",
)
_SERVICE_FILES = (
    "endpoint-rule-set-1.json.gz",
    "paginators-1.json",
    "service-2.json.gz",
    "service-2.sdk-extras.json",
    "waiters-2.json",
)


def _harvested_ids(product_wxs: Path) -> list[str]:
    root = ET.parse(product_wxs).getroot()
    return [
        element.attrib["Id"]
        for tag in ("Directory", "Component", "File")
        for element in root.iter(f"{{{_WIX_NS['wix']}}}{tag}")
    ]


class TestWixIdentifiers:
    """Harvested identifiers are unique, within the MSI column limit and XML-safe."""

    def test_long_nested_payload_paths_get_unique_short_ids(
        self, mock_windows_payload: Path, tmp_path: Path
    ) -> None:
        data_dir = mock_windows_payload / "_internal" / "botocore" / "data"
        for service in _LONG_SERVICE_NAMES:
            version_dir = data_dir / service / "2016-11-15"
            version_dir.mkdir(parents=True)
            for name in _SERVICE_FILES:
                (version_dir / name).write_bytes(b"{}")

        product_wxs, _, component_count = generate_wix_sources(
            payload_dir=mock_windows_payload,
            output_wix_dir=tmp_path / "wix",
            product_version="0.2.0",
        )

        ids = _harvested_ids(product_wxs)
        assert len(ids) == len(set(ids))
        assert max(len(identifier) for identifier in ids) <= 72
        assert all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", identifier) for identifier in ids)
        payload_files = [p for p in mock_windows_payload.rglob("*") if p.is_file()]
        assert component_count == len(payload_files) + 2

    def test_ids_are_stable_across_builds(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        first, _, _ = generate_wix_sources(mock_windows_payload, tmp_path / "a", "0.2.0")
        second, _, _ = generate_wix_sources(mock_windows_payload, tmp_path / "b", "0.2.0")

        assert _harvested_ids(first) == _harvested_ids(second)

    def test_names_with_xml_metacharacters_are_escaped(
        self, mock_windows_payload: Path, tmp_path: Path
    ) -> None:
        odd_dir = mock_windows_payload / "Tom & Jerry's"
        odd_dir.mkdir()
        (odd_dir / "R&D <draft>.txt").write_text("notes", encoding="utf-8")

        product_wxs, _, _ = generate_wix_sources(
            payload_dir=mock_windows_payload,
            output_wix_dir=tmp_path / "wix",
            product_version="0.2.0",
        )

        root = ET.parse(product_wxs).getroot()
        directory_names = {d.attrib.get("Name") for d in root.iter(f"{{{_WIX_NS['wix']}}}Directory")}
        files = {f.attrib["Name"]: f.attrib["Source"] for f in root.iter(f"{{{_WIX_NS['wix']}}}File")}
        assert "Tom & Jerry's" in directory_names
        assert Path(files["R&D <draft>.txt"]) == (odd_dir / "R&D <draft>.txt").resolve()

    def test_duplicate_or_oversized_ids_are_rejected(self) -> None:
        duplicate = ET.fromstring(
            '<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi"><Product>'
            '<Component Id="C_same" /><Component Id="C_same" /></Product></Wix>'
        )
        oversized = ET.fromstring(
            '<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi"><Product>'
            f'<Directory Id="Dir_{"x" * 70}" /></Product></Wix>'
        )

        with pytest.raises(WindowsPackagingError, match="Duplicate WiX identifiers"):
            _validate_wix_ids(duplicate)
        with pytest.raises(WindowsPackagingError, match="72 characters"):
            _validate_wix_ids(oversized)

    def test_symlinks_are_rejected(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        os.symlink("servonaut.exe", mock_windows_payload / "alias.exe")

        with pytest.raises(PayloadTreeError, match="symbolic link"):
            generate_wix_sources(mock_windows_payload, tmp_path / "wix", "0.2.0")


class TestUpgradeAndPrerequisites:
    """MSI upgrade rules, repair support and the WebView2 prerequisite."""

    @pytest.fixture
    def product(self, mock_windows_payload: Path, tmp_path: Path) -> ET.Element:
        product_wxs, _, _ = generate_wix_sources(
            mock_windows_payload, tmp_path / "wix", "0.2.0", packaging_revision=3
        )
        product = ET.parse(product_wxs).getroot().find("wix:Product", _WIX_NS)
        assert product is not None
        return product

    def test_same_version_rebuilds_upgrade_in_place(self, product: ET.Element) -> None:
        major_upgrade = product.find("wix:MajorUpgrade", _WIX_NS)
        assert major_upgrade is not None
        assert major_upgrade.attrib["AllowSameVersionUpgrades"] == "yes"

    def test_repair_is_not_disabled(self, product: ET.Element) -> None:
        property_ids = {p.attrib["Id"] for p in product.findall("wix:Property", _WIX_NS)}
        assert "ARPNOREPAIR" not in property_ids

    def test_launch_condition_requires_webview2(self, product: ET.Element) -> None:
        conditions = product.findall("wix:Condition", _WIX_NS)
        assert len(conditions) == 1
        condition = conditions[0]
        expression = " ".join((condition.text or "").split())
        searched = [
            p.attrib["Id"]
            for p in product.findall("wix:Property", _WIX_NS)
            if p.find("wix:RegistrySearch", _WIX_NS) is not None
        ]

        assert expression.startswith("Installed OR ")
        assert searched == ["WV2_REG_WOW6432", "WV2_REG_MACHINE", "WV2_REG_USER"]
        for property_id in searched:
            assert f'({property_id} AND {property_id} <> "0.0.0.0")' in expression
        assert "WebView2" in condition.attrib["Message"]
        assert WEBVIEW2_BOOTSTRAPPER_URL in condition.attrib["Message"]

    def test_registry_searches_use_the_webview2_client_guid(self, product: ET.Element) -> None:
        keys = [search.attrib["Key"] for search in product.iter(f"{{{_WIX_NS['wix']}}}RegistrySearch")]

        # Pinned: the Evergreen Runtime client id Microsoft documents for detection.
        assert WEBVIEW2_CLIENT_GUID == "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"  # leak-guard:allow
        assert len(keys) == 3
        assert all(key.endswith(f"\\Clients\\{WEBVIEW2_CLIENT_GUID}") for key in keys)

    def test_bundle_detect_condition_compares_versions(
        self, mock_windows_payload: Path, tmp_path: Path
    ) -> None:
        _, bundle_wxs, _ = generate_wix_sources(mock_windows_payload, tmp_path / "wix", "0.2.0")
        exe_package = ET.parse(bundle_wxs).getroot().find(".//wix:ExePackage", _WIX_NS)
        assert exe_package is not None

        detect = exe_package.attrib["DetectCondition"]
        comparisons = re.findall(r"(\w+) >= (\S+)", detect)
        assert [variable for variable, _ in comparisons] == [
            "WebView2VersionMachine64",
            "WebView2VersionMachine32",
            "WebView2VersionUser",
        ]
        assert {literal for _, literal in comparisons} == {f"v{MINIMUM_WEBVIEW2_VERSION}"}
        assert exe_package.attrib["DownloadUrl"] == WEBVIEW2_BOOTSTRAPPER_URL


class TestWixToolRequirements:
    """A release MSI needs WiX; placeholders exist only in dry-run mode."""

    def test_missing_wix_raises_instead_of_writing_a_placeholder(
        self, mock_windows_payload: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(package_windows_module.shutil, "which", lambda name: None)
        out_dir = tmp_path / "dist"

        with pytest.raises(WindowsPackagingError, match="WiX Toolset"):
            package_windows(mock_windows_payload, out_dir, "0.2.0")
        assert not list(out_dir.glob("*.msi*"))

    def test_wrong_wix_bin_dir_raises(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        with pytest.raises(WindowsPackagingError, match="WiX Toolset"):
            package_windows(
                mock_windows_payload, tmp_path / "dist", "0.2.0", wix_bin_dir=tmp_path / "typo"
            )
        assert not list((tmp_path / "dist").glob("*.msi*"))

    def test_dry_run_writes_only_a_simulated_placeholder(
        self, mock_windows_payload: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(package_windows_module.shutil, "which", lambda name: f"C:/wix/{name}")

        def fail_run(*args: object, **kwargs: object) -> None:
            raise AssertionError("dry run must not run WiX")

        monkeypatch.setattr(package_windows_module.subprocess, "run", fail_run)
        out_dir = tmp_path / "dist"

        result = package_windows(mock_windows_payload, out_dir, "0.2.0", dry_run=True)

        assert result.msi_path.name == "servonaut-0.2.0-windows-x64.msi.simulated"
        assert [p.name for p in out_dir.glob("*.msi*")] == [result.msi_path.name]

    def test_wix_tools_build_the_release_msi(
        self, mock_windows_payload: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(package_windows_module.shutil, "which", lambda name: f"C:/wix/{name}")
        commands: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            commands.append(cmd)
            Path(cmd[cmd.index("-out") + 1]).write_bytes(b"msi")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(package_windows_module.subprocess, "run", fake_run)

        result = package_windows(mock_windows_payload, tmp_path / "dist", "0.2.0")

        assert result.msi_path.name == "servonaut-0.2.0-windows-x64.msi"
        assert [Path(cmd[0]).name for cmd in commands] == ["candle.exe", "light.exe"]

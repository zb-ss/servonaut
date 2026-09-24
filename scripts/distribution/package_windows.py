"""Deterministic Windows x64 MSI and WiX Bootstrapper packaging for Servonaut Desktop."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Optional
import uuid
from xml.sax.saxutils import escape, quoteattr
import xml.etree.ElementTree as ET

from scripts.distribution.payload_tree import walk_payload
from scripts.distribution.webview2_detect import (
    MINIMUM_WEBVIEW2_VERSION,
    WEBVIEW2_BOOTSTRAPPER_URL,
    WEBVIEW2_CLIENT_GUID,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WINDOWS_TEMPLATE_DIR = _REPO_ROOT / "packaging" / "windows"
_DEFAULT_ICON = _WINDOWS_TEMPLATE_DIR / "servonaut.ico"

# Stable product and bundle upgrade codes across releases
PRODUCT_UPGRADE_CODE = "4B4F1B0A-742A-4A6F-99F2-2B6348F98EC4"  # leak-guard:allow
BUNDLE_UPGRADE_CODE = "9F8B5F4A-3C2D-4E1B-8A7C-5E4D3C2B1A0F"  # leak-guard:allow

# Stable RFC 4122 UUID namespace for deterministic component GUIDs
UUID_NAMESPACE_SERVONAUT = uuid.UUID("4b4f1b0a-742a-4a6f-99f2-2b6348f98ec4")  # leak-guard:allow


# Required binaries and files in PyInstaller onedir payload on Windows
REQUIRED_PAYLOAD_BINARIES: tuple[str, ...] = (
    "servonaut-desktop.exe",
    "servonaut-desktop-child.exe",
    "servonaut.exe",
)

REQUIRED_PAYLOAD_FILES: tuple[str, ...] = (
    *REQUIRED_PAYLOAD_BINARIES,
    "servonaut-runtime.json",
)

# Windows Installer stores Directory, Component and File keys in 72-character columns.
_WIX_ID_MAX_LENGTH = 72
_WIX_ID_DIGEST_LENGTH = 16
_HARVESTED_ID_ELEMENTS = frozenset({"Directory", "Component", "File"})
_XML_ATTRIBUTE_ENTITIES = {'"': "&quot;"}

# Dry-run installers get this suffix so they can never pass for a release artifact.
SIMULATED_SUFFIX = ".simulated"

_SEMVER_REGEX = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class WindowsPackagingError(Exception):
    """Raised when Windows MSI packaging or WiX generation fails."""


@dataclass(frozen=True, slots=True)
class WindowsPackageResult:
    """Result of Windows packaging containing paths and cryptographic metadata."""

    msi_path: Path
    product_wxs_path: Path
    bundle_wxs_path: Path
    sha256: str
    byte_size: int
    version: str
    packaging_revision: Optional[int]
    component_count: int


def deterministic_guid(key: str) -> str:
    """Derive a reproducible, stable RFC 4122 UUIDv5 GUID for a component or directory."""
    clean_key = key.replace("\\", "/").lower().strip("/")
    return str(uuid.uuid5(UUID_NAMESPACE_SERVONAUT, clean_key)).upper()


def _wix_id(prefix: str, relative_path: str) -> str:
    """Return a stable WiX identifier for ``relative_path`` of at most 72 characters.

    The identifier keeps the readable tail of the path for installer logs and ends
    with a digest of the full path, so long paths that share that tail stay distinct.
    ``prefix`` must start with a letter or underscore.
    """
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:_WIX_ID_DIGEST_LENGTH]
    readable_length = _WIX_ID_MAX_LENGTH - len(prefix) - len(digest) - 1
    readable = re.sub(r"[^A-Za-z0-9_.]", "_", relative_path)[-readable_length:]
    return f"{prefix}{readable}_{digest}"


def _validate_wix_ids(wix_root: ET.Element) -> None:
    """Reject duplicate or over-long Directory, Component and File identifiers."""
    ids = [
        element.attrib["Id"]
        for element in wix_root.iter()
        if element.tag.rpartition("}")[2] in _HARVESTED_ID_ELEMENTS and "Id" in element.attrib
    ]
    too_long = sorted({identifier for identifier in ids if len(identifier) > _WIX_ID_MAX_LENGTH})
    if too_long:
        raise WindowsPackagingError(
            f"WiX identifiers longer than {_WIX_ID_MAX_LENGTH} characters: {', '.join(too_long)}"
        )
    duplicates = sorted(identifier for identifier, count in Counter(ids).items() if count > 1)
    if duplicates:
        raise WindowsPackagingError(f"Duplicate WiX identifiers: {', '.join(duplicates)}")


def format_msi_version(product_version: str, packaging_revision: Optional[int] = None) -> str:
    """Convert a semantic version and packaging revision to a valid Windows Installer version.

    Windows Installer versions must strictly be: major.minor.build (or major.minor.build.revision),
    where major <= 255, minor <= 255, build <= 65535.
    """
    match = _SEMVER_REGEX.match(product_version)
    if not match:
        raise WindowsPackagingError(f"Product version '{product_version}' is not valid Semantic Versioning (X.Y.Z).")

    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3))

    if major > 255 or minor > 255 or patch > 65535:
        raise WindowsPackagingError(
            f"Version '{product_version}' exceeds MSI integer limits (major<=255, minor<=255, patch<=65535)."
        )

    if packaging_revision is not None:
        if packaging_revision < 0 or packaging_revision > 65535:
            raise WindowsPackagingError("Packaging revision must be between 0 and 65535 for MSI.")
        return f"{major}.{minor}.{patch}.{packaging_revision}"

    return f"{major}.{minor}.{patch}"


def _harvest_directory(
    root_payload_dir: Path,
    current_dir: Path,
    directory_id: str = "INSTALLFOLDER",
) -> tuple[str, list[str], list[str], int]:
    """Recursively harvest directory tree into WiX directory elements, components, and refs.

    Returns:
        (nested_directories_xml, component_xml_list, component_ref_list, total_files)
    """
    dir_elements: list[str] = []
    components: list[str] = []
    component_refs: list[str] = []
    file_count = 0

    # Sort items deterministically
    entries = sorted(list(current_dir.iterdir()), key=lambda p: p.name.lower())
    subdirs = [e for e in entries if e.is_dir()]
    files = [e for e in entries if e.is_file()]

    # 1. Harvest files in this directory
    for file_path in files:
        rel_str = file_path.relative_to(root_payload_dir).as_posix()
        guid = deterministic_guid(rel_str)
        comp_id = _wix_id("C_", rel_str)
        file_id = _wix_id("F_", rel_str)

        comp_xml = (
            f'    <DirectoryRef Id="{directory_id}">\n'
            f'      <Component Id="{comp_id}" Guid="{guid}">\n'
            f'        <File Id="{file_id}"\n'
            f'              Name={quoteattr(file_path.name)}\n'
            f'              Source={quoteattr(str(file_path.resolve()))}\n'
            f'              KeyPath="yes" />\n'
            f'      </Component>\n'
            f'    </DirectoryRef>'
        )
        components.append(comp_xml)
        component_refs.append(f'      <ComponentRef Id="{comp_id}" />')
        file_count += 1

    # 2. Harvest subdirectories
    for subdir in subdirs:
        sub_dir_id = _wix_id("Dir_", subdir.relative_to(root_payload_dir).as_posix())

        sub_nested_dirs, sub_comps, sub_refs, sub_count = _harvest_directory(
            root_payload_dir,
            subdir,
            directory_id=sub_dir_id,
        )
        file_count += sub_count
        components.extend(sub_comps)
        component_refs.extend(sub_refs)

        dir_xml = (
            f'          <Directory Id="{sub_dir_id}" Name={quoteattr(subdir.name)}>\n'
            f'{sub_nested_dirs}'
            f'          </Directory>'
        )
        dir_elements.append(dir_xml)

    nested_dirs_str = "\n".join(dir_elements)
    if nested_dirs_str:
        nested_dirs_str += "\n"

    return nested_dirs_str, components, component_refs, file_count


def generate_wix_sources(
    payload_dir: Path | str,
    output_wix_dir: Path | str,
    product_version: str,
    *,
    packaging_revision: Optional[int] = None,
    install_scope: str = "perMachine",
    icon_file: Optional[Path | str] = None,
    msi_filename: str = "servonaut.msi",
) -> tuple[Path, Path, int]:
    """Generate servonaut.wxs and bundle.wxs WiX sources from payload directory.

    Returns:
        (product_wxs_path, bundle_wxs_path, total_components)
    """
    src_dir = Path(payload_dir).resolve()
    out_dir = Path(output_wix_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not src_dir.is_dir():
        raise FileNotFoundError(f"Payload directory does not exist: {src_dir}")

    # Verify required Windows payload files
    for req_file in REQUIRED_PAYLOAD_FILES:
        target = src_dir / req_file
        if not target.is_file():
            raise WindowsPackagingError(
                f"Required Windows payload file '{req_file}' missing in {src_dir}"
            )

    # Windows Installer cannot represent symbolic links; reject them and any
    # special files before harvesting, as the standalone zip archiver does.
    walk_payload(src_dir, allow_symlinks=False)

    icon_path = Path(icon_file).resolve() if icon_file else _DEFAULT_ICON
    if not icon_path.is_file():
        raise FileNotFoundError(f"Icon file not found: {icon_path}")

    # Copy icon to WiX directory so relative paths work cleanly
    dest_icon = out_dir / "servonaut.ico"
    shutil.copy2(icon_path, dest_icon)

    msi_ver = format_msi_version(product_version, packaging_revision)

    # Harvest directory files and subdirectories
    nested_dirs, comps, comp_refs, total_files = _harvest_directory(src_dir, src_dir)

    # Configure scope variables
    if install_scope == "perMachine":
        install_root_dir = "ProgramFiles64Folder"
        reg_root = "HKLM"
        system_env = "yes"
    elif install_scope == "perUser":
        install_root_dir = "LocalAppDataFolder"
        reg_root = "HKCU"
        system_env = "no"
    else:
        raise WindowsPackagingError(f"Unsupported install_scope '{install_scope}'. Must be 'perMachine' or 'perUser'.")

    # Read product template
    template_wxs = _WINDOWS_TEMPLATE_DIR / "servonaut.wxs.template"
    if not template_wxs.is_file():
        raise FileNotFoundError(f"WiX template not found: {template_wxs}")

    wxs_content = template_wxs.read_text(encoding="utf-8")
    wxs_content = (
        wxs_content.replace("{{PRODUCT_VERSION}}", msi_ver)
        .replace("{{INSTALL_SCOPE}}", install_scope)
        .replace("{{ICON_PATH}}", dest_icon.name)
        .replace("{{INSTALL_ROOT_DIR}}", install_root_dir)
        .replace("{{PRODUCT_UPGRADE_CODE}}", PRODUCT_UPGRADE_CODE)
        .replace("{{WEBVIEW2_CLIENT_GUID}}", WEBVIEW2_CLIENT_GUID)
        .replace("{{WEBVIEW2_BOOTSTRAPPER_URL}}", escape(WEBVIEW2_BOOTSTRAPPER_URL, _XML_ATTRIBUTE_ENTITIES))
        .replace("{{SHORTCUT_GUID}}", deterministic_guid("component:start_menu_shortcut"))
        .replace("{{PATH_ENV_GUID}}", deterministic_guid("component:path_environment"))
        .replace("{{REGISTRY_ROOT}}", reg_root)
        .replace("{{SYSTEM_ENV}}", system_env)
        .replace("{{HARVESTED_DIRECTORIES}}", nested_dirs.rstrip())
        .replace("{{HARVESTED_COMPONENTS}}", "\n".join(comps))
        .replace("{{HARVESTED_COMPONENT_REFS}}", "\n".join(comp_refs))
    )

    product_wxs_path = out_dir / "servonaut.wxs"
    product_wxs_path.write_text(wxs_content, encoding="utf-8")

    # Validate XML syntax and harvested identifiers of generated product WXS
    try:
        product_root = ET.fromstring(wxs_content)
    except ET.ParseError as err:
        raise WindowsPackagingError(f"Generated servonaut.wxs is not well-formed XML: {err}") from err
    _validate_wix_ids(product_root)

    # Read bundle template
    template_bundle = _WINDOWS_TEMPLATE_DIR / "bundle.wxs.template"
    if not template_bundle.is_file():
        raise FileNotFoundError(f"WiX bundle template not found: {template_bundle}")

    bundle_content = template_bundle.read_text(encoding="utf-8")
    bundle_content = (
        bundle_content.replace("{{PRODUCT_VERSION}}", msi_ver)
        .replace("{{BUNDLE_UPGRADE_CODE}}", BUNDLE_UPGRADE_CODE)
        .replace("{{WEBVIEW2_CLIENT_GUID}}", WEBVIEW2_CLIENT_GUID)
        .replace("{{WEBVIEW2_MINIMUM_VERSION}}", MINIMUM_WEBVIEW2_VERSION)
        .replace("{{WEBVIEW2_BOOTSTRAPPER_URL}}", escape(WEBVIEW2_BOOTSTRAPPER_URL, _XML_ATTRIBUTE_ENTITIES))
        .replace("{{ICON_PATH}}", dest_icon.name)
        .replace("{{MSI_PATH}}", escape(msi_filename, _XML_ATTRIBUTE_ENTITIES))
    )

    bundle_wxs_path = out_dir / "bundle.wxs"
    bundle_wxs_path.write_text(bundle_content, encoding="utf-8")

    # Validate XML syntax of generated bundle WXS
    try:
        ET.fromstring(bundle_content)
    except ET.ParseError as err:
        raise WindowsPackagingError(f"Generated bundle.wxs is not well-formed XML: {err}") from err

    return product_wxs_path, bundle_wxs_path, total_files + 2  # +2 for shortcut & env components


def _find_wix_tools(wix_bin_dir: Optional[Path | str]) -> tuple[str, str]:
    """Return the WiX Toolset v3 candle and light executables, or raise if absent."""
    if wix_bin_dir:
        exe_suffix = ".exe" if sys.platform == "win32" else ""
        candle = Path(wix_bin_dir) / f"candle{exe_suffix}"
        light = Path(wix_bin_dir) / f"light{exe_suffix}"
        if candle.is_file() and light.is_file():
            return str(candle), str(light)
        raise WindowsPackagingError(f"WiX Toolset binaries candle and light were not found in {wix_bin_dir}.")

    candle_bin = shutil.which("candle.exe") or shutil.which("candle")
    light_bin = shutil.which("light.exe") or shutil.which("light")
    if not (candle_bin and light_bin):
        raise WindowsPackagingError(
            "WiX Toolset v3 (candle and light) was not found on PATH "
            "(use a dry run to write a simulated placeholder)."
        )
    return candle_bin, light_bin


def _compile_msi(
    candle_bin: str,
    light_bin: str,
    product_wxs: Path,
    work_dir: Path,
    msi_path: Path,
) -> None:
    """Compile and link the product WiX source into an MSI package."""
    obj_path = work_dir / "servonaut.wixobj"
    cmd_candle = [
        candle_bin,
        "-arch",
        "x64",
        "-ext",
        "WixUtilExtension",
        "-out",
        str(obj_path),
        str(product_wxs),
    ]
    res_cand = subprocess.run(cmd_candle, capture_output=True, text=True)
    if res_cand.returncode != 0:
        raise WindowsPackagingError(f"candle compilation failed:\n{res_cand.stderr}\n{res_cand.stdout}")

    cmd_light = [
        light_bin,
        "-ext",
        "WixUtilExtension",
        "-out",
        str(msi_path),
        str(obj_path),
    ]
    res_light = subprocess.run(cmd_light, capture_output=True, text=True)
    if res_light.returncode != 0:
        raise WindowsPackagingError(f"light linker failed:\n{res_light.stderr}\n{res_light.stdout}")


def _write_simulated_msi(dest_path: Path, product_wxs: Path, bundle_wxs: Path) -> None:
    """Write a deterministic dry-run stand-in derived from the generated WiX sources.

    It carries the compound-document magic bytes so layout checks can run, but it
    is not an installable package.
    """
    msi_header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # Microsoft Compound Document / MSI header
    hasher = hashlib.sha256()
    hasher.update(product_wxs.read_bytes())
    hasher.update(bundle_wxs.read_bytes())
    digest = hasher.digest()

    with open(dest_path, "wb") as f:
        f.write(msi_header)
        f.write(digest)
        # Pad to 4096 bytes minimum
        f.write(b"\x00" * (4096 - len(msi_header) - len(digest)))


def package_windows(
    payload_dir: Path | str,
    output_dir: Path | str,
    product_version: str,
    *,
    packaging_revision: Optional[int] = None,
    install_scope: str = "perMachine",
    icon_file: Optional[Path | str] = None,
    msi_filename: Optional[str] = None,
    dry_run: bool = False,
    wix_bin_dir: Optional[Path | str] = None,
) -> WindowsPackageResult:
    """Package a Windows x64 desktop payload into WiX sources and MSI installer.

    Compiles and links a standard .msi package with the WiX Toolset. With
    ``dry_run`` WiX never runs: the validated WiX sources are written together with
    a deterministic ``<name>.msi.simulated`` placeholder for layout checks.

    Returns:
        WindowsPackageResult: Package paths and verification metadata.

    Raises:
        WindowsPackagingError: If WiX is unavailable or fails outside a dry run.
    """
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    msi_name = msi_filename or f"servonaut-{product_version}-windows-x64.msi"
    msi_path = out_dir / msi_name

    # Step 1: Generate WiX Product and Bundle sources
    wix_src_dir = out_dir / "wix_sources"
    product_wxs, bundle_wxs, comp_count = generate_wix_sources(
        payload_dir=payload_dir,
        output_wix_dir=wix_src_dir,
        product_version=product_version,
        packaging_revision=packaging_revision,
        install_scope=install_scope,
        icon_file=icon_file,
        msi_filename=msi_name,
    )

    # Step 2: Compile the MSI, or write a clearly labelled placeholder in dry-run mode
    if dry_run:
        msi_path = out_dir / f"{msi_name}{SIMULATED_SUFFIX}"
        _write_simulated_msi(msi_path, product_wxs, bundle_wxs)
    else:
        candle_bin, light_bin = _find_wix_tools(wix_bin_dir)
        _compile_msi(candle_bin, light_bin, product_wxs, wix_src_dir, msi_path)

    # Compute final SHA-256 and size
    file_hasher = hashlib.sha256()
    with open(msi_path, "rb") as f:
        while chunk := f.read(64 * 1024):
            file_hasher.update(chunk)

    return WindowsPackageResult(
        msi_path=msi_path,
        product_wxs_path=product_wxs,
        bundle_wxs_path=bundle_wxs,
        sha256=file_hasher.hexdigest().lower(),
        byte_size=msi_path.stat().st_size,
        version=product_version,
        packaging_revision=packaging_revision,
        component_count=comp_count,
    )


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for Windows packaging."""
    parser = argparse.ArgumentParser(description="Package Servonaut desktop payload into Windows MSI installer.")
    parser.add_argument("--payload-dir", type=Path, required=True, help="Directory containing PyInstaller onedir payload.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Destination directory for output MSI and WiX sources.")
    parser.add_argument("--version", required=True, help="Product semantic version (X.Y.Z).")
    parser.add_argument("--revision", type=int, default=None, help="Optional packaging revision integer.")
    parser.add_argument("--scope", default="perMachine", choices=["perMachine", "perUser"], help="Installation scope.")
    parser.add_argument("--icon", type=Path, default=None, help="Custom application icon file (.ico).")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate WiX sources and a '.msi.simulated' placeholder without invoking WiX tools.",
    )

    args = parser.parse_args(argv)

    try:
        result = package_windows(
            payload_dir=args.payload_dir,
            output_dir=args.output_dir,
            product_version=args.version,
            packaging_revision=args.revision,
            install_scope=args.scope,
            icon_file=args.icon,
            dry_run=args.dry_run,
        )
        label = "Simulated Windows MSI placeholder written" if args.dry_run else "Windows MSI package created successfully"
        print(f"{label}: {result.msi_path}")
        print(f"Product WiX source:  {result.product_wxs_path}")
        print(f"Bundle WiX source:   {result.bundle_wxs_path}")
        print(f"Total Components:    {result.component_count}")
        print(f"SHA-256 Digest:      {result.sha256}")
        print(f"Package Size:        {result.byte_size} bytes")
        return 0
    except Exception as err:
        print(f"Error packaging Windows MSI: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

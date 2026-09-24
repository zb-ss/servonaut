"""Deterministic macOS Application Bundle (.app) and Drag-to-Applications DMG Packager."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
from typing import Optional

from scripts.distribution.payload_tree import walk_payload
from scripts.standalone_cli.artifact_types import PayloadEntry

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MACOS_DIR = _REPO_ROOT / "packaging" / "macos"

# Dry-run disk images get this suffix so they can never pass for a release artifact.
SIMULATED_SUFFIX = ".simulated"

REQUIRED_PAYLOAD_BINARIES: tuple[str, ...] = (
    "servonaut-desktop",
    "servonaut-desktop-child",
    "servonaut",
)

REQUIRED_PAYLOAD_FILES: tuple[str, ...] = (
    *REQUIRED_PAYLOAD_BINARIES,
    "servonaut-runtime.json",
)


class MacosPackagingError(Exception):
    """Raised when macOS application packaging fails."""


def resolve_epoch(source_epoch: Optional[int] = None) -> int:
    """Resolve an integer timestamp for deterministic archive metadata."""
    if source_epoch is not None:
        return source_epoch
    env_val = os.environ.get("SOURCE_DATE_EPOCH")
    if env_val and env_val.isdigit():
        return int(env_val)
    return 1700000000  # Default stable fallback epoch (2023-11-14)


def assemble_app_bundle(
    payload_dir: Path | str,
    output_dir: Path | str,
    product_version: str,
    *,
    packaging_revision: Optional[int] = None,
    bundle_name: str = "Servonaut.app",
    icon_file: Optional[Path | str] = None,
    bundle_id: str = "dev.servonaut.desktop",
    min_os_version: str = "13.0",
) -> Path:
    """Assemble a standard macOS Servonaut.app directory structure.

    Payload symbolic links are copied as links and must resolve inside the payload.

    Returns:
        Path: Path to the generated Servonaut.app bundle.
    """
    src_dir = Path(payload_dir).resolve()
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not src_dir.is_dir():
        raise FileNotFoundError(f"Payload directory does not exist: {src_dir}")

    # Validate required payload files
    for file_name in REQUIRED_PAYLOAD_FILES:
        target = src_dir / file_name
        if not target.exists():
            raise FileNotFoundError(
                f"Required desktop payload binary or file '{file_name}' missing in {src_dir}"
            )
    payload_entries = walk_payload(src_dir)

    app_path = out_dir / bundle_name
    if app_path.exists():
        if app_path.is_dir():
            shutil.rmtree(app_path)
        else:
            app_path.unlink()

    contents_dir = app_path / "Contents"
    macos_dir = contents_dir / "MacOS"
    resources_dir = contents_dir / "Resources"

    macos_dir.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)

    # 1. PkgInfo
    pkg_info = contents_dir / "PkgInfo"
    pkg_info.write_bytes(b"APPL????")

    # 2. Info.plist
    version_str = (
        f"{product_version}.{packaging_revision}"
        if packaging_revision is not None
        else product_version
    )
    plist_data = {
        "CFBundlePackageType": "APPL",
        "CFBundleName": "Servonaut",
        "CFBundleDisplayName": "Servonaut",
        "CFBundleIdentifier": bundle_id,
        "CFBundleVersion": version_str,
        "CFBundleShortVersionString": product_version,
        "CFBundleExecutable": "servonaut-desktop",
        "CFBundleIconFile": "AppIcon",
        "LSMinimumSystemVersion": min_os_version,
        "NSHighResolutionCapable": True,
        "NSSupportsAutomaticGraphicsSwitching": True,
        "NSMicrophoneUsageDescription": (
            "Servonaut requires microphone access for local voice commands and transcription."
        ),
    }

    info_plist = contents_dir / "Info.plist"
    with open(info_plist, "wb") as fp:
        plistlib.dump(plist_data, fp, fmt=plistlib.FMT_XML)

    # 3. Copy application icon
    src_icon = Path(icon_file) if icon_file else _MACOS_DIR / "AppIcon.icns"
    if src_icon.is_file():
        dest_icon = resources_dir / "AppIcon.icns"
        shutil.copy2(src_icon, dest_icon)
        dest_icon.chmod(0o644)

    # 4. Copy payload contents into Contents/MacOS/, keeping symbolic links as links
    for entry in payload_entries:
        dest = macos_dir / entry.relative_path
        if entry.kind == "directory":
            dest.mkdir(mode=0o755, parents=True, exist_ok=True)
            continue
        if entry.kind == "symlink":
            os.symlink(entry.link_target or "", dest)
            continue

        shutil.copy2(src_dir / entry.relative_path, dest)
        is_exec = (
            entry.relative_path.as_posix() in REQUIRED_PAYLOAD_BINARIES
            or bool(entry.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        )
        dest.chmod(0o755 if is_exec else 0o644)

    return app_path


def _tar_info(name: str, epoch: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.mtime = epoch
    info.uid = 0
    info.gid = 0
    return info


def _add_payload_entry(tar: tarfile.TarFile, root: Path, entry: PayloadEntry, name: str, epoch: int) -> None:
    info = _tar_info(name, epoch)
    if entry.kind == "directory":
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        tar.addfile(info)
    elif entry.kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = entry.link_target or ""
        info.mode = 0o777
        tar.addfile(info)
    else:
        info.size = entry.size
        is_exec = bool(entry.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        info.mode = 0o755 if is_exec else 0o644
        with open(root / entry.relative_path, "rb") as content_f:
            tar.addfile(info, content_f)


def _image_layout_tar(app_path: Path, epoch: int) -> bytes:
    """Return a tar of the image layout: the app bundle beside an Applications link."""
    tar_bio = io.BytesIO()
    with tarfile.open(mode="w", fileobj=tar_bio) as tar:
        applications = _tar_info("Applications", epoch)
        applications.type = tarfile.SYMTYPE
        applications.linkname = "/Applications"
        applications.mode = 0o777
        tar.addfile(applications)

        bundle = _tar_info(app_path.name, epoch)
        bundle.type = tarfile.DIRTYPE
        bundle.mode = 0o755
        tar.addfile(bundle)

        for entry in walk_payload(app_path):
            name = f"{app_path.name}/{entry.relative_path.as_posix()}"
            _add_payload_entry(tar, app_path, entry, name, epoch)
    return tar_bio.getvalue()


def _koly_trailer(volume_name: str) -> bytes:
    """Return a 512-byte UDIF-style 'koly' trailer carrying the volume name."""
    # Magic: 'koly' (4 bytes)
    # Version: 4 (uint32)
    # Header size: 512 (uint32)
    # Flags: 1 (uint32)
    koly = bytearray(512)
    struct.pack_into(
        ">4sIIII",
        koly,
        0,
        b"koly",
        4,
        512,
        1,
        0,
    )
    # Volume name at offset 416
    vol_bytes = volume_name.encode("utf-8")[:64]
    koly[416 : 416 + len(vol_bytes)] = vol_bytes
    return bytes(koly)


def _write_simulated_image(
    app_path: Path,
    dest_path: Path,
    volume_name: str,
    epoch: int,
) -> None:
    """Write a deterministic dry-run stand-in for the drag-to-Applications disk image.

    The stand-in is a tar of the image layout followed by a UDIF-style 'koly'
    trailer. It is not a mountable disk image.
    """
    dest_path.write_bytes(_image_layout_tar(app_path, epoch) + _koly_trailer(volume_name))


def _create_dmg_with_hdiutil(app_path: Path, dest_path: Path, volume_name: str) -> None:
    """Build a compressed UDZO disk image holding the app and an Applications link."""
    hdiutil_bin = shutil.which("hdiutil")
    if not hdiutil_bin:
        raise MacosPackagingError(
            "hdiutil was not found; macOS disk images can only be built on macOS "
            "(use a dry run to write a simulated placeholder)."
        )

    staging_dir = dest_path.parent / f".staging-{dest_path.name}"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True)
    try:
        shutil.copytree(app_path, staging_dir / app_path.name, symlinks=True)
        os.symlink("/Applications", staging_dir / "Applications")

        if dest_path.exists():
            dest_path.unlink()
        cmd = [
            hdiutil_bin,
            "create",
            "-volname",
            volume_name,
            "-srcfolder",
            str(staging_dir),
            "-ov",
            "-format",
            "UDZO",
            str(dest_path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise MacosPackagingError(f"hdiutil failed ({res.returncode}): {res.stderr}")
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def package_dmg(
    app_bundle_path: Path | str,
    output_dir: Path | str,
    product_version: str,
    target_arch: str,
    *,
    volume_name: str = "Servonaut",
    packaging_revision: Optional[int] = None,
    source_epoch: Optional[int] = None,
    filename: Optional[str] = None,
    dry_run: bool = False,
) -> tuple[Path, str, int]:
    """Package Servonaut.app into a drag-to-Applications .dmg disk image.

    With ``dry_run`` no disk image tool runs; a deterministic placeholder named
    ``<name>.dmg.simulated`` is written instead.

    Returns:
        tuple[Path, str, int]: (dmg_path, sha256_hex, byte_size)

    Raises:
        MacosPackagingError: If hdiutil is unavailable or fails outside a dry run.
    """
    app_path = Path(app_bundle_path).resolve()
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not app_path.is_dir():
        raise FileNotFoundError(f"App bundle directory does not exist: {app_path}")

    # Standardize architecture tag
    norm_arch = target_arch.replace("macos-", "")
    if norm_arch not in ("x86_64", "arm64", "x64"):
        raise MacosPackagingError(f"Unsupported macOS target architecture: {target_arch}")

    arch_tag = "macos-arm64" if "arm" in target_arch else "macos-x64"
    dmg_name = filename or f"servonaut-desktop-{product_version}-{arch_tag}.dmg"

    if dry_run:
        dest_path = out_dir / f"{dmg_name}{SIMULATED_SUFFIX}"
        _write_simulated_image(app_path, dest_path, volume_name, resolve_epoch(source_epoch))
    else:
        dest_path = out_dir / dmg_name
        _create_dmg_with_hdiutil(app_path, dest_path, volume_name)

    hasher = hashlib.sha256()
    with open(dest_path, "rb") as f:
        while chunk := f.read(64 * 1024):
            hasher.update(chunk)

    return dest_path, hasher.hexdigest().lower(), dest_path.stat().st_size


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble macOS Application Bundle (.app) and create drag-and-drop DMG."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--payload-dir",
        type=Path,
        help="Directory containing built desktop onedir payload to assemble into Servonaut.app.",
    )
    source.add_argument(
        "--app-bundle",
        type=Path,
        help="Existing (for example already signed) .app bundle to package without reassembling it.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory to write output artifacts.",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Product semantic version (X.Y.Z).",
    )
    parser.add_argument(
        "--arch",
        required=True,
        choices=["x86_64", "arm64", "macos-x64", "macos-arm64"],
        help="Target macOS architecture.",
    )
    parser.add_argument(
        "--revision",
        type=int,
        default=None,
        help="Packaging revision.",
    )
    parser.add_argument(
        "--volume-name",
        default="Servonaut",
        help="DMG disk volume name (default: Servonaut).",
    )
    parser.add_argument(
        "--filename",
        default=None,
        help="Custom output filename for the DMG archive.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Write a '.dmg.simulated' placeholder instead of running hdiutil.",
    )

    args = parser.parse_args(argv)

    try:
        if args.app_bundle is not None:
            app_path = args.app_bundle
        else:
            app_path = assemble_app_bundle(
                payload_dir=args.payload_dir,
                output_dir=args.output_dir,
                product_version=args.version,
                packaging_revision=args.revision,
            )
        dmg_path, sha256, byte_size = package_dmg(
            app_bundle_path=app_path,
            output_dir=args.output_dir,
            product_version=args.version,
            target_arch=args.arch,
            volume_name=args.volume_name,
            packaging_revision=args.revision,
            filename=args.filename,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    label = "Simulated macOS DMG placeholder written" if args.dry_run else "macOS DMG created"
    print(f"{label}: {dmg_path}")
    print(f"  SHA-256: {sha256}")
    print(f"  Size:    {byte_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

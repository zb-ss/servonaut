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

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MACOS_DIR = _REPO_ROOT / "packaging" / "macos"

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

    # 4. Copy payload contents into Contents/MacOS/
    for root, dirs, files in os.walk(src_dir):
        rel_root = Path(root).relative_to(src_dir)
        target_dir = macos_dir / rel_root
        target_dir.mkdir(mode=0o755, parents=True, exist_ok=True)

        for d in dirs:
            (target_dir / d).mkdir(mode=0o755, parents=True, exist_ok=True)

        for f in files:
            src_file = Path(root) / f
            dest_file = target_dir / f

            if dest_file.exists():
                dest_file.unlink()

            shutil.copy2(src_file, dest_file)

            # Executable permissions
            rel_path = (rel_root / f).as_posix()
            is_exec = (
                rel_path in REQUIRED_PAYLOAD_BINARIES
                or bool(src_file.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            )
            dest_file.chmod(0o755 if is_exec else 0o644)

    return app_path


def _write_deterministic_udif_fallback(
    staging_dir: Path,
    dest_path: Path,
    volume_name: str,
    epoch: int,
) -> None:
    """Create a deterministic disk image container with UDIF koly trailer.

    Used when hdiutil is unavailable on non-macOS host platforms.
    """
    tar_bio = io.BytesIO()
    with tarfile.open(mode="w", fileobj=tar_bio) as tar:
        for root, dirs, files in os.walk(staging_dir):
            dirs.sort()
            for d in dirs:
                full_d = Path(root) / d
                rel_d = full_d.relative_to(staging_dir).as_posix()
                ti = tarfile.TarInfo(name=rel_d)
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                ti.mtime = epoch
                ti.uid = 0
                ti.gid = 0
                tar.addfile(ti)

            for f in sorted(files):
                full_f = Path(root) / f
                rel_f = full_f.relative_to(staging_dir).as_posix()
                ti = tarfile.TarInfo(name=rel_f)
                ti.mtime = epoch
                ti.uid = 0
                ti.gid = 0

                if full_f.is_symlink():
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = os.readlink(full_f)
                    ti.mode = 0o777
                    tar.addfile(ti)
                else:
                    st = full_f.stat()
                    ti.size = st.st_size
                    is_exec = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    ti.mode = 0o755 if is_exec else 0o644
                    with open(full_f, "rb") as content_f:
                        tar.addfile(ti, content_f)

    payload_data = tar_bio.getvalue()

    # Construct standard 512-byte UDIF trailer ('koly')
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

    dest_path.write_bytes(payload_data + bytes(koly))


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
) -> tuple[Path, str, int]:
    """Package Servonaut.app into a drag-to-Applications .dmg disk image.

    Returns:
        tuple[Path, str, int]: (dmg_path, sha256_hex, byte_size)
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
    dest_path = out_dir / dmg_name

    epoch = resolve_epoch(source_epoch)
    staging_dir = out_dir / f".staging-{dmg_name}"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Copy app bundle into staging
        staged_app = staging_dir / app_path.name
        shutil.copytree(app_path, staged_app, symlinks=True)

        # 2. Add /Applications symlink
        app_symlink = staging_dir / "Applications"
        if not app_symlink.exists():
            os.symlink("/Applications", app_symlink)

        # 3. Create DMG
        hdiutil_bin = shutil.which("hdiutil")
        if hdiutil_bin and sys.platform == "darwin":
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
        else:
            _write_deterministic_udif_fallback(
                staging_dir=staging_dir,
                dest_path=dest_path,
                volume_name=volume_name,
                epoch=epoch,
            )

        # 4. Hash and size
        hasher = hashlib.sha256()
        with open(dest_path, "rb") as f:
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)

        sha256 = hasher.hexdigest().lower()
        byte_size = dest_path.stat().st_size
        return dest_path, sha256, byte_size

    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble macOS Application Bundle (.app) and create drag-and-drop DMG."
    )
    parser.add_argument(
        "--payload-dir",
        required=True,
        type=Path,
        help="Directory containing built desktop onedir payload.",
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

    args = parser.parse_args(argv)

    try:
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
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"macOS DMG created: {dmg_path}")
    print(f"  SHA-256: {sha256}")
    print(f"  Size:    {byte_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

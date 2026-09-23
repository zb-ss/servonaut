"""Deterministic Debian (.deb) packaging for Servonaut Desktop."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import math
import os
from pathlib import Path
import stat
import sys
import tarfile
from typing import Optional, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEB_TEMPLATE_DIR = _REPO_ROOT / "packaging" / "deb"

DEFAULT_DEPENDENCIES: tuple[str, ...] = (
    "libgtk-3-0 (>= 3.24.0) | libgtk-3-0t64",
    "libwebkit2gtk-4.1-0",
    "gir1.2-gtk-3.0",
    "gir1.2-webkit2-4.1",
    "libportaudio2",
    "openssh-client",
    "ca-certificates",
)

REQUIRED_PAYLOAD_BINARIES: tuple[str, ...] = (
    "servonaut-desktop",
    "servonaut-desktop-child",
    "servonaut",
)

REQUIRED_PAYLOAD_FILES: tuple[str, ...] = (
    *REQUIRED_PAYLOAD_BINARIES,
    "servonaut-runtime.json",
)


class DebPackagingError(Exception):
    """Raised when Debian package assembly or validation fails."""


def resolve_epoch(source_epoch: Optional[int] = None) -> int:
    """Resolve an integer timestamp for deterministic archive metadata."""
    if source_epoch is not None:
        return source_epoch
    env_val = os.environ.get("SOURCE_DATE_EPOCH")
    if env_val and env_val.isdigit():
        return int(env_val)
    return 1700000000  # Default stable fallback epoch (2023-11-14)


def _format_ar_member(name: str, data: bytes, mtime: int) -> bytes:
    """Format a single ar member header and padded content."""
    header = (
        f"{name:<16}"
        f"{mtime:<12}"
        f"{0:<6}"
        f"{0:<6}"
        f"{100644:<8}"
        f"{len(data):<10}"
        "`\n"
    ).encode("ascii")
    padding = b"\n" if len(data) % 2 != 0 else b""
    return header + data + padding


def _build_control_tar(
    *,
    package_name: str,
    version_str: str,
    architecture: str,
    installed_size_kib: int,
    maintainer: str,
    description: str,
    dependencies: Sequence[str],
    postinst_content: str,
    postrm_content: str,
    md5sums_content: str,
    epoch: int,
) -> bytes:
    """Construct the control.tar.gz archive in memory."""
    # Format control file
    control_lines = [
        f"Package: {package_name}",
        f"Version: {version_str}",
        "Section: utils",
        "Priority: optional",
        f"Architecture: {architecture}",
        f"Installed-Size: {installed_size_kib}",
        f"Maintainer: {maintainer}",
        f"Depends: {', '.join(dependencies)}",
        "Homepage: https://servonaut.dev",
        "Description: Modern server management TUI and desktop application",
    ]
    # Add continuation lines for description if multi-line
    desc_lines = [line.strip() for line in description.strip().splitlines()]
    if len(desc_lines) > 1:
        for extra_line in desc_lines[1:]:
            control_lines.append(f" {extra_line}")
    elif desc_lines and desc_lines[0] != "Modern server management TUI and desktop application":
        control_lines.append(f" {desc_lines[0]}")
    else:
        control_lines.append(
            " Servonaut provides server management including SSH access, SCP file transfer,"
        )
        control_lines.append(
            " log viewing, AI analysis assistant, and remote command execution."
        )

    control_bytes = ("\n".join(control_lines) + "\n").encode("utf-8")
    postinst_bytes = postinst_content.encode("utf-8")
    postrm_bytes = postrm_content.encode("utf-8")
    md5_bytes = md5sums_content.encode("utf-8")

    members = [
        ("./control", 0o644, control_bytes),
        ("./md5sums", 0o644, md5_bytes),
        ("./postinst", 0o755, postinst_bytes),
        ("./postrm", 0o755, postrm_bytes),
    ]

    bio = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=bio, mtime=epoch) as gz:
        with tarfile.open(mode="w", fileobj=gz) as tar:
            # Add root directory entry
            root_info = tarfile.TarInfo(name="./")
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o755
            root_info.mtime = epoch
            root_info.uid = 0
            root_info.gid = 0
            root_info.uname = "root"
            root_info.gname = "root"
            tar.addfile(root_info)

            for name, mode, content in members:
                ti = tarfile.TarInfo(name=name)
                ti.size = len(content)
                ti.mode = mode
                ti.mtime = epoch
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                tar.addfile(ti, io.BytesIO(content))

    return bio.getvalue()


def package_deb(
    payload_dir: Path | str,
    output_dir: Path | str,
    product_version: str,
    *,
    packaging_revision: Optional[int] = None,
    architecture: str = "amd64",
    maintainer: str = "Servonaut Maintainers <support@example.com>",
    description: str = "Modern server management TUI and desktop application",
    dependencies: Optional[Sequence[str]] = None,
    source_epoch: Optional[int] = None,
    desktop_file: Optional[Path | str] = None,
    icon_file: Optional[Path | str] = None,
    copyright_file: Optional[Path | str] = None,
    postinst_file: Optional[Path | str] = None,
    postrm_file: Optional[Path | str] = None,
    package_name: str = "servonaut",
    filename: Optional[str] = None,
) -> tuple[Path, str, int]:
    """Package a multi-executable desktop onedir payload into a standard Debian (.deb) package.

    Returns:
        tuple[Path, str, int]: (deb_path, sha256_hex, byte_size)
    """
    src_dir = Path(payload_dir).resolve()
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not src_dir.is_dir():
        raise FileNotFoundError(f"Payload directory does not exist: {src_dir}")

    # Validate required payload files
    for binary_name in REQUIRED_PAYLOAD_FILES:
        bin_path = src_dir / binary_name
        if not bin_path.exists():
            raise FileNotFoundError(
                f"Required desktop payload binary or file '{binary_name}' missing in {src_dir}"
            )

    epoch = resolve_epoch(source_epoch)
    dep_list = tuple(dependencies) if dependencies is not None else DEFAULT_DEPENDENCIES

    # Determine Debian version string
    version_str = (
        f"{product_version}-{packaging_revision}"
        if packaging_revision is not None
        else product_version
    )

    # Resolve extra packaging assets
    desk_path = Path(desktop_file) if desktop_file else _DEB_TEMPLATE_DIR / "servonaut.desktop"
    ic_path = Path(icon_file) if icon_file else _DEB_TEMPLATE_DIR / "servonaut.svg"
    copy_path = Path(copyright_file) if copyright_file else _DEB_TEMPLATE_DIR / "copyright"
    pinst_path = Path(postinst_file) if postinst_file else _DEB_TEMPLATE_DIR / "postinst"
    prm_path = Path(postrm_file) if postrm_file else _DEB_TEMPLATE_DIR / "postrm"

    if not desk_path.is_file():
        raise FileNotFoundError(f"Desktop launcher template missing: {desk_path}")
    if not ic_path.is_file():
        raise FileNotFoundError(f"Application icon missing: {ic_path}")
    if not copy_path.is_file():
        raise FileNotFoundError(f"Copyright notice missing: {copy_path}")
    if not pinst_path.is_file():
        raise FileNotFoundError(f"postinst script missing: {pinst_path}")
    if not prm_path.is_file():
        raise FileNotFoundError(f"postrm script missing: {prm_path}")

    desktop_bytes = desk_path.read_bytes()
    icon_bytes = ic_path.read_bytes()
    copyright_bytes = copy_path.read_bytes()
    postinst_content = pinst_path.read_text(encoding="utf-8")
    postrm_content = prm_path.read_text(encoding="utf-8")

    # Discover and sort all payload files
    payload_entries: list[tuple[Path, str]] = []
    for root, dirs, files in os.walk(src_dir):
        dirs.sort()
        for f in sorted(files):
            file_path = Path(root) / f
            rel = file_path.relative_to(src_dir).as_posix()
            payload_entries.append((file_path, rel))
    payload_entries.sort(key=lambda x: x[1])

    # Build data.tar.gz
    # Standard installation prefix: /opt/{package_name}
    data_bio = io.BytesIO()
    md5_entries: list[tuple[str, str]] = []
    total_uncompressed_bytes = 0

    # Collect all directories and files for data.tar.gz
    dirs_to_add: set[str] = {
        "./",
        "./opt",
        f"./opt/{package_name}",
        "./usr",
        "./usr/bin",
        "./usr/share",
        "./usr/share/applications",
        "./usr/share/icons",
        "./usr/share/icons/hicolor",
        "./usr/share/icons/hicolor/scalable",
        "./usr/share/icons/hicolor/scalable/apps",
        "./usr/share/doc",
        f"./usr/share/doc/{package_name}",
    }

    # Add directories from payload
    for file_path, rel_path in payload_entries:
        parent = Path(f"./opt/{package_name}") / Path(rel_path).parent
        while str(parent) not in (".", "./"):
            dirs_to_add.add(parent.as_posix())
            parent = parent.parent

    sorted_dirs = sorted(dirs_to_add)

    with gzip.GzipFile(filename="", mode="wb", fileobj=data_bio, mtime=epoch) as gz:
        with tarfile.open(mode="w", fileobj=gz) as tar:
            # 1. Add directories
            for d in sorted_dirs:
                ti = tarfile.TarInfo(name=d)
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                ti.mtime = epoch
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                tar.addfile(ti)

            # 2. Add payload files into /opt/{package_name}/
            for file_path, rel_path in payload_entries:
                st = file_path.stat()
                total_uncompressed_bytes += st.st_size
                content = file_path.read_bytes()

                md5_hex = hashlib.md5(content).hexdigest()
                norm_target_path = f"opt/{package_name}/{rel_path}"
                md5_entries.append((md5_hex, norm_target_path))

                tar_path = f"./opt/{package_name}/{rel_path}"
                ti = tarfile.TarInfo(name=tar_path)
                ti.size = st.st_size
                ti.mtime = epoch
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"

                # Check if executable
                is_exec = (
                    rel_path in REQUIRED_PAYLOAD_BINARIES
                    or bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                )
                ti.mode = 0o755 if is_exec else 0o644
                tar.addfile(ti, io.BytesIO(content))

            # 3. Add desktop entry
            ti_desk = tarfile.TarInfo(name=f"./usr/share/applications/{package_name}.desktop")
            ti_desk.size = len(desktop_bytes)
            ti_desk.mode = 0o644
            ti_desk.mtime = epoch
            ti_desk.uid = 0
            ti_desk.gid = 0
            ti_desk.uname = "root"
            ti_desk.gname = "root"
            tar.addfile(ti_desk, io.BytesIO(desktop_bytes))
            total_uncompressed_bytes += len(desktop_bytes)
            md5_entries.append((
                hashlib.md5(desktop_bytes).hexdigest(),
                f"usr/share/applications/{package_name}.desktop",
            ))

            # 4. Add SVG icon
            ti_icon = tarfile.TarInfo(
                name=f"./usr/share/icons/hicolor/scalable/apps/{package_name}.svg"
            )
            ti_icon.size = len(icon_bytes)
            ti_icon.mode = 0o644
            ti_icon.mtime = epoch
            ti_icon.uid = 0
            ti_icon.gid = 0
            ti_icon.uname = "root"
            ti_icon.gname = "root"
            tar.addfile(ti_icon, io.BytesIO(icon_bytes))
            total_uncompressed_bytes += len(icon_bytes)
            md5_entries.append((
                hashlib.md5(icon_bytes).hexdigest(),
                f"usr/share/icons/hicolor/scalable/apps/{package_name}.svg",
            ))

            # 5. Add copyright notice
            ti_copy = tarfile.TarInfo(name=f"./usr/share/doc/{package_name}/copyright")
            ti_copy.size = len(copyright_bytes)
            ti_copy.mode = 0o644
            ti_copy.mtime = epoch
            ti_copy.uid = 0
            ti_copy.gid = 0
            ti_copy.uname = "root"
            ti_copy.gname = "root"
            tar.addfile(ti_copy, io.BytesIO(copyright_bytes))
            total_uncompressed_bytes += len(copyright_bytes)
            md5_entries.append((
                hashlib.md5(copyright_bytes).hexdigest(),
                f"usr/share/doc/{package_name}/copyright",
            ))

            # 6. Add symlinks in /usr/bin/
            for bin_name in ("servonaut", "servonaut-desktop"):
                ti_sym = tarfile.TarInfo(name=f"./usr/bin/{bin_name}")
                ti_sym.type = tarfile.SYMTYPE
                ti_sym.linkname = f"/opt/{package_name}/{bin_name}"
                ti_sym.mode = 0o777
                ti_sym.mtime = epoch
                ti_sym.uid = 0
                ti_sym.gid = 0
                ti_sym.uname = "root"
                ti_sym.gname = "root"
                tar.addfile(ti_sym)

    data_bytes = data_bio.getvalue()

    # Sort md5sums
    md5_entries.sort(key=lambda x: x[1])
    md5sums_content = "".join(f"{h}  {p}\n" for h, p in md5_entries)

    # Installed-Size in KiB
    installed_size_kib = math.ceil(total_uncompressed_bytes / 1024)

    # Build control.tar.gz
    control_bytes = _build_control_tar(
        package_name=package_name,
        version_str=version_str,
        architecture=architecture,
        installed_size_kib=installed_size_kib,
        maintainer=maintainer,
        description=description,
        dependencies=dep_list,
        postinst_content=postinst_content,
        postrm_content=postrm_content,
        md5sums_content=md5sums_content,
        epoch=epoch,
    )

    # Construct the final .deb ar archive
    deb_binary = b"2.0\n"
    deb_content = (
        b"!<arch>\n"
        + _format_ar_member("debian-binary", deb_binary, epoch)
        + _format_ar_member("control.tar.gz", control_bytes, epoch)
        + _format_ar_member("data.tar.gz", data_bytes, epoch)
    )

    # Output file
    deb_filename = filename or f"{package_name}_{version_str}_{architecture}.deb"
    dest_path = out_dir / deb_filename
    dest_path.write_bytes(deb_content)

    hasher = hashlib.sha256()
    with open(dest_path, "rb") as f:
        while chunk := f.read(64 * 1024):
            hasher.update(chunk)

    sha256 = hasher.hexdigest().lower()
    byte_size = dest_path.stat().st_size
    return dest_path, sha256, byte_size


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Package a multi-executable desktop onedir payload into a Debian (.deb) package."
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
        help="Directory to write the generated .deb package to.",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Product semantic version (X.Y.Z).",
    )
    parser.add_argument(
        "--revision",
        type=int,
        default=None,
        help="Packaging revision (e.g. 1).",
    )
    parser.add_argument(
        "--arch",
        default="amd64",
        help="Debian architecture (default: amd64).",
    )
    parser.add_argument(
        "--maintainer",
        default="Servonaut Maintainers <support@example.com>",
        help="Package maintainer name and email.",
    )
    parser.add_argument(
        "--package-name",
        default="servonaut",
        help="Debian package name (default: servonaut).",
    )
    parser.add_argument(
        "--epoch",
        type=int,
        default=None,
        help="Timestamp for deterministic packaging (defaults to SOURCE_DATE_EPOCH or 1700000000).",
    )
    parser.add_argument(
        "--filename",
        default=None,
        help="Custom output filename for the .deb archive.",
    )

    args = parser.parse_args(argv)

    try:
        dest_path, sha256, byte_size = package_deb(
            payload_dir=args.payload_dir,
            output_dir=args.output_dir,
            product_version=args.version,
            packaging_revision=args.revision,
            architecture=args.arch,
            maintainer=args.maintainer,
            package_name=args.package_name,
            source_epoch=args.epoch,
            filename=args.filename,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Debian package created: {dest_path}")
    print(f"  SHA-256: {sha256}")
    print(f"  Size:    {byte_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

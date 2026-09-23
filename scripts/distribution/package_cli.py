"""Deterministic packaging for standalone CLI distribution archives."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import os
from pathlib import Path
import stat
import sys
import tarfile
from typing import Optional
import zipfile

_TAR_TARGETS = {"linux-x64-ubuntu-22.04", "macos-x64", "macos-arm64", "linux-x64"}
_ZIP_TARGETS = {"windows-x64"}


def resolve_epoch(source_epoch: Optional[int] = None) -> int:
    """Resolve an integer timestamp for deterministic archive metadata."""
    if source_epoch is not None:
        return source_epoch
    env_val = os.environ.get("SOURCE_DATE_EPOCH")
    if env_val and env_val.isdigit():
        return int(env_val)
    return 1700000000  # Default stable fallback epoch (2023-11-14)


def package_standalone_cli(
    build_dir: Path | str,
    output_dir: Path | str,
    target: str,
    product_version: str,
    *,
    source_epoch: Optional[int] = None,
) -> tuple[Path, str, int]:
    """Package a built standalone CLI directory into a deterministic release archive.

    Returns:
        tuple[Path, str, int]: (archive_path, sha256_hex, byte_size)
    """
    src_dir = Path(build_dir).resolve()
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not src_dir.is_dir():
        raise FileNotFoundError(f"Build directory does not exist: {src_dir}")

    # Check for binary existence
    bin_name = "servonaut.exe" if "windows" in target.lower() else "servonaut"
    main_bin = src_dir / bin_name
    if not main_bin.is_file():
        raise FileNotFoundError(f"Expected executable '{bin_name}' not found in {src_dir}")

    epoch = resolve_epoch(source_epoch)
    is_zip = "windows" in target.lower() or target in _ZIP_TARGETS
    extension = "zip" if is_zip else "tar.gz"
    archive_name = f"servonaut-{product_version}-{target}.{extension}"
    dest_path = out_dir / archive_name

    # Collect and sort all files deterministically
    entries: list[tuple[Path, str]] = []
    for root, dirs, files in os.walk(src_dir):
        dirs.sort()
        for f in sorted(files):
            file_path = Path(root) / f
            rel_path = file_path.relative_to(src_dir).as_posix()
            entries.append((file_path, rel_path))

    entries.sort(key=lambda x: x[1])

    if is_zip:
        _write_deterministic_zip(entries, dest_path, epoch)
    else:
        _write_deterministic_tar_gz(entries, dest_path, epoch)

    hasher = hashlib.sha256()
    with open(dest_path, "rb") as f:
        while chunk := f.read(64 * 1024):
            hasher.update(chunk)

    sha256 = hasher.hexdigest().lower()
    byte_size = dest_path.stat().st_size
    return dest_path, sha256, byte_size


def _write_deterministic_tar_gz(
    entries: list[tuple[Path, str]],
    dest_path: Path,
    epoch: int,
) -> None:
    temp_dest = dest_path.with_name(f"{dest_path.name}.tmp")
    try:
        with open(temp_dest, "wb") as raw_f:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_f, mtime=epoch) as gz_f:
                with tarfile.open(mode="w", fileobj=gz_f) as tar:
                    for src_file, rel_name in entries:
                        st = src_file.stat()
                        is_exec = (st.st_mode & 0o111) != 0
                        mode = 0o755 if is_exec else 0o644

                        info = tarfile.TarInfo(name=rel_name)
                        info.size = st.st_size
                        info.mtime = epoch
                        info.mode = mode
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""

                        with open(src_file, "rb") as content_f:
                            tar.addfile(info, content_f)

        temp_dest.replace(dest_path)
    finally:
        if temp_dest.exists():
            temp_dest.unlink(missing_ok=True)


def _write_deterministic_zip(
    entries: list[tuple[Path, str]],
    dest_path: Path,
    epoch: int,
) -> None:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    # Zip timestamps cannot be earlier than 1980
    year = max(dt.year, 1980)
    zip_time = (year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

    temp_dest = dest_path.with_name(f"{dest_path.name}.tmp")
    try:
        with zipfile.ZipFile(temp_dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for src_file, rel_name in entries:
                st = src_file.stat()
                is_exec = (st.st_mode & 0o111) != 0
                mode = 0o755 if is_exec else 0o644

                zinfo = zipfile.ZipInfo(filename=rel_name, date_time=zip_time)
                # Upper 16 bits of external_attr store POSIX permissions
                zinfo.external_attr = (mode & 0xFFFF) << 16
                zinfo.compress_type = zipfile.ZIP_DEFLATED

                with open(src_file, "rb") as content_f:
                    zf.writestr(zinfo, content_f.read())

        temp_dest.replace(dest_path)
    finally:
        if temp_dest.exists():
            temp_dest.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Package standalone CLI into release archives.")
    parser.add_argument("--build-dir", required=True, type=Path, help="Path to built standalone directory")
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory to save packaged archive")
    parser.add_argument("--target", required=True, type=str, help="Target name (e.g. linux-x64-ubuntu-22.04)")
    parser.add_argument("--version", required=True, type=str, help="Product version (X.Y.Z)")
    parser.add_argument("--epoch", type=int, default=None, help="SOURCE_DATE_EPOCH override")

    args = parser.parse_args()
    archive_path, sha256, size = package_standalone_cli(
        args.build_dir,
        args.output_dir,
        args.target,
        args.version,
        source_epoch=args.epoch,
    )
    print(f"Created {archive_path.name} (SHA-256: {sha256}, size: {size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Deterministic packaging for standalone CLI distribution archives."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import os
from pathlib import Path
import sys
import tarfile
from typing import Optional
import zipfile

from scripts.distribution.payload_tree import walk_payload
from scripts.standalone_cli.artifact_types import PayloadEntry
from scripts.standalone_cli.model import load_target_spec

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TARGET_POLICY = _REPO_ROOT / "packaging" / "standalone_cli" / "target-policy.json"


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

    Symbolic links are archived as links and must resolve inside the build
    directory; Windows zip archives cannot contain them at all.

    Returns:
        tuple[Path, str, int]: (archive_path, sha256_hex, byte_size)

    Raises:
        BuildValidationError: If the target is not defined by the standalone target policy.
        PayloadTreeError: If the build directory holds an unsafe or unsupported entry.
    """
    spec = load_target_spec(_TARGET_POLICY, target)
    src_dir = Path(build_dir).resolve()

    if not src_dir.is_dir():
        raise FileNotFoundError(f"Build directory does not exist: {src_dir}")

    # Check for binary existence
    bin_name = "servonaut.exe" if spec.platform == "win32" else "servonaut"
    main_bin = src_dir / bin_name
    if not main_bin.is_file():
        raise FileNotFoundError(f"Expected executable '{bin_name}' not found in {src_dir}")

    is_zip = spec.archive_format == "zip"
    entries = [
        entry
        for entry in walk_payload(src_dir, allow_symlinks=not is_zip)
        if entry.kind != "directory"
    ]

    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    epoch = resolve_epoch(source_epoch)
    archive_name = spec.artifact_name_template.format(
        product_version=product_version,
        target=spec.name,
        extension=spec.archive_extension,
    )
    dest_path = out_dir / archive_name

    if is_zip:
        _write_deterministic_zip(src_dir, entries, dest_path, epoch)
    else:
        _write_deterministic_tar_gz(src_dir, entries, dest_path, epoch)

    hasher = hashlib.sha256()
    with open(dest_path, "rb") as f:
        while chunk := f.read(64 * 1024):
            hasher.update(chunk)

    sha256 = hasher.hexdigest().lower()
    byte_size = dest_path.stat().st_size
    return dest_path, sha256, byte_size


def _archive_mode(entry: PayloadEntry) -> int:
    """Normalise permissions to 0o755 for executables and 0o644 otherwise."""
    return 0o755 if entry.mode & 0o111 else 0o644


def _write_deterministic_tar_gz(
    src_dir: Path,
    entries: list[PayloadEntry],
    dest_path: Path,
    epoch: int,
) -> None:
    temp_dest = dest_path.with_name(f"{dest_path.name}.tmp")
    try:
        with open(temp_dest, "wb") as raw_f:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_f, mtime=epoch) as gz_f:
                with tarfile.open(mode="w", fileobj=gz_f) as tar:
                    for entry in entries:
                        info = tarfile.TarInfo(name=entry.relative_path.as_posix())
                        info.mtime = epoch
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""

                        if entry.kind == "symlink":
                            info.type = tarfile.SYMTYPE
                            info.linkname = entry.link_target or ""
                            info.mode = 0o777
                            tar.addfile(info)
                            continue

                        info.size = entry.size
                        info.mode = _archive_mode(entry)
                        with open(src_dir / entry.relative_path, "rb") as content_f:
                            tar.addfile(info, content_f)

        temp_dest.replace(dest_path)
    finally:
        if temp_dest.exists():
            temp_dest.unlink(missing_ok=True)


def _write_deterministic_zip(
    src_dir: Path,
    entries: list[PayloadEntry],
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
            for entry in entries:
                zinfo = zipfile.ZipInfo(filename=entry.relative_path.as_posix(), date_time=zip_time)
                # Upper 16 bits of external_attr store POSIX permissions
                zinfo.external_attr = (_archive_mode(entry) & 0xFFFF) << 16
                zinfo.compress_type = zipfile.ZIP_DEFLATED

                with open(src_dir / entry.relative_path, "rb") as content_f:
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

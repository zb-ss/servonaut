"""Inspection engine for Servonaut desktop onedir payloads."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import stat
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from scripts.desktop_shell.assets import AssetPolicyError, verify_staged_assets
from scripts.desktop_shell.model import (
    EMBEDDED_NOTICE_POLICY_PATH,
    EXECUTABLE_ROLES,
    PAYLOAD_NOTICES_DIRECTORY,
    PYINSTALLER_WARNING_NAME,
    RUNTIME_NOTICE_NAME,
    VOICE_PAYLOAD_DIRECTORY,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    executable_toc_directory,
    load_assets_lock,
    load_desktop_build_policy,
    load_desktop_target_spec,
    load_frontend_licenses,
    load_size_baseline,
    load_voice_runtime_policy,
    uv_executable_name,
)
from scripts.desktop_shell.native_headers import (
    NativeHeaderError,
    is_macho_file,
    macho_minimum_macos,
    read_native_identity,
)
from scripts.desktop_shell.voice_bundle import VoiceBundleError, verify_voice_bundle
from scripts.standalone_cli.artifact_filesystem import matches_forbidden_path
from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadEntry,
    PayloadSnapshot,
)
from scripts.standalone_cli.embedded_notices import load_embedded_notice_policy
from scripts.standalone_cli.model import BuildValidationError
from scripts.standalone_cli.release_identity import (
    ReleaseIdentityError,
    validate_marker_identity,
)
from scripts.standalone_cli.toc_policy import validate_toc_policy

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"
_EXPECTED_FORMATS = {"win32": "pe", "linux": "elf", "darwin": "macho"}
_TOC_NAMES = ("Analysis-00.toc", "PYZ-00.toc")


class DesktopInspectionError(ValueError):
    """Raised when a desktop payload violates inspection policy."""


@dataclass(frozen=True)
class DesktopInspectionReport:
    """Audited inspection facts for a verified desktop onedir payload."""

    payload_root: str
    target: str
    product_version: str
    gui_executable: str
    child_executable: str
    console_executable: str
    marker_valid: bool
    assets_verified_count: int
    licenses_verified_count: int
    notices_verified_count: int
    voice_files_verified_count: int
    expanded_bytes: int
    regular_file_count: int
    binary_formats: dict[str, str]


def _verify_executable(
    exe_path: Path,
    target: DesktopTargetSpec,
    *,
    label: str,
) -> str:
    """Verify single executable file properties, format and CPU architecture."""
    if not exe_path.exists():
        raise DesktopInspectionError(f"{label} does not exist: {exe_path.name}")
    if exe_path.is_symlink():
        raise DesktopInspectionError(f"{label} must not be a symlink: {exe_path.name}")
    if not exe_path.is_file():
        raise DesktopInspectionError(f"{label} must be a regular file: {exe_path.name}")

    if target.platform != "win32" and not exe_path.stat().st_mode & 0o111:
        raise DesktopInspectionError(f"{label} is not executable: {exe_path.name}")

    expected_format = _EXPECTED_FORMATS[target.platform]
    try:
        identity = read_native_identity(exe_path)
    except NativeHeaderError as error:
        raise DesktopInspectionError(f"{label} header is invalid: {error}") from error
    fmt = "unknown" if identity is None else identity.format
    if identity is None or fmt != expected_format:
        raise DesktopInspectionError(
            f"{label} format {fmt!r} does not match expected {expected_format!r}"
        )
    if identity.architecture != target.architecture:
        raise DesktopInspectionError(
            f"{label} architecture {identity.architecture!r} does not match "
            f"target {target.architecture!r}"
        )
    return fmt


def _verify_marker(
    payload_root: Path, target: DesktopTargetSpec, product_version: str
) -> dict[str, object]:
    """Assert runtime marker validity and role alignment."""
    marker_path = payload_root / "servonaut-runtime.json"
    if not marker_path.is_file():
        raise DesktopInspectionError(
            "servonaut-runtime.json marker missing from payload root"
        )

    try:
        raw = json.loads(marker_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise DesktopInspectionError(
            f"Malformed JSON in runtime marker: {err}"
        ) from err

    if not isinstance(raw, dict):
        raise DesktopInspectionError("Runtime marker must be a JSON object")

    if raw.get("schema_version") != 1:
        raise DesktopInspectionError(
            f"Unsupported schema_version: {raw.get('schema_version')}"
        )

    if raw.get("distribution") != "packaged-desktop":
        raise DesktopInspectionError(
            f"Unexpected distribution: {raw.get('distribution')}"
        )

    if raw.get("product_version") != product_version:
        raise DesktopInspectionError(
            f"Product version mismatch in marker: {raw.get('product_version')} != {product_version}"
        )
    try:
        validate_marker_identity(raw)
    except ReleaseIdentityError as err:
        raise DesktopInspectionError(str(err)) from None

    ext = ".exe" if target.platform == "win32" else ""
    expected_console = f"servonaut{ext}"
    expected_child = f"servonaut-desktop-child{ext}"

    if raw.get("console_helper") != expected_console:
        raise DesktopInspectionError(
            f"Marker console_helper mismatch: {raw.get('console_helper')} != {expected_console}"
        )
    if raw.get("desktop_child") != expected_child:
        raise DesktopInspectionError(
            f"Marker desktop_child mismatch: {raw.get('desktop_child')} != {expected_child}"
        )
    return raw


def _read_build_provenance(
    build_metadata_dir: Path, target: DesktopTargetSpec, product_version: str
) -> dict[str, object]:
    """Bind the build metadata to the inspected target and product version."""
    try:
        raw = json.loads(
            (build_metadata_dir / "dependency-provenance.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DesktopInspectionError("build provenance is unavailable") from error
    if (
        not isinstance(raw, dict)
        or raw.get("target") != target.name
        or raw.get("product_version") != product_version
    ):
        raise DesktopInspectionError(
            "build metadata does not belong to the inspected target and version"
        )
    return raw


def _payload_snapshot(
    payload_root: Path,
    gui_path: Path,
    marker: dict[str, object],
    provenance: dict[str, object],
) -> PayloadSnapshot:
    """Record every payload entry from lstat without following links."""
    entries: list[PayloadEntry] = []
    for current, directories, files in os.walk(payload_root):
        for name in sorted((*directories, *files)):
            entries.append(_payload_entry(payload_root, Path(current) / name))
    return PayloadSnapshot(
        root=payload_root,
        entries=tuple(entries),
        expanded_regular_bytes=sum(
            entry.size for entry in entries if entry.kind == "file"
        ),
        executable_relative_path=PurePosixPath(gui_path.name),
        marker=MappingProxyType(marker),
        build_provenance=MappingProxyType(provenance),
        build_toolchain=MappingProxyType({}),
    )


def _payload_entry(payload_root: Path, path: Path) -> PayloadEntry:
    status = path.lstat()
    relative = PurePosixPath(path.relative_to(payload_root).as_posix())
    if stat.S_ISLNK(status.st_mode):
        return PayloadEntry(
            relative, "symlink", status.st_mode, 0, None, os.readlink(path)
        )
    if stat.S_ISDIR(status.st_mode):
        return PayloadEntry(relative, "directory", status.st_mode, 0, None, None)
    if stat.S_ISREG(status.st_mode):
        return PayloadEntry(relative, "file", status.st_mode, status.st_size, None, None)
    raise DesktopInspectionError(f"Payload contains an unsupported file type: {relative}")


def _verify_voice_bundle(
    payload_root: Path, target: DesktopTargetSpec, product_version: str
) -> int:
    """Require exactly the managed voice runtime inputs, matching their manifest."""
    voice_dir = payload_root.joinpath(*VOICE_PAYLOAD_DIRECTORY.parts)
    _verify_executable(
        voice_dir / uv_executable_name(target.platform), target, label="Voice runtime uv"
    )
    try:
        verify_voice_bundle(
            voice_dir, target, product_version, load_voice_runtime_policy()
        )
    except VoiceBundleError as error:
        raise DesktopInspectionError(f"Voice runtime bundle invalid: {error}") from error
    return len(target.voice_bundle_paths)


def _without_voice_bundle(
    snapshot: PayloadSnapshot, target: DesktopTargetSpec
) -> PayloadSnapshot:
    """Drop the voice bundle files, which _verify_voice_bundle checks one by one.

    Every other path, including anything else under a voice directory, still
    meets the forbidden path policy.
    """
    return dataclasses.replace(
        snapshot,
        entries=tuple(
            entry
            for entry in snapshot.entries
            if entry.kind != "file"
            or not matches_forbidden_path(entry.relative_path, target.voice_bundle_paths)
        ),
    )


def _verify_toc_policy(
    snapshot: PayloadSnapshot,
    target: DesktopTargetSpec,
    executables: dict[str, Path],
    build_metadata_dir: Path,
    max_bytes: int,
) -> None:
    """Reject forbidden payload paths and modules recorded by every executable's TOCs."""
    for role in EXECUTABLE_ROLES:
        toc_root = executable_toc_directory(build_metadata_dir, role)
        for name in _TOC_NAMES:
            if not (toc_root / "pyinstaller" / name).is_file():
                raise DesktopInspectionError(f"{role} executable {name} is missing")
        # The TOC policy reads only the payload entries, the target's forbidden
        # module and path lists, and <build_metadata_dir>/pyinstaller.
        descriptor = ArtifactDescriptor(
            payload_root=snapshot.root,
            executable=executables[role],
            archive=None,
            target=target,
            wheel=Path(),
            pyinstaller_warning_file=build_metadata_dir
            / "pyinstaller"
            / PYINSTALLER_WARNING_NAME,
            build_metadata_dir=toc_root,
        )
        try:
            validate_toc_policy(snapshot, descriptor, max_bytes)
        except ArtifactEvidenceError as error:
            raise DesktopInspectionError(
                f"Payload policy violation ({role} executable build record): {error}"
            ) from error


def _verify_frontend(payload_root: Path, target: DesktopTargetSpec) -> tuple[int, int]:
    """Verify every packaged frontend directory holds exactly the staged file set."""
    candidates = (payload_root / "frontend", payload_root / "_internal" / "frontend")
    present = [path for path in candidates if path.is_symlink() or path.exists()]
    if not present:
        raise DesktopInspectionError("frontend directory missing from desktop payload")

    locks = load_assets_lock(target.frontend_assets_lock)
    licenses = load_frontend_licenses(target.frontend_licenses)
    undeclared = {lock.license_id for lock in locks.values()} - set(licenses)
    if undeclared:
        raise DesktopInspectionError(f"Undeclared asset licenses: {sorted(undeclared)}")
    for frontend_dir in present:
        if frontend_dir.is_symlink():
            raise DesktopInspectionError("frontend directory must not be a symlink")
        try:
            verify_staged_assets(
                frontend_dir,
                lock_path=target.frontend_assets_lock,
                licenses_path=target.frontend_licenses,
            )
        except AssetPolicyError as error:
            raise DesktopInspectionError(f"Frontend assets invalid: {error}") from error
    return len(locks), len(licenses)


def _verify_notices(
    payload_root: Path, target: DesktopTargetSpec, max_bytes: int
) -> int:
    """Require exactly the CPython notice and the reviewed third-party notices."""
    try:
        policy = load_embedded_notice_policy(EMBEDDED_NOTICE_POLICY_PATH, max_bytes)
    except BuildValidationError as error:
        raise DesktopInspectionError("embedded notice policy is invalid") from error
    expected: dict[str, str | None] = {RUNTIME_NOTICE_NAME: None}
    for notice in policy:
        expected[notice.payload_path.name] = notice.sha256_by_target[target.name]

    notices_dir = payload_root.joinpath(*PAYLOAD_NOTICES_DIRECTORY.parts)
    if notices_dir.is_symlink() or not notices_dir.is_dir():
        raise DesktopInspectionError("license notices directory missing from payload")
    actual = {path.name for path in notices_dir.iterdir()}
    if actual != set(expected):
        raise DesktopInspectionError(
            "payload notices differ from policy: "
            f"missing {sorted(set(expected) - actual)}, "
            f"unexpected {sorted(actual - set(expected))}"
        )
    for name, expected_sha256 in expected.items():
        data = _read_notice(notices_dir / name, max_bytes)
        if expected_sha256 and hashlib.sha256(data).hexdigest() != expected_sha256:
            raise DesktopInspectionError(f"Notice does not match policy: {name}")
    return len(expected)


def _read_notice(path: Path, max_bytes: int) -> bytes:
    status = path.lstat()
    if not stat.S_ISREG(status.st_mode) or not 0 < status.st_size <= max_bytes:
        raise DesktopInspectionError(
            f"Notice must be a non-empty regular file within limits: {path.name}"
        )
    return path.read_bytes()


def _verify_size_baseline(snapshot: PayloadSnapshot, target: DesktopTargetSpec) -> int:
    """Hold the expanded payload within the target's reviewed size baseline."""
    baseline = load_size_baseline(target.size_baselines, target.name)
    file_count = sum(1 for entry in snapshot.entries if entry.kind == "file")
    if snapshot.expanded_regular_bytes > baseline.max_expanded_bytes:
        raise DesktopInspectionError(
            f"Payload size {snapshot.expanded_regular_bytes} bytes exceeds the "
            f"baseline of {baseline.max_expanded_bytes} bytes"
        )
    if file_count > baseline.max_regular_file_count:
        raise DesktopInspectionError(
            f"Payload file count {file_count} exceeds the baseline of "
            f"{baseline.max_regular_file_count}"
        )
    return file_count


def _verify_macos_binaries(
    snapshot: PayloadSnapshot, target: DesktopTargetSpec, max_bytes: int
) -> None:
    """Require thin, target-architecture Mach-O files within the macOS floor."""
    if target.macos_minimum_version is None:
        raise DesktopInspectionError("macOS target has no minimum version policy")
    floor = tuple(int(part) for part in target.macos_minimum_version.split("."))
    for entry in snapshot.entries:
        path = snapshot.root / entry.relative_path
        if entry.kind != "file" or not is_macho_file(path):
            continue
        try:
            identity = read_native_identity(path)
            minimum = macho_minimum_macos(path, max_bytes)
        except NativeHeaderError as error:
            raise DesktopInspectionError(str(error)) from error
        if identity is None or identity.architecture != target.architecture:
            raise DesktopInspectionError(
                f"Mach-O architecture does not match target: {entry.relative_path}"
            )
        if minimum > floor:
            raise DesktopInspectionError(
                f"Mach-O deployment target {'.'.join(map(str, minimum))} exceeds "
                f"macOS {target.macos_minimum_version}: {entry.relative_path}"
            )


def inspect_desktop_payload(
    payload_root: Path,
    target: DesktopTargetSpec,
    product_version: str,
    build_metadata_dir: Path,
) -> DesktopInspectionReport:
    """Run all inspection gates on a desktop onedir payload and its build metadata."""
    payload_root = payload_root.resolve(strict=True)
    if not payload_root.is_dir():
        raise DesktopInspectionError(f"Payload root is not a directory: {payload_root}")
    build_metadata_dir = build_metadata_dir.resolve(strict=True)
    if not build_metadata_dir.is_dir():
        raise DesktopInspectionError("Build metadata is not a directory")
    policy = load_desktop_build_policy()

    ext = ".exe" if target.platform == "win32" else ""
    executables = {
        "gui": payload_root / f"servonaut-desktop{ext}",
        "child": payload_root / f"servonaut-desktop-child{ext}",
        "console": payload_root / f"servonaut{ext}",
    }
    labels = {"gui": "GUI launcher", "child": "Child executable", "console": "Console helper"}
    formats = {
        role: _verify_executable(path, target, label=labels[role])
        for role, path in executables.items()
    }
    gui_path, child_path, console_path = executables.values()
    if (
        child_path.samefile(console_path)
        or gui_path.samefile(child_path)
        or gui_path.samefile(console_path)
    ):
        raise DesktopInspectionError("All three executables must be distinct files")

    marker = _verify_marker(payload_root, target, product_version)
    provenance = _read_build_provenance(build_metadata_dir, target, product_version)
    snapshot = _payload_snapshot(payload_root, gui_path, marker, provenance)
    voice_count = _verify_voice_bundle(payload_root, target, product_version)
    _verify_toc_policy(
        _without_voice_bundle(snapshot, target),
        target,
        executables,
        build_metadata_dir,
        policy.max_metadata_file_bytes,
    )
    asset_count, license_count = _verify_frontend(payload_root, target)
    notice_count = _verify_notices(payload_root, target, policy.max_metadata_file_bytes)
    file_count = _verify_size_baseline(snapshot, target)
    if target.platform == "darwin":
        _verify_macos_binaries(snapshot, target, policy.max_metadata_file_bytes)

    return DesktopInspectionReport(
        payload_root=str(payload_root),
        target=target.name,
        product_version=product_version,
        gui_executable=str(gui_path),
        child_executable=str(child_path),
        console_executable=str(console_path),
        marker_valid=True,
        assets_verified_count=asset_count,
        licenses_verified_count=license_count,
        notices_verified_count=notice_count,
        voice_files_verified_count=voice_count,
        expanded_bytes=snapshot.expanded_regular_bytes,
        regular_file_count=file_count,
        binary_formats=formats,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for desktop payload inspection."""
    parser = argparse.ArgumentParser(
        description="Inspect Servonaut desktop onedir payload."
    )
    parser.add_argument(
        "--payload", "--payload-root", dest="payload", type=Path, required=True
    )
    parser.add_argument("--build-metadata", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--policy", type=Path, default=_POLICY_PATH)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--output", type=Path)

    args = parser.parse_args(argv)
    try:
        target_spec = load_desktop_target_spec(args.policy, args.target)
        report = inspect_desktop_payload(
            payload_root=args.payload,
            target=target_spec,
            product_version=args.product_version,
            build_metadata_dir=args.build_metadata,
        )
        report_data = asdict(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(report_data, indent=2) + "\n", encoding="utf-8"
            )
        else:
            print(json.dumps(report_data, indent=2))
    except (DesktopInspectionError, DesktopPolicyValidationError, OSError) as err:
        parser.error(str(err))

    return 0


if __name__ == "__main__":
    sys.exit(main())

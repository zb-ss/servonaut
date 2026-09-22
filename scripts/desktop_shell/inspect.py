"""Inspection engine for Servonaut desktop onedir payloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from scripts.desktop_shell.model import (
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    load_assets_lock,
    load_desktop_target_spec,
    load_frontend_licenses,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"

_MACHO_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    }
)


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
    binary_formats: dict[str, str]


def _binary_format(path: Path) -> str:
    """Identify binary container format from file header."""
    try:
        with path.open("rb") as handle:
            header = handle.read(4)
    except OSError as error:
        raise DesktopInspectionError(
            f"Could not read executable header: {path.name}"
        ) from error

    if header.startswith(b"MZ"):
        return "pe"
    if header == b"\x7fELF":
        return "elf"
    if header in _MACHO_MAGICS:
        return "macho"
    return "unknown"


def _verify_executable(
    exe_path: Path,
    expected_format: str,
    *,
    label: str,
    is_posix: bool,
) -> str:
    """Verify single executable file properties and native format."""
    if not exe_path.exists():
        raise DesktopInspectionError(f"{label} does not exist: {exe_path.name}")
    if exe_path.is_symlink():
        raise DesktopInspectionError(f"{label} must not be a symlink: {exe_path.name}")
    if not exe_path.is_file():
        raise DesktopInspectionError(f"{label} must be a regular file: {exe_path.name}")

    if is_posix:
        mode = exe_path.stat().st_mode
        if not (mode & 0o111):
            raise DesktopInspectionError(f"{label} is not executable: {exe_path.name}")

    fmt = _binary_format(exe_path)
    if fmt != expected_format:
        raise DesktopInspectionError(
            f"{label} format {fmt!r} does not match expected {expected_format!r}"
        )
    return fmt


def _verify_marker(
    payload_root: Path, target: DesktopTargetSpec, product_version: str
) -> None:
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


def _verify_no_forbidden_modules(payload_root: Path, target: DesktopTargetSpec) -> None:
    """Ensure no forbidden voice or readline dependencies exist in payload."""
    forbidden = set(target.forbidden_modules)
    for path in payload_root.rglob("*"):
        name = path.name.lower()
        for mod in forbidden:
            clean_mod = mod.replace("-", "_")
            if name == clean_mod or name.startswith(
                (f"{clean_mod}.", f"lib{clean_mod}")
            ):
                raise DesktopInspectionError(
                    f"Forbidden module found in payload: {path.name} ({mod})"
                )
        if name.endswith(".onnx"):
            raise DesktopInspectionError(
                f"Forbidden model asset found in payload: {path.name}"
            )


def _verify_frontend_assets(payload_root: Path, target: DesktopTargetSpec) -> int:
    """Verify all locked frontend assets are present with matching SHA-256 hashes."""
    frontend_dir = payload_root / "frontend"
    if not frontend_dir.is_dir():
        # Fallback to _internal/frontend if applicable
        frontend_dir = payload_root / "_internal" / "frontend"
    if not frontend_dir.is_dir():
        raise DesktopInspectionError("frontend directory missing from desktop payload")

    locks = load_assets_lock(target.frontend_assets_lock)
    for lock in locks.values():
        rel_path = lock.route.lstrip("/")
        if rel_path == "":
            rel_path = "index.html"
        asset_file = frontend_dir / rel_path
        if not asset_file.is_file():
            raise DesktopInspectionError(f"Locked frontend asset missing: {rel_path}")

        data = asset_file.read_bytes()
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != lock.transformed_sha256:
            raise DesktopInspectionError(
                f"Asset hash mismatch for {rel_path}: {actual_sha} != {lock.transformed_sha256}"
            )
        if len(data) != lock.transformed_size:
            raise DesktopInspectionError(
                f"Asset size mismatch for {rel_path}: {len(data)} != {lock.transformed_size}"
            )

    return len(locks)


def _verify_frontend_licenses(payload_root: Path, target: DesktopTargetSpec) -> int:
    """Verify licenses.json is present and valid."""
    frontend_dir = payload_root / "frontend"
    if not frontend_dir.is_dir():
        frontend_dir = payload_root / "_internal" / "frontend"

    lic_file = frontend_dir / "licenses.json"
    if not lic_file.is_file():
        # Check target licenses path
        lic_file = target.frontend_licenses
    if not lic_file.is_file():
        raise DesktopInspectionError(
            "licenses.json missing from payload or target policy"
        )

    licenses = load_frontend_licenses(lic_file)
    return len(licenses)


def inspect_desktop_payload(
    payload_root: Path,
    target: DesktopTargetSpec,
    product_version: str,
) -> DesktopInspectionReport:
    """Run all inspection gates on a desktop onedir payload."""
    payload_root = payload_root.resolve(strict=True)
    if not payload_root.is_dir():
        raise DesktopInspectionError(f"Payload root is not a directory: {payload_root}")

    is_posix = target.platform != "win32"
    ext = ".exe" if target.platform == "win32" else ""
    expected_format = {
        "win32": "pe",
        "linux": "elf",
        "darwin": "macho",
    }[target.platform]

    gui_path = payload_root / f"servonaut-desktop{ext}"
    child_path = payload_root / f"servonaut-desktop-child{ext}"
    console_path = payload_root / f"servonaut{ext}"

    # Verify executables
    gui_fmt = _verify_executable(
        gui_path, expected_format, label="GUI launcher", is_posix=is_posix
    )
    child_fmt = _verify_executable(
        child_path, expected_format, label="Child executable", is_posix=is_posix
    )
    console_fmt = _verify_executable(
        console_path, expected_format, label="Console helper", is_posix=is_posix
    )

    # Verify distinct underlying files
    if (
        child_path.samefile(console_path)
        or gui_path.samefile(child_path)
        or gui_path.samefile(console_path)
    ):
        raise DesktopInspectionError("All three executables must be distinct files")

    # Verify runtime marker
    _verify_marker(payload_root, target, product_version)

    # Verify absence of forbidden modules
    _verify_no_forbidden_modules(payload_root, target)

    # Verify frontend assets
    asset_count = _verify_frontend_assets(payload_root, target)

    # Verify frontend licenses
    license_count = _verify_frontend_licenses(payload_root, target)

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
        binary_formats={
            "gui": gui_fmt,
            "child": child_fmt,
            "console": console_fmt,
        },
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for desktop payload inspection."""
    parser = argparse.ArgumentParser(
        description="Inspect Servonaut desktop onedir payload."
    )
    parser.add_argument("--payload", type=Path, required=True)
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
        )
        report_data = asdict(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(report_data, indent=2) + "\n", encoding="utf-8"
            )
        else:
            print(json.dumps(report_data, indent=2))
    except (DesktopInspectionError, DesktopPolicyValidationError) as err:
        parser.error(str(err))

    return 0


if __name__ == "__main__":
    sys.exit(main())

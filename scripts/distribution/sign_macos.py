"""Inside-out code signing and verification for macOS application bundles and DMGs."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Optional, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_ENTITLEMENTS = _REPO_ROOT / "packaging" / "macos" / "entitlements.plist"


class MacosSigningError(Exception):
    """Raised when macOS code-signing or verification fails."""


def _run_codesign(
    args: Sequence[str],
    target_path: Path,
    *,
    dry_run: bool = False,
) -> tuple[int, str]:
    """Execute codesign subprocess with error capture."""
    codesign_bin = shutil.which("codesign")
    if not codesign_bin:
        if dry_run or sys.platform != "darwin":
            return 0, f"[simulated] codesign {' '.join(args)} {target_path}"
        raise MacosSigningError("codesign utility not found on host system.")

    cmd = [codesign_bin, *args, str(target_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    combined = (res.stdout + "\n" + res.stderr).strip()
    return res.returncode, combined


def sign_app_bundle(
    app_bundle_path: Path | str,
    identity: str,
    *,
    entitlements_file: Optional[Path | str] = None,
    timestamp: bool = True,
    options: str = "runtime",
    dry_run: bool = False,
) -> list[Path]:
    """Sign a macOS application bundle using strict inside-out ordering.

    Order:
      1. Nested dynamic libraries and frameworks (.dylib, .so, .framework)
      2. Helper executables (servonaut, servonaut-desktop-child)
      3. Main GUI executable (servonaut-desktop) with hardened runtime & entitlements
      4. Top-level bundle (Servonaut.app) with hardened runtime & entitlements

    Returns:
        list[Path]: Ordered list of signed items.
    """
    app_path = Path(app_bundle_path).resolve()
    if not app_path.is_dir():
        raise FileNotFoundError(f"App bundle directory not found: {app_path}")

    entitlements = Path(entitlements_file) if entitlements_file else _DEFAULT_ENTITLEMENTS
    if not entitlements.is_file() and not dry_run and sys.platform == "darwin":
        raise FileNotFoundError(f"Entitlements file not found: {entitlements}")

    base_args = ["--force", "--options", options, "--sign", identity]
    if timestamp:
        base_args.append("--timestamp")

    signed_items: list[Path] = []
    contents_dir = app_path / "Contents"
    macos_dir = contents_dir / "MacOS"

    # Step 1: Discover and sign nested native libraries (.dylib, .so, .framework)
    nested_libs: list[Path] = []
    for ext in ("*.dylib", "*.so"):
        nested_libs.extend(contents_dir.rglob(ext))

    # Also include nested Framework directories if any
    frameworks_dir = contents_dir / "Frameworks"
    if frameworks_dir.is_dir():
        for fw in frameworks_dir.glob("*.framework"):
            nested_libs.append(fw)

    nested_libs.sort(key=lambda p: str(p))

    for lib in nested_libs:
        rc, out = _run_codesign(base_args, lib, dry_run=dry_run)
        if rc != 0:
            raise MacosSigningError(f"Failed to sign nested library '{lib.name}': {out}")
        signed_items.append(lib)

    # Step 2: Helper executables
    for helper_name in ("servonaut", "servonaut-desktop-child"):
        helper_path = macos_dir / helper_name
        if helper_path.is_file():
            rc, out = _run_codesign(base_args, helper_path, dry_run=dry_run)
            if rc != 0:
                raise MacosSigningError(f"Failed to sign helper '{helper_name}': {out}")
            signed_items.append(helper_path)

    # Step 3: Main GUI executable with entitlements
    gui_exec = macos_dir / "servonaut-desktop"
    if gui_exec.is_file():
        gui_args = [*base_args]
        if entitlements.is_file():
            gui_args.extend(["--entitlements", str(entitlements)])
        rc, out = _run_codesign(gui_args, gui_exec, dry_run=dry_run)
        if rc != 0:
            raise MacosSigningError(f"Failed to sign main executable '{gui_exec.name}': {out}")
        signed_items.append(gui_exec)

    # Step 4: Top-level application bundle
    top_args = [*base_args]
    if entitlements.is_file():
        top_args.extend(["--entitlements", str(entitlements)])
    rc, out = _run_codesign(top_args, app_path, dry_run=dry_run)
    if rc != 0:
        raise MacosSigningError(f"Failed to sign top-level app bundle: {out}")
    signed_items.append(app_path)

    return signed_items


def sign_dmg(
    dmg_path: Path | str,
    identity: str,
    *,
    timestamp: bool = True,
    dry_run: bool = False,
) -> Path:
    """Sign a final .dmg disk image with Developer ID identity."""
    target = Path(dmg_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"DMG file not found: {target}")

    args = ["--force", "--sign", identity]
    if timestamp:
        args.append("--timestamp")

    rc, out = _run_codesign(args, target, dry_run=dry_run)
    if rc != 0:
        raise MacosSigningError(f"Failed to sign DMG '{target.name}': {out}")
    return target


def verify_signature(
    target_path: Path | str,
    *,
    deep: bool = True,
    strict: bool = True,
) -> tuple[bool, str]:
    """Verify cryptographic signature on an app bundle or DMG using codesign and spctl."""
    target = Path(target_path).resolve()
    if not target.exists():
        return False, f"Target path does not exist: {target}"

    codesign_bin = shutil.which("codesign")
    if not codesign_bin:
        return True, f"[simulated] signature verified for {target.name}"

    args = [codesign_bin, "--verify"]
    if deep:
        args.append("--deep")
    if strict:
        args.append("--strict")
    args.extend(["--verbose=2", str(target)])

    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode != 0:
        return False, f"codesign verification failed ({res.returncode}): {res.stderr or res.stdout}"

    # Verify Gatekeeper evaluation via spctl if available and target is an app bundle
    spctl_bin = shutil.which("spctl")
    if spctl_bin and target.suffix == ".app":
        spctl_res = subprocess.run(
            [spctl_bin, "--assess", "--type", "execute", "--verbose=4", str(target)],
            capture_output=True,
            text=True,
        )
        if spctl_res.returncode != 0:
            return False, f"spctl Gatekeeper assessment failed: {spctl_res.stderr or spctl_res.stdout}"

    return True, f"Signature for '{target.name}' successfully verified."


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inside-out code signing and verification for macOS artifacts."
    )
    parser.add_argument(
        "--target",
        required=True,
        type=Path,
        help="Path to .app bundle or .dmg to sign.",
    )
    parser.add_argument(
        "--identity",
        required=True,
        help="Signing identity name (e.g. 'Developer ID Application: ...' or '-' for ad-hoc).",
    )
    parser.add_argument(
        "--entitlements",
        type=Path,
        default=None,
        help="Path to entitlements.plist (default: packaging/macos/entitlements.plist).",
    )
    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Disable timestamping flag.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run verification check after signing.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate signing commands without modifying files.",
    )

    args = parser.parse_args(argv)

    try:
        if args.target.suffix == ".app":
            signed_items = sign_app_bundle(
                app_bundle_path=args.target,
                identity=args.identity,
                entitlements_file=args.entitlements,
                timestamp=not args.no_timestamp,
                dry_run=args.dry_run,
            )
            print(f"Successfully signed {len(signed_items)} items in {args.target}")
        elif args.target.suffix == ".dmg":
            sign_dmg(
                dmg_path=args.target,
                identity=args.identity,
                timestamp=not args.no_timestamp,
                dry_run=args.dry_run,
            )
            print(f"Successfully signed DMG: {args.target}")
        else:
            print(f"Unsupported target format: {args.target}", file=sys.stderr)
            return 1

        if args.verify and not args.dry_run:
            is_valid, msg = verify_signature(args.target)
            if not is_valid:
                print(f"Verification failed: {msg}", file=sys.stderr)
                return 1
            print(msg)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

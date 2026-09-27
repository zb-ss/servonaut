"""Inside-out code signing and verification for macOS application bundles and DMGs.

The bundle must already have the signable layout of
:mod:`scripts.distribution.macos_layout`. Every piece of code is signed on its
own, innermost first, and never with ``--deep``, so the signing of the bundle
does not reach code that keeps its publisher's signature.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
from typing import Optional, Sequence

from scripts.desktop_shell.native_headers import NativeHeaderError, is_macho_file
from scripts.distribution.macos_layout import (
    EXECUTABLES,
    FRAMEWORKS_DIR,
    MACOS_DIR,
    MacosLayoutError,
    verify_app_layout,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MACOS_PACKAGING = _REPO_ROOT / "packaging" / "macos"
_DEFAULT_ENTITLEMENTS = _MACOS_PACKAGING / "entitlements.plist"
_DEFAULT_HELPER_ENTITLEMENTS = _MACOS_PACKAGING / "helper-entitlements.plist"

AD_HOC_IDENTITY = "-"
MAIN_EXECUTABLE = EXECUTABLES[0]
HELPER_EXECUTABLES: tuple[str, ...] = EXECUTABLES[1:]
# Code that keeps its publisher's signature. The packaged voice manifest pins
# the SHA-256 of the bundled uv, so re-signing it would stop voice from
# installing; its Developer ID signature is sealed into the bundle as it is.
PRESERVED_SIGNATURES: tuple[PurePosixPath, ...] = (FRAMEWORKS_DIR / "voice" / "uv",)


class MacosSigningError(Exception):
    """Raised when macOS code-signing or verification fails."""


def _require_codesign() -> str:
    codesign_bin = shutil.which("codesign")
    if not codesign_bin:
        raise MacosSigningError("codesign utility not found on host system.")
    return codesign_bin


def _run_codesign(
    args: Sequence[str],
    target_path: Path,
    *,
    dry_run: bool = False,
) -> tuple[int, str]:
    """Execute codesign subprocess with error capture; a dry run only reports the command."""
    if dry_run:
        return 0, f"[simulated] codesign {' '.join(args)} {target_path}"

    cmd = [_require_codesign(), *args, str(target_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    combined = (res.stdout + "\n" + res.stderr).strip()
    return res.returncode, combined


def _timestamp_args(identity: str, timestamp: Optional[bool]) -> list[str]:
    """A secure timestamp needs a real identity; an ad-hoc signature carries none."""
    use_timestamp = identity != AD_HOC_IDENTITY if timestamp is None else timestamp
    return ["--timestamp"] if use_timestamp else ["--timestamp=none"]


def _entitlements_path(path: Optional[Path | str], default: Path, *, dry_run: bool) -> Path:
    entitlements = Path(path) if path else default
    if not entitlements.is_file() and not dry_run:
        raise FileNotFoundError(f"Entitlements file not found: {entitlements}")
    return entitlements


def nested_code(app_path: Path) -> list[Path]:
    """Return the bundle's nested code in signing order, innermost first.

    That is every Mach-O file below ``Contents/Frameworks`` and
    ``Contents/MacOS`` except the bundle's own executables and the preserved
    signatures, plus every nested ``.framework`` bundle after its contents.
    Links are never followed.
    """
    preserved = {app_path / path for path in PRESERVED_SIGNATURES}
    executables = {app_path / MACOS_DIR / name for name in EXECUTABLES}
    found: list[Path] = []
    for location in (FRAMEWORKS_DIR, MACOS_DIR):
        for directory, subdirectories, files in os.walk(app_path / location):
            for name in subdirectories:
                path = Path(directory) / name
                if name.endswith(".framework") and not path.is_symlink():
                    found.append(path)
            for name in files:
                path = Path(directory) / name
                if path in preserved or path in executables or path.is_symlink():
                    continue
                if _is_code(path):
                    found.append(path)
    return sorted(found, key=lambda path: (-len(path.parts), str(path)))


def _is_code(path: Path) -> bool:
    try:
        return is_macho_file(path)
    except NativeHeaderError as error:
        raise MacosSigningError(str(error)) from error


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sign_app_bundle(
    app_bundle_path: Path | str,
    identity: str,
    *,
    entitlements_file: Optional[Path | str] = None,
    helper_entitlements_file: Optional[Path | str] = None,
    timestamp: Optional[bool] = None,
    options: str = "runtime",
    dry_run: bool = False,
) -> list[Path]:
    """Sign a macOS application bundle using strict inside-out ordering.

    Order:
      1. Nested code: libraries, extension modules and ``.framework`` bundles,
         innermost first, without entitlements.
      2. Helper executables (servonaut-desktop-child, servonaut) with the
         helper entitlements.
      3. The bundle, which signs its main executable (servonaut-desktop), with
         the launcher's entitlements.

    Every step uses the hardened runtime (``options``). ``timestamp`` defaults
    to a secure timestamp for a real identity and none for ad-hoc signing.

    Returns:
        list[Path]: Ordered list of signed items.

    Raises:
        MacosSigningError: When the layout is unsignable, codesign fails or a
            preserved signature changed.
    """
    app_path = Path(app_bundle_path).resolve()
    if not app_path.is_dir():
        raise FileNotFoundError(f"App bundle directory not found: {app_path}")

    entitlements = _entitlements_path(entitlements_file, _DEFAULT_ENTITLEMENTS, dry_run=dry_run)
    helper_entitlements = _entitlements_path(
        helper_entitlements_file, _DEFAULT_HELPER_ENTITLEMENTS, dry_run=dry_run
    )
    try:
        verify_app_layout(app_path)
    except MacosLayoutError as error:
        raise MacosSigningError(f"App bundle layout cannot be signed: {error}") from error

    base_args = [
        "--force",
        "--options",
        options,
        "--sign",
        identity,
        *_timestamp_args(identity, timestamp),
    ]
    preserved = {
        path: _sha256(path)
        for path in (app_path / relative for relative in PRESERVED_SIGNATURES)
        if path.is_file()
    }

    signed_items: list[Path] = []
    for code in nested_code(app_path):
        _sign(base_args, code, "nested code", dry_run=dry_run)
        signed_items.append(code)

    helper_args = [*base_args, "--entitlements", str(helper_entitlements)]
    for helper_name in HELPER_EXECUTABLES:
        helper_path = app_path / MACOS_DIR / helper_name
        if not helper_path.is_file():
            raise MacosSigningError(f"Helper executable missing: {helper_name}")
        _sign(helper_args, helper_path, "helper", dry_run=dry_run)
        signed_items.append(helper_path)

    if not (app_path / MACOS_DIR / MAIN_EXECUTABLE).is_file():
        raise MacosSigningError(f"Main executable missing: {MAIN_EXECUTABLE}")
    _sign([*base_args, "--entitlements", str(entitlements)], app_path, "app bundle", dry_run=dry_run)
    signed_items.append(app_path)

    for path, digest in preserved.items():
        if _sha256(path) != digest:
            raise MacosSigningError(
                f"Signing changed code that keeps its own signature: {path.name}"
            )
    return signed_items


def _sign(args: Sequence[str], target: Path, label: str, *, dry_run: bool) -> None:
    rc, out = _run_codesign(args, target, dry_run=dry_run)
    if rc != 0:
        raise MacosSigningError(f"Failed to sign {label} '{target.name}': {out}")


def sign_dmg(
    dmg_path: Path | str,
    identity: str,
    *,
    timestamp: Optional[bool] = None,
    dry_run: bool = False,
) -> Path:
    """Sign a final .dmg disk image."""
    target = Path(dmg_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"DMG file not found: {target}")

    args = ["--force", "--sign", identity, *_timestamp_args(identity, timestamp)]
    rc, out = _run_codesign(args, target, dry_run=dry_run)
    if rc != 0:
        raise MacosSigningError(f"Failed to sign DMG '{target.name}': {out}")
    return target


def verify_signature(
    target_path: Path | str,
    *,
    deep: bool = True,
    strict: bool = True,
    gatekeeper: bool = True,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """Verify the signature of an app bundle or DMG with codesign and, optionally, spctl.

    ``gatekeeper`` also asks spctl whether Gatekeeper would run an app. It
    rejects every ad-hoc signed app by design, so ad-hoc checks pass False.

    Raises:
        MacosSigningError: If codesign is unavailable outside a dry run.
    """
    target = Path(target_path).resolve()
    if not target.exists():
        return False, f"Target path does not exist: {target}"

    if dry_run:
        return True, f"[simulated] signature verified for {target.name}"

    args = [_require_codesign(), "--verify"]
    if deep:
        args.append("--deep")
    if strict:
        args.append("--strict")
    args.extend(["--verbose=2", str(target)])

    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode != 0:
        return False, f"codesign verification failed ({res.returncode}): {res.stderr or res.stdout}"

    spctl_bin = shutil.which("spctl")
    if gatekeeper and spctl_bin and target.suffix == ".app":
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
        help="Entitlements of the main executable (default: packaging/macos/entitlements.plist).",
    )
    parser.add_argument(
        "--helper-entitlements",
        type=Path,
        default=None,
        help="Entitlements of the helper executables "
        "(default: packaging/macos/helper-entitlements.plist).",
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
    timestamp = False if args.no_timestamp else None

    try:
        if args.target.suffix == ".app":
            signed_items = sign_app_bundle(
                app_bundle_path=args.target,
                identity=args.identity,
                entitlements_file=args.entitlements,
                helper_entitlements_file=args.helper_entitlements,
                timestamp=timestamp,
                dry_run=args.dry_run,
            )
            print(f"Successfully signed {len(signed_items)} items in {args.target}")
        elif args.target.suffix == ".dmg":
            sign_dmg(
                dmg_path=args.target,
                identity=args.identity,
                timestamp=timestamp,
                dry_run=args.dry_run,
            )
            print(f"Successfully signed DMG: {args.target}")
        else:
            print(f"Unsupported target format: {args.target}", file=sys.stderr)
            return 1

        if args.verify and not args.dry_run:
            gatekeeper = args.identity != AD_HOC_IDENTITY
            is_valid, msg = verify_signature(args.target, gatekeeper=gatekeeper)
            if not is_valid:
                print(f"Verification failed: {msg}", file=sys.stderr)
                return 1
            print(msg)
            if not gatekeeper:
                print("Gatekeeper assessment skipped: it rejects ad-hoc signed apps by design.")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

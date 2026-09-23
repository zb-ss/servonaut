"""Inside-out Authenticode code signing and verification for Windows executables, libraries, and MSI packages."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Optional, Sequence

DEFAULT_TIMESTAMP_URL = "http://timestamp.digicert.com"


class WindowsSigningError(Exception):
    """Raised when Windows code signing or signature verification fails."""


def _mask_command_args(cmd: Sequence[str]) -> list[str]:
    """Mask sensitive command-line arguments such as passwords."""
    masked: list[str] = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            masked.append("***MASKED***")
            skip_next = False
            continue
        if arg == "/p" or arg == "-pass" or arg.startswith("/p:"):
            masked.append(arg if not arg.startswith("/p:") else "/p:***MASKED***")
            if arg in ("/p", "-pass") and i + 1 < len(cmd):
                skip_next = True
        else:
            masked.append(arg)
    return masked


def _run_signing_command(
    args: Sequence[str],
    target_path: Path,
    *,
    dry_run: bool = False,
) -> tuple[int, str]:
    """Execute signtool (or osslsigncode) subprocess with sensitive argument masking."""
    signtool_bin = shutil.which("signtool.exe") or shutil.which("signtool")
    osslsigncode_bin = shutil.which("osslsigncode")

    if dry_run or (not signtool_bin and not osslsigncode_bin and sys.platform != "win32"):
        masked = " ".join(_mask_command_args(args))
        return 0, f"[simulated] signtool {masked} {target_path}"

    if not signtool_bin and not osslsigncode_bin:
        raise WindowsSigningError("Neither signtool nor osslsigncode was found on the host system.")

    tool_bin = signtool_bin or osslsigncode_bin
    cmd = [tool_bin, *args, str(target_path)]
    masked_cmd = " ".join(_mask_command_args(cmd))

    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        combined = (res.stdout + "\n" + res.stderr).strip()
        # Clean any accidental secret leak from stderr/stdout
        for a_idx, a_val in enumerate(args):
            if a_val in ("/p", "-pass") and a_idx + 1 < len(args):
                secret = args[a_idx + 1]
                if secret:
                    combined = combined.replace(secret, "***MASKED***")
        return res.returncode, combined
    except Exception as err:
        raise WindowsSigningError(f"Failed to execute signing tool ({masked_cmd}): {err}") from err


def sign_file(
    file_path: Path | str,
    *,
    cert_file: Optional[Path | str] = None,
    cert_thumbprint: Optional[str] = None,
    password: Optional[str] = None,
    timestamp_url: str = DEFAULT_TIMESTAMP_URL,
    dry_run: bool = False,
) -> Path:
    """Sign a single PE executable, DLL, or MSI using Authenticode."""
    target = Path(file_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"File to sign does not exist: {target}")

    if not cert_file and not cert_thumbprint and not dry_run:
        raise WindowsSigningError("Either cert_file or cert_thumbprint must be specified.")

    args: list[str] = ["sign", "/fd", "SHA256"]
    if timestamp_url:
        args.extend(["/tr", timestamp_url, "/td", "SHA256"])

    if cert_thumbprint:
        args.extend(["/sha1", cert_thumbprint])
    elif cert_file:
        cert_p = Path(cert_file).resolve()
        if not cert_p.is_file() and not dry_run:
            raise FileNotFoundError(f"Certificate file not found: {cert_p}")
        args.extend(["/f", str(cert_p)])
        if password:
            args.extend(["/p", password])

    rc, out = _run_signing_command(args, target, dry_run=dry_run)
    if rc != 0:
        raise WindowsSigningError(f"Failed to sign '{target.name}': {out}")

    return target


def sign_payload_binaries(
    payload_dir: Path | str,
    *,
    cert_file: Optional[Path | str] = None,
    cert_thumbprint: Optional[str] = None,
    password: Optional[str] = None,
    timestamp_url: str = DEFAULT_TIMESTAMP_URL,
    dry_run: bool = False,
) -> list[Path]:
    """Sign all binaries in a Windows payload using strict inside-out ordering:

    1. Nested dynamic libraries (.dll, .pyd) in subdirectories
    2. Subsystem helper executables (servonaut.exe, servonaut-desktop-child.exe)
    3. Main GUI launcher (servonaut-desktop.exe)

    Returns:
        list[Path]: Ordered list of signed files.
    """
    src_dir = Path(payload_dir).resolve()
    if not src_dir.is_dir():
        raise FileNotFoundError(f"Payload directory does not exist: {src_dir}")

    signed_files: list[Path] = []

    # 1. Discover nested dynamic libraries (.dll and .pyd)
    nested_libs: list[Path] = []
    for ext in ("*.dll", "*.pyd"):
        nested_libs.extend(src_dir.rglob(ext))

    # Sort deterministically
    nested_libs.sort(key=lambda p: str(p).lower())

    for lib in nested_libs:
        sign_file(
            lib,
            cert_file=cert_file,
            cert_thumbprint=cert_thumbprint,
            password=password,
            timestamp_url=timestamp_url,
            dry_run=dry_run,
        )
        signed_files.append(lib)

    # 2. Subsystem helper executables
    helpers = ["servonaut.exe", "servonaut-desktop-child.exe"]
    for helper_name in helpers:
        helper_path = src_dir / helper_name
        if helper_path.is_file():
            sign_file(
                helper_path,
                cert_file=cert_file,
                cert_thumbprint=cert_thumbprint,
                password=password,
                timestamp_url=timestamp_url,
                dry_run=dry_run,
            )
            signed_files.append(helper_path)

    # 3. Main GUI executable
    gui_path = src_dir / "servonaut-desktop.exe"
    if gui_path.is_file():
        sign_file(
            gui_path,
            cert_file=cert_file,
            cert_thumbprint=cert_thumbprint,
            password=password,
            timestamp_url=timestamp_url,
            dry_run=dry_run,
        )
        signed_files.append(gui_path)

    return signed_files


def sign_msi(
    msi_path: Path | str,
    *,
    cert_file: Optional[Path | str] = None,
    cert_thumbprint: Optional[str] = None,
    password: Optional[str] = None,
    timestamp_url: str = DEFAULT_TIMESTAMP_URL,
    dry_run: bool = False,
) -> Path:
    """Sign a final Windows MSI installer package using Authenticode."""
    target = Path(msi_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"MSI package file not found: {target}")

    return sign_file(
        target,
        cert_file=cert_file,
        cert_thumbprint=cert_thumbprint,
        password=password,
        timestamp_url=timestamp_url,
        dry_run=dry_run,
    )


def verify_signature(
    file_path: Path | str,
    *,
    dry_run: bool = False,
) -> bool:
    """Verify Authenticode signature on an executable or MSI package."""
    target = Path(file_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    signtool_bin = shutil.which("signtool.exe") or shutil.which("signtool")
    osslsigncode_bin = shutil.which("osslsigncode")

    if dry_run or (not signtool_bin and not osslsigncode_bin and sys.platform != "win32"):
        return True

    if not signtool_bin and not osslsigncode_bin:
        raise WindowsSigningError("Neither signtool nor osslsigncode was found to verify signature.")

    if signtool_bin:
        cmd = [signtool_bin, "verify", "/pa", "/v", str(target)]
    else:
        cmd = [osslsigncode_bin, "verify", str(target)]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise WindowsSigningError(f"Signature verification failed for '{target.name}': {res.stderr}\n{res.stdout}")

    return True


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for Windows signing."""
    parser = argparse.ArgumentParser(description="Sign Windows executables, DLLs, and MSI installers with Authenticode.")
    parser.add_argument("--payload-dir", type=Path, default=None, help="Directory of onedir payload to sign inside-out.")
    parser.add_argument("--msi", type=Path, default=None, help="MSI installer package to sign.")
    parser.add_argument("--cert-file", type=Path, default=None, help="Path to code signing certificate (.pfx / .p12).")
    parser.add_argument("--thumbprint", default=None, help="SHA-1 thumbprint of certificate in Windows certificate store.")
    parser.add_argument("--password", default=None, help="Certificate password (or set WINDOWS_SIGNING_PASSWORD env var).")
    parser.add_argument("--timestamp-url", default=DEFAULT_TIMESTAMP_URL, help="RFC 3161 timestamp server URL.")
    parser.add_argument("--dry-run", action="store_true", help="Simulate signing commands without modifying files.")
    parser.add_argument("--verify", action="store_true", help="Verify Authenticode signature.")

    args = parser.parse_args(argv)

    pwd = args.password or os.environ.get("WINDOWS_SIGNING_PASSWORD")

    try:
        if args.verify:
            target = args.msi or args.payload_dir
            if not target:
                parser.error("Specify --msi or --payload-dir with --verify.")
            verify_signature(target, dry_run=args.dry_run)
            print(f"Signature verified successfully for {target}")
            return 0

        if args.payload_dir:
            signed = sign_payload_binaries(
                args.payload_dir,
                cert_file=args.cert_file,
                cert_thumbprint=args.thumbprint,
                password=pwd,
                timestamp_url=args.timestamp_url,
                dry_run=args.dry_run,
            )
            print(f"Signed {len(signed)} payload binaries in inside-out order.")

        if args.msi:
            sign_msi(
                args.msi,
                cert_file=args.cert_file,
                cert_thumbprint=args.thumbprint,
                password=pwd,
                timestamp_url=args.timestamp_url,
                dry_run=args.dry_run,
            )
            print(f"Signed MSI installer package: {args.msi}")

        return 0
    except Exception as err:
        print(f"Signing error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

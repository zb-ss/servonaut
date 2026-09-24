"""Inside-out Authenticode code signing and verification for Windows executables, libraries, and MSI packages.

Secrets never reach a command line. A certificate that is already installed is
selected by its SHA-1 thumbprint. A PFX file is imported into the current user's
certificate store for the duration of the signing run (the password travels to
PowerShell through its environment), selected by thumbprint, and removed again.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterator, Optional, Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12

DEFAULT_TIMESTAMP_URL = "http://timestamp.digicert.com"

# The CLI reads the PFX password from this variable; there is no password flag.
SIGNING_PASSWORD_ENV = "WINDOWS_SIGNING_PASSWORD"

# Inputs handed to the certificate-store scripts through their environment.
_PFX_PATH_ENV = "SERVONAUT_SIGNING_PFX"
_PFX_PASSWORD_ENV = "SERVONAUT_SIGNING_PFX_PASSWORD"
_THUMBPRINT_ENV = "SERVONAUT_SIGNING_THUMBPRINT"

_HELPER_EXECUTABLES: tuple[str, ...] = ("servonaut.exe", "servonaut-desktop-child.exe")
_GUI_EXECUTABLE = "servonaut-desktop.exe"
_NESTED_LIBRARY_PATTERNS: tuple[str, ...] = ("*.dll", "*.pyd")

# Adds the PFX certificate and its key to CurrentUser\My unless that thumbprint is
# already present, and reports which case applied so only an import is undone.
_IMPORT_CERTIFICATE_SCRIPT = f"""
$ErrorActionPreference = 'Stop'
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
$store.Open('ReadWrite')
try {{
    if ($store.Certificates.Find('FindByThumbprint', $env:{_THUMBPRINT_ENV}, $false).Count -gt 0) {{
        'present'
    }} else {{
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'UserKeySet,PersistKeySet'
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $env:{_PFX_PATH_ENV}, $env:{_PFX_PASSWORD_ENV}, $flags)
        $store.Add($certificate)
        'added'
    }}
}} finally {{
    $store.Close()
}}
"""

_REMOVE_CERTIFICATE_SCRIPT = f"""
$ErrorActionPreference = 'Stop'
Remove-Item -Path "Cert:\\CurrentUser\\My\\$env:{_THUMBPRINT_ENV}" -DeleteKey
"""


class WindowsSigningError(Exception):
    """Raised when Windows code signing or signature verification fails."""


def _require_tool(*names: str) -> str:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    raise WindowsSigningError(f"{names[-1]} was not found on the host system.")


def _run_signtool(args: Sequence[str], *, dry_run: bool = False) -> tuple[int, str]:
    """Execute signtool, or only report the command in a dry run."""
    if dry_run:
        return 0, f"[simulated] signtool {' '.join(args)}"

    cmd = [_require_tool("signtool.exe", "signtool"), *args]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as err:
        raise WindowsSigningError(f"Failed to execute signtool: {err}") from err
    return res.returncode, (res.stdout + "\n" + res.stderr).strip()


def _run_powershell(script: str, env_overrides: dict[str, str]) -> str:
    """Run a PowerShell script whose inputs arrive through environment variables.

    The script is passed encoded so that no command-line quoting rules apply to it.
    """
    powershell = _require_tool("powershell.exe", "pwsh.exe", "pwsh")
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    cmd = [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, **env_overrides})
    except OSError as err:
        raise WindowsSigningError(f"Failed to execute PowerShell: {err}") from err
    if res.returncode != 0:
        raise WindowsSigningError(f"Certificate store operation failed: {res.stderr.strip()}")
    return res.stdout.strip()


def _pfx_thumbprint(pfx_path: Path, password: Optional[str]) -> str:
    """Return the SHA-1 thumbprint of the signing certificate held in a PFX file."""
    try:
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            pfx_path.read_bytes(),
            password.encode("utf-8") if password else None,
        )
    except ValueError as err:
        raise WindowsSigningError(
            f"Could not open '{pfx_path.name}'; check the signing password."
        ) from err
    if certificate is None or private_key is None:
        raise WindowsSigningError(f"'{pfx_path.name}' does not contain a certificate with its private key.")
    return certificate.fingerprint(hashes.SHA1()).hex().upper()


@contextmanager
def _signing_certificate(
    cert_file: Optional[Path | str],
    cert_thumbprint: Optional[str],
    password: Optional[str],
    dry_run: bool,
) -> Iterator[str]:
    """Yield the thumbprint signtool selects, importing a PFX for the duration."""
    if cert_thumbprint:
        yield cert_thumbprint
        return
    if not cert_file:
        raise WindowsSigningError("Either cert_file or cert_thumbprint must be specified.")

    pfx_path = Path(cert_file).resolve()
    if dry_run:
        yield f"<thumbprint of {pfx_path.name}>"
        return
    if not pfx_path.is_file():
        raise FileNotFoundError(f"Certificate file not found: {pfx_path}")

    thumbprint = _pfx_thumbprint(pfx_path, password)
    store_state = _run_powershell(
        _IMPORT_CERTIFICATE_SCRIPT,
        {_PFX_PATH_ENV: str(pfx_path), _PFX_PASSWORD_ENV: password or "", _THUMBPRINT_ENV: thumbprint},
    )
    try:
        yield thumbprint
    finally:
        if store_state == "added":
            _run_powershell(_REMOVE_CERTIFICATE_SCRIPT, {_THUMBPRINT_ENV: thumbprint})


def _sign_with_thumbprint(target: Path, thumbprint: str, timestamp_url: str, dry_run: bool) -> None:
    args: list[str] = ["sign", "/fd", "SHA256"]
    if timestamp_url:
        args.extend(["/tr", timestamp_url, "/td", "SHA256"])
    args.extend(["/sha1", thumbprint, str(target)])

    rc, out = _run_signtool(args, dry_run=dry_run)
    if rc != 0:
        raise WindowsSigningError(f"Failed to sign '{target.name}': {out}")


def payload_signing_order(payload_dir: Path | str) -> list[Path]:
    """Return a payload's binaries in strict inside-out order.

    1. Nested dynamic libraries (.dll, .pyd) in subdirectories
    2. Subsystem helper executables (servonaut.exe, servonaut-desktop-child.exe)
    3. Main GUI launcher (servonaut-desktop.exe)
    """
    src_dir = Path(payload_dir).resolve()
    if not src_dir.is_dir():
        raise FileNotFoundError(f"Payload directory does not exist: {src_dir}")

    nested_libs = [lib for pattern in _NESTED_LIBRARY_PATTERNS for lib in src_dir.rglob(pattern)]
    nested_libs.sort(key=lambda p: str(p).lower())

    executables = [src_dir / name for name in (*_HELPER_EXECUTABLES, _GUI_EXECUTABLE)]
    return [*nested_libs, *(exe for exe in executables if exe.is_file())]


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

    with _signing_certificate(cert_file, cert_thumbprint, password, dry_run) as thumbprint:
        _sign_with_thumbprint(target, thumbprint, timestamp_url, dry_run)
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
    """Sign all binaries in a Windows payload using strict inside-out ordering.

    Returns:
        list[Path]: Ordered list of signed files.
    """
    ordered = payload_signing_order(payload_dir)
    with _signing_certificate(cert_file, cert_thumbprint, password, dry_run) as thumbprint:
        for binary in ordered:
            _sign_with_thumbprint(binary, thumbprint, timestamp_url, dry_run)
    return ordered


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
    """Verify Authenticode signature on an executable or MSI package.

    Raises:
        WindowsSigningError: If signtool is unavailable outside a dry run, or the
            signature does not verify.
    """
    target = Path(file_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    rc, out = _run_signtool(["verify", "/pa", "/v", str(target)], dry_run=dry_run)
    if rc != 0:
        raise WindowsSigningError(f"Signature verification failed for '{target.name}': {out}")

    return True


def verify_payload_binaries(payload_dir: Path | str, *, dry_run: bool = False) -> list[Path]:
    """Verify the Authenticode signature of every binary in a signed payload."""
    ordered = payload_signing_order(payload_dir)
    for binary in ordered:
        verify_signature(binary, dry_run=dry_run)
    return ordered


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for Windows signing."""
    parser = argparse.ArgumentParser(description="Sign Windows executables, DLLs, and MSI installers with Authenticode.")
    parser.add_argument("--payload-dir", type=Path, default=None, help="Directory of onedir payload to sign inside-out.")
    parser.add_argument("--msi", type=Path, default=None, help="MSI installer package to sign.")
    parser.add_argument(
        "--cert-file",
        type=Path,
        default=None,
        help=f"Code signing certificate (.pfx / .p12); its password is read from {SIGNING_PASSWORD_ENV}.",
    )
    parser.add_argument("--thumbprint", default=None, help="SHA-1 thumbprint of certificate in Windows certificate store.")
    parser.add_argument("--timestamp-url", default=DEFAULT_TIMESTAMP_URL, help="RFC 3161 timestamp server URL.")
    parser.add_argument("--dry-run", action="store_true", help="Simulate signing commands without modifying files.")
    parser.add_argument("--verify", action="store_true", help="Verify Authenticode signatures instead of signing.")

    args = parser.parse_args(argv)
    if not args.msi and not args.payload_dir:
        parser.error("Specify --msi and/or --payload-dir.")

    try:
        if args.verify:
            if args.payload_dir:
                verified = verify_payload_binaries(args.payload_dir, dry_run=args.dry_run)
                print(f"Verified signatures on {len(verified)} payload binaries.")
            if args.msi:
                verify_signature(args.msi, dry_run=args.dry_run)
                print(f"Signature verified successfully for {args.msi}")
            return 0

        pwd = os.environ.get(SIGNING_PASSWORD_ENV)
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
    except (WindowsSigningError, OSError) as err:
        print(f"Signing error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

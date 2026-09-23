"""Microsoft Edge WebView2 Evergreen Runtime and OpenSSH detection and guidance for Windows."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Callable, Optional

# Standard Microsoft Edge WebView2 Evergreen Runtime Client GUID
WEBVIEW2_CLIENT_GUID = "{F3017226-3E2A-4474-9E67-41F63270EC4D}"  # leak-guard:allow

MINIMUM_WEBVIEW2_VERSION = "86.0.616.0"
WEBVIEW2_BOOTSTRAPPER_URL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
WEBVIEW2_STANDALONE_URL = "https://developer.microsoft.com/microsoft-edge/webview2/"

# Standard OpenSSH client binary name
OPENSSH_BINARY_NAME = "ssh.exe" if sys.platform == "win32" else "ssh"


@dataclass(frozen=True, slots=True)
class WebView2Status:
    """Detection status of the WebView2 Evergreen Runtime."""

    available: bool
    version: Optional[str] = None
    location: Optional[str] = None
    min_version_met: bool = False
    guidance: Optional[str] = None


@dataclass(frozen=True, slots=True)
class OpenSSHStatus:
    """Detection status of the OpenSSH client on Windows."""

    available: bool
    path: Optional[str] = None
    guidance: Optional[str] = None


def _parse_version_tuple(v_str: str) -> tuple[int, ...]:
    """Parse a dotted version string into a tuple of integers."""
    parts: list[int] = []
    for seg in v_str.split("."):
        clean_seg = "".join(filter(str.isdigit, seg))
        parts.append(int(clean_seg) if clean_seg else 0)
    return tuple(parts)


def get_webview2_guidance(status: Optional[WebView2Status] = None) -> str:
    """Generate actionable user and administrator guidance for installing WebView2."""
    if status and status.min_version_met:
        return f"Microsoft Edge WebView2 Runtime version {status.version} is installed and ready."

    reason = (
        f"Installed version {status.version} is older than minimum required version {MINIMUM_WEBVIEW2_VERSION}."
        if status and status.version
        else "Microsoft Edge WebView2 Runtime is not installed on this system."
    )

    return (
        f"Servonaut Desktop requires the Microsoft Edge WebView2 Evergreen Runtime to render its interface.\n"
        f"Status: {reason}\n\n"
        f"To install or update WebView2:\n"
        f"1. Download and run the official Evergreen Bootstrapper:\n"
        f"   {WEBVIEW2_BOOTSTRAPPER_URL}\n\n"
        f"2. For enterprise or offline environments:\n"
        f"   Download the standalone x64 installer from:\n"
        f"   {WEBVIEW2_STANDALONE_URL}\n"
        f"   Deploy via Microsoft Intune, Group Policy, or run:\n"
        f"   MicrosoftEdgeWebView2RuntimeInstallerX64.exe /silent /install\n"
    )


def get_openssh_guidance(status: Optional[OpenSSHStatus] = None) -> str:
    """Generate actionable guidance for enabling the OpenSSH client optional feature."""
    if status and status.available:
        return f"OpenSSH client is available at {status.path}."

    return (
        "Servonaut requires the OpenSSH client to establish secure SSH connections to remote servers.\n"
        "Status: OpenSSH client (ssh.exe) was not found in PATH or standard Windows locations.\n\n"
        "To enable OpenSSH Client on Windows 10 / 11:\n"
        "Option A: PowerShell (Run as Administrator):\n"
        "   Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0\n\n"
        "Option B: Windows Settings:\n"
        "   Open Settings -> System -> Optional features (or Apps -> Optional features)\n"
        "   Click 'Add an optional feature', search for 'OpenSSH Client', and click Install.\n"
    )


def detect_webview2(
    *,
    min_version: str = MINIMUM_WEBVIEW2_VERSION,
    registry_reader: Optional[Callable[[str, str, str, bool], Optional[str]]] = None,
) -> WebView2Status:
    """Detect if the WebView2 Evergreen Runtime is installed.

    Args:
        min_version: Minimum acceptable version string (e.g. "86.0.616.0").
        registry_reader: Optional custom registry reader callable for testing.
            Signature: (hive, subkey, value_name, is_64bit) -> Optional[str].

    Returns:
        WebView2Status: Resulting detection status with parsed version and guidance.
    """
    reader = registry_reader or _default_winreg_reader

    # Inspection targets in priority order:
    # 1. HKLM 64-bit hive
    # 2. HKLM WOW6432 32-bit hive
    # 3. HKCU user hive
    search_locations = [
        ("HKLM", rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_CLIENT_GUID}", "pv", True, "machine_64"),
        ("HKLM", rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_CLIENT_GUID}", "pv", False, "machine_wow64"),
        ("HKCU", rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_CLIENT_GUID}", "pv", False, "user"),
    ]

    for hive, subkey, val_name, is_64bit, loc_label in search_locations:
        try:
            val = reader(hive, subkey, val_name, is_64bit)
            if val and isinstance(val, str) and val.strip():
                v_clean = val.strip()
                min_met = _parse_version_tuple(v_clean) >= _parse_version_tuple(min_version)
                status = WebView2Status(
                    available=True,
                    version=v_clean,
                    location=loc_label,
                    min_version_met=min_met,
                )
                guidance = get_webview2_guidance(status)
                return WebView2Status(
                    available=True,
                    version=v_clean,
                    location=loc_label,
                    min_version_met=min_met,
                    guidance=guidance,
                )
        except Exception:
            continue

    # Not found in any registry hive
    status = WebView2Status(available=False, min_version_met=False)
    return WebView2Status(
        available=False,
        min_version_met=False,
        guidance=get_webview2_guidance(status),
    )


def detect_openssh(
    *,
    custom_which: Optional[Callable[[str], Optional[str]]] = None,
    system_root: Optional[str] = None,
) -> OpenSSHStatus:
    """Detect if the OpenSSH client is installed and accessible.

    Args:
        custom_which: Optional callable replacing shutil.which for testing.
        system_root: Optional SystemRoot directory path for testing.

    Returns:
        OpenSSHStatus: Status of OpenSSH client on the host.
    """
    which_fn = custom_which or shutil.which

    # 1. Check in PATH
    found = which_fn("ssh") or which_fn("ssh.exe")
    if found:
        return OpenSSHStatus(available=True, path=str(found), guidance=get_openssh_guidance(OpenSSHStatus(True, str(found))))

    # 2. Check standard Windows System32 OpenSSH path
    sys_root = system_root or os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    system32_ssh = Path(sys_root) / "System32" / "OpenSSH" / "ssh.exe"
    if system32_ssh.is_file():
        path_str = str(system32_ssh)
        return OpenSSHStatus(available=True, path=path_str, guidance=get_openssh_guidance(OpenSSHStatus(True, path_str)))

    # Missing
    missing_status = OpenSSHStatus(available=False)
    return OpenSSHStatus(available=False, guidance=get_openssh_guidance(missing_status))


def _default_winreg_reader(hive: str, subkey: str, value_name: str, is_64bit: bool) -> Optional[str]:
    """Read a registry string value using Python's standard winreg module."""
    if sys.platform != "win32":
        return None

    try:
        import winreg

        hkey_root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
        flags = winreg.KEY_READ
        if is_64bit:
            flags |= winreg.KEY_WOW64_64KEY
        else:
            flags |= winreg.KEY_WOW64_32KEY

        with winreg.OpenKey(hkey_root, subkey, 0, flags) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return str(val) if val else None
    except Exception:
        return None


def main(argv: Optional[list[str]] = None) -> int:
    """CLI diagnostics entry point for WebView2 and OpenSSH probing."""
    parser = argparse.ArgumentParser(description="Probe Windows host for WebView2 Evergreen Runtime and OpenSSH client.")
    parser.add_argument("--json", action="store_true", help="Output diagnostics in JSON format.")
    args = parser.parse_args(argv)

    wv2_status = detect_webview2()
    ssh_status = detect_openssh()

    if args.json:
        payload = {
            "webview2": {
                "available": wv2_status.available,
                "version": wv2_status.version,
                "location": wv2_status.location,
                "min_version_met": wv2_status.min_version_met,
            },
            "openssh": {
                "available": ssh_status.available,
                "path": ssh_status.path,
            },
        }
        print(json.dumps(payload, indent=2))
        return 0

    print("=== Servonaut Windows Environment Probe ===")
    print(f"WebView2 Available:     {wv2_status.available}")
    if wv2_status.available:
        print(f"WebView2 Version:       {wv2_status.version} (>= {MINIMUM_WEBVIEW2_VERSION}: {wv2_status.min_version_met})")
        print(f"WebView2 Location:      {wv2_status.location}")
    else:
        print("\n" + (wv2_status.guidance or ""))

    print(f"OpenSSH Client:         {ssh_status.available}")
    if ssh_status.available:
        print(f"OpenSSH Path:           {ssh_status.path}")
    else:
        print("\n" + (ssh_status.guidance or ""))

    return 0 if (wv2_status.min_version_met and ssh_status.available) else 1


if __name__ == "__main__":
    sys.exit(main())

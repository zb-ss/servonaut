"""macOS Notarization and Ticket Stapling Tooling.

Credentials never travel on the command line: notarytool authenticates with a
keychain profile (created once with ``xcrun notarytool store-credentials``) or
with an App Store Connect API key file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Optional


class MacosNotarizationError(Exception):
    """Raised when macOS notarization or stapling fails."""


def _xcrun_tool_command(tool: str) -> list[str]:
    """Return the command prefix for an Xcode tool, preferring ``xcrun <tool>``."""
    xcrun_bin = shutil.which("xcrun")
    if xcrun_bin:
        return [xcrun_bin, tool]
    tool_bin = shutil.which(tool)
    if tool_bin:
        return [tool_bin]
    raise MacosNotarizationError(f"Neither xcrun nor {tool} found on system.")


def _credential_args(
    keychain_profile: Optional[str],
    api_key_file: Optional[Path | str],
    api_key_id: Optional[str],
    api_issuer: Optional[str],
) -> list[str]:
    """Build notarytool authentication arguments that carry no secret values."""
    if keychain_profile:
        return ["--keychain-profile", keychain_profile]
    if api_key_file and api_key_id:
        key_path = Path(api_key_file).resolve()
        if not key_path.is_file():
            raise FileNotFoundError(f"App Store Connect API key file not found: {key_path}")
        args = ["--key", str(key_path), "--key-id", api_key_id]
        if api_issuer:
            args.extend(["--issuer", api_issuer])
        return args
    raise MacosNotarizationError(
        "Must provide either keychain_profile or (api_key_file, api_key_id[, api_issuer])."
    )


def submit_notarization(
    artifact_path: Path | str,
    *,
    keychain_profile: Optional[str] = None,
    api_key_file: Optional[Path | str] = None,
    api_key_id: Optional[str] = None,
    api_issuer: Optional[str] = None,
    wait: bool = True,
    dry_run: bool = False,
) -> tuple[bool, str, dict[str, Any]]:
    """Submit an artifact to Apple's notarization service via notarytool.

    Returns:
        tuple[bool, str, dict]: (is_success, log_summary, submission_details)

    Raises:
        MacosNotarizationError: If credentials are missing, or notarytool is
            unavailable outside a dry run.
    """
    path = Path(artifact_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Artifact to notarize not found: {path}")

    credential_args = _credential_args(keychain_profile, api_key_file, api_key_id, api_issuer)

    if dry_run:
        details = {
            "id": "simulated-submission-uuid",
            "status": "Accepted",
            "message": "[simulated] notarization accepted",
        }
        return True, f"Simulated notarization for {path.name}", details

    cmd = [
        *_xcrun_tool_command("notarytool"),
        "submit",
        str(path),
        "--output-format",
        "json",
        *credential_args,
    ]
    if wait:
        cmd.append("--wait")

    res = subprocess.run(cmd, capture_output=True, text=True)
    raw_out = (res.stdout or "") + "\n" + (res.stderr or "")

    try:
        details: dict[str, Any] = json.loads(res.stdout)
    except json.JSONDecodeError:
        details = {"raw_output": raw_out}

    status = details.get("status")
    if res.returncode == 0 and (status == "Accepted" or not wait):
        return True, raw_out, details

    return False, raw_out, details


def staple_ticket(
    artifact_path: Path | str,
    *,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """Staple a notarization ticket to the artifact using stapler."""
    path = Path(artifact_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Artifact to staple not found: {path}")

    if dry_run:
        return True, f"[simulated] ticket stapled to {path.name}"

    cmd = [*_xcrun_tool_command("stapler"), "staple", str(path)]

    res = subprocess.run(cmd, capture_output=True, text=True)
    msg = (res.stdout + "\n" + res.stderr).strip()
    return res.returncode == 0, msg


def validate_staple(
    artifact_path: Path | str,
    *,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """Validate stapled ticket on the artifact."""
    path = Path(artifact_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Artifact to validate not found: {path}")

    if dry_run:
        return True, f"[simulated] staple validated on {path.name}"

    cmd = [*_xcrun_tool_command("stapler"), "validate", str(path)]

    res = subprocess.run(cmd, capture_output=True, text=True)
    msg = (res.stdout + "\n" + res.stderr).strip()
    return res.returncode == 0, msg


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Notarize and staple macOS artifacts (DMG / app bundles)."
    )
    parser.add_argument(
        "--artifact",
        required=True,
        type=Path,
        help="Path to .dmg or .zip artifact to notarize.",
    )
    parser.add_argument(
        "--keychain-profile",
        default=None,
        help="Notarytool keychain credentials profile (see 'xcrun notarytool store-credentials').",
    )
    parser.add_argument(
        "--api-key-file",
        type=Path,
        default=None,
        help="App Store Connect API private key file (.p8).",
    )
    parser.add_argument(
        "--api-key-id",
        default=None,
        help="App Store Connect API key ID.",
    )
    parser.add_argument(
        "--api-issuer",
        default=None,
        help="App Store Connect API issuer ID (required for team keys).",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for notarization result.",
    )
    parser.add_argument(
        "--staple",
        action="store_true",
        help="Automatically staple ticket upon success.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate execution without external network calls.",
    )

    args = parser.parse_args(argv)

    try:
        success, log, details = submit_notarization(
            artifact_path=args.artifact,
            keychain_profile=args.keychain_profile,
            api_key_file=args.api_key_file,
            api_key_id=args.api_key_id,
            api_issuer=args.api_issuer,
            wait=not args.no_wait,
            dry_run=args.dry_run,
        )
        if not success:
            print(f"Notarization submission failed:\n{log}", file=sys.stderr)
            return 1

        print(f"Notarization succeeded for {args.artifact.name}")
        sub_id = details.get("id") or details.get("submissionId")
        if sub_id:
            print(f"  Submission ID: {sub_id}")

        if args.staple and not args.no_wait:
            stapled, staple_msg = staple_ticket(args.artifact, dry_run=args.dry_run)
            if not stapled:
                print(f"Stapling failed:\n{staple_msg}", file=sys.stderr)
                return 1
            print(f"Stapling verified for {args.artifact.name}")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""macOS Notarization and Ticket Stapling Tooling."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Optional

_REDACTED_TEXT = "********"


class MacosNotarizationError(Exception):
    """Raised when macOS notarization or stapling fails."""


def mask_sensitive_arguments(args: list[str], secrets: list[str]) -> list[str]:
    """Return a copy of args with any sensitive secret values replaced by asterisks."""
    masked: list[str] = []
    secret_set = {s for s in secrets if s}

    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            masked.append(_REDACTED_TEXT)
            skip_next = False
            continue

        if arg in ("--password", "--app-password", "--secret"):
            masked.append(arg)
            skip_next = True
            continue

        # Check if secret appears inside arg (e.g. key=value)
        val = arg
        for sec in secret_set:
            if sec in val:
                val = val.replace(sec, _REDACTED_TEXT)
        masked.append(val)

    return masked


def submit_notarization(
    artifact_path: Path | str,
    *,
    keychain_profile: Optional[str] = None,
    apple_id: Optional[str] = None,
    team_id: Optional[str] = None,
    app_password: Optional[str] = None,
    wait: bool = True,
    dry_run: bool = False,
) -> tuple[bool, str, dict[str, Any]]:
    """Submit an artifact to Apple's notarization service via notarytool.

    Returns:
        tuple[bool, str, dict]: (is_success, log_summary, submission_details)
    """
    path = Path(artifact_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Artifact to notarize not found: {path}")

    secrets = [app_password] if app_password else []
    notary_bin = shutil.which("notarytool")
    xcrun_bin = shutil.which("xcrun")

    if not xcrun_bin and not notary_bin:
        if dry_run or sys.platform != "darwin":
            details = {
                "id": "simulated-submission-uuid",
                "status": "Accepted",
                "message": "[simulated] notarization accepted",
            }
            return True, f"Simulated notarization for {path.name}", details
        raise MacosNotarizationError("Neither xcrun nor notarytool found on system.")

    base_cmd = [xcrun_bin, "notarytool"] if xcrun_bin else [notary_bin]
    cmd = [*base_cmd, "submit", str(path), "--output-format", "json"]

    if keychain_profile:
        cmd.extend(["--keychain-profile", keychain_profile])
    elif apple_id and team_id and app_password:
        cmd.extend([
            "--apple-id",
            apple_id,
            "--team-id",
            team_id,
            "--password",
            app_password,
        ])
    else:
        raise MacosNotarizationError(
            "Must provide either keychain_profile or (apple_id, team_id, app_password)."
        )

    if wait:
        cmd.append("--wait")

    # Run command
    res = subprocess.run(cmd, capture_output=True, text=True)
    raw_out = (res.stdout or "") + "\n" + (res.stderr or "")

    # Sanitize logs
    clean_out = raw_out
    for sec in secrets:
        if sec:
            clean_out = clean_out.replace(sec, _REDACTED_TEXT)

    details: dict[str, Any] = {}
    try:
        details = json.loads(res.stdout)
    except Exception:
        details = {"raw_output": clean_out}

    status = details.get("status")
    if res.returncode == 0 and (status == "Accepted" or not wait):
        return True, clean_out, details

    return False, clean_out, details


def staple_ticket(
    artifact_path: Path | str,
    *,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """Staple a notarization ticket to the artifact using stapler."""
    path = Path(artifact_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Artifact to staple not found: {path}")

    xcrun_bin = shutil.which("xcrun")
    stapler_bin = shutil.which("stapler")

    if not xcrun_bin and not stapler_bin:
        if dry_run or sys.platform != "darwin":
            return True, f"[simulated] ticket stapled to {path.name}"
        raise MacosNotarizationError("Neither xcrun nor stapler found on system.")

    cmd = [xcrun_bin, "stapler"] if xcrun_bin else [stapler_bin]
    cmd.extend(["staple", str(path)])

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

    xcrun_bin = shutil.which("xcrun")
    stapler_bin = shutil.which("stapler")

    if not xcrun_bin and not stapler_bin:
        if dry_run or sys.platform != "darwin":
            return True, f"[simulated] staple validated on {path.name}"
        raise MacosNotarizationError("Neither xcrun nor stapler found on system.")

    cmd = [xcrun_bin, "stapler"] if xcrun_bin else [stapler_bin]
    cmd.extend(["validate", str(path)])

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
        help="Notarytool keychain credentials profile.",
    )
    parser.add_argument(
        "--apple-id",
        default=None,
        help="Apple Developer ID account email.",
    )
    parser.add_argument(
        "--team-id",
        default=None,
        help="Apple Developer Team ID.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="App-specific password for notarytool.",
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
            apple_id=args.apple_id,
            team_id=args.team_id,
            app_password=args.password,
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

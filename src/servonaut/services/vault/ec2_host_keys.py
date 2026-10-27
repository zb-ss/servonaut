"""AWS EC2 console output verification for host keys.

At first boot, cloud-init prints SSH host key fingerprints and public keys to
the EC2 console output:

    -----BEGIN SSH HOST KEY FINGERPRINTS-----
    256 SHA256:... root@ip-... (ECDSA)
    256 SHA256:... root@ip-... (ED25519)
    -----END SSH HOST KEY FINGERPRINTS-----
    -----BEGIN SSH HOST KEY KEYS-----
    ecdsa-sha2-nistp256 AAAA... root@ip-...
    ssh-ed25519 AAAA... root@ip-...
    -----END SSH HOST KEY KEYS-----

This module parses those blocks and verifies host keys against them:
1. If the KEYS block is present and well-formed, those keys are used directly
   as the server's trusted host keys without an SSH visit. AWS is the
   authenticated source.
2. If only the FINGERPRINTS block is present, the server is visited once and
   its recorded host key fingerprint is compared against AWS.
3. If neither block is usable (e.g. rotated output, MD5-only, AccessDenied,
   or conflicting blocks), the row is marked unverified and requires explicit
   user confirmation before binding.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from servonaut.services.ssh_host_keys import (
    host_key_alias,
    known_hosts_name,
    servonaut_known_hosts_path,
)
from servonaut.services.vault.crypto import ssh_public_fingerprint

logger = logging.getLogger(__name__)

# Markers output by cloud-init during instance initialization.
BEGIN_KEYS = "-----BEGIN SSH HOST KEY KEYS-----"
END_KEYS = "-----END SSH HOST KEY KEYS-----"
BEGIN_FINGERPRINTS = "-----BEGIN SSH HOST KEY FINGERPRINTS-----"
END_FINGERPRINTS = "-----END SSH HOST KEY FINGERPRINTS-----"

# Maximum size of EC2 console output parsed (512 KB).
MAX_CONSOLE_OUTPUT_CHARS = 512 * 1024

_ALLOWED_HOST_KEY_TYPES = {
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
}

_SHA256_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")

_FAMILY_MAP = {
    "ed25519": "ED25519",
    "ecdsa": "ECDSA",
    "rsa": "RSA",
    "dsa": "DSA",
    "dss": "DSA",
}


def normalize_key_family(key_type: str) -> str:
    """Normalize OpenSSH key type or algorithm to a standard family name (ED25519, ECDSA, RSA, DSA)."""
    lowered = key_type.strip().lower()
    for needle, family in _FAMILY_MAP.items():
        if needle in lowered:
            return family
    return key_type.strip().upper()


def key_family_from_public_key(public_key_line: str) -> str:
    """Extract and normalize the key family from an OpenSSH public key line."""
    parts = public_key_line.strip().split()
    if not parts:
        return "UNKNOWN"
    return normalize_key_family(parts[0])


@dataclass(frozen=True)
class EC2ConsoleHostKeys:
    """Parsed result of EC2 console output."""

    keys: list[str] = field(default_factory=list)
    fingerprints: dict[str, str] = field(default_factory=dict)
    verified: bool = False
    source: str = ""
    error: Optional[str] = None
    has_keys_block: bool = False
    has_fingerprints_block: bool = False

    @property
    def is_usable(self) -> bool:
        return self.has_keys_block or self.has_fingerprints_block


def _extract_blocks(text: str, begin_marker: str, end_marker: str) -> list[str]:
    """Extract all text blocks strictly between begin_marker and end_marker."""
    blocks: list[str] = []
    cursor = 0
    while True:
        start = text.find(begin_marker, cursor)
        if start == -1:
            break
        start += len(begin_marker)
        end = text.find(end_marker, start)
        if end == -1:
            break
        blocks.append(text[start:end])
        cursor = end + len(end_marker)
    return blocks


def _parse_keys_block(block: str) -> Optional[list[str]]:
    """Parse and validate OpenSSH public keys in a KEYS block.

    Returns None if any non-empty line fails validation (junk inside markers).
    Normalizes keys to '<type> <base64>' without comments, validates with
    load_ssh_public_key, restricts to host-key types, and caps at 8 keys.
    """
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    if not lines:
        return None
    valid_keys: list[str] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            return None
        key_type, key_b64 = parts[0], parts[1]
        if key_type not in _ALLOWED_HOST_KEY_TYPES:
            return None
        normalized = f"{key_type} {key_b64}"
        try:
            load_ssh_public_key(normalized.encode("ascii"))
        except (ValueError, UnicodeEncodeError, TypeError):
            return None
        if normalized not in valid_keys:
            valid_keys.append(normalized)
    if not valid_keys or len(valid_keys) > 8:
        return None
    return valid_keys


def _parse_fingerprints_block(block: str) -> Optional[dict[str, str]]:
    """Parse SHA256 fingerprints from a FINGERPRINTS block.

    Matches lines like: '256 SHA256:... root@ip-... (ED25519)'.
    Returns None if no SHA256 fingerprints are found (e.g. MD5-only).
    """
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    if not lines:
        return None
    fingerprints: dict[str, str] = {}
    for line in lines:
        tokens = line.split()
        fp = None
        for tok in tokens:
            if tok.startswith("SHA256:"):
                clean = tok.rstrip("=")
                if _SHA256_FP_RE.match(clean):
                    fp = clean
                    break
        if not fp:
            continue

        # Match key type in parentheses, e.g. (ECDSA), (ED25519), (RSA)
        type_match = re.search(r"\(([A-Za-z0-9_-]+)\)", line)
        if not type_match:
            continue
        family = normalize_key_family(type_match.group(1))
        fingerprints[family] = fp

    return fingerprints if fingerprints else None


def parse_ec2_console_output(raw_output: Optional[str]) -> EC2ConsoleHostKeys:
    """Parse cloud-init SSH host keys and fingerprints from EC2 console output.

    Treats output as untrusted text:
    - only lines between markers
    - validates key types and base64
    - caps size parsed (512 KB)
    - verifies that multiple complete blocks do not disagree
    """
    if not isinstance(raw_output, str) or not raw_output.strip():
        return EC2ConsoleHostKeys(
            source="not verified: the console output is empty",
            error="the console output is empty",
        )

    if len(raw_output) > MAX_CONSOLE_OUTPUT_CHARS:
        return EC2ConsoleHostKeys(
            source="not verified: the console output exceeds the size limit",
            error="the console output exceeds the size limit",
        )

    # 1. Parse KEYS blocks
    keys_blocks = _extract_blocks(raw_output, BEGIN_KEYS, END_KEYS)
    parsed_keys_blocks: list[list[str]] = []
    for block in keys_blocks:
        parsed = _parse_keys_block(block)
        if parsed is not None:
            parsed_keys_blocks.append(parsed)

    keys_disagree = False
    chosen_keys: Optional[list[str]] = None
    if len(parsed_keys_blocks) > 1:
        first = parsed_keys_blocks[0]
        if any(b != first for b in parsed_keys_blocks):
            keys_disagree = True
        else:
            chosen_keys = parsed_keys_blocks[-1]
    elif len(parsed_keys_blocks) == 1:
        chosen_keys = parsed_keys_blocks[0]

    # 2. Parse FINGERPRINTS blocks
    fp_blocks = _extract_blocks(raw_output, BEGIN_FINGERPRINTS, END_FINGERPRINTS)
    parsed_fp_blocks: list[dict[str, str]] = []
    for block in fp_blocks:
        parsed_fps = _parse_fingerprints_block(block)
        if parsed_fps is not None:
            parsed_fp_blocks.append(parsed_fps)

    fps_disagree = False
    chosen_fps: Optional[dict[str, str]] = None
    if len(parsed_fp_blocks) > 1:
        first_fps = parsed_fp_blocks[0]
        if any(b != first_fps for b in parsed_fp_blocks):
            fps_disagree = True
        else:
            chosen_fps = parsed_fp_blocks[-1]
    elif len(parsed_fp_blocks) == 1:
        chosen_fps = parsed_fp_blocks[0]

    # Check for disagreement across multiple blocks
    if keys_disagree or fps_disagree:
        return EC2ConsoleHostKeys(
            source="not verified: several console output blocks disagree",
            error="several console output blocks disagree",
        )

    # If both KEYS and FINGERPRINTS are present, verify they agree with each other
    if chosen_keys is not None and chosen_fps is not None:
        for key in chosen_keys:
            family = key_family_from_public_key(key)
            fp = ssh_public_fingerprint(key)
            if family in chosen_fps and chosen_fps[family] != fp:
                return EC2ConsoleHostKeys(
                    source="not verified: console output keys and fingerprints disagree",
                    error="console output keys and fingerprints disagree",
                )

    # 1. KEYS block is present and well-formed
    if chosen_keys is not None:
        return EC2ConsoleHostKeys(
            keys=chosen_keys,
            fingerprints=chosen_fps or {},
            verified=True,
            source="verified by AWS console output",
            has_keys_block=True,
            has_fingerprints_block=chosen_fps is not None,
        )

    # 2. Only FINGERPRINTS block is present
    if chosen_fps is not None:
        return EC2ConsoleHostKeys(
            fingerprints=chosen_fps,
            verified=False,
            source="AWS console output",
            has_keys_block=False,
            has_fingerprints_block=True,
        )

    # 3. Neither block is usable
    return EC2ConsoleHostKeys(
        source="not verified: the console output no longer holds the first-boot host keys",
        error="the console output no longer holds the first-boot host keys",
    )


def verify_fetched_host_keys(
    fetched_keys: list[str],
    console_result: EC2ConsoleHostKeys,
) -> tuple[bool, str]:
    """Verify fetched host keys against console fingerprints.

    Returns (is_verified, source_or_reason).
    If mismatch detected, source_or_reason is 'mismatch'.
    """
    if not console_result.has_fingerprints_block or not console_result.fingerprints:
        return False, console_result.source or "not verified: no console fingerprints available"

    if not fetched_keys:
        return False, "not verified: no host keys to verify"

    for key in fetched_keys:
        family = key_family_from_public_key(key)
        try:
            fp = ssh_public_fingerprint(key)
        except Exception:
            return False, "mismatch"
        if family not in console_result.fingerprints:
            return False, f"not verified: console output does not list a fingerprint for {family}"
        if console_result.fingerprints[family] != fp:
            return False, "mismatch"

    return True, "verified by AWS console output"


def host_key_removal_command(instance: Mapping[str, Any], host: str, port: int = 22) -> str:
    """Generate the ssh-keygen command to remove an offending host key from Servonaut's known_hosts."""
    alias = host_key_alias(instance)
    name = alias or known_hosts_name(host, port if port != 22 else None)
    known_hosts = servonaut_known_hosts_path()
    return f"ssh-keygen -R {name} -f {known_hosts}"


def remove_recorded_host_key(
    instance: Mapping[str, Any], host: str, port: int = 22,
) -> bool:
    """Remove a mismatched host key from Servonaut's known_hosts file.

    Removes entries for all names trusted_host_keys looks up (host_key_alias,
    and host or [host]:port).
    Returns True if removal succeeded (or known_hosts does not exist), False on error.
    """
    import shutil
    import subprocess

    known_hosts = servonaut_known_hosts_path()
    if not known_hosts.is_file():
        return True

    keygen = shutil.which("ssh-keygen")
    if keygen is None:
        return False

    port_arg = port if port != 22 else None
    names = [name for name in (host_key_alias(instance), known_hosts_name(host, port_arg)) if name]
    success = True
    for name in names:
        try:
            res = subprocess.run(
                [keygen, "-R", name, "-f", str(known_hosts)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode != 0:
                success = False
        except (OSError, subprocess.SubprocessError):
            success = False
    return success


def fetch_ec2_console_output_sync(
    instance: Mapping[str, Any],
    *,
    accounts: Optional[Any] = None,
    client_factory: Optional[Callable[..., Any]] = None,
    aws_service: Optional[Any] = None,
) -> str:
    """Call ec2:GetConsoleOutput for an AWS instance using multi-account credentials.

    Botocore base64-decodes the Output field automatically.
    """
    instance_id = str(instance.get("id") or "")
    region = str(instance.get("region") or "")
    account = instance.get("account")

    if not instance_id:
        raise ValueError("Instance has no ID")

    client: Any = None
    if client_factory is not None:
        client = client_factory("ec2", region)
    elif aws_service is not None:
        client = aws_service._client("ec2", region or None)
    elif accounts is not None:
        try:
            factory = accounts.aws_client_factory(account)
            client = factory.client("ec2", region)
        except Exception as exc:
            raise ValueError(f"cannot read the console output for account {account!r}") from exc
    else:
        raise ValueError("cannot read the console output for this account: no account registry")

    response = client.get_console_output(InstanceId=instance_id)
    return response.get("Output") or ""

"""Cryptographic trust policy, signature verification, downgrade prevention, and target resolution."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import platform
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from servonaut.distribution.manifest import (
    ManifestError,
    ManifestSchemaError,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    ManifestSignature,
)
from servonaut.runtime import DistributionKind, RuntimeLayout


class ManifestSignatureError(ManifestError):
    """Raised when cryptographic verification of a release manifest fails."""


class ManifestExpiredError(ManifestError):
    """Raised when a manifest is past its declared expiration time."""


class ManifestDowngradeError(ManifestError):
    """Raised when an update represents an older or identical version."""


class ManifestOriginError(ManifestError):
    """Raised when a download URL origin violates the trust policy."""


class ManifestTargetError(ManifestError):
    """Base error for platform target resolution failures."""


class NoCompatibleArtifactError(ManifestTargetError):
    """Raised when no compatible artifact matches the running platform and distribution."""


class AmbiguousArtifactError(ManifestTargetError):
    """Raised when more than one artifact matches the current target parameters."""


_SEMVER_PART_REGEX = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$"
)


def parse_semver(version: str) -> tuple[int, int, int, int, str]:
    """Parse a semantic version string into a comparable tuple.

    Returns:
        (major, minor, patch, is_final, prerelease_string)
        where is_final is 1 for stable releases and 0 for prereleases.
    """
    match = _SEMVER_PART_REGEX.match(version.strip())
    if not match:
        raise ManifestSchemaError(f"Invalid semantic version string: '{version}'")
    major, minor, patch, prerelease, _build = match.groups()
    is_final = 0 if prerelease else 1
    return int(major), int(minor), int(patch), is_final, (prerelease or "")


def decode_signature_bytes(signature_str: str) -> bytes:
    """Decode a signature string from base64 (standard or urlsafe) or hex."""
    cleaned = signature_str.strip()
    if len(cleaned) == 128 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass
    # Try standard / urlsafe base64
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        try:
            return base64.b64decode(padded.encode("ascii"))
        except Exception as err:
            raise ManifestSignatureError(f"Malformed signature encoding: {err}") from err


def encode_signature_bytes(sig_bytes: bytes) -> str:
    """Encode raw signature bytes to URL-safe unpadded base64."""
    return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")


def load_ed25519_public_key(key_input: bytes | str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from raw bytes, hex, or base64."""
    if isinstance(key_input, str):
        cleaned = key_input.strip()
        if len(cleaned) == 64 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
            raw = bytes.fromhex(cleaned)
        else:
            padded = cleaned + "=" * (-len(cleaned) % 4)
            try:
                raw = base64.urlsafe_b64decode(padded.encode("ascii"))
            except Exception:
                raw = base64.b64decode(padded.encode("ascii"))
    else:
        raw = key_input

    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}.")
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    """Policy configuring required trust parameters for release manifests."""

    trusted_public_keys: Mapping[str, Ed25519PublicKey]
    minimum_signatures: int = 1
    allowed_origin_prefixes: Sequence[str] = (
        "https://github.com/zb-ss/servonaut/releases/download/",
    )
    allowed_channels: Sequence[ReleaseChannel] = (
        ReleaseChannel.STABLE,
        ReleaseChannel.PREVIEW,
    )
    enforce_https: bool = True
    require_freshness: bool = True
    clock_skew_tolerance_seconds: int = 300


def sign_manifest(
    manifest: ReleaseManifest,
    private_key: Ed25519PrivateKey,
    key_id: str,
    *,
    signed_at: Optional[str] = None,
) -> ReleaseManifest:
    """Sign a ReleaseManifest with an Ed25519 private key.

    Returns a new ReleaseManifest instance including the new signature.
    """
    canonical = manifest.canonical_bytes()
    sig_raw = private_key.sign(canonical)
    sig_str = encode_signature_bytes(sig_raw)
    timestamp = signed_at or datetime.now(timezone.utc).isoformat()

    new_sig = ManifestSignature(
        key_id=key_id,
        algorithm="ed25519",
        signature=sig_str,
        signed_at=timestamp,
    )
    existing_sigs = [s for s in manifest.signatures if s.key_id != key_id]
    existing_sigs.append(new_sig)

    return ReleaseManifest(
        schema_version=manifest.schema_version,
        channel=manifest.channel,
        product_version=manifest.product_version,
        published_at=manifest.published_at,
        artifacts=manifest.artifacts,
        signatures=tuple(existing_sigs),
        packaging_revision=manifest.packaging_revision,
        expires_at=manifest.expires_at,
    )


def verify_manifest(
    manifest: ReleaseManifest,
    policy: TrustPolicy,
    *,
    now: Optional[datetime] = None,
) -> None:
    """Verify that a release manifest satisfies cryptographic and origin trust policies.

    Raises:
        ManifestSignatureError: If required signatures are missing, forged, or invalid.
        ManifestExpiredError: If the manifest has expired.
        ManifestOriginError: If any artifact URL origin is not allowed.
        ManifestSchemaError: If channel or schema rules are violated.
    """
    if manifest.channel not in policy.allowed_channels:
        raise ManifestSchemaError(
            f"Release channel '{manifest.channel.value}' is not permitted by trust policy."
        )

    # Check expiration
    if policy.require_freshness and manifest.expires_at:
        check_time = now or datetime.now(timezone.utc)
        try:
            exp_time = datetime.fromisoformat(manifest.expires_at)
            if exp_time.tzinfo is None:
                exp_time = exp_time.replace(tzinfo=timezone.utc)
        except Exception as err:
            raise ManifestSchemaError(f"Malformed expires_at timestamp: {err}") from err

        diff = (check_time - exp_time).total_seconds()
        if diff > policy.clock_skew_tolerance_seconds:
            raise ManifestExpiredError(
                f"Release manifest expired at {manifest.expires_at} (current check time {check_time.isoformat()})."
            )

    # Check URL origins
    for artifact in manifest.artifacts:
        url = artifact.download_url
        if policy.enforce_https and not url.startswith("https://"):
            raise ManifestOriginError(
                f"Artifact '{artifact.artifact_id}' download URL must use HTTPS: '{url}'"
            )
        if policy.allowed_origin_prefixes:
            if not any(url.startswith(prefix) for prefix in policy.allowed_origin_prefixes):
                raise ManifestOriginError(
                    f"Artifact '{artifact.artifact_id}' download URL origin '{url}' is not in allowed origins."
                )

    # Cryptographic signature verification
    canonical_bytes = manifest.canonical_bytes()
    valid_key_ids: set[str] = set()

    for sig in manifest.signatures:
        if sig.algorithm.lower() != "ed25519":
            continue
        if sig.key_id not in policy.trusted_public_keys:
            continue

        public_key = policy.trusted_public_keys[sig.key_id]
        sig_bytes = decode_signature_bytes(sig.signature)

        try:
            public_key.verify(sig_bytes, canonical_bytes)
            valid_key_ids.add(sig.key_id)
        except InvalidSignature as err:
            raise ManifestSignatureError(
                f"Cryptographic signature verification failed for key_id '{sig.key_id}'."
            ) from err
        except Exception as err:
            raise ManifestSignatureError(
                f"Error processing signature for key_id '{sig.key_id}': {err}"
            ) from err

    if len(valid_key_ids) < policy.minimum_signatures:
        raise ManifestSignatureError(
            f"Release manifest requires at least {policy.minimum_signatures} trusted signature(s), "
            f"found {len(valid_key_ids)}."
        )


def check_downgrade(
    manifest: ReleaseManifest,
    current_version: str,
    current_packaging_revision: Optional[int] = None,
) -> None:
    """Validate that the manifest version is strictly newer than current installation.

    Raises:
        ManifestDowngradeError: If the manifest version or revision is older or identical.
    """
    manifest_v = parse_semver(manifest.product_version)
    current_v = parse_semver(current_version)

    manifest_rev = manifest.packaging_revision or 0
    current_rev = current_packaging_revision or 0

    manifest_order = (manifest_v[0], manifest_v[1], manifest_v[2], manifest_v[3], manifest_rev)
    current_order = (current_v[0], current_v[1], current_v[2], current_v[3], current_rev)

    if manifest_order < current_order:
        raise ManifestDowngradeError(
            f"Refusing downgrade: update version {manifest.product_version} (rev {manifest_rev}) "
            f"is older than current version {current_version} (rev {current_rev})."
        )
    if manifest_order == current_order:
        raise ManifestDowngradeError(
            f"No update available: update version {manifest.product_version} (rev {manifest_rev}) "
            f"is identical to current version {current_version} (rev {current_rev})."
        )


def normalize_platform(raw_platform: Optional[str] = None) -> str:
    """Normalize system platform identifier to 'linux', 'darwin', or 'windows'."""
    p = (raw_platform or sys.platform).lower()
    if p.startswith("linux"):
        return "linux"
    if p.startswith("darwin") or "macos" in p:
        return "darwin"
    if p.startswith("win32") or p.startswith("win") or "windows" in p:
        return "windows"
    raise ManifestTargetError(f"Unsupported operating system platform: '{p}'")


def normalize_arch(raw_arch: Optional[str] = None) -> str:
    """Normalize machine architecture identifier to 'x86_64' or 'arm64'."""
    a = (raw_arch or platform.machine()).lower()
    if a in {"x86_64", "amd64", "x64"}:
        return "x86_64"
    if a in {"arm64", "aarch64"}:
        return "arm64"
    raise ManifestTargetError(f"Unsupported machine architecture: '{a}'")


def resolve_target_artifact(
    manifest: ReleaseManifest,
    runtime_layout: RuntimeLayout | DistributionKind,
    *,
    platform_name: Optional[str] = None,
    machine_arch: Optional[str] = None,
) -> ReleaseArtifact:
    """Resolve the unique compatible ReleaseArtifact for the given runtime and platform.

    Raises:
        NoCompatibleArtifactError: When no artifact matches the criteria.
        AmbiguousArtifactError: When more than one artifact matches the criteria.
    """
    target_platform = normalize_platform(platform_name)
    target_arch = normalize_arch(machine_arch)
    target_dist = runtime_layout.kind if isinstance(runtime_layout, RuntimeLayout) else runtime_layout


    matches = [
        artifact
        for artifact in manifest.artifacts
        if artifact.distribution == target_dist
        and artifact.platform == target_platform
        and artifact.arch == target_arch
    ]

    if not matches:
        raise NoCompatibleArtifactError(
            f"No compatible artifact found for distribution='{target_dist.value}', "
            f"platform='{target_platform}', arch='{target_arch}' in manifest for {manifest.product_version}."
        )
    if len(matches) > 1:
        matched_ids = [a.artifact_id for a in matches]
        raise AmbiguousArtifactError(
            f"Ambiguous artifact resolution: multiple artifacts match distribution='{target_dist.value}', "
            f"platform='{target_platform}', arch='{target_arch}': {matched_ids}"
        )
    return matches[0]

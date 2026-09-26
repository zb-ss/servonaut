"""Cryptographic trust policy, signature verification, downgrade prevention, and target resolution."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import platform
import re
import sys
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from servonaut.distribution import trust_root
from servonaut.distribution.manifest import (
    ManifestError,
    ManifestSchemaError,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    ManifestSignature,
    bounded_repr,
    parse_semver,
    parse_timestamp,
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


class OperatingSystemTooOldError(NoCompatibleArtifactError):
    """Raised when every matching artifact requires a newer host operating system."""


_OS_VERSION_NUMBERS_REGEX = re.compile(r"[0-9]+(?:\.[0-9]+)*")

# Manifest channels a build may update from, keyed by the channel it follows.
# A stable build only follows stable releases; a preview build follows
# previews and may also move to a stable release.
_ACCEPTED_CHANNELS: Mapping[ReleaseChannel, tuple[ReleaseChannel, ...]] = {
    ReleaseChannel.STABLE: (ReleaseChannel.STABLE,),
    ReleaseChannel.PREVIEW: (ReleaseChannel.PREVIEW, ReleaseChannel.STABLE),
}


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
    """Policy configuring required trust parameters for release manifests.

    ``minimum_signatures`` must be between one and the number of trusted keys,
    so a policy can never accept an unsigned manifest. Origin prefixes default
    to the pinned trust root.
    """

    trusted_public_keys: Mapping[str, Ed25519PublicKey]
    minimum_signatures: int = 1
    allowed_origin_prefixes: Sequence[str] = trust_root.ALLOWED_ARTIFACT_ORIGINS
    allowed_channels: Sequence[ReleaseChannel] = (ReleaseChannel.STABLE,)
    enforce_https: bool = True
    require_freshness: bool = True
    clock_skew_tolerance_seconds: int = 300

    def __post_init__(self) -> None:
        minimum = self.minimum_signatures
        if (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or not 1 <= minimum <= len(self.trusted_public_keys)
        ):
            raise ValueError(
                "minimum_signatures must be at least 1 and no more than the "
                "number of trusted public keys."
            )
        for prefix in self.allowed_origin_prefixes:
            _validate_origin_prefix(prefix, enforce_https=self.enforce_https)


def channels_accepted_by(build_channel: ReleaseChannel) -> tuple[ReleaseChannel, ...]:
    """Return the manifest channels a build following ``build_channel`` accepts."""
    try:
        return _ACCEPTED_CHANNELS[build_channel]
    except KeyError:
        raise ValueError(
            f"Packaged builds cannot follow the {build_channel.value} channel."
        ) from None


def release_trust_policy(build_channel: ReleaseChannel) -> Optional[TrustPolicy]:
    """Build the update trust policy for a running build from the pinned trust root.

    Returns None when no release key is pinned, meaning updates are not
    configured for this build.
    """
    keys = {
        key_id: load_ed25519_public_key(encoded)
        for key_id, encoded in trust_root.PINNED_RELEASE_KEYS.items()
    }
    if not keys:
        return None
    return TrustPolicy(
        trusted_public_keys=keys,
        allowed_origin_prefixes=trust_root.ALLOWED_ARTIFACT_ORIGINS,
        allowed_channels=channels_accepted_by(build_channel),
    )


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
        ManifestExpiredError: If the manifest has expired, or declares no expiry
            while the policy requires freshness.
        ManifestOriginError: If any artifact URL origin is not allowed.
        ManifestSchemaError: If channel or schema rules are violated.
    """
    if manifest.channel not in policy.allowed_channels:
        raise ManifestSchemaError(
            f"Release channel '{manifest.channel.value}' is not permitted by trust policy."
        )
    _check_freshness(manifest, policy, now)
    _check_download_origins(manifest, policy)

    trusted = _count_trusted_signatures(manifest, policy)
    if trusted < policy.minimum_signatures:
        raise ManifestSignatureError(
            f"Release manifest requires at least {policy.minimum_signatures} trusted signature(s), "
            f"found {trusted}."
        )


def _check_freshness(
    manifest: ReleaseManifest, policy: TrustPolicy, now: Optional[datetime]
) -> None:
    if not policy.require_freshness:
        return
    if manifest.expires_at is None:
        raise ManifestExpiredError(
            "Release manifest declares no expires_at but the trust policy requires freshness."
        )
    expires = parse_timestamp(manifest.expires_at)
    check_time = now or datetime.now(timezone.utc)
    if (check_time - expires).total_seconds() > policy.clock_skew_tolerance_seconds:
        raise ManifestExpiredError(
            f"Release manifest expired at {bounded_repr(manifest.expires_at)} "
            f"(current check time {check_time.isoformat()})."
        )


def _check_download_origins(manifest: ReleaseManifest, policy: TrustPolicy) -> None:
    allowed = [_strict_url_parts(prefix) for prefix in policy.allowed_origin_prefixes]
    for artifact in manifest.artifacts:
        url = artifact.download_url
        label = bounded_repr(artifact.artifact_id)
        parts = _strict_url_parts(url)
        if policy.enforce_https and parts.scheme != "https":
            raise ManifestOriginError(
                f"Artifact {label} download URL must use HTTPS: {bounded_repr(url)}"
            )
        if allowed and not any(_within_origin(parts, prefix) for prefix in allowed):
            raise ManifestOriginError(
                f"Artifact {label} download URL origin {bounded_repr(url)} is not in allowed origins."
            )


def _strict_url_parts(url: object) -> urllib.parse.SplitResult:
    """Parse a URL, refusing forms that could slip past a prefix comparison."""
    if (
        not isinstance(url, str)
        or not url.isascii()
        or any(char <= " " or char == "\x7f" for char in url)
    ):
        raise ManifestOriginError(f"URL {bounded_repr(url)} contains disallowed characters.")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise ManifestOriginError(f"URL {bounded_repr(url)} is not a valid URL.") from None
    if parts.hostname is None or port is not None or parts.netloc.lower() != parts.hostname:
        raise ManifestOriginError(
            f"URL {bounded_repr(url)} must name a host without user information or a port."
        )
    if _has_unsafe_path_segment(parts.path):
        raise ManifestOriginError(
            f"URL {bounded_repr(url)} must not contain dot segments or encoded separators."
        )
    return parts


def _has_unsafe_path_segment(path: str) -> bool:
    for segment in path.split("/"):
        decoded = urllib.parse.unquote(segment)
        if decoded in {".", ".."} or "/" in decoded or "\\" in decoded:
            return True
    return False


def _within_origin(
    parts: urllib.parse.SplitResult, prefix: urllib.parse.SplitResult
) -> bool:
    return (
        parts.scheme == prefix.scheme
        and parts.hostname == prefix.hostname
        and parts.path.startswith(prefix.path)
    )


def _validate_origin_prefix(prefix: object, *, enforce_https: bool) -> None:
    try:
        parts = _strict_url_parts(prefix)
    except ManifestOriginError as err:
        raise ValueError(str(err)) from None
    schemes = {"https"} if enforce_https else {"http", "https"}
    if parts.scheme not in schemes or not parts.path.endswith("/") or parts.query or parts.fragment:
        raise ValueError(
            f"Allowed origin prefix {bounded_repr(prefix)} must be an HTTPS URL whose path ends in '/'."
        )


def _count_trusted_signatures(manifest: ReleaseManifest, policy: TrustPolicy) -> int:
    canonical_bytes = manifest.canonical_bytes()
    valid_key_ids: set[str] = set()
    for sig in manifest.signatures:
        public_key = policy.trusted_public_keys.get(sig.key_id)
        if sig.algorithm.lower() != "ed25519" or public_key is None:
            continue
        try:
            public_key.verify(decode_signature_bytes(sig.signature), canonical_bytes)
        except InvalidSignature as err:
            raise ManifestSignatureError(
                f"Cryptographic signature verification failed for key_id {bounded_repr(sig.key_id)}."
            ) from err
        valid_key_ids.add(sig.key_id)
    return len(valid_key_ids)


def check_downgrade(
    manifest: ReleaseManifest,
    current_version: str,
    current_packaging_revision: Optional[int] = None,
) -> None:
    """Validate that the manifest version is strictly newer than current installation.

    Versions are ordered by Semantic Versioning precedence, then by the integer
    packaging revision. Packaged builds always carry the revision their build
    wrote into the runtime marker; ``None`` (a build without a marker, or a
    manifest without a revision) orders before every revision of its version.

    Raises:
        ManifestDowngradeError: If the manifest version or revision is older or identical.
        ManifestSchemaError: If either version is not a valid semantic version.
    """
    manifest_rev = manifest.packaging_revision or 0
    current_rev = current_packaging_revision or 0
    manifest_order = (parse_semver(manifest.product_version).precedence, manifest_rev)
    current_order = (parse_semver(current_version).precedence, current_rev)

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


def host_os_version(platform_name: str) -> Optional[str]:
    """Return the running host's operating-system version, when it can be determined.

    Only macOS and Windows report a version comparable with an artifact's
    ``min_os``; any other platform, or a platform other than the running
    host's, returns None.
    """
    if platform_name == "darwin" and sys.platform == "darwin":
        return platform.mac_ver()[0] or None
    if platform_name == "windows" and sys.platform == "win32":
        return platform.version() or None
    return None


def resolve_target_artifact(
    manifest: ReleaseManifest,
    runtime_layout: RuntimeLayout | DistributionKind,
    *,
    platform_name: Optional[str] = None,
    machine_arch: Optional[str] = None,
    os_version: Optional[str] = None,
) -> ReleaseArtifact:
    """Resolve the unique compatible ReleaseArtifact for the given runtime and platform.

    ``os_version`` defaults to :func:`host_os_version`; an artifact's
    ``min_os`` is only enforced when a host version is known.

    Raises:
        NoCompatibleArtifactError: When no artifact matches the criteria.
        OperatingSystemTooOldError: When matching artifacts need a newer OS.
        AmbiguousArtifactError: When more than one artifact matches the criteria.
    """
    target_platform = normalize_platform(platform_name)
    target_arch = normalize_arch(machine_arch)
    target_dist = runtime_layout.kind if isinstance(runtime_layout, RuntimeLayout) else runtime_layout
    host_version = os_version if os_version is not None else host_os_version(target_platform)

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

    supported = [artifact for artifact in matches if _meets_min_os(artifact, host_version)]
    if not supported:
        required = sorted({artifact.min_os for artifact in matches if artifact.min_os})
        raise OperatingSystemTooOldError(
            f"Update {manifest.product_version} requires {target_platform} {required[0]} or later; "
            f"this host runs {host_version}."
        )
    if len(supported) > 1:
        matched_ids = [a.artifact_id for a in supported]
        raise AmbiguousArtifactError(
            f"Ambiguous artifact resolution: multiple artifacts match distribution='{target_dist.value}', "
            f"platform='{target_platform}', arch='{target_arch}': {bounded_repr(matched_ids)}"
        )
    return supported[0]


def _meets_min_os(artifact: ReleaseArtifact, host_version: Optional[str]) -> bool:
    """True unless both versions are known and the host is older than ``min_os``."""
    if artifact.min_os is None or host_version is None:
        return True
    host = _os_version_numbers(host_version)
    required = _os_version_numbers(artifact.min_os)
    if host is None or required is None:
        return True
    width = max(len(host), len(required))
    return host + (0,) * (width - len(host)) >= required + (0,) * (width - len(required))


def _os_version_numbers(version: str) -> Optional[tuple[int, ...]]:
    if _OS_VERSION_NUMBERS_REGEX.fullmatch(version) is None:
        return None
    return tuple(int(part) for part in version.split("."))

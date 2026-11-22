"""Canonical signed authorization for automatic desktop updates."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution.manifest import (
    ArtifactKind,
    ManifestSchemaError,
    ManifestSignature,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    SUPPORTED_ARCHITECTURES,
    canonicalize_json,
    parse_semver,
    parse_timestamp,
    validate_packaging_revision,
)
from servonaut.distribution.trust import (
    ManifestExpiredError,
    TrustPolicy,
    encode_signature_bytes,
    verify_release_signatures,
)

PURPOSE = "servonaut.desktop-apply-policy"
CHANNELS = (ReleaseChannel.STABLE, ReleaseChannel.PREVIEW)
# The longest lifetime a signed apply policy may claim. The publisher signs
# shorter policies and renews them well before they expire, and every check
# fetches the policy uncached, so a withdrawal or pause reaches online
# installs at their next check whatever the lifetime. The lifetime only bounds
# how long a replayed old policy could still be accepted.
MAX_POLICY_VALIDITY = timedelta(days=7)
_MAX_SEQUENCE = (1 << 53) - 1
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TARGET_PLATFORMS = {
    ArtifactKind.MACOS_DMG: "darwin",
    ArtifactKind.WINDOWS_MSI: "windows",
    ArtifactKind.UBUNTU_DEB: "linux",
}


@dataclass(frozen=True, order=True, slots=True)
class DesktopArtifactIdentity:
    product_version: str
    packaging_revision: int
    kind: ArtifactKind
    platform: str
    arch: str
    sha256: str

    def __post_init__(self) -> None:
        parse_semver(self.product_version)
        validate_packaging_revision(self.packaging_revision)
        if not isinstance(self.kind, ArtifactKind) or self.kind not in _TARGET_PLATFORMS:
            raise ManifestSchemaError("Invalid desktop artifact kind.")
        if not isinstance(self.platform, str) or self.platform != _TARGET_PLATFORMS[self.kind]:
            raise ManifestSchemaError("Desktop artifact platform does not match its kind.")
        if not isinstance(self.arch, str) or self.arch not in SUPPORTED_ARCHITECTURES:
            raise ManifestSchemaError("Invalid desktop artifact architecture.")
        if not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
            raise ManifestSchemaError("Invalid desktop artifact SHA-256.")

    @classmethod
    def from_dict(cls, data: Any) -> DesktopArtifactIdentity:
        fields = {"product_version", "packaging_revision", "kind", "platform", "arch", "sha256"}
        if not isinstance(data, Mapping) or set(data) != fields:
            raise ManifestSchemaError("Invalid desktop artifact identity.")
        try:
            kind = ArtifactKind(data["kind"])
        except (ValueError, TypeError):
            raise ManifestSchemaError("Invalid desktop artifact kind.") from None
        return cls(data["product_version"], data["packaging_revision"],
                   kind, data["platform"], data["arch"], data["sha256"])

    @classmethod
    def from_artifact(cls, manifest: ReleaseManifest, artifact: ReleaseArtifact) -> DesktopArtifactIdentity:
        return cls(manifest.product_version, manifest.packaging_revision, artifact.kind,
                   artifact.platform, artifact.arch, artifact.sha256.lower())


@dataclass(frozen=True, slots=True)
class DesktopApplyPolicy:
    channel: ReleaseChannel
    sequence: int
    issued_at: str
    expires_at: str
    paused: bool
    permitted: tuple[DesktopArtifactIdentity, ...]
    withdrawn: tuple[DesktopArtifactIdentity, ...] = ()
    signatures: tuple[ManifestSignature, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.channel, ReleaseChannel) or self.channel not in CHANNELS:
            raise ManifestSchemaError("Invalid desktop policy channel.")
        validate_policy_sequence(self.sequence)
        lifetime = parse_timestamp(self.expires_at) - parse_timestamp(self.issued_at)
        if not timedelta(0) < lifetime <= MAX_POLICY_VALIDITY:
            raise ManifestSchemaError("Desktop apply policy must last at most seven days.")
        if type(self.paused) is not bool or (self.paused and self.permitted):
            raise ManifestSchemaError("A paused desktop policy cannot permit artifacts.")
        if len(set(self.permitted)) != len(self.permitted) or len(set(self.withdrawn)) != len(self.withdrawn):
            raise ManifestSchemaError("Desktop policy contains duplicate artifact identities.")
        if set(self.permitted).intersection(self.withdrawn):
            raise ManifestSchemaError("Desktop policy permits a withdrawn artifact.")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "purpose": PURPOSE,
            "channel": self.channel.value,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "paused": self.paused,
            "permitted": [asdict(identity) for identity in self.permitted],
            "withdrawn": [asdict(identity) for identity in self.withdrawn],
        }

    def canonical_bytes(self) -> bytes:
        return canonicalize_json(self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "signatures": [signature.to_dict() for signature in self.signatures]}

    @classmethod
    def from_dict(cls, data: Any) -> DesktopApplyPolicy:
        if (not isinstance(data, Mapping) or data.get("purpose") != PURPOSE
                or type(data.get("schema_version")) is not int or data["schema_version"] != 1):
            raise ManifestSchemaError("Unsupported desktop policy document.")
        try:
            channel = ReleaseChannel(data["channel"])
            identities = data["permitted"]
            withdrawn = data["withdrawn"]
            signatures = data["signatures"]
            if not all(isinstance(entries, list) for entries in (identities, withdrawn, signatures)):
                raise TypeError
            result = cls(
                channel, data["sequence"], data["issued_at"], data["expires_at"], data["paused"],
                tuple(DesktopArtifactIdentity.from_dict(item) for item in identities),
                tuple(DesktopArtifactIdentity.from_dict(item) for item in withdrawn),
                tuple(ManifestSignature.from_dict(item) for item in signatures),
            )
        except (KeyError, TypeError, ValueError):
            raise ManifestSchemaError("Invalid desktop policy document.") from None
        if set(data) != set(result.to_dict()):
            raise ManifestSchemaError("Unexpected desktop policy fields.")
        return result

    @classmethod
    def from_json(cls, body: bytes) -> DesktopApplyPolicy:
        try:
            data = json.loads(body)
        except (ValueError, RecursionError):
            raise ManifestSchemaError("Invalid desktop policy JSON.") from None
        return cls.from_dict(data)


def validate_policy_sequence(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SEQUENCE:
        raise ManifestSchemaError("Desktop policy sequence is outside its supported range.")
    return value


def sign_apply_policy(policy: DesktopApplyPolicy, key: Ed25519PrivateKey, key_id: str) -> DesktopApplyPolicy:
    signature = ManifestSignature(
        key_id, "ed25519", encode_signature_bytes(key.sign(policy.canonical_bytes())), policy.issued_at,
    )
    others = tuple(entry for entry in policy.signatures if entry.key_id != key_id)
    return replace(policy, signatures=(*others, signature))


class DesktopPolicyClockError(ManifestExpiredError):
    """The signed policy was issued beyond the configured future clock tolerance."""


def verify_apply_policy(
    policy: DesktopApplyPolicy, trust: TrustPolicy, channel: ReleaseChannel, *,
    now: datetime | None = None, check_expiry: bool = True,
) -> None:
    if policy.channel is not channel or channel not in trust.allowed_channels:
        raise ManifestSchemaError("Desktop policy belongs to another channel.")
    verify_release_signatures(policy.canonical_bytes(), policy.signatures, trust, label="Desktop apply policy")
    moment = now or datetime.now(timezone.utc)
    if check_expiry:
        if parse_timestamp(policy.issued_at) - moment > timedelta(seconds=trust.clock_skew_tolerance_seconds):
            raise DesktopPolicyClockError("The desktop update policy is newer than this computer's clock.")
        if moment >= parse_timestamp(policy.expires_at):
            raise ManifestExpiredError("The desktop update policy expired.")


def policy_url_for_manifest(manifest_url: str) -> str:
    parts = urlsplit(manifest_url)
    stem = parts.path.removesuffix(".json")
    return urlunsplit((parts.scheme, parts.netloc, f"{stem}-apply.json", parts.query, ""))

"""Servonaut distribution models, release manifests, and cryptographic trust policy."""

from servonaut.distribution.manifest import (
    ArtifactKind,
    ManifestError,
    ManifestSchemaError,
    ManifestSignature,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    canonicalize_json,
)
from servonaut.distribution.trust import (
    AmbiguousArtifactError,
    ManifestDowngradeError,
    ManifestExpiredError,
    ManifestOriginError,
    ManifestSignatureError,
    ManifestTargetError,
    NoCompatibleArtifactError,
    TrustPolicy,
    check_downgrade,
    decode_signature_bytes,
    encode_signature_bytes,
    load_ed25519_public_key,
    normalize_arch,
    normalize_platform,
    parse_semver,
    resolve_target_artifact,
    sign_manifest,
    verify_manifest,
)

from servonaut.distribution.builder import (
    ManifestBuilder,
    ManifestBuilderError,
)
from servonaut.distribution.verify import (
    VerificationError,
    verify_artifact_signature,
    verify_file_sha256,
    verify_release_file,
)

__all__ = [
    "AmbiguousArtifactError",
    "ArtifactKind",
    "ManifestBuilder",
    "ManifestBuilderError",
    "ManifestDowngradeError",
    "ManifestError",
    "ManifestExpiredError",
    "ManifestOriginError",
    "ManifestSchemaError",
    "ManifestSignature",
    "ManifestSignatureError",
    "ManifestTargetError",
    "NoCompatibleArtifactError",
    "ReleaseArtifact",
    "ReleaseChannel",
    "ReleaseManifest",
    "TrustPolicy",
    "VerificationError",
    "canonicalize_json",
    "check_downgrade",
    "decode_signature_bytes",
    "encode_signature_bytes",
    "load_ed25519_public_key",
    "normalize_arch",
    "normalize_platform",
    "parse_semver",
    "resolve_target_artifact",
    "sign_manifest",
    "verify_artifact_signature",
    "verify_file_sha256",
    "verify_manifest",
    "verify_release_file",
]


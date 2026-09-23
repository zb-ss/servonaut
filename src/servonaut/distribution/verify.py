"""Pure verification utilities for downloaded release artifacts and signed manifests."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from servonaut.distribution.manifest import ManifestError, ReleaseArtifact, ReleaseManifest
from servonaut.distribution.trust import TrustPolicy, verify_manifest


class VerificationError(ManifestError):
    """Raised when release artifact or manifest verification fails."""


def verify_file_sha256(file_path: Path | str, expected_sha256: str) -> bool:
    """Verify that a local file matches the expected SHA-256 digest via streaming."""
    path = Path(file_path).resolve()
    if not path.is_file():
        return False

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(64 * 1024):
            hasher.update(chunk)

    computed = hasher.hexdigest().lower()
    expected = expected_sha256.strip().lower()
    return hmac.compare_digest(computed, expected)


def verify_artifact_signature(
    artifact: ReleaseArtifact,
    public_key: Ed25519PublicKey,
) -> bool:
    """Verify an artifact's detached Ed25519 signature over its SHA-256 digest."""
    if not artifact.signature:
        return False

    try:
        sig_bytes = bytes.fromhex(artifact.signature)
        public_key.verify(sig_bytes, artifact.sha256.encode("ascii"))
        return True
    except (ValueError, InvalidSignature):
        return False


def verify_release_file(
    manifest: ReleaseManifest,
    file_path: Path | str,
    *,
    trust_policy: Optional[TrustPolicy] = None,
) -> tuple[bool, str]:
    """Verify a release artifact against a release manifest and optional trust policy.

    Returns:
        tuple[bool, str]: (is_valid, diagnostic_message)
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        return False, f"File does not exist: {path}"

    if trust_policy is not None:
        try:
            verify_manifest(manifest, trust_policy)
        except ManifestError as exc:
            return False, f"Manifest trust verification failed: {exc}"

    matching = [art for art in manifest.artifacts if art.filename == path.name]
    if not matching:
        return False, f"Artifact '{path.name}' is not registered in the release manifest."
    if len(matching) > 1:
        return False, f"Ambiguous artifact: multiple entries match filename '{path.name}'."

    target_art = matching[0]

    # Verify byte size
    actual_size = path.stat().st_size
    if actual_size != target_art.byte_size:
        return (
            False,
            f"Size mismatch for '{path.name}': expected {target_art.byte_size} bytes, observed {actual_size} bytes.",
        )

    # Verify SHA-256
    if not verify_file_sha256(path, target_art.sha256):
        return False, f"SHA-256 integrity verification failed for '{path.name}'."

    # Verify detached artifact signature if present and trusted keys exist
    if target_art.signature and trust_policy and trust_policy.trusted_public_keys:
        verified_any = False
        for pubkey in trust_policy.trusted_public_keys.values():
            if verify_artifact_signature(target_art, pubkey):
                verified_any = True
                break
        if not verified_any:
            return False, f"Detached signature on '{path.name}' could not be verified by any trusted key."

    return True, f"Artifact '{path.name}' successfully verified against release manifest v{manifest.product_version}."

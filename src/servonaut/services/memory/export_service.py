"""Export service for the server memory subsystem.

Provides tier-gated compliance export and cryptographic verification.

Spec coverage:
- §3.6  GET  /api/v1/memory/export          (requires ``memory_compliance_export``)
- §3.6  GET  /api/v1/memory/export-signing-key  (PUBLIC — no auth required)

Rate limit: 2 exports per hour (``RateLimitKey.EXPORT``).

File storage:
- Tarballs land in ``~/.servonaut/exports/`` (mode 0o700, files 0o600).
- The signing-key cache lives at ``~/.servonaut/memory/signing_keys.json``.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    MemoryBackendError,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class KeyRotationMismatchError(MemoryBackendError):
    """Raised when the server returns a signing key with a different key_id
    than the one requested.

    This indicates the key has been rotated between a cache miss and the
    refetch.  The new key is cached before this exception is raised.

    Attributes:
        requested_key_id: The key_id that was requested.
        received_key_id: The key_id actually returned by the server.
    """

    def __init__(self, requested_key_id: str, received_key_id: str) -> None:
        self.requested_key_id = requested_key_id
        self.received_key_id = received_key_id
        super().__init__(
            f"Signing key rotation mismatch: requested {requested_key_id!r}, "
            f"received {received_key_id!r}. The key was rotated; the new key "
            "has been cached."
        )


class SignatureMismatchError(MemoryBackendError):
    """Raised by ``verify_export`` when the Ed25519 signature does not match
    the manifest contents.

    This indicates the tarball has been tampered with or corrupted.
    """


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SigningKey:
    """A public signing key for verifying export tarballs.

    Attributes:
        key_id: Rotation identifier (opaque string).
        public_key: Raw 32-byte Ed25519 public key.
        algorithm: Always ``"ed25519"``.
        fetched_at: When this key was fetched from the server.
    """

    key_id: str
    public_key: bytes
    algorithm: str
    fetched_at: datetime


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class MemoryExportService:
    """Client for the memory export API endpoints (spec §3.6).

    All export operations are tier-gated on ``memory_compliance_export``
    (Teams plan).  The signing-key endpoint is public and requires no auth.

    Args:
        api_client: Authenticated API client (used for the tarball download).
        rate_limiter: Shared rate limiter instance.
        auth_service: Auth service (used for entitlement checks).
    """

    EXPORT_DIR: Path = Path.home() / ".servonaut" / "exports"
    SIGNING_KEY_CACHE: Path = Path.home() / ".servonaut" / "memory" / "signing_keys.json"

    _FEATURE = "memory_compliance_export"

    def __init__(
        self,
        api_client: "APIClient",
        rate_limiter: RateLimiter,
        auth_service: "AuthService",
    ) -> None:
        self._api = api_client
        self._rate_limiter = rate_limiter
        self._auth = auth_service

    # ------------------------------------------------------------------
    # Entitlement gate helper
    # ------------------------------------------------------------------

    def _require_feature(self) -> None:
        """Raise ``UpsellRequired`` if the user is not entitled."""
        if not self._auth.has_feature(self._FEATURE):
            raise UpsellRequired(self._FEATURE)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    async def export(
        self,
        from_: Optional[str] = None,
        to_: Optional[str] = None,
    ) -> Path:
        """Download a signed compliance export tarball and save it to disk.

        Args:
            from_: Optional ISO-8601 start timestamp filter.
            to_: Optional ISO-8601 end timestamp filter.

        Returns:
            Path to the saved tarball (inside ``EXPORT_DIR``).

        Raises:
            UpsellRequired: If ``memory_compliance_export`` is not in the plan.
            BackendMaintenance: On 503.
            BetaWaitlist: On 403 feature_not_available.
            ValidationFailed: On 422.
        """
        self._require_feature()
        await self._rate_limiter.acquire(RateLimitKey.EXPORT)

        params: Dict[str, str] = {}
        if from_ is not None:
            params["from"] = from_
        if to_ is not None:
            params["to"] = to_

        try:
            body, headers = await self._api.get_bytes(
                "/api/v1/memory/export",
                params=params if params else None,
            )
        except Exception as exc:
            raise _translate_api_error(exc) from exc

        filename = _parse_content_disposition(headers)
        if not filename:
            # Derive a safe fallback filename from timestamp
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"memory-export-{ts}.tar.gz"

        self.EXPORT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        dest = self.EXPORT_DIR / filename

        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                dest.unlink()
            except OSError:
                pass
            raise

        # Belt-and-suspenders mode fix
        os.chmod(str(dest), 0o600)
        logger.info("Export saved to %s (%d bytes)", dest, len(body))
        return dest

    # ------------------------------------------------------------------
    # Signing key management
    # ------------------------------------------------------------------

    async def get_signing_key(self, key_id: Optional[str] = None) -> SigningKey:
        """Fetch or return a cached Ed25519 signing key.

        When ``key_id`` is ``None``, the latest key is fetched from the server
        and cached.  When ``key_id`` is provided, the cache is checked first;
        a cache miss triggers a server fetch.

        Args:
            key_id: Specific rotation ID to look up, or ``None`` for latest.

        Returns:
            A ``SigningKey`` with the raw public key bytes.

        Raises:
            KeyRotationMismatchError: If the server returns a different key_id
                than requested (key was rotated between cache miss and fetch).
        """
        cache = self._load_key_cache()

        if key_id is not None and key_id in cache:
            return cache[key_id]

        # Fetch from the public endpoint (no auth required).
        fetched = await self._fetch_signing_key_from_server()
        self._save_key_to_cache(fetched)

        if key_id is not None and fetched.key_id != key_id:
            raise KeyRotationMismatchError(
                requested_key_id=key_id,
                received_key_id=fetched.key_id,
            )

        return fetched

    async def _fetch_signing_key_from_server(self) -> SigningKey:
        """Hit the public /api/v1/memory/export-signing-key endpoint.

        The endpoint requires no authentication (auditors can verify exports
        without a Servonaut account).
        """
        try:
            data = await self._api.get("/api/v1/memory/export-signing-key")
        except Exception as exc:
            raise _translate_api_error(exc) from exc

        raw_pk = base64.b64decode(data["public_key_b64"])
        return SigningKey(
            key_id=data["key_id"],
            public_key=raw_pk,
            algorithm=data.get("algorithm", "ed25519"),
            fetched_at=datetime.now(timezone.utc),
        )

    def _load_key_cache(self) -> Dict[str, SigningKey]:
        """Load the signing-key cache from disk.

        Returns an empty dict if the cache file does not exist or is corrupt.
        """
        if not self.SIGNING_KEY_CACHE.exists():
            return {}
        try:
            raw = json.loads(self.SIGNING_KEY_CACHE.read_text())
            result: Dict[str, SigningKey] = {}
            for kid, entry in raw.items():
                result[kid] = SigningKey(
                    key_id=kid,
                    public_key=base64.b64decode(entry["public_key_b64"]),
                    algorithm=entry.get("algorithm", "ed25519"),
                    fetched_at=datetime.fromisoformat(entry["fetched_at"]),
                )
            return result
        except Exception as exc:
            logger.warning("Signing key cache corrupt, ignoring: %s", exc)
            return {}

    def _save_key_to_cache(self, key: SigningKey) -> None:
        """Persist a signing key entry to the cache file."""
        cache_raw: Dict[str, Any] = {}
        if self.SIGNING_KEY_CACHE.exists():
            try:
                cache_raw = json.loads(self.SIGNING_KEY_CACHE.read_text())
            except Exception:
                cache_raw = {}

        cache_raw[key.key_id] = {
            "public_key_b64": base64.b64encode(key.public_key).decode(),
            "algorithm": key.algorithm,
            "fetched_at": key.fetched_at.isoformat(),
        }

        self.SIGNING_KEY_CACHE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.SIGNING_KEY_CACHE.write_text(json.dumps(cache_raw, indent=2))
        except Exception as exc:
            logger.warning("Failed to persist signing key cache: %s", exc)

    # ------------------------------------------------------------------
    # Export verification
    # ------------------------------------------------------------------

    async def verify_export(self, tarball_path: Path) -> bool:
        """Verify the Ed25519 signature of a downloaded export tarball.

        The tarball is expected to contain:
        - ``manifest.json`` — envelope metadata and ``signing_key_id``
        - ``manifest.sig`` — detached Ed25519 signature over ``manifest.json``

        Args:
            tarball_path: Path to the ``.tar.gz`` file to verify.

        Returns:
            ``True`` if the signature is valid.

        Raises:
            SignatureMismatchError: If the signature does not match the manifest.
            FileNotFoundError: If ``tarball_path`` does not exist.
            KeyError: If ``manifest.json`` or ``manifest.sig`` is missing from tarball.
        """
        with tarfile.open(str(tarball_path), "r:gz") as tf:
            manifest_bytes = _extract_member(tf, "manifest.json")
            sig_bytes = _extract_member(tf, "manifest.sig")

            # Parse manifest to find the signing key id
            try:
                manifest_data = json.loads(manifest_bytes)
                signing_key_id: Optional[str] = manifest_data.get("signing_key_id")
            except Exception:
                signing_key_id = None

        key = await self.get_signing_key(key_id=signing_key_id)

        try:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError

            VerifyKey(key.public_key).verify(manifest_bytes, sig_bytes)
            return True
        except Exception as exc:
            # nacl.exceptions is not always importable at type-check time;
            # catch broadly and re-raise as our domain error.
            from nacl.exceptions import BadSignatureError as _BSE
            if isinstance(exc, _BSE):
                raise SignatureMismatchError(
                    "Export tarball signature is invalid — the manifest may have been tampered with."
                ) from exc
            raise SignatureMismatchError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_content_disposition(headers: Dict[str, str]) -> Optional[str]:
    """Extract the suggested filename from a Content-Disposition header.

    Handles both quoted and unquoted filename parameters.

    Args:
        headers: Response headers dict (keys are lowercase).

    Returns:
        Filename string, or ``None`` if not found / not parseable.
    """
    cd = headers.get("content-disposition", "")
    if not cd:
        return None
    # Try RFC 5987 filename* first, then plain filename=
    match = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';\r\n]+)["\']?', cd, re.IGNORECASE)
    if match:
        filename = match.group(1).strip()
        # Sanitise: keep only safe filename characters
        safe = re.sub(r"[^\w\-.]", "_", filename)
        return safe or None
    return None


def _extract_member(tf: tarfile.TarFile, name: str) -> bytes:
    """Extract a named member from an open TarFile and return its bytes.

    Validates the member is a regular file with a safe name so a malicious
    tarball cannot trick us into following a symlink, absolute path, or
    parent-directory traversal even if a future caller switches to disk
    extraction. PEP 706 ``data_filter`` semantics in spirit.

    Args:
        tf: Open TarFile object.
        name: Member name (e.g. ``"manifest.json"``).

    Returns:
        Raw bytes of the member.

    Raises:
        KeyError: If the member does not exist in the tarball.
        SignatureMismatchError: If the member is unsafe (symlink, absolute
            path, or contains ``..``).
    """
    try:
        member = tf.getmember(name)
    except KeyError:
        raise KeyError(f"Tarball is missing required member: {name!r}")
    if member.issym() or member.islnk():
        raise SignatureMismatchError(f"Refusing to follow link in tarball: {name!r}")
    if not member.isfile():
        raise SignatureMismatchError(f"Tarball member is not a regular file: {name!r}")
    safe_name = member.name
    if safe_name.startswith("/") or ".." in safe_name.split("/"):
        raise SignatureMismatchError(f"Tarball member has unsafe path: {safe_name!r}")
    f = tf.extractfile(member)
    if f is None:
        raise KeyError(f"Cannot read tarball member: {name!r}")
    return f.read()


def _translate_api_error(exc: Exception) -> Exception:
    """Translate an ``APIError`` subclass into a memory domain exception."""
    from servonaut.services.api_client import (
        APIError,
        ForbiddenEntitlementError,
        FeatureNotAvailableError,
        FeatureDisabledError,
        ValidationFailedError,
    )

    if not isinstance(exc, APIError):
        return exc

    if isinstance(exc, ForbiddenEntitlementError):
        return UpsellRequired("memory_compliance_export")
    if isinstance(exc, FeatureNotAvailableError):
        return BetaWaitlist()
    if isinstance(exc, FeatureDisabledError):
        return BackendMaintenance()
    if isinstance(exc, ValidationFailedError):
        errors = []
        if exc.details:
            errors = exc.details.get("errors", [])
        return ValidationFailed(errors)
    return exc

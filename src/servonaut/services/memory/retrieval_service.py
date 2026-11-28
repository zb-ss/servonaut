"""MemoryRetrievalService — decrypt and fetch server-side memory envelopes.

Features:
- LRU cache (10 entries, 60s TTL) with asyncio.Lock for concurrency safety.
- Cache invalidation on crypto fingerprint change (key rotation detection).
- Maps 403 forbidden_entitlement → UpsellRequired.
- Maps 404 (access_revoked / not_found) → MemoryBackendError("access_revoked").
- All instance_id parameters validated against RESERVED_INSTANCE_IDS + INSTANCE_ID_RE.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from servonaut.services.api_client import (
    ForbiddenEntitlementError,
    NotFoundError,
)
from servonaut.services.memory.interfaces import (
    INSTANCE_ID_RE,
    RESERVED_INSTANCE_IDS,
    DecryptedEnvelope,
    KeyMaterial,
    MemoryBackendError,
    MemoryNotFound,
    ReservedInstanceIdError,
    UpsellRequired,
    VaultCustodyLocked,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)

# LRU cache settings
_LRU_MAX = 10
_LRU_TTL_SECONDS = 60.0


class StaleEnvelopes(MemoryBackendError):
    """The memory on the service no longer matches the envelopes a consent named."""

    code = "stale_envelopes"

    def __init__(self) -> None:
        super().__init__("stale_envelopes")


class EnvelopeKeyError(MemoryBackendError):
    """A hosted-summary key could not be released; ``code`` picks the text people read."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _plaintext_fits_module(module: str, plaintext: Any) -> bool:
    """Whether a decrypted payload has the shape that module's writers produce.

    Probe modules carry ``observed``/``declared``/``raw_output``, annotations
    carry ``content`` and findings carry ``findings`` (see the sync service).
    """
    if not isinstance(plaintext, dict):
        return False
    if module == "annotations":
        return "content" in plaintext
    if module == "findings":
        return "findings" in plaintext
    return any(key in plaintext for key in ("observed", "declared", "raw_output"))


def _validate_instance_id(instance_id: str) -> None:
    """Reject reserved or malformed instance IDs before they reach the wire.

    Mirrors :func:`sync_service._validate_reserved` so retrieval (read path)
    and sync (write path) enforce the same gate. Case-insensitive on the
    reserved-set check because the server may lower-case path segments.
    """
    if not instance_id:
        raise ReservedInstanceIdError("Instance ID is empty")
    if instance_id.lower() in RESERVED_INSTANCE_IDS:
        raise ReservedInstanceIdError(
            f"Instance ID {instance_id!r} is reserved by the server API"
        )
    if not INSTANCE_ID_RE.match(instance_id):
        raise ReservedInstanceIdError(
            f"Instance ID {instance_id!r} does not match pattern [A-Za-z0-9_\\-]{{1,128}}"
        )


class _LRUCache:
    """Thread-safe LRU cache with TTL expiry (10 entries / 60s default)."""

    def __init__(self, maxsize: int = _LRU_MAX, ttl: float = _LRU_TTL_SECONDS) -> None:
        self._maxsize = maxsize
        self._ttl = ttl
        self._data: OrderedDict[str, tuple[Any, float]] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        if key not in self._data:
            return None
        value, ts = self._data[key]
        if time.monotonic() - ts > self._ttl:
            del self._data[key]
            return None
        # Move to end (most-recently-used)
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: Any) -> None:
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = (value, time.monotonic())
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


#: Server-written summaries; their plaintext may be bare Markdown, not JSON.
_SUMMARY_MODULE = "ai_summary"


def _parse_plaintext(module: str, plaintext_bytes: bytes) -> Any:
    """Decode an envelope's plaintext.

    Probe modules are always JSON; anything else is corrupt and raises. A
    hosted summary is written by the service as bare UTF-8 Markdown, so for
    that module text that is not JSON is the summary itself.
    """
    text = plaintext_bytes.decode("utf-8")
    if module != _SUMMARY_MODULE:
        return json.loads(text)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text
    # Markdown such as "42" also parses as JSON; only an object or a string is a summary payload.
    return parsed if isinstance(parsed, (dict, str)) else text


class MemoryRetrievalService:
    """Fetch and decrypt envelopes from the server memory API.

    Args:
        api_client: Authenticated APIClient.
        crypto: The crypto module (services.memory.crypto) — used for decrypt_envelope.
        passphrase_provider: Async callable returning the user's passphrase string.
        rate_limiter: Optional shared RateLimiter; defaults to a private one.
        key_material_provider: Returns Memory Sync's unlocked key, or None
            while it is locked. Asked before this service unlocks on its own,
            so an unlocked Memory Sync never leads to a second prompt.
        user_id_provider: Async callable returning the signed-in user's id.
            Its own unlock needs it: envelopes are decrypted for that user.
    """

    def __init__(
        self,
        api_client: "APIClient",
        crypto: Any,
        passphrase_provider: Callable[[], Any],
        rate_limiter: Optional[RateLimiter] = None,
        key_material_provider: Optional[Callable[[], Optional[KeyMaterial]]] = None,
        user_id_provider: Optional[Callable[[], Any]] = None,
    ) -> None:
        self._api = api_client
        self._crypto = crypto
        self._passphrase_provider = passphrase_provider
        self._rate_limiter = rate_limiter or RateLimiter()
        self._key_material_provider = key_material_provider
        self._user_id_provider = user_id_provider

        self._cache = _LRUCache()
        self._lock = asyncio.Lock()

        # Track current fingerprint for rotation detection
        self._last_fingerprint: Optional[str] = None

        # Active keypair material (set after key fetch)
        self._self_user_id: Optional[int] = None
        self._self_pubkey: Optional[bytes] = None
        self._self_privkey: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Key material plumbing
    # ------------------------------------------------------------------

    def set_key_material(self, material: KeyMaterial) -> None:
        """Inject already-unwrapped keypair material from the sync service.

        Used by the app after :class:`MemorySyncService` finishes bootstrap
        so the retrieval layer can decrypt without re-prompting for the
        passphrase or re-hitting the rate-limited ``/keys/me`` endpoint.

        Args:
            material: :class:`KeyMaterial` carrying user_id + pubkey + privkey.
        """
        self._self_user_id = material.user_id
        self._self_pubkey = material.public_key
        self._self_privkey = material.private_key

    async def _ensure_keypair(self) -> None:
        """Fetch and cache the active keypair from the server."""
        import base64
        from servonaut.services.memory.crypto import WrappedPrivateKey, unwrap_private_key

        await self._rate_limiter.acquire(RateLimitKey.KEYS_ME)
        data = await self._api.get(
            "/api/v1/memory/keys/me", retry_on_401=False
        )
        # A vault-custody key has no passphrase to ask for, and this service
        # never prompts for (or reads) a vault item: Memory Sync's own unlock
        # hands the key over.
        from servonaut.services.memory.key_custody import CUSTODY_VAULT, parse_key_record

        if parse_key_record(data).custody == CUSTODY_VAULT:
            raise VaultCustodyLocked("vault_locked")
        pub_b64 = data.get("public_key", "")
        wrapped_json = data.get("wrapped_private_key", "")
        fingerprint = data.get("fingerprint", "")

        pub_bytes = base64.b64decode(pub_b64)

        # Detect key rotation — clear cache on fingerprint change
        if self._last_fingerprint and self._last_fingerprint != fingerprint:
            logger.info(
                "retrieval: fingerprint changed (%s → %s) — clearing LRU cache",
                self._last_fingerprint[:8], fingerprint[:8],
            )
            self._cache.clear()

        self._last_fingerprint = fingerprint
        self._self_pubkey = pub_bytes

        try:
            passphrase = await self._passphrase_provider("unlock")
        except TypeError:
            passphrase = await self._passphrase_provider()
        wrapped = WrappedPrivateKey.from_json(wrapped_json)
        self._self_privkey = unwrap_private_key(wrapped, passphrase)

    async def _ensure_key_material(self) -> None:
        """Have a keypair and the user id to decrypt for.

        Memory Sync's unlocked key comes first; this service only unlocks on
        its own (``/keys/me`` plus a passphrase prompt) while Memory Sync is
        locked, and then resolves the user id itself.
        """
        if self._self_privkey is not None and self._self_pubkey is not None and self._self_user_id is not None:
            return
        material = self._key_material_provider() if self._key_material_provider is not None else None
        if material is not None:
            self.set_key_material(material)
            return
        if self._self_privkey is None or self._self_pubkey is None:
            await self._ensure_keypair()
        if self._self_user_id is None and self._user_id_provider is not None:
            self._self_user_id = await self._user_id_provider()

    # ------------------------------------------------------------------
    # Private decrypt helper
    # ------------------------------------------------------------------

    async def _decrypt_envelope_dict(self, raw: Dict[str, Any]) -> "DecryptedEnvelope":
        """Decrypt a raw envelope dict from the server API.

        On fingerprint change (rotation), clears the LRU cache first.
        """
        await self._ensure_key_material()

        if self._self_user_id is None:
            # Without a resolved user_id we cannot pick the right dek_wrap;
            # raise loudly instead of silently falling back to user 0 which
            # would either decrypt the wrong envelope or leak diagnostics.
            raise RuntimeError(
                "MemoryRetrievalService user_id not initialised — "
                "call set_key_material() (or wait for bootstrap) first"
            )

        from servonaut.services.memory.crypto import decrypt_envelope
        plaintext_bytes = decrypt_envelope(
            raw,
            self_user_id=self._self_user_id,
            self_private_key=self._self_privkey,
            self_public_key=self._self_pubkey,
        )
        plaintext = _parse_plaintext(raw.get("module", ""), plaintext_bytes)

        return DecryptedEnvelope(
            id=raw.get("id", ""),
            instance_id=raw.get("instance_id", ""),
            module=raw.get("module", ""),
            snapshot_version=raw.get("snapshot_version", 0),
            probed_at=raw.get("probed_at", ""),
            ttl_seconds=raw.get("ttl_seconds", 86400),
            truncated=raw.get("truncated", False),
            partial=raw.get("partial", False),
            sudo_used=raw.get("sudo_used", False),
            safe_metrics=raw.get("safe_metrics"),
            plaintext=plaintext,
            created_at=raw.get("created_at", ""),
            grant_id=raw.get("grant_id"),
            required_role=raw.get("required_role"),
        )

    # ------------------------------------------------------------------
    # Error mapping helpers
    # ------------------------------------------------------------------

    def _map_403(self, exc: ForbiddenEntitlementError) -> "UpsellRequired":
        plan = "teams" if (exc.details or {}).get("required_plan") == "teams" else "solo"
        return UpsellRequired(plan)

    def _map_404(self, exc: NotFoundError) -> "MemoryBackendError":
        return MemoryNotFound("access_revoked")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def decrypt_envelope(
        self,
        raw: Dict[str, Any],
        *,
        expected_instance_id: str = "",
        expected_module: str = "",
    ) -> DecryptedEnvelope:
        """Decrypt a raw server envelope after validating its intended target.

        This public wrapper is used by endpoints whose response is an envelope
        but whose URL is not the normal module-retrieval route, such as hosted
        AI summaries.
        """
        if not isinstance(raw, dict):
            raise MemoryBackendError("invalid_envelope")
        if expected_instance_id:
            _validate_instance_id(expected_instance_id)
            if str(raw.get("instance_id", "")) != expected_instance_id:
                raise MemoryBackendError("envelope_instance_mismatch")
        if expected_module and str(raw.get("module", "")) != expected_module:
            raise MemoryBackendError("envelope_module_mismatch")

        async with self._lock:
            return await self._decrypt_envelope_dict(raw)

    async def list_instances(self) -> List[Dict[str, Any]]:
        """GET /api/v1/memory — list instances visible to the caller."""
        async with self._lock:
            cache_key = "__list_instances__"
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached
            try:
                await self._rate_limiter.acquire(RateLimitKey.GENERAL)
                data = await self._api.get("/api/v1/memory")
                result = data.get("instances", [])
                self._cache.set(cache_key, result)
                return result
            except ForbiddenEntitlementError as exc:
                raise self._map_403(exc) from exc
            except NotFoundError as exc:
                raise self._map_404(exc) from exc

    async def list_instance_modules(self, instance_id: str) -> Dict[str, Any]:
        """GET /api/v1/memory/{instance_id} — list modules the caller can decrypt."""
        _validate_instance_id(instance_id)
        async with self._lock:
            cache_key = f"modules:{instance_id}"
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached
            try:
                await self._rate_limiter.acquire(RateLimitKey.GENERAL)
                data = await self._api.get(f"/api/v1/memory/{instance_id}")
                self._cache.set(cache_key, data)
                return data
            except ForbiddenEntitlementError as exc:
                raise self._map_403(exc) from exc
            except NotFoundError as exc:
                raise self._map_404(exc) from exc

    async def get_module(self, instance_id: str, module: str) -> DecryptedEnvelope:
        """GET /api/v1/memory/{instance_id}/{module} — fetch latest snapshot."""
        _validate_instance_id(instance_id)
        async with self._lock:
            cache_key = f"module:{instance_id}:{module}"
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached
            try:
                await self._rate_limiter.acquire(RateLimitKey.GENERAL)
                raw = await self._api.get(f"/api/v1/memory/{instance_id}/{module}")
                decrypted = await self._decrypt_envelope_dict(raw)
                self._cache.set(cache_key, decrypted)
                return decrypted
            except ForbiddenEntitlementError as exc:
                raise self._map_403(exc) from exc
            except NotFoundError as exc:
                raise self._map_404(exc) from exc

    async def get_module_envelope_raw(self, instance_id: str, module: str) -> Dict[str, Any]:
        """GET /api/v1/memory/{instance_id}/{module} — return undecrypted envelope.

        Used by team-share flows that need to re-wrap the existing DEK to
        additional recipients without ever decrypting the payload here.
        Bypasses the decrypt cache because consumers want the wire format.
        """
        _validate_instance_id(instance_id)
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            raw = await self._api.get(f"/api/v1/memory/{instance_id}/{module}")
            return raw
        except ForbiddenEntitlementError as exc:
            raise self._map_403(exc) from exc
        except NotFoundError as exc:
            raise self._map_404(exc) from exc

    async def get_history(
        self,
        instance_id: str,
        module: str,
        from_: Optional[str] = None,
        to_: Optional[str] = None,
        limit: int = 100,
    ) -> List[DecryptedEnvelope]:
        """GET /api/v1/memory/{instance_id}/{module}/history."""
        _validate_instance_id(instance_id)
        params: Dict[str, Any] = {"limit": limit}
        if from_:
            params["from"] = from_
        if to_:
            params["to"] = to_
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            data = await self._api.get(
                f"/api/v1/memory/{instance_id}/{module}/history",
                params=params,
            )
            snapshots = data.get("snapshots", [])
            result: List[DecryptedEnvelope] = []
            for raw in snapshots:
                try:
                    decrypted = await self._decrypt_envelope_dict(raw)
                    result.append(decrypted)
                except Exception as exc:
                    logger.warning("Could not decrypt history snapshot: %s", exc)
            return result
        except ForbiddenEntitlementError as exc:
            raise self._map_403(exc) from exc
        except NotFoundError as exc:
            raise self._map_404(exc) from exc

    async def envelope_keys(
        self, instance_id: str, envelope_ids: Dict[str, str]
    ) -> List[Dict[str, str]]:
        """Data keys of exactly the named envelopes, for a hosted summary.

        Fetches each envelope by id, checks that the service returned that
        envelope for that module, opens the caller's own wrap and returns
        ``{"envelope_id", "dek"}`` with the key as base64. The private key
        never leaves this service, and every data-key buffer is zeroed once
        encoded. Keys are not cached.

        Raises:
            StaleEnvelopes: An envelope is gone, or is not the one asked for.
            VaultCustodyLocked: Memory Sync's key is in the vault, which is locked.
        """
        import base64
        from servonaut.services.memory.crypto import CryptoError, open_dek, secure_zero

        _validate_instance_id(instance_id)
        if not envelope_ids:
            raise StaleEnvelopes()
        await self._ensure_key_material()
        private_key = self._self_privkey
        if private_key is None:
            raise MemoryBackendError("memory_locked")
        keys: List[Dict[str, str]] = []
        for module, envelope_id in sorted(envelope_ids.items()):
            # Both come from the service and end up in a URL path.
            if not (INSTANCE_ID_RE.fullmatch(str(module)) and INSTANCE_ID_RE.fullmatch(str(envelope_id))):
                raise MemoryBackendError("invalid_envelope")
            raw = await self._fetch_envelope_at(instance_id, module, envelope_id)
            if str(raw.get("id", "")) != envelope_id:
                raise StaleEnvelopes()
            dek = None
            try:
                dek = open_dek(raw.get("wrapped_dek", ""), private_key=private_key)
                self._check_envelope_belongs(raw, dek, instance_id, module)
                keys.append({
                    "envelope_id": envelope_id,
                    "dek": base64.b64encode(bytes(dek)).decode("ascii"),
                })
            except CryptoError as exc:
                raise EnvelopeKeyError("envelope_key_unreadable") from exc
            finally:
                if dek is not None:
                    secure_zero(dek)
        return keys

    @staticmethod
    def _check_envelope_belongs(
        raw: Dict[str, Any], dek: bytearray, instance_id: str, module: str
    ) -> None:
        """Refuse to release a key for an envelope that is not this instance's module.

        Envelopes carry no associated data, and the plaintext does not name its
        instance or module, so the binding is as strong as the format allows:
        the service's own instance/module fields must agree with the request,
        the ciphertext must open under this key, and the payload must have the
        shape that module's writers produce. Residual risk: a hostile service
        could still hand over another instance's envelope of the same module
        that this user can open; the hosted summary then covers that memory
        instead. Only envelopes the user's own key opens are ever reachable,
        and AAD in the envelope format would close the gap.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from servonaut.services.memory.crypto import validate_ciphertext, validate_iv, validate_tag

        for field, expected in (("instance_id", instance_id), ("module", module)):
            if field in raw and str(raw[field]) != expected:
                raise EnvelopeKeyError("envelope_mismatch")
        try:
            iv = validate_iv(raw["iv"])
            tag = validate_tag(raw["tag"])
            ciphertext = validate_ciphertext(raw["ciphertext"])
            plaintext = json.loads(AESGCM(bytes(dek)).decrypt(iv, ciphertext + tag, None))
        except Exception as exc:  # noqa: BLE001 - any failure means the key does not open this envelope
            raise EnvelopeKeyError("envelope_key_unreadable") from exc
        if not _plaintext_fits_module(module, plaintext):
            raise EnvelopeKeyError("envelope_mismatch")

    async def _fetch_envelope_at(
        self, instance_id: str, module: str, envelope_id: str
    ) -> Dict[str, Any]:
        """One envelope by id; a missing one means the memory changed."""
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            raw = await self._api.get(
                f"/api/v1/memory/{instance_id}/{module}/at/{envelope_id}"
            )
        except ForbiddenEntitlementError as exc:
            raise self._map_403(exc) from exc
        except NotFoundError as exc:
            raise StaleEnvelopes() from exc
        if not isinstance(raw, dict):
            raise MemoryBackendError("invalid_envelope")
        return raw

    async def get_snapshot(self, instance_id: str, module: str, snapshot_id: str) -> DecryptedEnvelope:
        """GET /api/v1/memory/{instance_id}/{module}/at/{snapshot_id}."""
        _validate_instance_id(instance_id)
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            raw = await self._api.get(
                f"/api/v1/memory/{instance_id}/{module}/at/{snapshot_id}"
            )
            return await self._decrypt_envelope_dict(raw)
        except ForbiddenEntitlementError as exc:
            raise self._map_403(exc) from exc
        except NotFoundError as exc:
            raise self._map_404(exc) from exc

    async def restore_snapshot(self, instance_id: str, snapshot_id: str) -> Dict[str, Any]:
        """POST /api/v1/memory/{instance_id}/restore/{snapshot_id}.

        Per spec §3.4 this endpoint returns a lightweight summary
        ``{id, instance_id, module, snapshot_version, restored_from_snapshot_id}``
        — NOT a full envelope, so we do NOT decrypt. The caller can fetch the
        new envelope through :meth:`get_module` afterwards.

        Returns:
            Restore summary dict from the server.
        """
        _validate_instance_id(instance_id)
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            return await self._api.post(
                f"/api/v1/memory/{instance_id}/restore/{snapshot_id}",
                json={},
            )
        except ForbiddenEntitlementError as exc:
            raise self._map_403(exc) from exc
        except NotFoundError as exc:
            raise self._map_404(exc) from exc

    async def delete_instance(self, instance_id: str) -> None:
        """DELETE /api/v1/memory/{instance_id} — soft-delete the whole instance."""
        _validate_instance_id(instance_id)
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            await self._api.delete(f"/api/v1/memory/{instance_id}")
        except ForbiddenEntitlementError as exc:
            raise self._map_403(exc) from exc
        except NotFoundError as exc:
            raise self._map_404(exc) from exc

    async def delete_module(self, instance_id: str, module: str) -> int:
        """DELETE /api/v1/memory/{instance_id}?module={module} — hard-delete all envelopes.

        Returns number of deleted envelopes.
        """
        _validate_instance_id(instance_id)
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            data = await self._api.delete(
                f"/api/v1/memory/{instance_id}",
                params={"module": module},
            )
            return data.get("deleted_envelopes", 0)
        except ForbiddenEntitlementError as exc:
            raise self._map_403(exc) from exc
        except NotFoundError as exc:
            raise self._map_404(exc) from exc

    def clear_cache(self) -> None:
        """Invalidate all cached entries (e.g. after key rotation)."""
        self._cache.clear()
        logger.debug("retrieval: LRU cache cleared")

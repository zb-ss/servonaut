"""MemorySyncService — background sync loop for the memory subsystem.

Responsibilities:
- Bootstrap: probe server for feature gates, key enrolment, instance upsert.
- Enqueue: accept ModuleResult objects from MemoryService._persist_result.
- Drain: encrypt queued envelopes and POST /memory/sync in batches of ≤50.
- Persistence: append-only JSONL queue at ~/.servonaut/memory/sync_queue.jsonl.
- Status: observable via subscribe() for UI widgets.
- Per-rejection state machine drives halt/error/drop decisions.

Trust boundary for the persistent queue
---------------------------------------

The on-disk queue at ``~/.servonaut/memory/sync_queue.jsonl`` carries the
plaintext SyncEnvelope payloads (post-redaction) — encryption is done at
drain time so the persisted queue is readable to any process running as
the same user. The directory is created with mode ``0o700`` and the file
with mode ``0o600`` to keep other local users out, but it is NOT a
defence against malware running as the user themselves. Operators who
need at-rest secrecy from local processes should disable redaction-only
mode and rely on full-disk encryption.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from servonaut.services.api_client import (
    APIError,
    BatchTooLargeError,
    FeatureDisabledError,
    FeatureNotAvailableError,
    ForbiddenEntitlementError,
    NotFoundError,
    QuotaExceededError,
    RateLimitedError,
    ValidationFailedError,
)
from servonaut.services.memory.interfaces import (
    INSTANCE_ID_RE,
    RESERVED_INSTANCE_IDS,
    BackendMaintenance,
    BetaWaitlist,
    KeyMaterial,
    MemoryBackendError,
    MemorySyncStatus,
    MissingSelfWrap,
    ModuleResult,
    NoActiveKeypair,
    QuotaExceeded,
    QuotaInfo,
    RateLimited,
    ReservedInstanceIdError,
    SyncBatchResult,
    SyncEnvelope,
    SyncRejection,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter

# Import at module level so tests can patch servonaut.services.memory.sync_service.encrypt_envelope
# The actual function is in crypto.py; lazy import only if PyNaCl is available.
try:
    from servonaut.services.memory.crypto import encrypt_envelope, unwrap_private_key, wrap_private_key, generate_keypair, WrappedPrivateKey
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    encrypt_envelope = None  # type: ignore[assignment]
    unwrap_private_key = None  # type: ignore[assignment]
    wrap_private_key = None  # type: ignore[assignment]
    generate_keypair = None  # type: ignore[assignment]
    WrappedPrivateKey = None  # type: ignore[assignment,misc]

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.services.memory.crypto import (
        Envelope,
        KeyPair,
    )
    from servonaut.services.memory.service import MemoryService
    from servonaut.services.config.manager import ConfigManager
    from servonaut.services.auth_service import AuthService

logger = logging.getLogger(__name__)

# Hard limits per spec §3.3
_BATCH_SIZE = 50
_QUEUE_CAP = 5000
_QUEUE_WATCHDOG_WARN = 1000

# Halt backoff multiplier for quota_exceeded (10× the normal interval)
_QUOTA_BACKOFF_FACTOR = 10

# Poison-pill envelopes (size-1 batch_too_large) get parked here for triage.
_POISON_PATH = Path.home() / ".servonaut" / "memory" / "sync_poison.jsonl"


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _validate_reserved(instance_id: str) -> None:
    """Raise :class:`ReservedInstanceIdError` for reserved or malformed ids.

    Case-insensitive against ``RESERVED_INSTANCE_IDS`` so ``"SYNC"`` /
    ``"Keys"`` cannot bypass the gate (server may lower-case path segments).
    """
    if instance_id is None or instance_id == "":
        raise ReservedInstanceIdError("Instance ID is empty")
    if instance_id.lower() in RESERVED_INSTANCE_IDS:
        raise ReservedInstanceIdError(
            f"Instance ID {instance_id!r} is reserved by the server API"
        )
    if not INSTANCE_ID_RE.match(instance_id):
        raise ReservedInstanceIdError(
            f"Instance ID {instance_id!r} does not match pattern [A-Za-z0-9_\\-]{{1,128}}"
        )


class MemorySyncService:
    """Manages background sync of memory module results to the server.

    Constructor:
        api_client: APIClient with Bearer token auth.
        crypto: crypto module reference (duck-typed; expects encrypt_envelope,
            wrap_private_key, unwrap_private_key, generate_keypair functions
            and KeyPair / WrappedPrivateKey types from services.memory.crypto).
        memory_service: MemoryService for listing managed instances.
        config_manager: ConfigManager for reading instance config.
        auth_service: AuthService for user_id resolution.
        rate_limiter: Shared RateLimiter instance.
    """

    def __init__(
        self,
        api_client: "APIClient",
        crypto: Any,
        memory_service: "MemoryService",
        config_manager: "ConfigManager",
        auth_service: "AuthService",
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self._api = api_client
        self._crypto = crypto
        self._memory_service = memory_service
        self._config_manager = config_manager
        self._auth_service = auth_service
        self._rate_limiter = rate_limiter or RateLimiter()

        # Queue state
        self._pending: deque[SyncEnvelope] = deque()
        self._inflight: Optional[List[SyncEnvelope]] = None

        # Halt + status
        self._halted_reason: Optional[str] = None
        self._last_sync_at: Optional[str] = None
        self._last_error: Optional[str] = None
        self._state: str = "idle"  # idle|running|halted|error|disabled
        self._quota: Optional[QuotaInfo] = None

        # Key material cached after bootstrap
        self._self_user_id: Optional[int] = None
        self._self_pubkey: Optional[bytes] = None
        self._self_privkey: Optional[bytes] = None

        # Hook fired after key-material becomes available (or rotates).
        self._key_material_listener: Optional[Callable[[], None]] = None

        # Status listeners
        self._listeners: List[Callable[[MemorySyncStatus], None]] = []

        # Persistent queue path
        self._queue_path = (
            Path.home() / ".servonaut" / "memory" / "sync_queue.jsonl"
        )

        # Background loop handle
        self._loop_task: Optional[asyncio.Task] = None
        self._stopped = False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def status(self) -> MemorySyncStatus:
        return MemorySyncStatus(
            state=self._state,
            last_sync_at=self._last_sync_at,
            last_error=self._last_error,
            pending_envelopes=len(self._pending),
            quota=self._quota,
            halted_reason=self._halted_reason,
        )

    def subscribe(self, listener: Callable[[MemorySyncStatus], None]) -> None:
        """Register a status-change listener."""
        self._listeners.append(listener)

    def set_key_material_listener(self, listener: Callable[[], None]) -> None:
        """Register a callback fired whenever the active keypair changes.

        Used by the app to mirror the unwrapped material onto the retrieval
        and team services without those services reaching into private attrs.
        """
        self._key_material_listener = listener

    def get_key_material(self) -> Optional[KeyMaterial]:
        """Return the active :class:`KeyMaterial`, or ``None`` if unwired."""
        if (
            self._self_user_id is None
            or self._self_pubkey is None
            or self._self_privkey is None
        ):
            return None
        return KeyMaterial(
            user_id=self._self_user_id,
            public_key=self._self_pubkey,
            private_key=self._self_privkey,
        )

    def enqueue_module(
        self,
        instance: Dict[str, Any],
        module: str,
        result: ModuleResult,
    ) -> None:
        """Append a ModuleResult to the pending queue.

        Called from MemoryService._persist_result after every successful probe.
        Silently drops if the queue is at capacity (_QUEUE_CAP).
        """
        if len(self._pending) >= _QUEUE_CAP:
            logger.warning(
                "sync queue at cap (%d); dropping %s/%s", _QUEUE_CAP, instance.get("id"), module
            )
            return

        instance_id = instance.get("id") or instance.get("name", "")
        env = SyncEnvelope(
            instance_id=instance_id,
            module=module,
            probed_at=result.probed_at or _now_iso(),
            ttl_seconds=result.ttl_seconds,
            truncated=result.truncated,
            partial=result.partial,
            sudo_used=result.sudo_used,
            memory_disabled=False,
            safe_metrics=self._extract_safe_metrics(result),
            plaintext_payload={
                "observed": result.observed,
                "declared": result.declared,
                "raw_output": result.raw_output,
            },
        )
        self._pending.append(env)

        if len(self._pending) >= _QUEUE_WATCHDOG_WARN:
            logger.warning(
                "sync queue depth %d ≥ watchdog threshold %d",
                len(self._pending),
                _QUEUE_WATCHDOG_WARN,
            )

        self._append_to_jsonl(env)
        self._notify_listeners()

    async def bootstrap(
        self, passphrase_provider: Callable[[], "asyncio.Coroutine[Any, Any, str]"]
    ) -> None:
        """Run the CLI bootstrap sequence (spec §5).

        1. GET /memory/settings — implicit gate probe.
        2. GET /memory/keys/me — enrol if 404.
        3. POST /memory/instances — upsert managed instances.

        Raises:
            BackendMaintenance: on 503 feature_disabled.
            BetaWaitlist: on 403 feature_not_available.
            UpsellRequired: on 403 forbidden_entitlement.
        """
        # Guarantee user_id before any crypto
        self._self_user_id = await self._auth_service.fetch_user_id()

        # Step 1: settings gate probe
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            await self._api.get("/api/v1/memory/settings")
        except FeatureDisabledError as exc:
            raise BackendMaintenance("Server feature_disabled") from exc
        except FeatureNotAvailableError as exc:
            raise BetaWaitlist("feature_not_available") from exc
        except ForbiddenEntitlementError as exc:
            plan = "teams" if (exc.details or {}).get("required_plan") == "teams" else "solo"
            raise UpsellRequired(plan) from exc

        # Step 2: key enrolment
        await self._ensure_keypair(passphrase_provider)

        # Step 3: upsert managed instances
        await self.upsert_all_instances()

        # Replay persisted queue
        self._replay_jsonl()

        self._state = "idle"
        # Successful bootstrap clears any prior halt-reason so the next loop
        # iteration drains normally instead of skipping forever.
        self._halted_reason = None
        self._notify_listeners()

    async def upsert_instance(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        """Register or update one instance with the server.

        Validates instance_id against RESERVED_INSTANCE_IDS and INSTANCE_ID_RE.

        Raises:
            ReservedInstanceIdError: If instance_id is a reserved path segment.
            QuotaExceeded: On 429 quota_exceeded from the server.
            ValidationFailed: On 422 from the server.
        """
        instance_id = instance.get("id") or instance.get("name", "")
        self._validate_instance_id(instance_id)

        display_name = instance.get("name", instance_id)
        provider = instance.get("provider", "custom") or "custom"
        # Normalise provider to server-accepted values
        _KNOWN_PROVIDERS = {"aws", "ovh", "gcp", "azure", "custom"}
        if provider not in _KNOWN_PROVIDERS:
            provider = "custom"

        payload = {
            "instance_id": instance_id,
            "display_name": display_name,
            "provider": provider,
            "memory_disabled": self._memory_service.is_memory_disabled(
                instance_id, display_name
            ),
        }
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            return await self._api.post("/api/v1/memory/instances", json=payload)
        except QuotaExceededError as exc:
            raise QuotaExceeded("memory_instances_max reached") from exc
        except ValidationFailedError as exc:
            errors = (exc.details or {}).get("errors", [])
            raise ValidationFailed(errors) from exc
        except ForbiddenEntitlementError as exc:
            plan = "teams" if (exc.details or {}).get("required_plan") == "teams" else "solo"
            raise UpsellRequired(plan) from exc

    async def upsert_all_instances(self) -> Dict[str, str]:
        """Upsert all managed instances from the local memory index.

        Returns a dict of {instance_id: status} where status is
        "ok", "quota_exceeded", "reserved", or "validation_failed".
        """
        results: Dict[str, str] = {}
        try:
            stored = self._memory_service.list_all()
        except Exception:
            stored = []

        # Build a unified list of instance dicts to upsert
        instance_dicts: List[Dict[str, Any]] = []
        for entry in stored:
            iid = entry.get("instance_id", "")
            if iid:
                instance_dicts.append({
                    "id": iid,
                    "name": entry.get("name", iid),
                    "provider": entry.get("provider", "custom"),
                })

        for inst in instance_dicts:
            iid = inst.get("id", "")
            try:
                await self.upsert_instance(inst)
                results[iid] = "ok"
            except ReservedInstanceIdError:
                results[iid] = "reserved"
            except QuotaExceeded:
                results[iid] = "quota_exceeded"
                logger.warning("Instance quota exceeded at %s — stopping upsert loop", iid)
                break
            except (ValidationFailed, Exception) as exc:
                logger.warning("upsert_instance failed for %s: %s", iid, exc)
                results[iid] = "validation_failed"

        return results

    async def drain_now(self) -> SyncBatchResult:
        """Encrypt and POST one batch of pending envelopes.

        Returns the SyncBatchResult; raises MemoryBackendError on fatal conditions.
        """
        if self._halted_reason:
            return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)

        if not self._pending:
            return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)

        if self._self_pubkey is None or self._self_user_id is None:
            logger.warning("drain_now: no active keypair; cannot encrypt")
            return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)

        # Pop a batch (up to _BATCH_SIZE)
        batch: List[SyncEnvelope] = []
        for _ in range(_BATCH_SIZE):
            if not self._pending:
                break
            batch.append(self._pending.popleft())

        self._inflight = batch
        self._state = "running"
        self._notify_listeners()

        try:
            result = await self._post_batch(batch)
            self._inflight = None
            # Only reset to idle if a rejection handler didn't already halt/error us
            if self._state == "running":
                self._last_sync_at = _now_iso()
                self._last_error = None
                self._state = "idle"
            if result.quota:
                self._quota = result.quota
            self._notify_listeners()
            return result

        except MissingSelfWrap:
            # Our crypto bug — re-raise so the caller (and tests) can see it
            self._inflight = None
            self._notify_listeners()
            raise

        except BatchTooLargeError:
            # 413 only fires for "too many envelopes per batch" or "single
            # envelope exceeds the listener cap". For a size-1 batch, splitting
            # makes no progress — park the envelope as a poison pill instead.
            if len(batch) == 1:
                self._handle_poison_envelope(batch[0])
                self._inflight = None
                self._state = "idle"
                self._notify_listeners()
                return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)
            logger.warning("drain_now: batch_too_large; splitting and re-queuing")
            mid = len(batch) // 2
            self._pending.extendleft(reversed(batch[mid:]))
            self._pending.extendleft(reversed(batch[:mid]))
            self._inflight = None
            self._state = "idle"
            self._notify_listeners()
            return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)

        except RateLimitedError as exc:
            logger.warning("drain_now: 429 rate_limited; re-queuing batch")
            self._rate_limiter.record_429(RateLimitKey.SYNC)
            self._pending.extendleft(reversed(batch))
            self._inflight = None
            self._state = "idle"
            self._last_error = "rate_limited"
            self._notify_listeners()
            return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)

        except APIError as exc:
            logger.error("drain_now: API error %s: %s", exc.code, exc)
            self._pending.extendleft(reversed(batch))
            self._inflight = None
            self._state = "error"
            self._last_error = str(exc)
            self._notify_listeners()
            return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)

        except Exception as exc:
            logger.exception("drain_now: unexpected error")
            self._pending.extendleft(reversed(batch))
            self._inflight = None
            self._state = "error"
            self._last_error = str(exc)
            self._notify_listeners()
            return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)

    async def start_background_loop(self, interval_s: int = 60) -> None:
        """Start the async drain loop coroutine.

        This is a long-running coroutine that should be awaited in a Textual
        worker or asyncio task. It drains the queue every interval_s seconds.
        """
        self._stopped = False
        quota_halt_count = 0

        while not self._stopped:
            try:
                await asyncio.sleep(interval_s)
            except asyncio.CancelledError:
                logger.info("sync background loop cancelled")
                break

            if self._stopped:
                break

            if self._halted_reason == "no_active_keypair":
                logger.debug("sync loop: halted (no_active_keypair); skipping drain")
                continue

            if self._halted_reason == "quota_exceeded":
                quota_halt_count += 1
                if quota_halt_count < _QUOTA_BACKOFF_FACTOR:
                    logger.debug(
                        "sync loop: halted (quota_exceeded) — backoff %d/%d",
                        quota_halt_count, _QUOTA_BACKOFF_FACTOR,
                    )
                    continue
                # Reset after 10 cycles
                quota_halt_count = 0
                self._halted_reason = None

            if not self._pending:
                continue

            try:
                await self.drain_now()
            except Exception as exc:
                logger.exception("sync loop: drain_now crashed: %s", exc)

    def stop(self) -> None:
        """Signal the background loop to stop after the current cycle."""
        self._stopped = True
        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()

    async def rotate_keypair(self, old_passphrase: str, new_passphrase: str) -> None:
        """Rotate the user's X25519 keypair (POST /memory/keys/rotate).

        Decrypts the existing private key with *old_passphrase*, generates a
        fresh keypair, wraps it with *new_passphrase*, then POSTs to the
        rotate endpoint. Updates the in-process key material and fires the
        key-material listener so retrieval/team services pick up the change.

        Args:
            old_passphrase: Existing passphrase that unwraps the current key.
            new_passphrase: New passphrase used to wrap the freshly generated key.

        Raises:
            RuntimeError: If crypto is unavailable, or unwrap fails.
        """
        if not _HAS_CRYPTO:
            raise RuntimeError("Memory crypto unavailable — cannot rotate keypair")

        # Acquire the old key locally first to surface bad-passphrase errors before
        # we burn rate-limit budget on the rotate POST.
        await self._rate_limiter.acquire(RateLimitKey.KEYS_ME)
        data = await self._api.get("/api/v1/memory/keys/me", retry_on_401=False)
        wrapped_old = WrappedPrivateKey.from_json(data.get("wrapped_private_key", ""))
        try:
            unwrap_private_key(wrapped_old, old_passphrase)
        except Exception as exc:
            raise RuntimeError("Old passphrase did not unwrap the existing keypair") from exc

        new_kp = generate_keypair()
        new_wrapped = wrap_private_key(new_kp.private_key, new_passphrase)

        import base64
        payload = {
            "public_key": base64.b64encode(new_kp.public_key).decode(),
            "wrapped_private_key": new_wrapped.to_json(),
            "fingerprint": new_kp.fingerprint,
        }

        await self._rate_limiter.acquire(RateLimitKey.KEYS_ROTATE)
        try:
            await self._api.post(
                "/api/v1/memory/keys/rotate", json=payload, retry_on_401=False
            )
        except RateLimitedError as exc:
            self._rate_limiter.record_429(RateLimitKey.KEYS_ROTATE)
            raise RateLimited(
                endpoint="/api/v1/memory/keys/rotate", retry_after_s=86400.0
            ) from exc

        self._self_pubkey = new_kp.public_key
        self._self_privkey = new_kp.private_key
        if self._key_material_listener is not None:
            try:
                self._key_material_listener()
            except Exception:
                logger.warning("key_material_listener raised after rotate", exc_info=True)
        logger.info("Rotated memory keypair fingerprint=%s", new_kp.fingerprint)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _notify_listeners(self) -> None:
        status = self.status
        for listener in self._listeners:
            try:
                listener(status)
            except Exception as exc:
                logger.warning("sync status listener raised: %s", exc)

    def _validate_instance_id(self, instance_id: str) -> None:
        _validate_reserved(instance_id)

    def _extract_safe_metrics(self, result: ModuleResult) -> Optional[Dict[str, Any]]:
        """Extract only allowlisted numeric keys from result.observed.

        spec §3.3 declares safe_metrics is "string→number only" — we drop
        any value that cannot be coerced to a float so a misbehaving
        prober cannot ship strings into the metrics field.
        """
        _GLOBAL_ALLOWLIST = frozenset({
            "cpu_count",
            "ram_gb",
            "disk_total_gb",
            "disk_used_gb",
            "load_avg_1m",
        })
        observed = result.observed or {}
        metrics: Dict[str, Any] = {}
        for key in _GLOBAL_ALLOWLIST:
            val = observed.get(key)
            if val is None:
                continue
            if isinstance(val, bool):
                # bool is a subclass of int — exclude explicitly to keep semantics clean.
                continue
            if isinstance(val, (int, float)):
                metrics[key] = float(val)
        return metrics or None

    async def _ensure_keypair(
        self, passphrase_provider: Callable[[], Any]
    ) -> None:
        """Fetch or enrol the caller's X25519 keypair."""
        try:
            await self._rate_limiter.acquire(RateLimitKey.KEYS_ME)
            data = await self._api.get(
                "/api/v1/memory/keys/me", retry_on_401=False
            )
            pub_b64 = data.get("public_key", "")
            wrapped_json = data.get("wrapped_private_key", "")
            import base64
            pub_bytes = base64.b64decode(pub_b64)
            self._self_pubkey = pub_bytes

            # Unwrap the private key using the passphrase
            passphrase = await passphrase_provider("unlock")
            wrapped = WrappedPrivateKey.from_json(wrapped_json)
            self._self_privkey = unwrap_private_key(wrapped, passphrase)
            logger.info("Bootstrap: loaded existing keypair fingerprint=%s", data.get("fingerprint"))
            return

        except NotFoundError:
            # No active key — enrol a new one
            logger.info("Bootstrap: no active keypair; enrolling new key")

        passphrase = await passphrase_provider("enrol")
        kp = generate_keypair()
        wrapped = wrap_private_key(kp.private_key, passphrase)
        import base64
        payload = {
            "public_key": base64.b64encode(kp.public_key).decode(),
            "wrapped_private_key": wrapped.to_json(),
            "fingerprint": kp.fingerprint,
        }
        await self._api.post(
            "/api/v1/memory/keys", json=payload, retry_on_401=False
        )
        self._self_pubkey = kp.public_key
        self._self_privkey = kp.private_key
        logger.info("Bootstrap: enrolled new keypair fingerprint=%s", kp.fingerprint)

    async def _post_batch(self, batch: List[SyncEnvelope]) -> SyncBatchResult:
        """Encrypt and POST a batch of SyncEnvelopes. Returns SyncBatchResult."""
        import json as json_mod

        envelopes_payload: List[Dict[str, Any]] = []
        for env in batch:
            plaintext_bytes = json_mod.dumps(env.plaintext_payload, separators=(",", ":")).encode()
            enc = encrypt_envelope(
                plaintext_bytes,
                self_public_key=self._self_pubkey,
                self_user_id=self._self_user_id,
            )
            wire = enc.to_dict()
            wire.update({
                "instance_id": env.instance_id,
                "module": env.module,
                "probed_at": env.probed_at,
                "ttl_seconds": env.ttl_seconds,
                "truncated": env.truncated,
                "partial": env.partial,
                "sudo_used": env.sudo_used,
                "memory_disabled": env.memory_disabled,
            })
            if env.safe_metrics:
                wire["safe_metrics"] = env.safe_metrics
            envelopes_payload.append(wire)

        await self._rate_limiter.acquire(RateLimitKey.SYNC)
        response = await self._api.post(
            "/api/v1/memory/sync",
            json={"envelopes": envelopes_payload},
        )

        # Parse response
        accepted = response.get("accepted", [])
        raw_rejected = response.get("rejected", [])
        quota_raw = response.get("quota")

        rejected: List[SyncRejection] = []
        for r in raw_rejected:
            idx = r.get("index", 0)
            reason = r.get("reason", "unknown")
            message = r.get("message", "")
            rejection = SyncRejection(index=idx, reason=reason, message=message)
            rejected.append(rejection)
            # Apply per-rejection state machine
            self._handle_rejection(rejection, batch)

        quota: Optional[QuotaInfo] = None
        if quota_raw:
            quota = QuotaInfo(
                envelopes_used=quota_raw.get("envelopes_used", 0),
                envelopes_soft_cap=quota_raw.get("envelopes_soft_cap", 0),
                envelopes_hard_cap=quota_raw.get("envelopes_hard_cap", 0),
                retention_days=quota_raw.get("retention_days", 30),
            )
            self._quota = quota

        return SyncBatchResult(accepted=accepted, rejected=rejected, quota=quota)

    def _handle_rejection(self, rejection: SyncRejection, batch: List[SyncEnvelope]) -> None:
        """Apply the per-rejection state machine."""
        reason = rejection.reason

        if reason == "duplicate_hash":
            logger.debug("sync rejection[%d]: duplicate_hash — dropping", rejection.index)

        elif reason == "bad_crypto":
            logger.error(
                "sync rejection[%d]: bad_crypto — dropping (crypto library issue?)",
                rejection.index,
            )

        elif reason == "missing_self_wrap":
            # Our bug — raise immediately (spec: don't drop silently)
            logger.critical("sync rejection[%d]: missing_self_wrap — halting", rejection.index)
            self._state = "error"
            self._last_error = "missing_self_wrap"
            raise MissingSelfWrap(
                f"Server rejected envelope at index {rejection.index}: missing_self_wrap. "
                "This is a local crypto bug."
            )

        elif reason == "no_active_keypair":
            logger.error("sync rejection: no_active_keypair — halting loop")
            self._halted_reason = "no_active_keypair"
            self._state = "halted"
            self._last_error = "no_active_keypair"
            self._notify_listeners()

        elif reason == "memory_disabled":
            # Server says this instance is opted-out — persist that to local config
            logger.info(
                "sync rejection[%d]: memory_disabled — recording opt-out locally",
                rejection.index,
            )
            if rejection.index < len(batch):
                env = batch[rejection.index]
                try:
                    cfg = self._config_manager.get()
                    if hasattr(cfg, "memory") and hasattr(cfg.memory, "per_server_overrides"):
                        # Match the shape consumed by MemoryConfig.is_module_enabled
                        # (config/schema.py:297) — `memory_disabled: True`, NOT `enabled: False`.
                        cfg.memory.per_server_overrides[env.instance_id] = {
                            "memory_disabled": True
                        }
                        self._config_manager.save()
                except Exception as exc:
                    logger.warning("Could not persist memory_disabled opt-out: %s", exc)

        elif reason == "quota_exceeded":
            logger.warning("sync rejection: quota_exceeded — halting for %d× interval", _QUOTA_BACKOFF_FACTOR)
            self._halted_reason = "quota_exceeded"
            self._state = "halted"
            self._last_error = "quota_exceeded"
            self._notify_listeners()

        else:
            logger.warning("sync rejection[%d]: unknown reason %r", rejection.index, reason)

    def _append_to_jsonl(self, env: SyncEnvelope) -> None:
        """Append a SyncEnvelope to the persistent JSONL queue.

        Creates the parent directory with mode ``0o700`` and the file with
        mode ``0o600`` so other local users cannot read the plaintext queue.
        """
        try:
            parent = self._queue_path.parent
            parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass

            line = json.dumps({
                "instance_id": env.instance_id,
                "module": env.module,
                "probed_at": env.probed_at,
                "ttl_seconds": env.ttl_seconds,
                "truncated": env.truncated,
                "partial": env.partial,
                "sudo_used": env.sudo_used,
                "memory_disabled": env.memory_disabled,
                "safe_metrics": env.safe_metrics,
                "plaintext_payload": env.plaintext_payload,
            })

            existed = self._queue_path.exists()
            # Append-only, owner-readable only.
            fd = os.open(
                str(self._queue_path),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                # Make sure fd doesn't leak when fdopen wrap fails
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            # Belt-and-suspenders mode fix in case umask widened the bits
            # at create time.
            try:
                os.chmod(self._queue_path, 0o600)
            except OSError:
                pass
        except Exception as exc:
            logger.warning("Could not persist envelope to JSONL queue: %s", exc)

    def _handle_poison_envelope(self, env: SyncEnvelope) -> None:
        """Park an envelope the server keeps refusing as too-large.

        Logs an error, persists the offending envelope to a poison-pill
        JSONL for operator triage, and notifies status listeners. This
        replaces the previous infinite-split loop on size-1 batches.
        """
        logger.error(
            "drain_now: dropping poison envelope (single-envelope 413) "
            "instance=%s module=%s",
            env.instance_id, env.module,
        )
        try:
            _POISON_PATH.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(_POISON_PATH.parent, 0o700)
            except OSError:
                pass
            line = json.dumps({
                "instance_id": env.instance_id,
                "module": env.module,
                "probed_at": env.probed_at,
                "ttl_seconds": env.ttl_seconds,
                "truncated": env.truncated,
                "partial": env.partial,
                "sudo_used": env.sudo_used,
                "memory_disabled": env.memory_disabled,
                "safe_metrics": env.safe_metrics,
                "plaintext_payload": env.plaintext_payload,
                "dropped_at": _now_iso(),
                "reason": "batch_too_large_size_1",
            })
            fd = os.open(
                str(_POISON_PATH),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            try:
                os.chmod(_POISON_PATH, 0o600)
            except OSError:
                pass
        except Exception as exc:
            logger.warning("Could not write poison-pill envelope: %s", exc)
        self._last_error = "envelope_too_large"
        self._notify_listeners()

    def _replay_jsonl(self) -> None:
        """Replay the persisted JSONL queue into _pending on bootstrap.

        Always unlinks the queue file after a replay attempt so a single
        malformed line cannot cause unbounded plaintext accumulation.
        """
        if not self._queue_path.exists():
            return
        replayed = 0
        try:
            try:
                with open(self._queue_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            env = SyncEnvelope(
                                instance_id=data["instance_id"],
                                module=data["module"],
                                probed_at=data["probed_at"],
                                ttl_seconds=data.get("ttl_seconds", 86400),
                                truncated=data.get("truncated", False),
                                partial=data.get("partial", False),
                                sudo_used=data.get("sudo_used", False),
                                memory_disabled=data.get("memory_disabled", False),
                                safe_metrics=data.get("safe_metrics"),
                                plaintext_payload=data.get("plaintext_payload", {}),
                            )
                            if len(self._pending) < _QUEUE_CAP:
                                self._pending.append(env)
                                replayed += 1
                        except Exception as exc:
                            logger.warning("JSONL replay: skipping malformed line: %s", exc)
            finally:
                # Always unlink the persisted queue — leaving it around after a
                # malformed read keeps plaintext on disk indefinitely.
                try:
                    self._queue_path.unlink(missing_ok=True)
                except OSError as exc:
                    logger.warning("JSONL replay: could not unlink queue: %s", exc)
            if replayed:
                logger.info("Replayed %d envelopes from JSONL queue", replayed)
        except Exception as exc:
            logger.warning("JSONL replay failed: %s", exc)

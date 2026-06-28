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
import hashlib
import json
import logging
import os
import random
import tempfile
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
    from servonaut.services.memory.retrieval_service import MemoryRetrievalService
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

# Local passphrase-encrypted keypair cache.  Stores ONLY the wrapped
# (passphrase-encrypted) material: public_key, wrapped_private_key, fingerprint.
# The unwrapped private key and the passphrase are NEVER written here.
# Path constant; each MemorySyncService instance also stores this as
# self._key_cache_path so tests can override it.
_KEY_CACHE_PATH = Path.home() / ".servonaut" / "memory" / "keys.json"


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

        # Local keypair cache path (overridable in tests via svc._key_cache_path)
        self._key_cache_path = _KEY_CACHE_PATH

        # Background loop handle
        self._loop_task: Optional[asyncio.Task] = None
        self._stopped = False

        # instance_ids we've registered (or re-registered) this session via
        # the unknown_instance recovery path. Used to skip redundant
        # /api/v1/memory/instances POSTs when several envelopes for the
        # same id are rejected in one batch.
        self._registered_instance_ids: set[str] = set()

        # Optional collaborator wired after construction to avoid an import
        # cycle (sync_service ← retrieval_service would be circular).
        self._retrieval_service: Optional["MemoryRetrievalService"] = None

        # Optional entitlement predicate injected by the app after construction.
        # When set, enqueue_module is a no-op if it returns False.
        # This prevents enrolled-but-lapsed users from accumulating plaintext
        # envelopes on the on-disk JSONL queue that can never reach the server.
        # When None (default), the gate is open — preserves current behaviour
        # for headless callers (CLI, MCP) that don't wire the predicate.
        self._entitlement_check: Optional[Callable[[], bool]] = None

        # Optional callback fired when a cross-device key-rotation mismatch
        # is detected in the drain loop (missing_self_wrap rejection from the
        # server).  The app wires this to show a user-visible notify so the
        # user knows to re-unlock from the Memory Sync screen.
        self._on_key_mismatch: Optional[Callable[[], None]] = None

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

    def set_entitlement_check(self, fn: Callable[[], bool]) -> None:
        """Wire an entitlement predicate for the enqueue gate.

        When *fn* returns ``False``, :meth:`enqueue_module` silently skips
        enqueuing so enrolled-but-lapsed users don't accumulate plaintext
        envelopes on disk that can never reach the server.

        The predicate is called on every :meth:`enqueue_module` invocation
        (i.e. after every successful SSH probe) and should be cheap — a
        cached boolean attribute on the auth service is ideal.

        Callers that do not call this method get the previous behaviour:
        ``is_configured`` is the only gate, and any configured user can
        enqueue regardless of current plan entitlement.
        """
        self._entitlement_check = fn

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

    def is_enrolled_locally(self) -> bool:
        """Return ``True`` when the local passphrase-encrypted keypair cache exists.

        The cache stores only ``{public_key, wrapped_private_key, fingerprint}``
        — never the unwrapped private key or the passphrase.  Its presence is
        used by the startup reactivation path to decide whether to attempt a
        bootstrap without prompting the user to go through the Memory Sync setup
        screen again.
        """
        return self._key_cache_path.exists()

    def clear_local_keypair_cache(self) -> None:
        """Delete the local passphrase-encrypted keypair cache file.

        Safe to call when the cache does not exist.  Called by the "Disable
        Memory Sync" and "Forget on this device" actions to prevent the
        startup reactivation path from re-unlocking without user intent.
        """
        try:
            self._key_cache_path.unlink(missing_ok=True)
        except Exception as exc:
            logger.warning("clear_local_keypair_cache: %s", exc)

    def lock(self) -> None:
        """Clear the in-memory private key material.

        Drops ``_self_pubkey`` and ``_self_privkey`` from RAM so
        ``is_configured`` becomes ``False``.  Used by
        ``MemorySyncSetupScreen._do_disable`` (instead of poking private
        attrs directly, per the project's memory-encapsulation convention)
        and by the cross-device-rotation recovery path.
        """
        self._self_pubkey = None
        self._self_privkey = None
        self._notify_listeners()

    def can_unwrap_local(self, passphrase: str) -> bool:
        """Test whether *passphrase* can unwrap the locally cached keypair.

        Reads ``keys.json`` and attempts
        :func:`~servonaut.services.memory.crypto.unwrap_private_key`;
        returns ``True`` on success, ``False`` on any failure (wrong
        passphrase, no cache, corrupt data, crypto unavailable, etc.).

        **No network calls.  No mutation of ``_self_*``.**  Safe to call
        on the startup reactivation path before ``bootstrap`` so that a
        wrong/stale cached passphrase is distinguished from a transient
        backend error without triggering an erroneous keychain clear.
        """
        if not _HAS_CRYPTO:
            return False
        if not self._key_cache_path.exists():
            return False
        try:
            raw = self._key_cache_path.read_text(encoding="utf-8")
            cached = json.loads(raw)
            wrapped_json = cached.get("wrapped_private_key", "")
            if not wrapped_json:
                return False
            wrapped = WrappedPrivateKey.from_json(wrapped_json)
            unwrap_private_key(wrapped, passphrase)
            return True
        except Exception:
            return False

    def set_key_mismatch_listener(self, fn: Callable[[], None]) -> None:
        """Register a callback fired when a cross-device key-rotation mismatch is detected.

        Called from the drain loop when the server returns ``missing_self_wrap``
        (the local keypair cache references a key the server no longer
        recognises — most likely because the keypair was rotated on another
        device).  The callback is responsible for showing a user-visible
        notification so the user knows to re-unlock from the Memory Sync screen.
        """
        self._on_key_mismatch = fn

    @property
    def is_configured(self) -> bool:
        """``True`` once the user has enrolled (or unlocked) their keypair.

        Drives the lazy-setup UX: nothing in this service touches the network
        or writes plaintext to disk until the user opts in via
        ``MemorySyncSetupScreen``.

        ``_self_user_id`` is part of the gate because every envelope's DEK
        self-wrap is keyed by ``recipient_user_id == caller``; without a
        known user_id the server rejects every envelope with
        ``missing_self_wrap``. If we treated the service as configured
        anyway, the screen's "Sync now" button would silently no-op
        because ``drain_now`` early-returns on missing user_id.
        """
        return (
            self._self_pubkey is not None
            and self._self_privkey is not None
            and self._self_user_id is not None
        )

    def enqueue_module(
        self,
        instance: Dict[str, Any],
        module: str,
        result: ModuleResult,
    ) -> None:
        """Append a ModuleResult to the pending queue.

        Called from MemoryService._persist_result after every successful probe.
        No-op if the user hasn't set up Memory Sync yet — we don't want to
        accumulate plaintext envelopes on disk for users who never opt in.
        Silently drops if the queue is at capacity (_QUEUE_CAP).
        """
        if not self.is_configured:
            return
        # Entitlement gate: if a predicate is wired and returns False (e.g.
        # plan lapsed), skip enqueuing.  We do NOT want to accumulate plaintext
        # envelopes on the JSONL queue for users whose subscription no longer
        # grants access to Memory Sync — those envelopes can never be drained.
        # When no predicate is set (None) the gate is open to preserve backward
        # compatibility for callers (CLI, MCP) that don't wire this check.
        # NOTE: backfill_from_local_store routes all module re-enqueues through
        # this method, so it inherits the entitlement gate automatically.
        if self._entitlement_check is not None and not self._entitlement_check():
            return
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

    def set_retrieval_service(
        self, svc: Optional["MemoryRetrievalService"]
    ) -> None:
        """Wire in the retrieval service after construction.

        Deferred to avoid a circular import: ``sync_service`` would otherwise
        depend on ``retrieval_service`` which depends on ``sync_service``.
        Called from ``app.py::_init_services`` (and the headless CLI sync
        wiring) once both services exist.
        """
        self._retrieval_service = svc

    def enqueue_annotations(
        self,
        instance: Dict[str, Any],
        content: str,
        *,
        probed_at: Optional[str] = None,
    ) -> None:
        """Append an annotations envelope to the pending queue.

        Mirrors :meth:`enqueue_module` for all guard/persistence behaviour.
        The caller is responsible for hash-dedup: call this only when the
        annotation content has actually changed (or for first-time backfill).

        No-op when:
        - Memory Sync is not configured (user has not enrolled a keypair).
        - The instance has memory disabled (opt-out by id or name).
        - The queue is at capacity.
        """
        if not self.is_configured:
            return

        instance_id = instance.get("id") or instance.get("name", "")
        if self._memory_service.is_memory_disabled(
            instance_id, instance.get("name", "")
        ):
            return

        if len(self._pending) >= _QUEUE_CAP:
            logger.warning(
                "sync queue at cap (%d); dropping annotations for %s",
                _QUEUE_CAP,
                instance_id,
            )
            return

        env = SyncEnvelope(
            instance_id=instance_id,
            module="annotations",
            probed_at=probed_at or _now_iso(),
            ttl_seconds=86400,
            truncated=False,
            partial=False,
            sudo_used=False,
            memory_disabled=False,
            safe_metrics=None,
            plaintext_payload={"content": content},
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

    def _parse_iso(self, ts: Optional[str]) -> Optional[datetime]:
        """Parse an ISO-8601 timestamp string into an aware datetime.

        Returns ``None`` for falsy input or unparseable strings so callers
        can use simple ``None``-guard comparisons without try/except.
        Naive datetimes (no ``+HH:MM`` / ``Z`` suffix) are treated as UTC.
        """
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts.rstrip("Z"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None

    async def pull_annotations(
        self,
        instance_id: str,
        instance_name: str = "",
        provider: str = "custom",
    ) -> str:
        """Fetch and write back the annotations envelope from the server.

        Implements a last-writer-wins merge: the local copy is never
        silently clobbered when it was modified more recently than the
        server copy.

        Returns one of:
        - ``"opt_out"``    — instance has memory disabled; no network call.
        - ``"unavailable"`` — retrieval service not wired (Memory Sync not set up).
        - ``"not_found"``  — server has no annotations envelope for this instance.
        - ``"unchanged"``  — server content matches the local copy (same hash).
        - ``"local_newer"`` — local copy is newer; server copy was NOT written back.
        - ``"updated"``    — server copy was newer; local file updated.
        """
        # 1. Opt-out gate (both id and name).
        if self._memory_service.is_memory_disabled(instance_id, instance_name):
            return "opt_out"

        # 2. Retrieval service must be wired.
        if self._retrieval_service is None:
            return "unavailable"

        # 3. Fetch and decrypt the envelope from the server.
        try:
            decrypted = await self._retrieval_service.get_module(
                instance_id, "annotations"
            )
        except (MemoryBackendError, UpsellRequired):
            return "not_found"
        except Exception:
            logger.warning(
                "pull_annotations: unexpected error fetching %s/annotations",
                instance_id,
                exc_info=True,
            )
            return "not_found"

        # 4. Extract content and server timestamp.
        content: str = decrypted.plaintext.get("content", "")
        server_ts: Optional[str] = decrypted.probed_at or decrypted.created_at

        # 5. Read local bookkeeping.
        meta = self._memory_service.get_annotations_meta(instance_id)
        local_hash: str = meta.get("annotations_hash", "")
        local_modified: Optional[str] = meta.get("annotations_modified_at") or None

        # 6. Unchanged short-circuit: same content already on disk.
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if content_hash == local_hash:
            return "unchanged"

        # 7. Last-writer-wins precedence.
        local_dt = self._parse_iso(local_modified)
        server_dt = self._parse_iso(server_ts)

        if local_dt is not None and server_dt is not None and local_dt > server_dt:
            return "local_newer"
        if server_dt is None and local_dt is not None:
            # Undatable server copy — keep known-good local.
            return "local_newer"

        # 8. Server wins: write back to local store.
        self._memory_service.write_annotations(instance_id, content, provider)
        self._memory_service.set_annotations_meta(
            instance_id,
            annotations_hash=content_hash,
            annotations_synced_at=server_ts,
            annotations_modified_at=server_ts,
        )
        return "updated"

    # ------------------------------------------------------------------
    # Findings sync methods
    # ------------------------------------------------------------------

    def _findings_sync_enabled(self) -> bool:
        """Return ``True`` when the findings-sync feature gate is on.

        Reads ``config.memory.findings_sync_enabled`` via the config manager.
        Uses a strict equality check (``== True``) so that test stubs backed
        by ``MagicMock`` — which have no explicit ``findings_sync_enabled``
        attribute and thus return a truthy auto-mock — do not accidentally
        open the gate.  Returns ``False`` if anything in the chain is
        missing or raises.
        """
        try:
            cfg = self._config_manager.get()
            return getattr(cfg.memory, "findings_sync_enabled", False) == True  # noqa: E712
        except Exception:
            return False

    def enqueue_findings(
        self,
        instance: Dict[str, Any],
        records: List[Dict[str, Any]],
        *,
        probed_at: Optional[str] = None,
    ) -> None:
        """Append a findings envelope to the pending queue.

        Mirrors :meth:`enqueue_annotations` for all guard / persistence behaviour
        with an additional feature gate check.

        No-op when:
        - Memory Sync is not configured (user has not enrolled a keypair).
        - ``findings_sync_enabled`` is ``False`` (gate: hold the push until
          the backend enum is in production).
        - The instance has memory disabled (opt-out by id or name).
        - The queue is at capacity.
        - *records* is empty.

        Args:
            instance: Instance dict with at least an ``"id"`` key.
            records: List of finding dicts to bundle into a single envelope.
            probed_at: ISO-8601 timestamp to stamp the envelope; defaults to now.
        """
        if not self.is_configured:
            return
        if not self._findings_sync_enabled():
            return

        instance_id = instance.get("id") or instance.get("name", "")
        if self._memory_service.is_memory_disabled(
            instance_id, instance.get("name", "")
        ):
            return

        if not records:
            return

        if len(self._pending) >= _QUEUE_CAP:
            logger.warning(
                "sync queue at cap (%d); dropping findings for %s",
                _QUEUE_CAP,
                instance_id,
            )
            return

        env = SyncEnvelope(
            instance_id=instance_id,
            module="findings",
            probed_at=probed_at or _now_iso(),
            ttl_seconds=86400,
            truncated=False,
            partial=False,
            sudo_used=False,
            memory_disabled=False,
            safe_metrics=None,
            plaintext_payload={"findings": records},
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

    async def pull_findings(
        self,
        instance_id: str,
        instance_name: str = "",
        provider: str = "custom",
    ) -> str:
        """Fetch and merge the findings envelope from the server.

        Pulling is NOT gated by ``findings_sync_enabled`` — pulling existing
        data back from the server is safe regardless of whether the push gate
        is open.

        Returns one of:
        - ``"opt_out"``    — instance has memory disabled; no network call.
        - ``"unavailable"`` — retrieval service not wired.
        - ``"not_found"``  — server has no findings envelope for this instance.
        - ``"unchanged"``  — server returned no findings to merge.
        - ``"updated"``    — at least one finding was created or updated locally.
        """
        # 1. Opt-out gate (both id and name).
        if self._memory_service.is_memory_disabled(instance_id, instance_name):
            return "opt_out"

        # 2. Retrieval service must be wired.
        if self._retrieval_service is None:
            return "unavailable"

        # 3. Fetch and decrypt the envelope from the server.
        try:
            decrypted = await self._retrieval_service.get_module(
                instance_id, "findings"
            )
        except (MemoryBackendError, UpsellRequired):
            return "not_found"
        except Exception:
            logger.warning(
                "pull_findings: unexpected error fetching %s/findings",
                instance_id,
                exc_info=True,
            )
            return "not_found"

        # 4. Extract findings list from the decrypted envelope.
        incoming = decrypted.plaintext.get("findings", [])
        if not isinstance(incoming, list):
            return "not_found"

        # 5. Merge into local store.
        stats = self._memory_service.merge_findings(instance_id, incoming, provider)

        # 6. Update findings bookkeeping in the index.
        server_ts: Optional[str] = decrypted.probed_at or decrypted.created_at
        self._memory_service.set_findings_meta(
            instance_id,
            findings_synced_at=server_ts,
            findings_count=stats.get("active_after", 0),
        )

        return "updated" if (stats.get("created") or stats.get("updated")) else "unchanged"

    # Modules the CLI must NOT push: server-generated only.
    _BACKFILL_SKIP_MODULES: frozenset = frozenset({"ai_summary"})

    def backfill_from_local_store(self) -> int:
        """Enqueue every cached module on disk that isn't already pending.

        Bridges the gap users hit when they probed servers BEFORE enrolling
        a Memory Sync keypair: enqueue_module was a no-op then, so the
        existing local memory cache has never been pushed.

        Walks ``MemoryService.list_all()`` (the on-disk index), reconstructs
        a ModuleResult per cached module, and routes through enqueue_module
        so the JSONL persistence + watchdog + safe_metrics paths run
        exactly once per envelope. Returns the count of newly queued
        envelopes.

        Idempotent within a session: skips (instance_id, module) pairs
        already in the pending queue. The server still de-duplicates by
        ciphertext_hash, so re-runs across sessions are safe too.
        """
        if not self.is_configured:
            logger.debug("backfill skipped: sync not configured")
            return 0
        # Avoid double-enqueuing what's already pending this session.
        already_queued = {(env.instance_id, env.module) for env in self._pending}
        if self._inflight:
            already_queued.update(
                (env.instance_id, env.module) for env in self._inflight
            )

        enqueued = 0
        for entry in self._memory_service.list_all():
            instance_id = entry.get("instance_id")
            if not instance_id:
                continue
            if self._memory_service.is_memory_disabled(
                instance_id, entry.get("name", "")
            ):
                continue
            provider = entry.get("provider", "custom")
            instance_dict = {
                "id": instance_id,
                "name": entry.get("name", instance_id),
                "provider": provider,
            }
            modules = self._memory_service.get_all_modules(instance_id, provider)
            for module_name, data in modules.items():
                if module_name in self._BACKFILL_SKIP_MODULES:
                    continue
                if (instance_id, module_name) in already_queued:
                    continue
                result = ModuleResult(
                    module=module_name,
                    instance_id=instance_id,
                    observed=data.get("observed", {}) or {},
                    declared=data.get("declared", {}) or {},
                    sudo_used=bool(data.get("sudo_used", False)),
                    truncated=bool(data.get("truncated", False)),
                    partial=bool(data.get("partial", False)),
                    probed_at=data.get("probed_at", "") or "",
                    ttl_seconds=int(data.get("ttl_seconds", 86400)),
                    raw_output=data.get("raw_output", "") or "",
                )
                before = len(self._pending)
                self.enqueue_module(instance_dict, module_name, result)
                if len(self._pending) > before:
                    enqueued += 1
                    already_queued.add((instance_id, module_name))
            # Annotations: enqueue the .md content once if present and not already pending.
            if (instance_id, "annotations") not in already_queued:
                try:
                    content = self._memory_service.read_annotations(instance_id, provider)
                except Exception:
                    content = ""
                if content.strip():
                    meta = self._memory_service.get_annotations_meta(instance_id)
                    before = len(self._pending)
                    self.enqueue_annotations(instance_dict, content, probed_at=meta.get("annotations_synced_at") or None)
                    if len(self._pending) > before:
                        enqueued += 1
                        already_queued.add((instance_id, "annotations"))
            # Findings: enqueue all local findings once if any exist and not already pending.
            if (instance_id, "findings") not in already_queued:
                try:
                    recs = self._memory_service.list_findings(
                        instance_id, provider, include_superseded=True
                    )
                except Exception:
                    recs = []
                if recs:
                    before = len(self._pending)
                    self.enqueue_findings(instance_dict, recs)  # gate-guarded internally → no-op while gate off
                    if len(self._pending) > before:
                        enqueued += 1
                        already_queued.add((instance_id, "findings"))
        if enqueued:
            logger.info("backfill_from_local_store: enqueued %d envelopes", enqueued)
        return enqueued

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

        M7: idempotent — if a concurrent bootstrap call (e.g. manual setup
        worker racing the startup autostart worker) has already loaded the
        keypair, return immediately to avoid a redundant network round-trip
        or a second passphrase prompt.
        """
        # M7: already configured — no-op so concurrent bootstrap calls
        # don't double-prompt the user.
        if self.is_configured:
            return

        # Guarantee user_id before any crypto. Without it we cannot build
        # the DEK self-wrap (recipient_user_id == caller) and the server
        # would reject every envelope with `missing_self_wrap`.
        self._self_user_id = await self._auth_service.fetch_user_id()
        if self._self_user_id is None:
            raise MemoryBackendError(
                "Could not resolve your user_id from /api/v1/me — sign out "
                "and back in to refresh your session, then retry setup."
            )

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

        if self._self_pubkey is None:
            logger.warning("drain_now: no active keypair; cannot encrypt")
            self._last_error = (
                "no active keypair — open Memory Sync and re-enrol the keypair"
            )
            self._notify_listeners()
            return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)
        # user_id may be stale (e.g. user logged in before we started
        # fetching it from /api/v1/me). One re-fetch attempt before
        # giving up so the user doesn't have to sign out/in.
        if self._self_user_id is None:
            try:
                self._self_user_id = await self._auth_service.fetch_user_id()
            except Exception as exc:
                logger.warning("drain_now: fetch_user_id retry failed: %s", exc)
            if self._self_user_id is None:
                logger.warning("drain_now: user_id unresolved; cannot self-wrap")
                self._last_error = (
                    "could not resolve user_id — sign out and back in, then retry"
                )
                self._notify_listeners()
                return SyncBatchResult(
                    accepted=[], rejected=[], quota=self._quota
                )

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
            if getattr(exc, "code", None) == "conflict_retry" or exc.status == 409:
                # Transient (instance, module, snapshot_version) contention from a
                # concurrent drain (e.g. two devices on one account). The server
                # rolled the batch back atomically, so a plain retry succeeds —
                # re-queue and let the next drain pick it up. NOT a user-visible
                # error (don't set state=error / last_error for a self-healing case).
                logger.info(
                    "drain_now: conflict_retry (409) — re-queueing batch for retry"
                )
                self._pending.extendleft(reversed(batch))
                self._inflight = None
                self._notify_listeners()
                return SyncBatchResult(accepted=[], rejected=[], quota=self._quota)
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

            if self._halted_reason == "key_mismatch":
                logger.debug("sync loop: halted (key_mismatch); exiting loop")
                break

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
            except MissingSelfWrap:
                # S-1: cross-device key-rotation recovery.
                # The server rejected our envelope with missing_self_wrap,
                # meaning the public key we have cached locally is no longer
                # the one registered on the server (another device rotated the
                # keypair after we bootstrapped).
                #
                # Action: clear the local keypair cache + lock in-memory key +
                # clear the OS keychain passphrase + reset the remember flag so
                # the startup reactivation path re-prompts the user on the next
                # launch.  Halt the loop so we don't keep burning rate-limit
                # budget with envelopes that will always be rejected.
                logger.error(
                    "sync loop: missing_self_wrap — clearing local keypair cache "
                    "(cross-device rotation?); halting drain until re-enrolment"
                )
                self.clear_local_keypair_cache()
                self.lock()
                try:
                    from servonaut.services.memory import passphrase_store as _ps
                    _ps.clear_passphrase()
                except Exception:
                    pass
                try:
                    import dataclasses as _dc
                    cfg = self._config_manager.get()
                    _updated = _dc.replace(cfg.memory, sync_remember_device=False)
                    self._config_manager.update(memory=_updated)
                except Exception:
                    pass
                self._halted_reason = "key_mismatch"
                self._state = "halted"
                self._last_error = "Memory Sync key changed — re-unlock to resume sync"
                self._notify_listeners()
                if self._on_key_mismatch is not None:
                    try:
                        self._on_key_mismatch()
                    except Exception:
                        pass
                break  # exit the loop; user must re-enrol
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
        # Overwrite the local cache with the new wrapped keypair so that
        # the next startup can skip the /keys/me network call.  The old
        # cached passphrase (if any) in the OS keychain is now invalid;
        # the caller (_do_rotate in the screen) is responsible for clearing
        # it and optionally storing the new one.  Include user_id so the
        # cache remains bound to this account after rotation (MAJOR-2).
        import base64 as _b64
        self._persist_key_cache(
            _b64.b64encode(new_kp.public_key).decode(),
            new_wrapped.to_json(),
            new_kp.fingerprint,
            user_id=self._self_user_id,
        )
        if self._key_material_listener is not None:
            try:
                self._key_material_listener()
            except Exception:
                logger.warning("key_material_listener raised after rotate", exc_info=True)
        logger.info("Rotated memory keypair fingerprint=%s", new_kp.fingerprint)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _derive_public_key(self, private_key_bytes: bytes) -> Optional[bytes]:
        """Derive the X25519 public key from raw *private_key_bytes*.

        Returns the 32-byte public key on success, or ``None`` when PyNaCl
        is unavailable or derivation fails.  Used by ``_ensure_keypair`` to
        verify that the cached public key is consistent with the unwrapped
        private key (M5 pubkey-integrity check).
        """
        try:
            import nacl.public as _nacl_pub
            return bytes(_nacl_pub.PrivateKey(private_key_bytes).public_key)
        except Exception:
            return None

    def _persist_key_cache(
        self, public_key_b64: str, wrapped_private_key_json: str, fingerprint: str, *, user_id: Optional[int] = None
    ) -> None:
        """Write passphrase-encrypted keypair material to the local cache.

        Uses an atomic 0600 write (mirrors ``auth_service._save_token``) so
        a crash mid-write cannot leave a partial file.

        Security contract:
        - Only encrypted material is written here.
        - The unwrapped private key and the passphrase are NEVER stored.
        - Parent directory is created with mode 0700.
        - ``user_id`` is stored so the reactivation path can detect a
          different account on the same OS user and ignore the stale cache.

        Failures are logged as warnings but never re-raised — a missing cache
        is safe; it just means the next bootstrap must hit the network.
        """
        data: Dict[str, Any] = {
            "public_key": public_key_b64,
            "wrapped_private_key": wrapped_private_key_json,
            "fingerprint": fingerprint,
        }
        # MAJOR-2: bind cache to the authenticated user_id so a different
        # account on the same OS user does not silently reuse this cached
        # keypair on the next launch.
        if user_id is not None:
            data["user_id"] = user_id
        try:
            parent = self._key_cache_path.parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # M9: mode arg to mkdir is umask-masked and a no-op on existing
            # dirs, so chmod explicitly to guarantee 0o700 regardless of umask.
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
            # M8: use a unique temp filename (mkstemp) so concurrent writes
            # from two app instances don't overwrite each other's temp file.
            fd, tmp_path_str = tempfile.mkstemp(
                dir=parent, prefix=".keys_", suffix=".tmp"
            )
            tmp_path = Path(tmp_path_str)
            try:
                # Restrict to owner-readable immediately after creation
                # (mkstemp uses mode 0o600 on most platforms; chmod is
                # belt-and-suspenders in case the platform differs).
                os.chmod(tmp_path, 0o600)
                with os.fdopen(fd, "w") as f:
                    json.dump(data, f)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
                raise
            os.replace(tmp_path, self._key_cache_path)
            # Belt-and-suspenders: ensure the final file is 0o600 after replace.
            try:
                os.chmod(self._key_cache_path, 0o600)
            except OSError:
                pass
            logger.debug(
                "_persist_key_cache: wrote cache fingerprint=%s", fingerprint
            )
        except Exception as exc:
            logger.warning("_persist_key_cache: failed to write cache: %s", exc)

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
        """Fetch or enrol the caller's X25519 keypair.

        Fast path (local cache):
            If ``keys.json`` is present, unwrap the private key from it using
            the passphrase and return — **no network call is made**.  This
            avoids consuming one of the server's 3/hour ``/keys/me`` rate-limit
            slots on every app restart.

            A bad passphrase re-raises the unwrap exception immediately; we do
            NOT silently fall back to the network, because that would mask the
            wrong-passphrase error with a misleading "rate-limit" or
            "key-not-found" message.

        Network path (cache absent):
            Fetches the wrapped key from ``GET /api/v1/memory/keys/me``,
            unwraps it, and persists the encrypted material to the cache.

        Enrol path (404 on keys/me):
            Generates a fresh keypair, wraps it, POSTs to
            ``POST /api/v1/memory/keys``, and persists to the cache.
        """
        import base64

        # ------------------------------------------------------------------
        # Fast path: local passphrase-encrypted cache
        # ------------------------------------------------------------------
        if self._key_cache_path.exists():
            cached: Optional[Dict[str, Any]] = None
            try:
                raw = self._key_cache_path.read_text(encoding="utf-8")
                cached = json.loads(raw)
            except Exception as exc:
                logger.warning(
                    "_ensure_keypair: cache read/parse failed (%s); "
                    "falling back to server",
                    exc,
                )
            if cached is not None:
                pub_b64 = cached.get("public_key", "")
                wrapped_json = cached.get("wrapped_private_key", "")
                fingerprint = cached.get("fingerprint", "")
                if pub_b64 and wrapped_json:
                    # MAJOR-2: user_id binding — reject cache if it was written
                    # by a different account on this OS user (e.g. two engineers
                    # share a laptop with different servonaut.dev accounts).
                    cached_uid = cached.get("user_id")
                    if (
                        cached_uid is not None
                        and self._self_user_id is not None
                        and int(cached_uid) != int(self._self_user_id)
                    ):
                        logger.warning(
                            "_ensure_keypair: cached user_id %s != current user_id %s — "
                            "ignoring cache (different account on same OS user); "
                            "clearing and falling back to server",
                            cached_uid, self._self_user_id,
                        )
                        self.clear_local_keypair_cache()
                        # Fall through to network path
                    else:
                        # Ask for the passphrase BEFORE touching _self_pubkey so
                        # that if the provider raises (user cancel) the service
                        # stays unconfigured and in a clean state.
                        passphrase = await passphrase_provider("unlock")
                        wrapped = WrappedPrivateKey.from_json(wrapped_json)
                        # Bad passphrase raises here — do NOT silently refetch from
                        # the server, and do NOT swallow the exception.
                        privkey = unwrap_private_key(wrapped, passphrase)
                        # M5: derive the public key from the unwrapped private key
                        # and verify it matches the cached public_key.  A mismatch
                        # means the cache was corrupted — clear it and fall back to
                        # the network path so the server's authoritative copy is used.
                        derived_pub = self._derive_public_key(privkey)
                        if derived_pub is not None and derived_pub != base64.b64decode(pub_b64):
                            logger.error(
                                "_ensure_keypair: derived pubkey does not match cached "
                                "pubkey — cache is corrupt; clearing and falling back to "
                                "network path"
                            )
                            self.clear_local_keypair_cache()
                            # Fall through to network path; passphrase_provider
                            # will be called again from the network/enrol path.
                        else:
                            # Only update state AFTER successful unwrap + pubkey check.
                            self._self_pubkey = base64.b64decode(pub_b64)
                            self._self_privkey = privkey
                            logger.info(
                                "Bootstrap: loaded keypair from local cache fingerprint=%s",
                                fingerprint,
                            )
                            return

        # ------------------------------------------------------------------
        # Network path: GET /api/v1/memory/keys/me
        # ------------------------------------------------------------------
        try:
            await self._rate_limiter.acquire(RateLimitKey.KEYS_ME)
            data = await self._api.get(
                "/api/v1/memory/keys/me", retry_on_401=False
            )
            pub_b64 = data.get("public_key", "")
            wrapped_json = data.get("wrapped_private_key", "")
            fingerprint = data.get("fingerprint", "")

            passphrase = await passphrase_provider("unlock")
            wrapped = WrappedPrivateKey.from_json(wrapped_json)
            privkey = unwrap_private_key(wrapped, passphrase)
            # Update state AFTER successful unwrap.
            self._self_pubkey = base64.b64decode(pub_b64)
            self._self_privkey = privkey
            # Persist encrypted material so the next bootstrap skips the
            # /keys/me rate-limit slot.  Include user_id so the cache is
            # bound to this account (MAJOR-2).
            self._persist_key_cache(pub_b64, wrapped_json, fingerprint, user_id=self._self_user_id)
            logger.info(
                "Bootstrap: loaded existing keypair fingerprint=%s",
                fingerprint,
            )
            return

        except RateLimitedError as exc:
            # Server-side 3/hour cap on /keys/me — ratchet the local limiter
            # so the next click sleeps locally instead of round-tripping.
            self._rate_limiter.record_429(RateLimitKey.KEYS_ME)
            raise RateLimited(
                endpoint="/api/v1/memory/keys/me", retry_after_s=1200.0
            ) from exc
        except NotFoundError:
            # No active key — enrol a new one (fall through below).
            logger.info("Bootstrap: no active keypair; enrolling new key")

        # ------------------------------------------------------------------
        # Enrol path: generate fresh keypair + POST /api/v1/memory/keys
        # ------------------------------------------------------------------
        passphrase = await passphrase_provider("enrol")
        kp = generate_keypair()
        wrapped = wrap_private_key(kp.private_key, passphrase)
        pub_b64 = base64.b64encode(kp.public_key).decode()
        payload = {
            "public_key": pub_b64,
            "wrapped_private_key": wrapped.to_json(),
            "fingerprint": kp.fingerprint,
        }
        await self._api.post(
            "/api/v1/memory/keys", json=payload, retry_on_401=False
        )
        self._self_pubkey = kp.public_key
        self._self_privkey = kp.private_key
        # Persist encrypted material after successful enrolment.  Include
        # user_id so the cache is bound to this account (MAJOR-2).
        self._persist_key_cache(pub_b64, wrapped.to_json(), kp.fingerprint, user_id=self._self_user_id)
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
            await self._handle_rejection(rejection, batch)

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

    async def _handle_rejection(
        self, rejection: SyncRejection, batch: List[SyncEnvelope]
    ) -> None:
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
                except Exception as exc:  # noqa: BLE001 — must not crash the sync run
                    logger.warning("Could not persist memory_disabled opt-out: %s", exc)

        elif reason == "quota_exceeded":
            logger.warning("sync rejection: quota_exceeded — halting for %d× interval", _QUOTA_BACKOFF_FACTOR)
            self._halted_reason = "quota_exceeded"
            self._state = "halted"
            self._last_error = "quota_exceeded"
            self._notify_listeners()

        elif reason == "unknown_instance":
            await self._handle_unknown_instance(rejection, batch)

        elif reason == "validation_failed":
            # Server rejected on a malformed payload — log with the server's
            # message + the offending instance_id for triage and drop.
            instance_id = (
                batch[rejection.index].instance_id
                if 0 <= rejection.index < len(batch)
                else "—"
            )
            logger.warning(
                "sync rejection[%d]: validation_failed message=%s instance_id=%s",
                rejection.index, rejection.message or "", instance_id,
            )

        else:
            # Truly unknown reason — log VERBATIM with structured fields so a
            # new server-side code never surfaces as opaque "unknown reason".
            instance_id = (
                batch[rejection.index].instance_id
                if 0 <= rejection.index < len(batch)
                else "—"
            )
            logger.warning(
                "sync rejection[%d]: reason=%s message=%s instance_id=%s",
                rejection.index, reason, rejection.message or "", instance_id,
            )

    async def _handle_unknown_instance(
        self, rejection: SyncRejection, batch: List[SyncEnvelope]
    ) -> None:
        """Auto-register the instance with the server and re-queue the envelope.

        The backend rejects envelopes whose ``instance_id`` has no
        ``memory_instances`` row for this user (or whose row was
        soft-deleted). Recover by calling ``POST /api/v1/memory/instances``
        with local metadata, then re-queue the rejected envelope so the
        next drain cycle picks it up against the now-existing row.

        No inline retry: re-attempting the sync in the same call would
        tight-loop if the registration itself fails (e.g.
        ``quota_exceeded`` on the instances endpoint).
        """
        if not (0 <= rejection.index < len(batch)):
            logger.warning(
                "sync rejection: unknown_instance with out-of-range index %d "
                "(batch size %d) — cannot recover",
                rejection.index, len(batch),
            )
            return
        env = batch[rejection.index]
        instance_id = env.instance_id

        # Skip the round-trip when this id was already (re-)registered this
        # session — a second envelope for the same id will succeed without
        # another /memory/instances POST.
        if instance_id in self._registered_instance_ids:
            logger.debug(
                "sync rejection[%d]: unknown_instance for already-registered "
                "%s — re-queuing without POST",
                rejection.index, instance_id,
            )
        else:
            display_name, provider = self._lookup_local_metadata(instance_id)
            instance_dict = {
                "id": instance_id,
                "name": display_name,
                "provider": provider,
            }
            try:
                await self.upsert_instance(instance_dict)
            except (
                QuotaExceeded,
                ValidationFailed,
                ReservedInstanceIdError,
                UpsellRequired,
            ) as exc:
                logger.warning(
                    "auto-register failed for %s after unknown_instance "
                    "rejection: %s — dropping envelope",
                    instance_id, exc,
                )
                return
            except APIError as exc:
                logger.warning(
                    "auto-register POST failed for %s (%s) — dropping envelope",
                    instance_id, exc,
                )
                return
            except Exception as exc:  # noqa: BLE001 — must not crash the sync run
                logger.warning(
                    "unexpected error auto-registering %s: %s — dropping envelope",
                    instance_id, exc,
                )
                return
            self._registered_instance_ids.add(instance_id)
            logger.info(
                "auto-registered instance %s after unknown_instance rejection",
                instance_id,
            )

        # Re-queue for the next drain cycle. Append to the right so the
        # envelope doesn't jump ahead of work we haven't tried yet — order
        # doesn't matter for correctness now that the row exists.
        if len(self._pending) >= _QUEUE_CAP:
            logger.warning(
                "sync queue at cap (%d); cannot re-queue %s/%s",
                _QUEUE_CAP, instance_id, env.module,
            )
            return
        self._pending.append(env)

    def _lookup_local_metadata(self, instance_id: str) -> tuple[str, str]:
        """Return ``(display_name, provider)`` for *instance_id*.

        Looks the instance up in the local memory store; falls back to
        ``(instance_id, "custom")`` when there's no cached entry.
        """
        try:
            for entry in self._memory_service.list_all():
                if entry.get("instance_id") == instance_id:
                    return (
                        entry.get("name") or instance_id,
                        entry.get("provider") or "custom",
                    )
        except Exception as exc:  # noqa: BLE001 — fallback to defaults
            logger.debug("local metadata lookup failed for %s: %s", instance_id, exc)
        return (instance_id, "custom")

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

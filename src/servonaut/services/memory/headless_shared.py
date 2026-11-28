"""Shared team memory for processes that have no app to unlock Memory Sync.

The standalone MCP server (and the relay's tool executor) can read the memory
a team shares only with an unlocked Memory Sync key, and nothing here may
change state the way the app's unlock does: no key is enrolled, nothing is
uploaded, no setting, config value, keychain entry or cache is written.

So the only unlocks offered are the ones the user already granted. A key
kept in the vault is read through a read-only
:class:`~servonaut.services.memory.key_custody.MemoryKeyCustody` once the
vault is unlocked on this device. Otherwise the app unlocked Memory Sync with
"Keep unlocked for 30 days" (the ``sync_remember_device`` setting, "Remember
on this device" in code), which keeps the passphrase in the OS keychain for a
limited time; this module reads that passphrase and opens the local keypair
cache with it, and otherwise leaves Memory Sync locked.

Building the services does no network call and no key derivation; the unlock
runs on the first read that needs it.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from enum import Enum
from typing import Any, Callable, Optional

from servonaut.services.memory import passphrase_store
from servonaut.services.memory import sync_service as _sync_module
from servonaut.services.memory.remembered_passphrase import remember_passphrase_expired
from servonaut.services.memory.sync_service import (
    LocalUnlock, MemorySyncService, VaultUnlock,
)

logger = logging.getLogger(__name__)

_FEATURE = "memory_sync"

_LABEL = "\u201cKeep unlocked for 30 days\u201d"


class LockReason(str, Enum):
    """Why Memory Sync is locked in this process."""

    NOT_SET_UP = "not_set_up"
    NOT_KEPT = "not_kept"
    NO_KEYCHAIN = "no_keychain"
    UNLOCK_FAILED = "unlock_failed"
    VAULT_LOCKED = "vault_locked"


_HINTS = {
    LockReason.NOT_SET_UP: (
        "This server is shared through a team. To read the memory the team "
        f"shares, set up Memory Sync in the Servonaut app and choose {_LABEL}. "
        "Servonaut's MCP server then reads it without a restart."
    ),
    LockReason.NOT_KEPT: (
        "This server is shared through a team, and Memory Sync is locked for "
        "Servonaut's MCP server. Unlock Memory Sync in the Servonaut app and "
        f"choose {_LABEL}; the MCP server then reads it without a restart."
    ),
    LockReason.NO_KEYCHAIN: (
        "This server is shared through a team, but Servonaut's MCP server "
        "cannot unlock Memory Sync on this computer because no OS keychain is "
        "available. Read the shared memory in the Servonaut app."
    ),
    LockReason.UNLOCK_FAILED: (
        "This server is shared through a team, and Servonaut's MCP server "
        "could not unlock Memory Sync. Unlock it again in the Servonaut app "
        f"and choose {_LABEL}."
    ),
    LockReason.VAULT_LOCKED: (
        "This server is shared through a team, and the Memory Sync key is "
        "kept in your vault. Unlock your vault or add this device to it so "
        "Servonaut's MCP server can read the shared memory, or set "
        "SERVONAUT_VAULT_DEVICE_KEY on a computer without a keychain."
    ),
}

#: Reader not wired: signed out, or a plan without Memory Sync.
NOT_WIRED_HINT = (
    "This server is shared through a team. Reading the memory a team shares "
    "needs you signed in to Servonaut on a plan that includes Memory Sync."
)


def locked_hint(reason: LockReason) -> str:
    """The ``get_server_memory`` hint for a shared server that cannot be read."""
    return _HINTS[reason]


class HeadlessSharedMemory:
    """A shared-memory reader plus the read-only unlock it needs.

    Attributes:
        reader: The :class:`SharedMemoryReader` to bind to the tools.
    """

    def __init__(
        self,
        reader: Any,
        sync_service: Any,
        config_manager: Any,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.reader = reader
        self._sync = sync_service
        self._config_manager = config_manager
        self._clock = clock
        # A vault attempt that did not unlock is not repeated until then, so a
        # tool that asks on every read does not hit the service each time.
        self._vault_retry_at: float = 0.0
        self._vault_outcome: Optional[VaultUnlock] = None
        # A digest, never the passphrase: it only recognises one that already
        # failed, so the slow key derivation is not repeated for it.
        self._failed_digest: Optional[str] = None
        self._lock: Optional[asyncio.Lock] = None

    @property
    def is_unlocked(self) -> bool:
        return bool(self._sync.is_configured)

    async def ensure_unlocked(self) -> bool:
        """``True`` when Memory Sync is unlocked in this process."""
        return await self.check_lock() is None

    async def check_lock(self) -> Optional[LockReason]:
        """``None`` when unlocked, else why it is locked. Never raises.

        Cheap while locked and not kept unlocked, so the tools may call it on
        every read: unlocking in the app is then picked up without a restart.
        The reason is returned, not stored, so concurrent calls cannot mix
        their answers up.
        """
        if self.is_unlocked:
            return None
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self.is_unlocked:
                return None
            try:
                reason = await self._unlock_from_vault()
                if reason is not _NO_VAULT_ANSWER:
                    return reason
                return await self._unlock_from_remembered_passphrase()
            except Exception as exc:  # noqa: BLE001 - a fallback must never fail a tool
                logger.debug("Shared memory unlock skipped (%s)", type(exc).__name__)
                return LockReason.UNLOCK_FAILED

    async def _unlock_from_vault(self) -> Any:
        """``None`` when unlocked, ``VAULT_LOCKED`` when the vault holds the key
        but cannot give it up, else ``_NO_VAULT_ANSWER`` (try the passphrase path).
        """
        if self._clock() < self._vault_retry_at:
            outcome = self._vault_outcome
        else:
            outcome = await self._sync.unlock_from_vault()
            self._vault_outcome = outcome
            if outcome is not VaultUnlock.OK:
                wait = self._config_manager.get().memory.vault_key_recheck_wait()
                self._vault_retry_at = self._clock() + wait
        if outcome is VaultUnlock.OK:
            return None if self.is_unlocked else _NO_VAULT_ANSWER
        if outcome is VaultUnlock.VAULT_LOCKED:
            return LockReason.VAULT_LOCKED
        return _NO_VAULT_ANSWER

    async def _unlock_from_remembered_passphrase(self) -> Optional[LockReason]:
        if not self._sync.is_enrolled_locally():
            return LockReason.NOT_SET_UP
        # The file, not the copy loaded at start: the app may have saved the
        # setting since this process began.
        remembered, expires_at = self._config_manager.read_saved_memory_remember()
        if not remembered or remember_passphrase_expired(expires_at):
            return LockReason.NOT_KEPT
        if not await asyncio.to_thread(passphrase_store.keyring_available):
            return LockReason.NO_KEYCHAIN
        passphrase = await asyncio.to_thread(self._stored_passphrase)
        if passphrase is None:
            return LockReason.NOT_KEPT
        digest = hashlib.sha256(passphrase.encode("utf-8")).hexdigest()
        if digest == self._failed_digest:
            return LockReason.UNLOCK_FAILED
        outcome = await self._sync.unlock_local(passphrase)
        if outcome is LocalUnlock.NO_CACHE:
            return LockReason.NOT_SET_UP
        if outcome is LocalUnlock.BAD_PASSPHRASE:
            self._failed_digest = digest
        return None if self._sync.is_configured else LockReason.UNLOCK_FAILED

    @staticmethod
    def _stored_passphrase() -> Optional[str]:
        if not passphrase_store.keyring_available():
            return None
        return passphrase_store.get_passphrase() or None


#: Sentinel: the vault gave no answer, so the passphrase path decides.
_NO_VAULT_ANSWER = object()


async def _no_passphrase(mode: str = "unlock") -> str:
    """The retrieval service's passphrase source: this process never asks."""
    raise RuntimeError(
        "Memory Sync is locked here; unlock it in the Servonaut app."
    )


def build_read_only_key_custody(
    api_client: Any,
    auth_service: Any,
    rate_limiter: Any,
    config_manager: Any,
    vault_runtime: Any = None,
) -> Any:
    """A ``MemoryKeyCustody(writable=False)`` for a process that must not write.

    It reads the key from *vault_runtime* once that is unlocked (the vault is
    asked lazily, so a vault that unlocks later is picked up) and never
    writes the marker, enrols or cleans up.
    """
    from servonaut.services.memory.key_custody import DEFAULT_MARKER_PATH, MemoryKeyCustody
    from servonaut.services.vault.errors import NO_LOCAL_IDENTITY, VaultUserError

    def app_keys() -> Any:
        if vault_runtime is None or not vault_runtime.is_unlocked:
            return None
        return vault_runtime.app_keys

    def signer() -> Any:
        if vault_runtime is None:
            raise VaultUserError(NO_LOCAL_IDENTITY)
        return vault_runtime.device_signer()

    return MemoryKeyCustody(
        api_client,
        auth_service,
        rate_limiter,
        app_keys,
        signer,
        DEFAULT_MARKER_PATH,
        False,
        memory_config_provider=lambda: config_manager.get().memory,
        key_cache_path=_sync_module._KEY_CACHE_PATH,
    )


def build_headless_shared_memory(
    config_manager: Any, auth_service: Any, api_client: Any, vault_runtime: Any = None,
) -> Optional[HeadlessSharedMemory]:
    """The shared-memory reader for a process without an app, or ``None``.

    ``None`` when the user is not signed in or the plan has no Memory Sync,
    the same gate the app puts on its own unlock. Does no network call and
    no key derivation; ``memory_service`` is deliberately not given a sync
    service, so nothing in this process starts uploading.
    """
    if api_client is None or auth_service is None:
        return None
    if not auth_service.is_authenticated or not auth_service.has_feature(_FEATURE):
        return None

    import servonaut.services.memory.crypto as memory_crypto
    from servonaut.services.memory.rate_limiter import RateLimiter
    from servonaut.services.memory.retrieval_service import MemoryRetrievalService
    from servonaut.services.memory.shared_view import SharedMemoryReader
    from servonaut.services.memory.team_service import TeamMemoryService
    from servonaut.services.memory.team_wraps import default_pin_store

    def memory_settings() -> Any:
        return config_manager.get().memory

    rate_limiter = RateLimiter()
    sync = MemorySyncService(
        api_client=api_client,
        crypto=memory_crypto,
        memory_service=None,
        config_manager=config_manager,
        auth_service=auth_service,
        rate_limiter=rate_limiter,
    )
    sync.set_key_custody(build_read_only_key_custody(
        api_client, auth_service, rate_limiter, config_manager, vault_runtime,
    ))
    retrieval = MemoryRetrievalService(
        api_client=api_client,
        crypto=memory_crypto,
        passphrase_provider=_no_passphrase,
        rate_limiter=rate_limiter,
        key_material_provider=sync.get_key_material,
        user_id_provider=auth_service.fetch_user_id,
    )

    def _hand_key_to_retrieval() -> None:
        material = sync.get_key_material()
        if material is None:
            return
        retrieval.set_key_material(material)
        retrieval.clear_cache()

    sync.set_key_material_listener(_hand_key_to_retrieval)
    team_service = TeamMemoryService(
        api_client=api_client,
        auth_service=auth_service,
        crypto=memory_crypto,
        key_store_provider=sync.get_key_material,
        retrieval_service=retrieval,
        cache_ttl_provider=lambda: memory_settings().team_memory_cache_seconds,
        pin_store_provider=lambda: default_pin_store(
            lock_wait=memory_settings().record_lock_wait
        ),
        future_skew_provider=lambda: memory_settings().team_memory_future_skew_seconds,
    )
    reader = SharedMemoryReader(
        team_service,
        lambda: memory_settings().team_memory_cache_seconds,
        teams_provider=auth_service.list_teams,
    )
    return HeadlessSharedMemory(reader, sync, config_manager)

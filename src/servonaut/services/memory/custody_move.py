"""Move an existing Memory Sync key from passphrase custody into the vault.

The move is one way: once the service records the key as vault custody there
is no passphrase copy to go back to.  Every step can be repeated after a
crash, in this order:

1. preflight (no writes);
2. a record that is already vault custody skips to the local cleanup;
3. the recovery-key gate, before anything is written;
4. the private key, from the unlocked sync material or the service's copy
   opened with the passphrase;
5. the vault item, read back and compared;
6. the device-signed custody switch at the service;
7. local cleanup, only after the service confirmed.

Nothing here logs, prints or puts a key, passphrase or recovery key into an
exception.  Callers read what a failure means from :class:`MoveStopped`.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from servonaut.services.api_client import APIError, NotFoundError, RateLimitedError
from servonaut.services.memory import crypto
from servonaut.services.memory.custody_errors import custody_code_message, custody_error_message
from servonaut.services.memory.interfaces import KeyMaterial
from servonaut.services.memory.key_custody import (
    CUSTODY_VAULT,
    KeyRecord,
    MemoryKeyCustody,
    parse_key_record,
)
from servonaut.services.memory.rate_limiter import RateLimitKey
from servonaut.services.vault.errors import VaultUserError
from servonaut.services.vault.items import MEMORY_KEY
from servonaut.services.vault.onboarding import identity_step
from servonaut.services.vault.team_vault_client import VaultStateError

logger = logging.getLogger(__name__)

try:
    import httpx

    _TRANSPORT_ERRORS: tuple[type[BaseException], ...] = (OSError, httpx.HTTPError)
except ImportError:  # pragma: no cover — httpx ships with the paid-feature extra
    _TRANSPORT_ERRORS = (OSError,)

_KEYS_ME_PATH = "/api/v1/memory/keys/me"
_CUSTODY_PATH = "/api/v1/memory/keys/me/custody"
_KEY_ITEM_NAME = "Servonaut Memory Sync key"
_KEY_ITEM_VERSION = 1
_RAW_KEY_BYTES = 32

# Step names handed to the progress callback, in run order.
STEP_PREFLIGHT = "preflight"
STEP_ALREADY_VAULT = "already_vault"
STEP_RECOVERY = "recovery_check"
STEP_KEY = "unlock_key"
STEP_ITEM = "vault_item"
STEP_SWITCH = "switch_custody"
STEP_CLEANUP = "cleanup"

OUTCOME_MOVED = "moved"
OUTCOME_ALREADY_VAULT = "already_vault"
OUTCOME_NOTHING_TO_MOVE = "nothing_to_move"

_MSG_VAULT_NOT_READY = (
    "Your vault is not ready for this. Unlock your vault on this device, "
    "confirm your vault identity, and try again."
)
_MSG_UPSELL = "Memory Sync is not part of your plan. Nothing was changed."
_MSG_SIGN_IN = "Sign in with servonaut login first. Nothing was changed."
_MSG_RECOVERY_MISMATCH = (
    "That recovery key does not open your vault identity. Nothing was changed. "
    "If you no longer have your recovery key, run servonaut vault recovery-key "
    "to replace it, then try again."
)
_MSG_WRONG_PASSPHRASE = (
    "That passphrase did not open your Memory Sync key. Nothing was changed."
)
_MSG_KEY_MISMATCH = (
    "The key opened with that passphrase does not match the key at the "
    "service. Nothing was changed."
)
_MSG_NO_PERSONAL_VAULT = (
    "Your account has no personal vault to keep this key in. Nothing was changed."
)
_MSG_READBACK = (
    "The key did not read back from your vault correctly. Nothing was moved."
)
_MSG_ITEM_MISSING = (
    "Your Memory Sync key is kept in your vault, but this vault does not hold "
    "it. Unlock the vault that holds it and try again."
)
_MSG_UNREACHABLE = "The Servonaut service could not be reached. Try again later."
_MSG_REFUSED = "The Servonaut service refused the request. Nothing was moved."
_MSG_KEY_UNREADABLE = "The Memory Sync key record at the service could not be read."
_MSG_PASSPHRASE_UNAVAILABLE = "The key at the service is not under a passphrase."


class MoveStopped(Exception):
    """The move cannot continue; ``message`` is plain, final text safe to show.

    ``reason`` is a short code for callers and tests; it is never shown.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


class MoveAborted(Exception):
    """The person running the move declined or cancelled; nothing further was written."""


@dataclass
class MoveReport:
    """What a run did. Public facts only."""

    outcome: str
    vault_created: bool = False
    item_created: bool = False
    warnings: list[str] = field(default_factory=list)


Progress = Callable[[str], None]


class MemoryCustodyMover:
    """Run the move; see the module docstring for the steps.

    Args:
        api_client: Service client.
        auth_service: Entitlement check and the signed-in user id.
        rate_limiter: The Memory Sync limiter.
        vault: The vault command service (unlock state, app keys, device
            signer, recovery-key check).
        sync: The Memory Sync service whose key is adopted after the move.
        custody: A writable key custody (marker, leftover cleanup).
        config_manager: Passed to the leftover cleanup for the remember flags.
    """

    def __init__(
        self,
        api_client: Any,
        auth_service: Any,
        rate_limiter: Any,
        vault: Any,
        sync: Any,
        custody: MemoryKeyCustody,
        config_manager: Any,
    ) -> None:
        self._api = api_client
        self._auth = auth_service
        self._limiter = rate_limiter
        self._vault = vault
        self._sync = sync
        self._custody = custody
        self._config_manager = config_manager

    async def run(
        self,
        passphrase_provider: Callable[[], str],
        recovery_key_provider: Callable[[], str],
        progress: Optional[Progress] = None,
        *,
        recovery_gate: Optional[Callable[[], Awaitable[None]]] = None,
    ) -> MoveReport:
        """Move the key; raises :class:`MoveStopped` (or :class:`MoveAborted`) when it cannot.

        The providers are plain blocking callables (a hidden prompt, a stdin
        line); they run off the event loop and only when the step needs them.
        A caller that has already proven the recovery key in this run (the CLI
        runs two moves behind one proof) passes its own *recovery_gate*, which
        replaces the prompt.
        """
        say = progress or (lambda _step: None)
        gate = recovery_gate or (lambda: self.prove_recovery(recovery_key_provider))
        try:
            return await self._run(passphrase_provider, gate, say)
        except (APIError, VaultStateError, VaultUserError, *_TRANSPORT_ERRORS) as exc:
            raise self._stopped_from(exc) from exc

    async def _run(
        self,
        passphrase_provider: Callable[[], str],
        recovery_gate: Callable[[], Awaitable[None]],
        say: Progress,
    ) -> MoveReport:
        say(STEP_PREFLIGHT)
        record = await self._preflight()
        if record is None:
            return MoveReport(OUTCOME_NOTHING_TO_MOVE)
        report = MoveReport(OUTCOME_MOVED)
        if record.custody == CUSTODY_VAULT:
            say(STEP_ALREADY_VAULT)
            material = await self._material_from_existing_item(record)
            report.outcome = OUTCOME_ALREADY_VAULT
        else:
            say(STEP_RECOVERY)
            await recovery_gate()
            say(STEP_KEY)
            material = await self._private_key(record, passphrase_provider)
            say(STEP_ITEM)
            await self._ensure_item(record, material, report)
            say(STEP_SWITCH)
            await self._switch_custody(record)
        say(STEP_CLEANUP)
        await self._local_cleanup(material, report)
        return report

    # ------------------------------------------------------------------
    # Step 1
    # ------------------------------------------------------------------

    async def _preflight(self) -> Optional[KeyRecord]:
        """No writes. ``None`` means the account has no key to move."""
        if not getattr(self._auth, "is_authenticated", False):
            raise MoveStopped("not_signed_in", _MSG_SIGN_IN)
        if not self._auth.has_feature("memory_sync"):
            raise MoveStopped("forbidden_entitlement", _MSG_UPSELL)
        if not self._vault.is_unlocked:
            raise MoveStopped("vault_not_ready", _MSG_VAULT_NOT_READY)
        status = await self._vault.status()
        if identity_step(status) is not None:
            raise MoveStopped("vault_not_ready", _MSG_VAULT_NOT_READY)
        return await self._fetch_record()

    async def _fetch_record(self) -> Optional[KeyRecord]:
        await self._limiter.acquire(RateLimitKey.KEYS_ME)
        try:
            data = await self._api.get(_KEYS_ME_PATH, retry_on_401=False)
        except NotFoundError:
            return None
        except RateLimitedError:
            self._limiter.record_429(RateLimitKey.KEYS_ME)
            raise
        try:
            return parse_key_record(data)
        except Exception as exc:  # noqa: BLE001 — parse_key_record's own error type
            raise MoveStopped("key_record_unreadable", _MSG_KEY_UNREADABLE) from exc

    # ------------------------------------------------------------------
    # Step 2
    # ------------------------------------------------------------------

    async def _material_from_existing_item(self, record: KeyRecord) -> KeyMaterial:
        """A key already in vault custody: the vault must hold it, readable."""
        user_id = await self._user_id()
        payload = await self._vault.app_keys.read(MEMORY_KEY, record.fingerprint)
        material = _material_from_payload(payload, user_id, record.fingerprint)
        if material is None:
            raise MoveStopped("vault_item_missing", _MSG_ITEM_MISSING)
        return material

    # ------------------------------------------------------------------
    # Step 3
    # ------------------------------------------------------------------

    async def prove_recovery(self, provider: Callable[[], str]) -> None:
        """Check the recovery key before anything is written; raises :class:`MoveStopped`."""
        try:
            await prove_recovery_key(self._vault, provider)
        except (APIError, VaultStateError, *_TRANSPORT_ERRORS) as exc:
            raise self._stopped_from(exc) from exc

    # ------------------------------------------------------------------
    # Step 4
    # ------------------------------------------------------------------

    async def _private_key(
        self, record: KeyRecord, passphrase_provider: Callable[[], str],
    ) -> KeyMaterial:
        unlocked = self._sync.get_key_material()
        if unlocked is not None and crypto.fingerprint(unlocked.public_key) == record.fingerprint:
            return unlocked
        wrapped = _wrapped_from_record(record)
        passphrase = await asyncio.to_thread(passphrase_provider)
        try:
            # Argon2id is slow by design and must not stall the event loop.
            private_key = await asyncio.to_thread(crypto.unwrap_private_key, wrapped, passphrase)
        except crypto.DecryptionFailedError as exc:
            raise MoveStopped("wrong_passphrase", _MSG_WRONG_PASSPHRASE) from exc
        finally:
            del passphrase
        return await self._verified_material(record, private_key)

    async def _verified_material(self, record: KeyRecord, private_key: bytes) -> KeyMaterial:
        derived = _derive_public(private_key)
        try:
            recorded = base64.b64decode(record.public_key, validate=True)
        except (binascii.Error, ValueError):
            recorded = b""
        if (
            len(private_key) != _RAW_KEY_BYTES or derived is None or derived != recorded
            or crypto.fingerprint(derived) != record.fingerprint
        ):
            raise MoveStopped("key_mismatch", _MSG_KEY_MISMATCH)
        return KeyMaterial(user_id=await self._user_id(), public_key=derived, private_key=private_key)

    # ------------------------------------------------------------------
    # Step 5
    # ------------------------------------------------------------------

    async def _ensure_item(
        self, record: KeyRecord, material: KeyMaterial, report: MoveReport,
    ) -> None:
        items = self._vault.app_keys
        report.vault_created = await items.personal_vault_id() is None
        if await items.personal_vault_id(create=True) is None:
            raise MoveStopped("no_personal_vault", _MSG_NO_PERSONAL_VAULT)
        existing = [ref.public_fingerprint for ref in await items.list(MEMORY_KEY)]
        if record.fingerprint not in existing:
            await self._create_item(items, material)
            report.item_created = True
        stored = await items.read(MEMORY_KEY, record.fingerprint)
        if not _same_key(stored, material):
            if report.item_created:
                await self._drop_item(items, record.fingerprint)
            raise MoveStopped("readback_mismatch", _MSG_READBACK)

    async def _create_item(self, items: Any, material: KeyMaterial) -> None:
        payload = {
            "v": _KEY_ITEM_VERSION,
            "name": _KEY_ITEM_NAME,
            "user_id": material.user_id,
            "public_key": base64.b64encode(material.public_key).decode(),
            "private_key": base64.b64encode(material.private_key).decode(),
            "public_fingerprint": crypto.fingerprint(material.public_key),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await items.create(MEMORY_KEY, payload)

    @staticmethod
    async def _drop_item(items: Any, fingerprint: str) -> None:
        try:
            await items.delete(MEMORY_KEY, fingerprint)
        except Exception:  # noqa: BLE001 — must not hide the mismatch that led here
            logger.warning("could not delete the unused Memory Sync key item", exc_info=True)

    # ------------------------------------------------------------------
    # Step 6
    # ------------------------------------------------------------------

    async def _switch_custody(self, record: KeyRecord) -> None:
        """The irreversible call. The item stays on a refusal: it is harmless and reused."""
        try:
            signer = self._vault.device_signer()
        except VaultUserError as exc:
            message = custody_code_message("device_signature_required")
            raise MoveStopped("device_signature_required", message or _MSG_REFUSED) from exc
        await self._limiter.acquire(RateLimitKey.GENERAL)
        await self._api.request_signed(
            "POST", _CUSTODY_PATH,
            json={"custody": CUSTODY_VAULT, "fingerprint": record.fingerprint},
            device=signer,
        )

    # ------------------------------------------------------------------
    # Step 7
    # ------------------------------------------------------------------

    async def _local_cleanup(self, material: KeyMaterial, report: MoveReport) -> None:
        """Runs only after the service confirmed; a failure is a warning, a re-run finishes it."""
        try:
            self._custody.forget_passphrase_leftovers(self._sync, self._config_manager)
            await self._custody.mark_vault_custody(material)
            self._sync.adopt_key_material(
                material.user_id, material.public_key, material.private_key,
            )
        except Exception as exc:  # noqa: BLE001 — the key already moved; report, never undo
            logger.warning("local cleanup after the move failed (%s)", type(exc).__name__)
            report.warnings.append(
                "The key was moved, but this device could not finish its local "
                "cleanup. Run the same command again to finish it."
            )

    # ------------------------------------------------------------------

    async def _user_id(self) -> int:
        user_id = await self._auth.fetch_user_id()
        if user_id is None:
            raise MoveStopped("user_id_unavailable", _MSG_UNREACHABLE)
        return int(user_id)

    @staticmethod
    def _stopped_from(exc: Exception) -> MoveStopped:
        """Plain text for a failure; the service's own wording is never used."""
        if isinstance(exc, VaultUserError):
            return MoveStopped("vault_error", str(exc))
        if isinstance(exc, APIError):
            if exc.code == "forbidden_entitlement":
                return MoveStopped(exc.code, _MSG_UPSELL)
            message = custody_error_message(exc)
            return MoveStopped(exc.code or "api_error", message or _MSG_REFUSED)
        if isinstance(exc, VaultStateError):
            return MoveStopped("vault_state", _MSG_VAULT_NOT_READY)
        return MoveStopped("unreachable", _MSG_UNREACHABLE)


async def prove_recovery_key(vault: Any, provider: Callable[[], str]) -> None:
    """Ask for the vault recovery key and check it against the vault identity.

    The one gate every key move passes before it writes anything (Memory Sync
    and config sync, on every surface). The provider is a blocking callable and
    runs off the event loop. Raises :class:`MoveStopped`.
    """
    recovery_key = await asyncio.to_thread(provider)
    try:
        matches = await vault.verify_recovery_key(recovery_key)
    except VaultUserError as exc:
        # A typo or a non-key: the vault's own sentence says how it is wrong.
        raise MoveStopped("recovery_key_invalid", str(exc)) from exc
    finally:
        del recovery_key
    if not matches:
        raise MoveStopped("recovery_key_mismatch", _MSG_RECOVERY_MISMATCH)


def _wrapped_from_record(record: KeyRecord) -> Any:
    blob = record.wrapped_private_key
    if isinstance(blob, dict):
        blob = json.dumps(blob)
    if not isinstance(blob, str) or not blob:
        raise MoveStopped("not_passphrase", _MSG_PASSPHRASE_UNAVAILABLE)
    try:
        return crypto.WrappedPrivateKey.from_json(blob)
    except crypto.CryptoError as exc:
        raise MoveStopped("key_record_unreadable", _MSG_KEY_UNREADABLE) from exc


def _derive_public(private_key: bytes) -> Optional[bytes]:
    try:
        import nacl.public

        return bytes(nacl.public.PrivateKey(private_key).public_key)
    except Exception:  # noqa: BLE001 — any failure means the key does not verify
        return None


def _material_from_payload(
    payload: Optional[dict], user_id: int, fingerprint: str,
) -> Optional[KeyMaterial]:
    if not isinstance(payload, dict):
        return None
    try:
        public = base64.b64decode(payload["public_key"], validate=True)
        private = base64.b64decode(payload["private_key"], validate=True)
        owner = int(payload["user_id"])
    except (KeyError, TypeError, ValueError, binascii.Error):
        return None
    if owner != user_id or crypto.fingerprint(public) != fingerprint:
        return None
    if len(private) != _RAW_KEY_BYTES or _derive_public(private) != public:
        return None
    return KeyMaterial(user_id=user_id, public_key=public, private_key=private)


def _same_key(stored: Optional[dict], material: KeyMaterial) -> bool:
    """The vault copy equals the key we hold: owner, public, private (via its public) and fingerprint."""
    if not isinstance(stored, dict):
        return False
    try:
        public = base64.b64decode(stored["public_key"], validate=True)
        private = base64.b64decode(stored["private_key"], validate=True)
        owner = int(stored["user_id"])
    except (KeyError, TypeError, ValueError, binascii.Error):
        return False
    return (
        owner == material.user_id
        and public == material.public_key
        and private == material.private_key
        and _derive_public(private) == public
        and stored.get("public_fingerprint") == crypto.fingerprint(material.public_key)
    )

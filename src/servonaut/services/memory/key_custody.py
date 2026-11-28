"""Where the Memory Sync key is kept, and how a device gets at it.

A key kept in the user's vault is a ``memory_key`` item of the personal
vault; a key kept under a passphrase is a wrapped blob at the service (and,
on devices that unlocked it before, a local ``keys.json``).  This module
decides which applies, loads the key from the vault when it can, and
enrols a new key in the vault.  It holds no state beyond a small public
marker file, so every surface (app, CLI, MCP server, relay) can build one.

The marker (``key_custody.json``) holds public values only.  It lets a
device start without asking the service where the key is kept, because
that lookup is rate limited and a vault-custody account has no local
``keys.json`` to stand in for it.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import logging
import os
import re
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from servonaut.config.schema import MemoryConfig
from servonaut.services.api_client import APIError, NotFoundError, RateLimitedError
from servonaut.services.memory import crypto
from servonaut.services.memory.interfaces import (
    KeyMaterial,
    VaultCustodyLocked,
    VaultCustodyUnavailable,
)
from servonaut.services.memory.rate_limiter import RateLimitKey
from servonaut.services.vault.app_keys import AppKeyItems
from servonaut.services.vault.errors import VaultUserError
from servonaut.services.vault.items import MEMORY_KEY
from servonaut.services.vault.team_vault_client import VaultStateError

logger = logging.getLogger(__name__)

CUSTODY_VAULT = "vault"
CUSTODY_PASSPHRASE = "passphrase"

MODE_VAULT = "vault"
MODE_NEEDS_VAULT_DEVICE = "needs_vault_device"
MODE_PASSPHRASE = "passphrase"

_KEYS_ME_PATH = "/api/v1/memory/keys/me"
_KEYS_PATH = "/api/v1/memory/keys"
_KEYS_ROTATE_PATH = "/api/v1/memory/keys/rotate"
_MEMORY_KEY_IN_USE = "memory_key_in_use"
_ITEM_TYPE_EXISTS = "item_type_exists"
_MARKER_FILE_VERSION = 1
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ITEM_NAME = "Servonaut Memory Sync key"
_KEY_ITEM_VERSION = 1
_RAW_KEY_BYTES = 32


@dataclass(frozen=True)
class KeyRecord:
    """The service's record of the active key; ``custody`` is already fail-closed."""

    id: Any
    fingerprint: str
    public_key: str
    wrapped_private_key: Any
    custody: str
    custody_changed_at: Optional[str]


def parse_key_record(data: Any) -> KeyRecord:
    """Read ``GET /keys/me`` so that anything unclear means vault custody.

    Passphrase custody needs a non-empty wrapped key and a custody value
    that is absent or ``"passphrase"``.  A record with a null wrap, an
    explicit vault value or an unknown value is vault custody: treating it
    as a passphrase key would prompt for a passphrase that cannot open it.
    ``custody_changed_at`` may be null (a key enrolled directly in the vault).
    """
    if not isinstance(data, dict):
        raise VaultCustodyUnavailable("The key record from the service is unreadable.")
    wrapped = data.get("wrapped_private_key")
    custody = data.get("custody")
    has_wrap = bool(wrapped) and isinstance(wrapped, (str, dict))
    is_passphrase = has_wrap and custody in (None, CUSTODY_PASSPHRASE)
    return KeyRecord(
        id=data.get("id"),
        fingerprint=str(data.get("fingerprint") or ""),
        public_key=str(data.get("public_key") or ""),
        wrapped_private_key=wrapped if is_passphrase else None,
        custody=CUSTODY_PASSPHRASE if is_passphrase else CUSTODY_VAULT,
        custody_changed_at=data.get("custody_changed_at") or None,
    )


class ResolutionKind(str, Enum):
    VAULT_KEY = "vault_key"
    VAULT_LOCKED = "vault_locked"
    PASSPHRASE = "passphrase"
    NOT_ENROLLED = "not_enrolled"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Resolution:
    """The outcome of :meth:`MemoryKeyCustody.resolve`.

    ``material`` is set for ``VAULT_KEY``; ``record`` for ``PASSPHRASE`` when
    the service was asked (``None`` means "use keys.json"); ``reason`` explains
    ``VAULT_LOCKED`` and ``UNAVAILABLE``; ``error`` carries the failure behind
    an ``UNAVAILABLE`` (for example a rate limit) so the caller can re-raise it.
    """

    kind: ResolutionKind
    material: Optional[KeyMaterial] = None
    fingerprint: Optional[str] = None
    record: Optional[KeyRecord] = None
    reason: Optional[str] = None
    error: Optional[BaseException] = None


@dataclass(frozen=True)
class CustodyMarker:
    """Public facts about where this account's key is kept, as last seen."""

    user_id: int
    custody: str
    fingerprint: str
    public_key: str
    checked_at: str


@dataclass(frozen=True)
class RotationResult:
    """How a vault-mode key rotation ended (public values only).

    ``old_item_kept`` is true when the service still needs the previous key
    for older memory; the next vault unlock retries the delete through
    :meth:`MemoryKeyCustody.retry_pending_item_cleanup`.  ``upload_error`` is
    ``None`` when local memory was uploaded again under the new key, else the
    reason the queue was left non-empty.
    """

    fingerprint: str
    previous_fingerprint: str
    old_item_kept: bool
    upload_error: Optional[str] = None


#: Called with the new key once the service accepted it; uploads local memory
#: again under it and returns an error reason, or ``None`` when the queue drained.
RotationUploader = Callable[[KeyMaterial], Awaitable[Optional[str]]]


@dataclass
class _VaultOutcome:
    """Either a final answer from the vault step, or what it learned for the next step."""

    resolution: Optional[Resolution] = None
    record: Optional[KeyRecord] = None
    looked_up: bool = False


class MemoryKeyCustody:
    """Decide where the key lives, load it from the vault, enrol it in the vault.

    Args:
        api_client: Service client (``get`` for the key record, ``request_signed`` for key writes).
        auth_service: Resolves the signed-in user id.
        rate_limiter: The Memory Sync limiter; the key lookup takes a ``KEYS_ME`` slot.
        app_keys_provider: Returns the vault's :class:`AppKeyItems`, or ``None``
            while the vault is absent or locked.
        signer_provider: Returns the device signer; raises ``VaultUserError`` when locked.
        marker_path: Where the public marker lives.
        writable: Whether this process may write the marker, enrol and clean up.
            Headless processes pass ``False``.
        remote_identity_provider: Tells whether the account has a vault
            identity anywhere; needed by :meth:`enrolment_mode`.
        memory_config_provider: Supplies the custody check interval.
        on_vault_detected: Called (writable only) when the throttled check
            finds the key moved to the vault; the owner runs the local cleanup.
        key_cache_path: The passphrase key file; defaults to ``keys.json``
            beside the marker.
        clock: Seconds since the epoch; tests replace it.
    """

    def __init__(
        self,
        api_client: Any,
        auth_service: Any,
        rate_limiter: Any,
        app_keys_provider: Callable[[], Optional[AppKeyItems]],
        signer_provider: Callable[[], Any],
        marker_path: Path,
        writable: bool,
        *,
        remote_identity_provider: Optional[Callable[[], Awaitable[bool]]] = None,
        memory_config_provider: Optional[Callable[[], MemoryConfig]] = None,
        on_vault_detected: Optional[Callable[[], None]] = None,
        key_cache_path: Optional[Path] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._api = api_client
        self._auth = auth_service
        self._limiter = rate_limiter
        self._app_keys_provider = app_keys_provider
        self._signer_provider = signer_provider
        self._marker_path = Path(marker_path)
        self._writable = writable
        self._remote_identity_provider = remote_identity_provider
        self._memory_config_provider = memory_config_provider
        self._on_vault_detected = on_vault_detected
        self._key_cache_path = key_cache_path or self._marker_path.parent / "keys.json"
        self._clock = clock

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    async def resolve(self) -> Resolution:
        """Say where the key is and, for the vault, hand it over."""
        try:
            user_id = await self._user_id()
        except (APIError, OSError, VaultCustodyUnavailable) as exc:
            return Resolution(ResolutionKind.UNAVAILABLE, reason="user_id_unavailable", error=exc)
        marker = self._read_marker(user_id)
        items = self._app_keys_provider()
        if items is not None:
            outcome = await self._resolve_from_vault(items, user_id, marker)
            if outcome.resolution is not None:
                return outcome.resolution
            return await self._resolve_without_item(user_id, marker, outcome.record, outcome.looked_up)
        return await self._resolve_without_item(user_id, marker, None, False)

    async def _resolve_from_vault(
        self, items: AppKeyItems, user_id: int, marker: Optional[CustodyMarker],
    ) -> _VaultOutcome:
        try:
            refs = await items.list(MEMORY_KEY)
        except VaultUserError:
            return _VaultOutcome()  # locked: handled like an absent vault
        except (VaultStateError, APIError, OSError) as exc:
            return _VaultOutcome(Resolution(
                ResolutionKind.UNAVAILABLE, reason="vault_unreadable", error=exc))
        if not refs:
            return _VaultOutcome()
        fingerprints = [ref.public_fingerprint for ref in refs]
        trust_marker = marker is not None and marker.fingerprint in fingerprints and (
            len(refs) == 1 or not self._writable
        )
        if trust_marker:
            return await self._adopt(items, user_id, marker.fingerprint, marker.custody)
        if not self._writable and len(refs) == 1:
            return await self._adopt(items, user_id, fingerprints[0], None)
        return await self._resolve_by_service(items, user_id, fingerprints)

    async def _resolve_by_service(
        self, items: AppKeyItems, user_id: int, fingerprints: list[str],
    ) -> _VaultOutcome:
        try:
            record = await self._fetch_record()
        except (APIError, OSError) as exc:
            return _VaultOutcome(Resolution(
                ResolutionKind.UNAVAILABLE, reason="keys_me_unavailable", error=exc))
        if record is None:
            # Items without a key at the service: an enrolment that crashed
            # before its POST. The enrolment resumes from the item.
            return _VaultOutcome(Resolution(ResolutionKind.NOT_ENROLLED))
        if record.fingerprint in fingerprints:
            return await self._adopt(items, user_id, record.fingerprint, record.custody)
        return _VaultOutcome(record=record, looked_up=True)

    async def _adopt(
        self, items: AppKeyItems, user_id: int, fingerprint: str, custody: Optional[str],
    ) -> _VaultOutcome:
        try:
            payload = await items.read(MEMORY_KEY, fingerprint)
        except VaultUserError:
            return _VaultOutcome()
        except (VaultStateError, APIError, OSError) as exc:
            return _VaultOutcome(Resolution(
                ResolutionKind.UNAVAILABLE, reason="vault_unreadable", error=exc))
        material = self._material_from_payload(payload, user_id, fingerprint)
        if material is None:
            return _VaultOutcome(Resolution(
                ResolutionKind.UNAVAILABLE, reason="vault_key_invalid"))
        self._write_marker(CustodyMarker(
            user_id=user_id,
            custody=custody or CUSTODY_VAULT,
            fingerprint=fingerprint,
            public_key=base64.b64encode(material.public_key).decode(),
            checked_at=self._now_iso(),
        ))
        return _VaultOutcome(Resolution(
            ResolutionKind.VAULT_KEY, material=material, fingerprint=fingerprint))

    async def _resolve_without_item(
        self, user_id: int, marker: Optional[CustodyMarker],
        record: Optional[KeyRecord], looked_up: bool,
    ) -> Resolution:
        if marker is not None and marker.custody == CUSTODY_VAULT:
            return Resolution(ResolutionKind.VAULT_LOCKED, fingerprint=marker.fingerprint,
                              reason="vault_locked")
        if looked_up:
            return self._from_record(user_id, record)
        if self._key_cache_path.exists():
            return await self._throttled_check(user_id, marker)
        try:
            record = await self._fetch_record()
        except (APIError, OSError) as exc:
            return Resolution(ResolutionKind.UNAVAILABLE, reason="keys_me_unavailable", error=exc)
        if record is None:
            return Resolution(ResolutionKind.NOT_ENROLLED)
        return self._from_record(user_id, record)

    def _from_record(self, user_id: int, record: Optional[KeyRecord]) -> Resolution:
        if record is None:
            return Resolution(ResolutionKind.NOT_ENROLLED)
        self._write_marker(CustodyMarker(
            user_id=user_id, custody=record.custody, fingerprint=record.fingerprint,
            public_key=record.public_key, checked_at=self._now_iso(),
        ))
        if record.custody == CUSTODY_VAULT:
            return Resolution(ResolutionKind.VAULT_LOCKED, fingerprint=record.fingerprint,
                              record=record, reason="vault_locked")
        return Resolution(ResolutionKind.PASSPHRASE, fingerprint=record.fingerprint, record=record)

    async def _throttled_check(self, user_id: int, marker: Optional[CustodyMarker]) -> Resolution:
        """Devices on the ``keys.json`` fast path ask the service at most once per interval."""
        fast_path = Resolution(ResolutionKind.PASSPHRASE, record=None)
        if not self._writable or not self._check_due(marker):
            return fast_path
        try:
            record = await self._fetch_record()
        except (APIError, OSError) as exc:
            logger.debug("custody check skipped: %s", exc.__class__.__name__)
            return fast_path
        if record is None:
            return fast_path
        resolution = self._from_record(user_id, record)
        if resolution.kind is ResolutionKind.VAULT_LOCKED:
            self._run_vault_detected()
            return resolution
        return fast_path

    def _check_due(self, marker: Optional[CustodyMarker]) -> bool:
        if marker is None:
            return True
        try:
            checked = datetime.fromisoformat(marker.checked_at).timestamp()
        except ValueError:
            return True
        return self._clock() - checked >= self._check_interval_seconds()

    def _check_interval_seconds(self) -> float:
        config = self._memory_config_provider() if self._memory_config_provider else MemoryConfig()
        return config.custody_check_interval_seconds()

    def _run_vault_detected(self) -> None:
        if self._on_vault_detected is None:
            return
        try:
            self._on_vault_detected()
        except Exception:  # noqa: BLE001 — cleanup is best effort; a re-run finishes it
            logger.warning("passphrase leftovers cleanup failed", exc_info=True)

    async def _fetch_record(self) -> Optional[KeyRecord]:
        """``GET /keys/me`` through the limiter; ``None`` when the account has no key."""
        await self._limiter.acquire(RateLimitKey.KEYS_ME)
        try:
            data = await self._api.get(_KEYS_ME_PATH, retry_on_401=False)
        except NotFoundError:
            return None
        except RateLimitedError:
            self._limiter.record_429(RateLimitKey.KEYS_ME)
            raise
        return parse_key_record(data)

    async def _user_id(self) -> int:
        user_id = await self._auth.fetch_user_id()
        if user_id is None:
            raise VaultCustodyUnavailable("Could not resolve your user id.")
        return int(user_id)

    @staticmethod
    def _material_from_payload(
        payload: Optional[dict], user_id: int, fingerprint: str,
    ) -> Optional[KeyMaterial]:
        """The key from a verified item payload, or ``None`` when it is not this account's key."""
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

    # ------------------------------------------------------------------
    # Enrolment
    # ------------------------------------------------------------------

    async def enrolment_mode(self) -> str:
        """How a new key would be kept: ``vault``, ``needs_vault_device`` or ``passphrase``.

        An account that has a vault never gets a passphrase key: when this
        device cannot reach the vault the answer is ``needs_vault_device``.
        """
        if self._app_keys_provider() is not None:
            return MODE_VAULT
        if self._remote_identity_provider is None:
            return MODE_PASSPHRASE
        try:
            has_identity = await self._remote_identity_provider()
        except (APIError, VaultStateError, VaultUserError, OSError) as exc:
            raise VaultCustodyUnavailable("Could not check your vault.") from exc
        return MODE_NEEDS_VAULT_DEVICE if has_identity else MODE_PASSPHRASE

    async def enrol_in_vault(self) -> KeyMaterial:
        """Create the key in the vault, then register it with the service.

        Safe to run again after a crash: an item that already exists while
        the service has no key is reused.  A refusal by the service deletes
        the item this call created; a transport failure keeps it, because
        the request may have been applied.
        """
        if not self._writable:
            raise RuntimeError("a read-only custody cannot enrol a key")
        items = self._app_keys_provider()
        if items is None:
            raise VaultCustodyLocked("vault_locked")
        signer = self._signer()
        user_id = await self._user_id()
        await self._require_no_service_key()
        material, created = await self._existing_or_new_item(items, user_id)
        fingerprint = crypto.fingerprint(material.public_key)
        try:
            await self._post_vault_key(material, fingerprint, signer)
        except APIError:
            if created:
                await self._drop_item(items, fingerprint)
            raise
        self._write_marker(CustodyMarker(
            user_id=user_id, custody=CUSTODY_VAULT, fingerprint=fingerprint,
            public_key=base64.b64encode(material.public_key).decode(),
            checked_at=self._now_iso(),
        ))
        return material

    def _signer(self) -> Any:
        try:
            return self._signer_provider()
        except VaultUserError as exc:
            raise VaultCustodyLocked("device_signature_required") from exc

    async def _require_no_service_key(self) -> None:
        if await self._fetch_record() is not None:
            raise VaultCustodyUnavailable("A Memory Sync key is already registered for your account.")

    async def _existing_or_new_item(
        self, items: AppKeyItems, user_id: int,
    ) -> tuple[KeyMaterial, bool]:
        refs = await items.list(MEMORY_KEY)
        if len(refs) > 1:
            raise VaultCustodyUnavailable("Your vault holds more than one Memory Sync key.")
        if refs:
            payload = await items.read(MEMORY_KEY, refs[0].public_fingerprint)
            material = self._material_from_payload(payload, user_id, refs[0].public_fingerprint)
            if material is None:
                raise VaultCustodyUnavailable("The Memory Sync key in your vault could not be read.")
            return material, False
        return await self._create_item(items, user_id), True

    async def _create_item(self, items: AppKeyItems, user_id: int) -> KeyMaterial:
        pair = crypto.generate_keypair()
        payload = {
            "v": _KEY_ITEM_VERSION,
            "name": _KEY_ITEM_NAME,
            "user_id": user_id,
            "public_key": base64.b64encode(pair.public_key).decode(),
            "private_key": base64.b64encode(pair.private_key).decode(),
            "public_fingerprint": pair.fingerprint,
            "created_at": self._now_iso(),
        }
        await items.create(MEMORY_KEY, payload)
        stored = await items.read(MEMORY_KEY, pair.fingerprint)
        material = self._material_from_payload(stored, user_id, pair.fingerprint)
        if material is None or material.private_key != pair.private_key:
            await self._drop_item(items, pair.fingerprint)
            raise VaultCustodyUnavailable("The new key did not read back from your vault. Nothing was changed.")
        return material

    async def _post_vault_key(self, material: KeyMaterial, fingerprint: str, signer: Any) -> None:
        await self._limiter.acquire(RateLimitKey.GENERAL)
        await self._api.request_signed(
            "POST", _KEYS_PATH,
            json={
                "public_key": base64.b64encode(material.public_key).decode(),
                "fingerprint": fingerprint,
                "custody": CUSTODY_VAULT,
            },
            device=signer,
        )

    @staticmethod
    async def _drop_item(items: AppKeyItems, fingerprint: str) -> None:
        try:
            await items.delete(MEMORY_KEY, fingerprint)
        except Exception:  # noqa: BLE001 — cleanup must not hide the refusal that led here
            logger.warning("could not delete the unused Memory Sync key item", exc_info=True)

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    async def rotate_in_vault(self, upload: RotationUploader) -> RotationResult:
        """Replace the vault-held key: next item, signed rotate call, re-upload, delete the old item.

        Every step can be repeated after a crash.  A crash after the next
        item exists leaves it as a non-active item that the next run deletes
        (the service never learned of it); a crash after the service accepted
        the key leaves the old item as a non-active item whose delete the
        service allows once no memory is wrapped to it.  Either way the
        active key is whichever the service names, and that is the one
        :meth:`resolve` adopts.

        Raises:
            VaultCustodyLocked: The vault or the device signer is not available.
            VaultCustodyUnavailable: The account is not in vault custody, or
                the vault does not hold the active key.
            APIError: The service refused (an ``item_type_exists`` answer means
                the previous key is still needed); the next item is deleted again.
        """
        if not self._writable:
            raise RuntimeError("a read-only custody cannot rotate a key")
        items = self._app_keys_provider()
        if items is None:
            raise VaultCustodyLocked("vault_locked")
        signer = self._signer()
        user_id = await self._user_id()
        previous = await self._active_fingerprint_in_vault(items)
        if await self._finish_earlier_rotation(items, previous):
            raise APIError(
                code=_ITEM_TYPE_EXISTS, status=409,
                message="a previous Memory Sync key item is still in use",
            )
        material = await self._create_item(items, user_id)
        fingerprint = crypto.fingerprint(material.public_key)
        try:
            await self._post_rotation(material, fingerprint, signer)
        except APIError:
            await self._drop_item(items, fingerprint)
            raise
        self._write_marker(CustodyMarker(
            user_id=user_id, custody=CUSTODY_VAULT, fingerprint=fingerprint,
            public_key=base64.b64encode(material.public_key).decode(),
            checked_at=self._now_iso(),
        ))
        upload_error = await self._run_upload(upload, material)
        kept = await self._delete_unless_in_use(items, previous)
        return RotationResult(
            fingerprint=fingerprint, previous_fingerprint=previous,
            old_item_kept=kept, upload_error=upload_error,
        )

    async def retry_pending_item_cleanup(self) -> bool:
        """Delete a previous key's item that a rotation had to keep; never raises.

        Call it after the vault unlocks.  Returns ``True`` when the vault is
        left with no item besides the active key (or there was nothing to do),
        ``False`` when an item was kept or the check could not be made.  The
        service decides what may go: it refuses to delete a key that is
        active or still has memory wrapped to it.
        """
        if not self._writable:
            return True
        items = self._app_keys_provider()
        if items is None:
            return False
        try:
            refs = await items.list(MEMORY_KEY)
            if len(refs) < 2:
                return True
            active = await self._known_active_fingerprint()
            if active is None or active not in [ref.public_fingerprint for ref in refs]:
                return False
            return not await self._finish_earlier_rotation(items, active)
        except (APIError, VaultStateError, VaultUserError, OSError, VaultCustodyUnavailable):
            logger.debug("pending key item cleanup skipped", exc_info=True)
            return False

    async def _known_active_fingerprint(self) -> Optional[str]:
        """The active key's fingerprint from the marker, else one ``GET /keys/me``."""
        marker = self._read_marker(await self._user_id())
        if marker is not None:
            return marker.fingerprint
        record = await self._fetch_record()
        return record.fingerprint if record is not None else None

    async def _active_fingerprint_in_vault(self, items: AppKeyItems) -> str:
        """The service's active key, required to be vault custody and held by this vault."""
        record = await self._fetch_record()
        if record is None or record.custody != CUSTODY_VAULT:
            raise VaultCustodyUnavailable("Your Memory Sync key is not kept in your vault.")
        held = [ref.public_fingerprint for ref in await items.list(MEMORY_KEY)]
        if record.fingerprint not in held:
            raise VaultCustodyUnavailable("Your vault does not hold your active Memory Sync key.")
        return record.fingerprint

    async def _finish_earlier_rotation(self, items: AppKeyItems, active: str) -> bool:
        """Delete every item but the active key's; return ``True`` when one had to stay.

        A non-active item is either a "next" key the service never saw or a
        previous key.  Deleting is right for both, and safe: the service
        refuses the delete of a key that is active or still has memory wrapped
        to it.  A kept item makes a new rotation stop with ``item_type_exists``
        (the service's own limit of two items per kind).
        """
        kept = False
        for ref in await items.list(MEMORY_KEY):
            if ref.public_fingerprint == active:
                continue
            kept = await self._delete_unless_in_use(items, ref.public_fingerprint) or kept
        return kept

    async def _delete_unless_in_use(self, items: AppKeyItems, fingerprint: str) -> bool:
        """Delete one item; ``True`` when it was kept (still in use or not deletable now)."""
        try:
            await items.delete(MEMORY_KEY, fingerprint)
        except APIError as exc:
            if exc.code != _MEMORY_KEY_IN_USE:
                logger.warning("could not delete a Memory Sync key item (%s)", exc.code)
            return True
        except (VaultStateError, VaultUserError, OSError):
            logger.warning("could not delete a Memory Sync key item", exc_info=True)
            return True
        return False

    async def _post_rotation(self, material: KeyMaterial, fingerprint: str, signer: Any) -> None:
        await self._limiter.acquire(RateLimitKey.KEYS_ROTATE)
        try:
            await self._api.request_signed(
                "POST", _KEYS_ROTATE_PATH,
                json={
                    "public_key": base64.b64encode(material.public_key).decode(),
                    "fingerprint": fingerprint,
                    "custody": CUSTODY_VAULT,
                },
                device=signer,
            )
        except RateLimitedError:
            self._limiter.record_429(RateLimitKey.KEYS_ROTATE)
            raise

    @staticmethod
    async def _run_upload(upload: RotationUploader, material: KeyMaterial) -> Optional[str]:
        """The rotation is done once the service accepted the key; an upload problem is reported, not raised."""
        try:
            return await upload(material)
        except Exception as exc:  # noqa: BLE001 — the key change already happened
            logger.warning("re-upload after rotation failed (%s)", exc.__class__.__name__)
            return "upload_failed"

    # ------------------------------------------------------------------
    # Local leftovers and marker
    # ------------------------------------------------------------------

    def forget_passphrase_leftovers(self, sync: Any, config_manager: Any) -> None:
        """Remove what only a passphrase key needs: ``keys.json``, the keychain entry, the remember flags.

        Writable callers only, idempotent, never raises.
        """
        if not self._writable:
            return
        try:
            sync.clear_local_keypair_cache()
        except Exception:  # noqa: BLE001
            logger.warning("could not remove the local key file", exc_info=True)
        try:
            from servonaut.services.memory import passphrase_store

            passphrase_store.clear_passphrase()
        except Exception:  # noqa: BLE001
            logger.warning("could not clear the remembered passphrase", exc_info=True)
        self._reset_remember_flags(config_manager)

    @staticmethod
    def _reset_remember_flags(config_manager: Any) -> None:
        try:
            memory = config_manager.get().memory
            if not memory.sync_remember_device and not memory.sync_remember_expires_at:
                return
            config_manager.update(memory=dataclasses.replace(
                memory, sync_remember_device=False, sync_remember_expires_at=""))
        except Exception:  # noqa: BLE001
            logger.warning("could not reset the remember flags", exc_info=True)

    def clear_marker(self) -> None:
        """Delete the marker (sign-out). Writable callers only."""
        if not self._writable:
            return
        try:
            self._marker_path.unlink(missing_ok=True)
        except OSError:
            logger.warning("could not delete the custody marker", exc_info=True)

    def _now_iso(self) -> str:
        return datetime.fromtimestamp(self._clock(), tz=timezone.utc).isoformat()

    def _read_marker(self, user_id: int) -> Optional[CustodyMarker]:
        """The marker for this account, or ``None`` when absent, unreadable or another account's."""
        try:
            data = json.loads(self._marker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        fingerprint = data.get("fingerprint")
        if (
            data.get("user_id") != user_id
            or data.get("custody") not in (CUSTODY_VAULT, CUSTODY_PASSPHRASE)
            or not isinstance(fingerprint, str) or not _FINGERPRINT_RE.match(fingerprint)
        ):
            return None
        return CustodyMarker(
            user_id=user_id, custody=data["custody"], fingerprint=fingerprint,
            public_key=str(data.get("public_key") or ""),
            checked_at=str(data.get("checked_at") or ""),
        )

    def _write_marker(self, marker: CustodyMarker) -> None:
        """Atomic 0600 write of public values; a failure only costs a later lookup."""
        if not self._writable:
            return
        data = {"v": _MARKER_FILE_VERSION, **dataclasses.asdict(marker)}
        try:
            parent = self._marker_path.parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=".custody_", suffix=".tmp")
            try:
                os.chmod(tmp_name, 0o600)
                with os.fdopen(fd, "w") as handle:
                    json.dump(data, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_name, self._marker_path)
            except BaseException:
                Path(tmp_name).unlink(missing_ok=True)
                raise
            os.chmod(self._marker_path, 0o600)
        except OSError as exc:
            logger.warning("could not write the custody marker: %s", exc.__class__.__name__)


def _derive_public(private_key: bytes) -> Optional[bytes]:
    try:
        import nacl.public

        return bytes(nacl.public.PrivateKey(private_key).public_key)
    except Exception:  # noqa: BLE001 — any failure means the key does not verify
        return None

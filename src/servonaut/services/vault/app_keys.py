"""Typed key items that Servonaut features keep in the user's personal vault.

Memory Sync and config sync store their keys as ``memory_key`` and
``config_sync_key`` items.  Other packages go through :class:`AppKeyItems`
instead of the generic item service, so these items are only ever written
with the verified payload shapes and only ever found in the personal vault.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .errors import VaultUserError
from .items import APP_KEY_TYPES, VaultItemService
from .team_vault_client import TeamVaultClient, VaultStateError, _positive_int

PERSONAL_VAULT_NAME = "Personal"
_LIST_PAGE_SIZE = 200


@dataclass(frozen=True)
class AppKeyRef:
    """A live key item: ids and public values only, never key material."""

    item_id: str
    revision: int
    public_fingerprint: str


def _check_type(item_type: str) -> None:
    if item_type not in APP_KEY_TYPES:
        raise ValueError("unsupported Servonaut key item type")


class AppKeyItems:
    """Create, find, read and delete the user's Servonaut key items."""

    def __init__(
        self,
        vaults: TeamVaultClient,
        items: VaultItemService,
        can_create_personal_vault: Callable[[], bool],
    ) -> None:
        self._vaults = vaults
        self._items = items
        self._can_create_personal_vault = can_create_personal_vault

    async def personal_vault_id(self, create: bool = False) -> str | None:
        """The personal vault's id; it is created only when *create* is set and the plan allows it."""
        for vault in await self._vaults.list_vaults():
            if vault.get("kind") == "personal" and vault.get("vault_id"):
                return str(vault["vault_id"])
        if not create or not self._can_create_personal_vault():
            return None
        created = await self._vaults.create_personal(PERSONAL_VAULT_NAME)
        vault_id = created.get("vault_id") if isinstance(created, Mapping) else None
        if not vault_id:
            raise VaultStateError("the personal vault was created without an id")
        return str(vault_id)

    async def list(self, item_type: str) -> list[AppKeyRef]:
        """Live items of *item_type* in the personal vault (empty without one)."""
        _check_type(item_type)
        vault_id = await self.personal_vault_id()
        if vault_id is None:
            return []
        return await self._list_in(vault_id, item_type)

    async def _list_in(self, vault_id: str, item_type: str) -> list[AppKeyRef]:
        refs: list[AppKeyRef] = []
        cursor: str | None = None
        seen: set[str] = set()
        while True:
            page = await self._items.list_items(vault_id, cursor=cursor, limit=_LIST_PAGE_SIZE)
            rows = page.get("data", [])
            if not isinstance(rows, list):
                raise VaultStateError("vault item list has an invalid response shape")
            refs.extend(self._ref(row) for row in rows if self._is_live(row, item_type))
            meta = page.get("meta", {})
            cursor = meta.get("next_cursor") if isinstance(meta, Mapping) else None
            if cursor is None:
                return refs
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise VaultStateError("vault item list cursor is invalid")
            seen.add(cursor)

    @staticmethod
    def _is_live(row: Any, item_type: str) -> bool:
        return (
            isinstance(row, Mapping) and row.get("type") == item_type
            and not row.get("deleted") and not row.get("deleted_at")
        )

    @staticmethod
    def _ref(row: Mapping[str, Any]) -> AppKeyRef:
        fingerprint = row.get("public_fingerprint")
        if not isinstance(fingerprint, str):
            raise VaultStateError("a Servonaut key item has no fingerprint")
        return AppKeyRef(
            item_id=str(row["item_id"]),
            revision=_positive_int(row.get("revision"), "item.revision"),
            public_fingerprint=fingerprint,
        )

    async def read(self, item_type: str, public_fingerprint: str) -> dict[str, Any] | None:
        """The verified payload of the live item with this fingerprint, or None.

        Every read fetches the vault and the item fresh, so a key changed or
        removed on another device is never served from memory.
        """
        _check_type(item_type)
        vault_id = await self.personal_vault_id()
        if vault_id is None:
            return None
        ref = self._find(await self._list_in(vault_id, item_type), public_fingerprint)
        if ref is None:
            return None
        vault = await self._vaults.get_vault(vault_id)
        item = await self._items.get_item(vault_id, ref.item_id)
        if item.get("type") != item_type or item.get("public_fingerprint") != public_fingerprint:
            raise VaultStateError("the vault item does not match the key that was asked for")
        return self._items.read_item(vault, item)

    async def create(self, item_type: str, payload: Mapping[str, Any]) -> AppKeyRef:
        """Store a new key item under a fresh id; the payload is validated before anything is sent."""
        _check_type(item_type)
        vault_id = await self.personal_vault_id(create=True)
        if vault_id is None:
            raise VaultUserError("your account has no personal vault to keep this key in")
        item_id = str(uuid.uuid4())
        written = await self._items.write_item(
            vault_id, item_id, item_type, payload, expected_revision=0, retry_stale_once=False,
        )
        revision = _positive_int(written.get("revision", 1), "item.revision")
        return AppKeyRef(item_id=item_id, revision=revision, public_fingerprint=str(payload["public_fingerprint"]))

    async def delete(self, item_type: str, public_fingerprint: str) -> bool:
        """Delete the live item with this fingerprint; False when there is none.

        The service refuses with ``memory_key_in_use`` or ``config_key_in_use``
        while the key is still needed; that refusal is raised unchanged.
        """
        _check_type(item_type)
        vault_id = await self.personal_vault_id()
        if vault_id is None:
            return False
        ref = self._find(await self._list_in(vault_id, item_type), public_fingerprint)
        if ref is None:
            return False
        await self._items.delete_item(vault_id, ref.item_id, ref.revision)
        return True

    @staticmethod
    def _find(refs: list[AppKeyRef], public_fingerprint: str) -> AppKeyRef | None:
        return next((ref for ref in refs if ref.public_fingerprint == public_fingerprint), None)

"""Read-only ``SecretProviderInterface`` adapter for native vault secrets."""
from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Optional

from servonaut.services.interfaces import SecretProviderInterface, _validate_secret_name

from .items import VaultItemService
from .team_vault_client import TeamVaultClient, VaultStateError


ReferenceLookup = Callable[[str], Mapping[str, str] | None | Awaitable[Mapping[str, str] | None]]


class ReadOnlyVaultProviderError(RuntimeError):
    """Raised for CRUD operations that do not map safely to a vault item."""


class ServonautVaultProvider(SecretProviderInterface):
    """Resolve explicitly configured vault secret references in process memory.

    A native vault's encrypted item names cannot be enumerated by a generic
    secrets backend without downloading and decrypting every item.  Consumers
    therefore provide the binding/config-derived name → ``{vault_id,item_id}``
    lookup.  Values never enter logs, the provider's list output, or MCP.
    """

    def __init__(self, vaults: TeamVaultClient, items: VaultItemService, lookup: ReferenceLookup) -> None:
        self._vaults = vaults
        self._items = items
        self._lookup = lookup

    @property
    def provider_name(self) -> str:
        return "servonaut_vault"

    async def get_secret(self, name: str) -> Optional[str]:
        reference = await self._reference(name)
        if reference is None:
            return None
        vault = await self._vaults.get_vault(reference["vault_id"])
        item = await self._items.get_item(reference["vault_id"], reference["item_id"])
        payload = self._items.read_item(vault, item)
        if item.get("type") != "secret" or not isinstance(payload.get("value"), str):
            raise VaultStateError("vault reference does not resolve to a secret item")
        return payload["value"]

    async def get_ssh_key(self, vault_id: str, item_id: str) -> dict[str, Any]:
        """Return a verified SSH-key payload only to the in-process SSH layer."""
        vault = await self._vaults.get_vault(vault_id)
        item = await self._items.get_item(vault_id, item_id)
        payload = self._items.read_item(vault, item)
        if item.get("type") not in {"ssh_key", "break_glass"}:
            raise VaultStateError("vault reference does not resolve to an SSH key")
        return payload

    async def set_secret(self, name: str, value: str) -> None:
        _validate_secret_name(name)
        if not isinstance(value, str):
            raise TypeError("secret value must be a string")
        raise ReadOnlyVaultProviderError("create a named vault item through the vault service")

    async def delete_secret(self, name: str) -> bool:
        _validate_secret_name(name)
        raise ReadOnlyVaultProviderError("delete vault items through the vault service")

    async def list_secrets(self) -> list[str]:
        """Native vault references are opaque; generic enumeration reveals none."""
        return []

    async def _reference(self, name: str) -> Mapping[str, str] | None:
        name = _validate_secret_name(name)
        result = self._lookup(name)
        if inspect.isawaitable(result):
            result = await result
        if result is None:
            return None
        if not isinstance(result, Mapping) or not isinstance(result.get("vault_id"), str) or not isinstance(result.get("item_id"), str):
            raise VaultStateError("vault secret reference is malformed")
        return result

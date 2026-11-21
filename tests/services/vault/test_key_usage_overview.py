"""The usage overview of a key list: no per-key item or vault reads."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.vault.binding_reads import BindingReadsPaused
from servonaut.services.vault.command_service import VaultCommandService

SERVERS = [{"id": "i-0001", "name": "web-1"}, {"id": "i-0002", "name": "web-2"}]
ID_A = "11111111-1111-4111-8111-111111111111"
ID_B = "22222222-2222-4222-8222-222222222222"
ID_C = "33333333-3333-4333-8333-333333333333"
WITH_USAGE = {"vault_id": "v", "my_role": "owner", "capabilities": ["item_usage"]}
WITHOUT_USAGE = {"vault_id": "v", "kind": "personal", "capabilities": []}


def _row(item_id: str, **extra) -> dict:
    return {"item_id": item_id, "type": "ssh_key", "bound_server_ids": [], **extra}


def _make(vault: dict, answered: list[str] | None = None) -> VaultCommandService:
    service = VaultCommandService.__new__(VaultCommandService)

    async def items_usage(_vault_id, ids):
        keep = ids if answered is None else [i for i in ids if i in answered]
        return {"data": [{"item_id": i.lower(), "team_servers": [],
                          "other_members": {"members": 0, "servers": 0}} for i in keep]}

    service.items = SimpleNamespace(get_item=AsyncMock(), read_item=MagicMock(),
                                    items_usage=AsyncMock(side_effect=items_usage))
    service.vaults = SimpleNamespace(get_vault=AsyncMock(return_value=vault))
    service.personal_binding = AsyncMock(return_value=None)
    service.binding_reads = MagicMock()
    return service


@pytest.mark.asyncio
async def test_with_the_capability_one_request_and_no_per_key_reads() -> None:
    service = _make(WITH_USAGE)
    result = await service.ssh_keys_usage_overview(
        vault_id="v", items=[_row(ID_A), _row(ID_B)], servers=SERVERS)
    assert set(result) == {ID_A, ID_B}
    service.items.items_usage.assert_awaited_once()
    service.items.get_item.assert_not_awaited()
    service.items.read_item.assert_not_called()
    service.vaults.get_vault.assert_awaited_once()
    service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_key_the_service_omits_has_no_entry() -> None:
    service = _make(WITH_USAGE, answered=[ID_A])
    result = await service.ssh_keys_usage_overview(
        vault_id="v", items=[_row(ID_A), _row(ID_B)], servers=SERVERS)
    assert set(result) == {ID_A}


@pytest.mark.asyncio
async def test_an_uppercase_id_is_answered_from_the_lowercase_row() -> None:
    upper = ID_A.upper()
    service = _make(WITH_USAGE)
    result = await service.ssh_keys_usage_overview(vault_id="v", items=[_row(upper)], servers=SERVERS)
    assert set(result) == {upper}


@pytest.mark.asyncio
async def test_without_the_capability_each_server_is_read_once() -> None:
    service = _make(WITHOUT_USAGE)
    rows = [_row(ID_A, bound_server_ids=[{"server_id": "s1", "name": "site-1"}]), _row(ID_B), _row(ID_C)]
    result = await service.ssh_keys_usage_overview(vault_id="v", items=rows, servers=SERVERS)
    assert service.personal_binding.await_count == len(SERVERS)
    service.items.items_usage.assert_not_awaited()
    service.items.get_item.assert_not_awaited()
    assert set(result) == {ID_A, ID_B, ID_C}
    assert result[ID_A]["team_servers"] == ["site-1"] and result[ID_B]["team_servers"] == []


@pytest.mark.asyncio
async def test_a_failed_binding_read_is_unchecked_for_every_key() -> None:
    service = _make(WITHOUT_USAGE)
    service.personal_binding.side_effect = RuntimeError("down")
    result = await service.ssh_keys_usage_overview(
        vault_id="v", items=[_row(ID_A), _row(ID_B)], servers=SERVERS)
    for usage in result.values():
        assert usage["unchecked"] == ["web-1", "web-2"]


@pytest.mark.asyncio
async def test_a_paused_read_raises() -> None:
    service = _make(WITHOUT_USAGE)
    service.personal_binding.side_effect = BindingReadsPaused("paused")
    with pytest.raises(BindingReadsPaused):
        await service.ssh_keys_usage_overview(vault_id="v", items=[_row(ID_A)], servers=SERVERS)


@pytest.mark.asyncio
async def test_empty_items_make_no_request_beyond_the_capability_check() -> None:
    service = _make(WITH_USAGE)
    assert await service.ssh_keys_usage_overview(vault_id="v", items=[], servers=SERVERS) == {}
    service.items.items_usage.assert_not_awaited()
    service.personal_binding.assert_not_awaited()

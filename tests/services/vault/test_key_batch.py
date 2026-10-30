"""Reviewing and deleting several vault SSH keys at once: each server's binding read once per pass."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault.command_service import KeyDeletion, VaultCommandService
from servonaut.services.vault.errors import VaultKeyInUse, VaultUserError, vault_failure_reason

SERVERS = [{"id": f"i-000{n}", "name": f"web-{n}"} for n in range(1, 4)]


def _item(item_id: str, **extra) -> dict:
    return {"item_id": item_id, "type": "ssh_key", "revision": 3, "bound_server_ids": [],
            "public_fingerprint": f"SHA256:{item_id}", **extra}


@pytest.fixture
def service() -> VaultCommandService:
    service = VaultCommandService.__new__(VaultCommandService)
    items = {key: _item(key) for key in ("k1", "k2", "k3")}

    async def get_item(_vault_id, item_id):
        if item_id not in items:
            raise APIError(code="not_found", message="not found", status=404)
        return items[item_id]

    service.items = SimpleNamespace(
        get_item=AsyncMock(side_effect=get_item),
        read_item=MagicMock(side_effect=lambda _vault, item: {"name": f"name-{item['item_id']}"}),
        delete_item=AsyncMock(),
    )
    service.vaults = SimpleNamespace(get_vault=AsyncMock(return_value={"vault_id": "vault"}))
    service.personal_binding = AsyncMock(return_value=None)
    service.list_exposures = AsyncMock(return_value={"data": []})
    service.test_items = items
    return service


@pytest.mark.asyncio
async def test_a_review_reads_each_servers_binding_once_for_every_key(service) -> None:
    # Regression: each key re-read every server's binding (keys x servers
    # signed reads), which could trip the service's rate limit.
    async def binding(row, **_kwargs):
        return {"vault_id": "vault", "vault_item_id": "k2"} if row["id"] == "i-0002" else None

    service.personal_binding.side_effect = binding

    usages = await service.ssh_keys_usage(vault_id="vault", item_ids=["k1", "k2", "k3"], servers=SERVERS)

    assert service.personal_binding.await_count == 3
    assert list(usages) == ["k1", "k2", "k3"]
    assert usages["k1"]["own_servers"] == [] and usages["k1"]["checked"] == 3
    assert usages["k2"]["own_servers"] == ["web-2"]
    assert usages["k3"]["name"] == "name-k3" and usages["k3"]["fingerprint"] == "SHA256:k3"


@pytest.mark.asyncio
async def test_a_review_reports_an_unreadable_key_without_stopping(service) -> None:
    usages = await service.ssh_keys_usage(vault_id="vault", item_ids=["k1", "gone"], servers=SERVERS)

    # A plain reason for the user, never the raw API diagnostic.
    assert usages["gone"] == {"error": vault_failure_reason(APIError(code="not_found", message="not found", status=404))}
    assert usages["k1"]["own_servers"] == []


@pytest.mark.asyncio
async def test_a_delete_pass_reads_bindings_and_exposures_once_and_reports_each_key(service) -> None:
    async def binding(row, **_kwargs):
        return {"vault_id": "vault", "vault_item_id": "k2"} if row["id"] == "i-0002" else None

    service.personal_binding.side_effect = binding
    service.list_exposures.return_value = {"data": [{"item_id": "k3", "status": "open", "resolved_at": None}]}
    progress: list = []

    results = await service.delete_ssh_keys(
        vault_id="vault", item_ids=["k1", "k2", "k3"], servers=SERVERS,
        on_progress=lambda i, total, r: progress.append((i, total, r.item_id, r.deleted)),
    )

    assert service.personal_binding.await_count == 3
    # A deletion reads every binding again: a reused read could miss one made since the review.
    assert all(call.kwargs == {"fresh": True} for call in service.personal_binding.await_args_list)
    assert service.list_exposures.await_count == 1
    assert [r.item_id for r in results] == ["k1", "k2", "k3"]
    assert [r.deleted for r in results] == [True, False, False]
    assert isinstance(results[1].error, VaultKeyInUse)
    assert isinstance(results[2].error, VaultUserError) and "exposures" in str(results[2].error)
    assert progress == [(1, 3, "k1", True), (2, 3, "k2", False), (3, 3, "k3", False)]
    service.items.delete_item.assert_awaited_once_with("vault", "k1", 3)


@pytest.mark.asyncio
async def test_an_unchecked_override_applies_only_to_the_key_and_servers_reviewed(service) -> None:
    service.personal_binding.side_effect = APIError(code="unavailable", message="down", status=503)
    usages = await service.ssh_keys_usage(vault_id="vault", item_ids=["k1", "k2"], servers=SERVERS[:1])
    reviewed = {"k1": usages["k1"]["unchecked_targets"]}

    results = await service.delete_ssh_keys(
        vault_id="vault", item_ids=["k1", "k2"], servers=SERVERS[:1], unchecked_by_key=reviewed,
    )

    assert [r.deleted for r in results] == [True, False]
    assert isinstance(results[1].error, VaultKeyInUse)
    service.items.delete_item.assert_awaited_once_with("vault", "k1", 3)


@pytest.mark.asyncio
async def test_an_override_for_other_servers_is_refused(service) -> None:
    service.personal_binding.side_effect = APIError(code="unavailable", message="down", status=503)

    results = await service.delete_ssh_keys(
        vault_id="vault", item_ids=["k1"], servers=SERVERS[:2],
        unchecked_by_key={"k1": [["aws", "", "i-0001"]]},
    )

    assert results == [KeyDeletion("k1", False, results[0].error)]
    assert isinstance(results[0].error, VaultUserError) and "assignment checks changed" in str(results[0].error)
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_unreadable_exposures_fail_every_key_without_deleting(service) -> None:
    service.list_exposures.side_effect = APIError(code="unavailable", message="down", status=503)

    results = await service.delete_ssh_keys(vault_id="vault", item_ids=["k1", "k2"], servers=[])

    assert [r.deleted for r in results] == [False, False]
    assert all(isinstance(r.error, APIError) for r in results)
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failed_delete_of_one_key_does_not_stop_the_rest(service) -> None:
    service.items.delete_item.side_effect = [APIError(code="conflict", message="stale", status=409), None]

    results = await service.delete_ssh_keys(vault_id="vault", item_ids=["k1", "k2"], servers=[])

    assert [r.deleted for r in results] == [False, True]
    assert isinstance(results[0].error, APIError)

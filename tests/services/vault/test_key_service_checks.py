"""The service-backed usage review and delete of vault SSH keys: which checks the capabilities skip."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault.binding_reads import BindingReadsPaused
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.errors import (
    KEY_ASSIGNMENTS_CHANGED,
    KEY_IN_USE_ON_SERVICE,
    KEY_USAGE_MISSING,
    UNBIND_NOT_AVAILABLE,
    VAULT_UNREADABLE,
    VaultKeyInUse,
    VaultUserError,
)
from servonaut.services.vault.team_vault_client import VaultStateError

SERVERS = [{"id": "i-0001", "name": "web-1"}, {"id": "i-0002", "name": "web-2"}]


def _item(item_id: str, **extra) -> dict:
    return {"item_id": item_id, "type": "ssh_key", "revision": 3, "bound_server_ids": [],
            "public_fingerprint": f"SHA256:{item_id}", **extra}


def _usage(item_id: str, **extra) -> dict:
    return {"item_id": item_id, "team_servers": [], "own_instances": [],
            "other_members": {"members": 0, "servers": 0}, **extra}


def _make(vault: dict | Exception) -> VaultCommandService:
    service = VaultCommandService.__new__(VaultCommandService)
    items: dict[str, dict] = {}

    async def get_item(_vault_id, item_id):
        return items.setdefault(item_id, _item(item_id))

    service.items = SimpleNamespace(
        get_item=AsyncMock(side_effect=get_item),
        read_item=MagicMock(side_effect=lambda _vault, item: {"name": f"name-{item['item_id']}"}),
        delete_item=AsyncMock(),
        items_usage=AsyncMock(side_effect=lambda _v, ids: {"data": [_usage(i) for i in ids], "meta": {}}),
    )
    service.vaults = SimpleNamespace(
        get_vault=AsyncMock(side_effect=vault) if isinstance(vault, Exception) else AsyncMock(return_value=vault),
    )
    service.personal_binding = AsyncMock(return_value=None)
    service.binding_reads = MagicMock()
    service.list_exposures = AsyncMock(return_value={"data": []})
    service.test_items = items
    return service


def _in_use_error(**details) -> APIError:
    return APIError(code="item_in_use", message="in use", status=409, details=_usage("k1", **details))


@pytest.mark.asyncio
async def test_a_vault_with_both_capabilities_never_reads_own_servers() -> None:
    vault = {"vault_id": "v", "my_role": "owner", "capabilities": ["delete_refuses_bound", "item_usage"]}
    service = _make(vault)
    service.binding_reads = SimpleNamespace(paused=True)

    single = await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    many = await service.ssh_keys_usage(vault_id="v", item_ids=["k1", "k2"], servers=SERVERS)
    await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
    results = await service.delete_ssh_keys(vault_id="v", item_ids=["k2"], servers=SERVERS)

    assert single["own_servers"] == [] and set(many) == {"k1", "k2"}
    assert all(r.deleted for r in results)
    service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_refuses_bound_delete_leaves_the_in_use_decision_to_the_service() -> None:
    """The item record does not know other members' servers, so it never refuses on its own."""
    service = _make({"vault_id": "v", "kind": "team", "capabilities": ["delete_refuses_bound"]})
    service.test_items["k1"] = _item("k1", bound_server_ids=[{"server_id": "s1", "name": "site-1"}])
    service.items.delete_item.side_effect = _in_use_error(
        team_servers=[{"server_id": "s1", "name": "site-1"}], other_members={"members": 2, "servers": 4},
    )
    with pytest.raises(VaultKeyInUse) as caught:
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
    service.items.delete_item.assert_awaited_once_with("v", "k1", 3, unbind=False)
    assert caught.value.team_servers == ["site-1"] and caught.value.team_server_ids == ["s1"]
    assert (caught.value.other_members, caught.value.other_servers) == (2, 4)
    service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_refuses_bound_delete_reads_the_item_before_deleting() -> None:
    service = _make({"vault_id": "v", "kind": "team", "capabilities": ["delete_refuses_bound"]})
    order: list[str] = []

    async def get_item(*_args):
        order.append("get")
        return _item("k1")

    async def delete_item(*_args, **_kwargs):
        order.append("delete")

    service.items.get_item.side_effect = get_item
    service.items.delete_item.side_effect = delete_item
    await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
    assert order == ["get", "delete"]


@pytest.mark.asyncio
@pytest.mark.parametrize("caps", [None, "item_usage", ["unknown", 3]])
async def test_missing_or_unusable_capabilities_keep_the_per_server_path(caps) -> None:
    vault = {"vault_id": "v", "kind": "personal", "capabilities": caps}
    service = _make(vault)
    await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    assert service.personal_binding.await_count == 2
    service.items.items_usage.assert_not_awaited()
    assert await service.key_checks_read_own_servers(vault_id="v") is True


@pytest.mark.asyncio
async def test_a_failed_vault_read_falls_back_to_the_per_server_path() -> None:
    service = _make(RuntimeError("down"))
    usage = await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    assert usage["can_unbind"] is False
    assert service.personal_binding.await_count == 2


@pytest.mark.asyncio
async def test_item_usage_single_review_is_one_request_with_names_and_counts() -> None:
    service = _make({"vault_id": "v", "capabilities": ["item_usage"], "my_role": "member"})
    service.items.items_usage.side_effect = None
    service.items.items_usage.return_value = {"data": [_usage(
        "k1", team_servers=[{"server_id": "s1", "name": "site-1"}],
        own_instances=[{"provider": "aws", "instance_id": "i-0001"}, {"provider": "aws", "instance_id": "i-9999"}],
        other_members={"members": 2, "servers": 5},
    )], "meta": {}}

    usage = await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)

    service.items.items_usage.assert_awaited_once_with("v", ["k1"])
    service.personal_binding.assert_not_awaited()
    assert usage["team_servers"] == ["site-1"]
    assert usage["own_servers"] == ["web-1", "aws i-9999"]
    assert usage["other_members"] == {"members": 2, "servers": 5}
    assert usage["can_unbind"] is False


@pytest.mark.asyncio
async def test_item_usage_bulk_review_chunks_at_500() -> None:
    service = _make({"vault_id": "v", "capabilities": ["item_usage"]})
    ids = [f"k{n}" for n in range(1201)]
    usages = await service.ssh_keys_usage(vault_id="v", item_ids=ids, servers=SERVERS)
    assert [len(c.args[1]) for c in service.items.items_usage.await_args_list] == [500, 500, 201]
    assert len(usages) == 1201 and "error" not in usages["k0"]
    service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_item_usage_malformed_or_missing_answers() -> None:
    service = _make({"vault_id": "v", "capabilities": ["item_usage"]})
    service.items.items_usage.side_effect = None
    service.items.items_usage.return_value = {"data": "nope"}
    with pytest.raises(VaultStateError):
        await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    service.items.items_usage.return_value = {"data": [_usage("k1")]}
    usages = await service.ssh_keys_usage(vault_id="v", item_ids=["k1", "k2"], servers=SERVERS)
    assert "error" not in usages["k1"] and usages["k2"] == {"error": KEY_USAGE_MISSING}
    with pytest.raises(VaultUserError, match="no usage"):
        await service.ssh_key_usage(vault_id="v", item_id="k2", servers=SERVERS)


@pytest.mark.asyncio
async def test_refuses_bound_delete_reads_no_bindings_and_maps_a_409() -> None:
    caps = {"vault_id": "v", "capabilities": ["delete_refuses_bound", "item_usage"]}
    for role, expected in (("owner", True), ("admin", True), ("member", False)):
        service = _make({**caps, "my_role": role})
        service.items.delete_item.side_effect = _in_use_error(
            team_servers=[{"server_id": "s1", "name": "site-1"}],
            own_instances=[{"provider": "aws", "instance_id": "i-0002"}],
            other_members={"members": 1, "servers": 2},
        )
        with pytest.raises(VaultKeyInUse) as caught:
            await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
        error = caught.value
        assert error.team_servers == ["site-1"] and error.own_servers == ["web-2"]
        assert (error.other_members, error.other_servers, error.can_unbind) == (1, 2, expected)
        service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("details", [None, ["x"], {"item_id": "k1"}])
async def test_a_409_without_usable_details_gets_a_fixed_message(details) -> None:
    service = _make({"vault_id": "v", "capabilities": ["delete_refuses_bound"]})
    service.items.delete_item.side_effect = APIError(code="item_in_use", message="x", status=409, details=details)
    with pytest.raises(VaultUserError) as caught:
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
    assert str(caught.value) == KEY_IN_USE_ON_SERVICE


@pytest.mark.asyncio
async def test_other_api_errors_propagate() -> None:
    service = _make({"vault_id": "v", "capabilities": ["delete_refuses_bound"]})
    service.items.delete_item.side_effect = APIError(code="stale_revision", message="x", status=409)
    with pytest.raises(APIError):
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)


_BOTH = ["delete_refuses_bound", "item_usage"]
_SHOWN = {
    "team_server_ids": ["s1"], "own_targets": [["aws", "i-0001"]], "other_members": {"members": 1, "servers": 2},
}


def _bound(**details) -> dict:
    return {"data": [_usage("k1", **details)]}


@pytest.mark.asyncio
async def test_unbind_sends_the_flag_and_skips_only_the_in_use_refusal() -> None:
    service = _make({"vault_id": "v", "capabilities": _BOTH, "my_role": "owner"})
    service.items.items_usage = AsyncMock(return_value=_bound(
        team_servers=[{"server_id": "s1", "name": "site-1"}],
        own_instances=[{"provider": "aws", "instance_id": "i-0001"}], other_members={"members": 1, "servers": 2},
    ))
    await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS, unbind=True, confirmed_usage=_SHOWN)
    service.items.delete_item.assert_awaited_once_with("v", "k1", 3, unbind=True)

    service.items.delete_item.reset_mock()
    service.list_exposures.return_value = {"data": [{"item_id": "k1", "status": "open", "resolved_at": None}]}
    with pytest.raises(VaultUserError, match="exposures"):
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS, unbind=True, confirmed_usage=_SHOWN)
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_unbind_without_the_confirmed_usage_is_a_programming_error() -> None:
    service = _make({"vault_id": "v", "capabilities": _BOTH, "my_role": "owner"})
    with pytest.raises(ValueError):
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS, unbind=True)
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh", [
    {"team_servers": [{"server_id": "s9", "name": "site-9"}]},
    {"own_instances": [{"provider": "aws", "instance_id": "i-0002"}]},
    {"other_members": {"members": 1, "servers": 3}},
])
async def test_unbind_refuses_when_the_assignments_changed_since_the_review(fresh) -> None:
    service = _make({"vault_id": "v", "capabilities": _BOTH, "my_role": "owner"})
    service.items.items_usage = AsyncMock(return_value=_bound(**fresh))
    with pytest.raises(VaultUserError) as caught:
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS, unbind=True, confirmed_usage=_SHOWN)
    assert str(caught.value) == KEY_ASSIGNMENTS_CHANGED
    service.items.delete_item.assert_not_awaited()
    service.binding_reads.forget_all.assert_not_called()


@pytest.mark.asyncio
async def test_a_successful_unbind_drops_the_remembered_personal_bindings() -> None:
    service = _make({"vault_id": "v", "capabilities": _BOTH, "my_role": "admin"})
    service.items.items_usage = AsyncMock(return_value=_bound(team_servers=[{"server_id": "s1", "name": "site-1"}]))
    await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS, unbind=True, confirmed_usage=_SHOWN)
    service.binding_reads.forget_all.assert_called_once_with()

    plain = _make({"vault_id": "v", "capabilities": _BOTH, "my_role": "admin"})
    await plain.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
    plain.binding_reads.forget_all.assert_not_called()


@pytest.mark.asyncio
async def test_unbind_needs_the_usage_endpoint_too() -> None:
    """Only the service's usage object knows other members' servers, so only it can build the confirmation."""
    service = _make({"vault_id": "v", "capabilities": ["delete_refuses_bound"], "my_role": "owner"})
    assert (await service._key_checks("v")).can_unbind is False
    with pytest.raises(VaultUserError) as caught:
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS, unbind=True, confirmed_usage=_SHOWN)
    assert str(caught.value) == UNBIND_NOT_AVAILABLE
    usage = await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    assert usage["can_unbind"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("vault", [
    {"vault_id": "v", "my_role": "owner"},
    {"vault_id": "v", "capabilities": ["item_usage"], "my_role": "owner"},
    {"vault_id": "v", "capabilities": _BOTH, "my_role": "member"},
])
async def test_unbind_needs_the_capability_and_an_administrator(vault) -> None:
    service = _make(vault)
    with pytest.raises(VaultUserError) as caught:
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS, unbind=True, confirmed_usage=_SHOWN)
    assert str(caught.value) == UNBIND_NOT_AVAILABLE
    service.items.delete_item.assert_not_awaited()
    service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_personal_vault_with_item_usage_only_checks_through_the_service() -> None:
    service = _make({"vault_id": "v", "capabilities": ["item_usage"]})
    service.items.items_usage.side_effect = None
    service.items.items_usage.return_value = {"data": [_usage("k1", own_instances=[
        {"provider": "aws", "instance_id": "i-0001"}])]}
    with pytest.raises(VaultKeyInUse) as caught:
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
    assert caught.value.own_servers == ["web-1"]
    service.items.items_usage.assert_awaited_once()
    service.personal_binding.assert_not_awaited()
    service.items.delete_item.assert_not_awaited()

    service.items.items_usage.return_value = {"data": [_usage("k1")]}
    results = await service.delete_ssh_keys(vault_id="v", item_ids=["k1"], servers=SERVERS)
    assert results[0].deleted
    service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_bulk_delete_with_refuses_bound_maps_the_service_refusal_per_key() -> None:
    service = _make({"vault_id": "v", "capabilities": ["item_usage", "delete_refuses_bound"], "my_role": "owner"})
    service.items.delete_item.side_effect = [_in_use_error(other_members={"members": 1, "servers": 1}), None]
    results = await service.delete_ssh_keys(vault_id="v", item_ids=["k1", "k2"], servers=SERVERS)
    assert isinstance(results[0].error, VaultKeyInUse) and results[1].deleted
    assert all(c.kwargs == {"unbind": False} for c in service.items.delete_item.await_args_list)
    service.items.items_usage.assert_not_awaited()
    service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_other_members_servers_refuse_a_plain_delete() -> None:
    service = _make({"vault_id": "v", "capabilities": ["item_usage"]})
    service.items.items_usage.side_effect = None
    service.items.items_usage.return_value = {"data": [_usage("k1", other_members={"members": 1, "servers": 3})]}
    with pytest.raises(VaultKeyInUse) as caught:
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
    assert caught.value.other_servers == 3
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("vault, expected", [
    ({}, True),
    ({"kind": "personal", "capabilities": ["delete_refuses_bound"]}, True),
    ({"kind": "personal", "capabilities": ["item_usage"]}, False),
    ({"kind": "team"}, True),
    ({"kind": "team", "capabilities": ["delete_refuses_bound"]}, True),
    ({"kind": "team", "capabilities": ["item_usage"]}, False),
])
async def test_key_checks_read_own_servers_truth_table(vault, expected) -> None:
    service = _make({"vault_id": "v", **vault})
    assert await service.key_checks_read_own_servers(vault_id="v") is expected


@pytest.mark.asyncio
async def test_server_supplied_names_lose_terminal_controls() -> None:
    service = _make({"vault_id": "v", "capabilities": ["item_usage"]})
    service.items.items_usage.side_effect = None
    service.items.items_usage.return_value = {"data": [_usage(
        "k1", team_servers=[{"server_id": "s1", "name": "site\x1b[31m-1‮"}],
        own_instances=[{"provider": "aws\x1b", "instance_id": "i-\x9b9"}],
    )]}
    usage = await service.ssh_key_usage(vault_id="v", item_id="k1", servers=[])
    joined = "".join(usage["team_servers"] + usage["own_servers"])
    assert "\x1b" not in joined and "‮" not in joined and "\x9b" not in joined


@pytest.mark.asyncio
async def test_a_paused_personal_review_still_raises_on_the_old_path() -> None:
    service = _make({"vault_id": "v"})
    service.personal_binding.side_effect = BindingReadsPaused("paused", retry_after=30.0)
    with pytest.raises(BindingReadsPaused):
        await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)


@pytest.mark.asyncio
async def test_refuses_bound_without_item_usage_deletes_after_an_unchecked_review() -> None:
    service = _make({"kind": "personal", "capabilities": ["delete_refuses_bound"], "my_role": "owner"})
    service.personal_binding.side_effect = RuntimeError("down")

    usage = await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    assert usage["unchecked_targets"]
    result = await service.delete_ssh_key(
        vault_id="v", item_id="k1", servers=SERVERS,
        allow_unchecked=True, unchecked_targets=usage["unchecked_targets"],
    )

    assert result["deleted"] is True
    service.items.delete_item.assert_awaited_once()


@pytest.mark.asyncio
async def test_item_usage_rechecks_the_service_at_delete_time() -> None:
    service = _make({"kind": "team", "capabilities": ["item_usage"], "my_role": "owner"})
    service.items.items_usage = AsyncMock(return_value={"data": [_usage(
        "k1", own_instances=[{"provider": "aws", "instance_id": "i-0001"}])]})

    with pytest.raises(VaultKeyInUse):
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)

    service.items.items_usage.assert_awaited_once()
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_team_vault_on_an_old_service_still_reads_own_servers_at_delete() -> None:
    service = _make({"kind": "team", "my_role": "owner"})
    service.personal_binding = AsyncMock(return_value={"vault_id": "v", "vault_item_id": "k1"})

    with pytest.raises(VaultKeyInUse):
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)

    service.personal_binding.assert_awaited()
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_team_vault_on_an_old_service_still_reads_own_servers_when_reviewing() -> None:
    service = _make({"kind": "team"})
    await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    assert service.personal_binding.await_count == 2
    service.items.items_usage.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failed_vault_read_logs_only_the_exception_type(caplog) -> None:
    service = _make(RuntimeError("secret-detail"))
    with caplog.at_level("WARNING"):
        await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert warnings and "RuntimeError" in warnings[0].getMessage()
    assert "secret-detail" not in caplog.text


@pytest.mark.asyncio
async def test_a_service_refusal_on_the_vault_read_is_logged_with_its_status_and_code_only(caplog) -> None:
    service = _make(APIError(code="rate_limited", message="site-1 key-name", status=429))
    with caplog.at_level("WARNING"):
        await service.ssh_key_usage(vault_id="v", item_id="k1", servers=SERVERS)
    assert "HTTP 429" in caplog.text and "rate_limited" in caplog.text
    assert "site-1" not in caplog.text and "key-name" not in caplog.text


@pytest.mark.asyncio
async def test_a_failed_vault_read_on_a_delete_keeps_the_service_refusal() -> None:
    refusal = APIError(code="rate_limited", message="slow down", status=429)
    service = _make(refusal)
    with pytest.raises(APIError) as caught:
        await service.delete_ssh_key(vault_id="v", item_id="k1", servers=SERVERS)
    assert caught.value is refusal
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("unbind", [False, True])
async def test_delete_fails_closed_when_the_vault_cannot_be_read(unbind) -> None:
    service = _make(RuntimeError("down"))
    with pytest.raises(VaultUserError) as caught:
        await service.delete_ssh_key(
            vault_id="v", item_id="k1", servers=SERVERS, unbind=unbind, confirmed_usage=_SHOWN if unbind else None,
        )
    assert str(caught.value) == VAULT_UNREADABLE != UNBIND_NOT_AVAILABLE
    service.items.delete_item.assert_not_awaited()
    service.personal_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_bulk_delete_fails_closed_when_the_vault_cannot_be_read() -> None:
    service = _make(RuntimeError("down"))
    results = await service.delete_ssh_keys(vault_id="v", item_ids=["k1", "k2"], servers=SERVERS)
    assert [r.deleted for r in results] == [False, False]
    assert all(str(r.error) == VAULT_UNREADABLE for r in results)
    service.items.delete_item.assert_not_awaited()

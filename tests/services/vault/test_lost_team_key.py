"""An own server whose remembered team-vault binding lost its right connects as an unbound server would."""
from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.identity_store import IdentityStore

VAULT_ID = "11111111-1111-4111-8111-111111111111"
ITEM_ID = "22222222-2222-4222-8222-222222222222"
INSTANCE = {"id": "i-0abc1234", "name": "web-1", "provider": "aws", "region": "eu-west-1", "public_ip": "198.51.100.7"}
BINDING = {"source": "servonaut_vault", "vault_id": VAULT_ID, "vault_item_id": ITEM_ID}


def _config() -> SimpleNamespace:
    return SimpleNamespace(vault=SimpleNamespace(
        allow_file_key_store=False, request_timeout_seconds=30.0, strict_verification=False,
        auto_grant=True, agent_key_ttl_seconds=60, poll_after_seconds=300,
        approval_poll_initial_seconds=0.01, approval_poll_max_seconds=0.01,
        binding_read_cache_seconds=60.0, binding_read_backoff_seconds=60.0,
    ))


def _refused(status: int) -> APIError:
    return APIError(code="refused", message="refused", status=status)


def _service(tmp_path, fresh_answers):
    """A service whose first binding read answers BINDING and later ones *fresh_answers* (one per read)."""
    store = IdentityStore(
        tmp_path / "vault_keys.json",
        environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    )
    store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    service = VaultCommandService(object(), SimpleNamespace(user_id=1, access_token="token-1"), _config(), store=store)
    service._resolve_ca_ssh = AsyncMock(return_value=None)  # type: ignore[method-assign]
    service.ssh_destination = lambda _instance: ("198.51.100.7", 22)  # type: ignore[method-assign]
    answers = [BINDING, *fresh_answers]
    reads: list[int] = []

    async def get(_provider, _instance_id, _device):
        answer = answers[min(len(reads), len(answers) - 1)]
        reads.append(1)
        if isinstance(answer, Exception):
            raise answer
        return answer

    service._get_personal_binding = get  # type: ignore[method-assign]
    service.vaults.get_vault = AsyncMock(return_value={"vault_id": VAULT_ID, "kind": "team"})  # type: ignore[method-assign]
    service.items.get_item = AsyncMock(return_value={})  # type: ignore[method-assign]
    service.bindings.verify_binding = lambda *_a, **_k: {"host_keys": ["pin"], "login_user": "deploy"}  # type: ignore[method-assign]
    return service, reads


async def _warm(service) -> None:
    assert await service.personal_binding(INSTANCE) == BINDING


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 404])
async def test_a_refused_vault_and_a_gone_binding_connect_without_the_key(tmp_path, caplog, status) -> None:
    service, reads = _service(tmp_path, [None])
    service.vaults.get_vault = AsyncMock(side_effect=_refused(status))  # type: ignore[method-assign]
    await _warm(service)
    caplog.set_level(logging.INFO)

    assert await service.resolve_ssh(INSTANCE) is None

    assert len(reads) == 2
    assert await service.personal_binding(INSTANCE) is None
    assert len(reads) == 2
    assert service.take_lost_team_key(INSTANCE) is True
    assert service.take_lost_team_key(INSTANCE) is False
    records = [r for r in caplog.records if r.name == "servonaut.services.vault.command_service"]
    assert len(records) == 1
    text = records[0].getMessage()
    for private in (INSTANCE["id"], INSTANCE["name"], VAULT_ID, ITEM_ID):
        assert private not in text


@pytest.mark.asyncio
async def test_a_binding_that_is_still_there_keeps_the_refusal(tmp_path) -> None:
    service, _reads = _service(tmp_path, [BINDING])
    service.vaults.get_vault = AsyncMock(side_effect=_refused(404))  # type: ignore[method-assign]
    await _warm(service)

    with pytest.raises(APIError):
        await service.resolve_ssh(INSTANCE)
    assert service.take_lost_team_key(INSTANCE) is False


@pytest.mark.asyncio
async def test_a_failing_re_read_keeps_the_original_refusal(tmp_path) -> None:
    service, _reads = _service(tmp_path, [RuntimeError("down")])
    original = _refused(404)
    service.vaults.get_vault = AsyncMock(side_effect=original)  # type: ignore[method-assign]
    await _warm(service)

    with pytest.raises(APIError) as caught:
        await service.resolve_ssh(INSTANCE)
    assert caught.value is original
    assert service.take_lost_team_key(INSTANCE) is False


@pytest.mark.asyncio
async def test_a_refused_key_of_a_team_vault_falls_back_but_a_personal_vault_raises(tmp_path) -> None:
    service, reads = _service(tmp_path, [None])
    service.items.get_item = AsyncMock(side_effect=_refused(403))  # type: ignore[method-assign]
    await _warm(service)
    assert await service.resolve_ssh(INSTANCE) is None
    assert len(reads) == 2

    service, reads = _service(tmp_path / "personal", [None])
    service.vaults.get_vault = AsyncMock(return_value={"vault_id": VAULT_ID, "kind": "personal"})  # type: ignore[method-assign]
    service.items.get_item = AsyncMock(side_effect=_refused(403))  # type: ignore[method-assign]
    await _warm(service)
    with pytest.raises(APIError):
        await service.resolve_ssh(INSTANCE)
    assert len(reads) == 1


@pytest.mark.asyncio
async def test_other_statuses_raise_without_a_re_read(tmp_path) -> None:
    service, reads = _service(tmp_path, [None])
    service.vaults.get_vault = AsyncMock(side_effect=_refused(500))  # type: ignore[method-assign]
    await _warm(service)

    with pytest.raises(APIError):
        await service.resolve_ssh(INSTANCE)
    assert len(reads) == 1


@pytest.mark.asyncio
async def test_a_shared_row_with_a_native_binding_still_fails_closed(tmp_path) -> None:
    service, reads = _service(tmp_path, [None])
    service.vaults.get_vault = AsyncMock(side_effect=_refused(404))  # type: ignore[method-assign]
    shared = {"id": "shared-1", "name": "web-1", "is_shared": True, "credential_binding": BINDING}

    with pytest.raises(APIError):
        await service.resolve_ssh(shared)
    assert reads == []


@pytest.mark.asyncio
async def test_credential_team_falls_back_when_the_binding_is_gone_and_raises_when_it_is_not(tmp_path) -> None:
    service, _reads = _service(tmp_path, [None])
    service.vaults.get_vault = AsyncMock(side_effect=_refused(404))  # type: ignore[method-assign]
    await _warm(service)
    assert await service.credential_team(INSTANCE) is None

    service, _reads = _service(tmp_path / "still", [BINDING])
    service.vaults.get_vault = AsyncMock(side_effect=_refused(404))  # type: ignore[method-assign]
    await _warm(service)
    with pytest.raises(APIError):
        await service.credential_team(INSTANCE)


@pytest.mark.asyncio
async def test_a_binding_read_since_the_loss_clears_it(tmp_path) -> None:
    # The loss is found by one path (a command, a copy); a new key is bound before the next connect.
    service, _reads = _service(tmp_path, [None, BINDING])
    service.vaults.get_vault = AsyncMock(side_effect=_refused(403))  # type: ignore[method-assign]
    await _warm(service)
    assert await service.resolve_ssh(INSTANCE) is None

    assert await service.personal_binding(INSTANCE, fresh=True) == BINDING

    assert service.take_lost_team_key(INSTANCE) is False


@pytest.mark.asyncio
async def test_binding_a_key_clears_an_earlier_loss(tmp_path) -> None:
    service, _reads = _service(tmp_path, [None])
    service.vaults.get_vault = AsyncMock(side_effect=_refused(404))  # type: ignore[method-assign]
    await _warm(service)
    assert await service.resolve_ssh(INSTANCE) is None
    service.vaults.get_vault = AsyncMock(return_value={"scope": "user:1", "kind": "personal"})  # type: ignore[method-assign]
    service.items.read_item = lambda *_a: {"public_fingerprint": "SHA256:abc"}  # type: ignore[method-assign]
    service.bindings._validate_host_keys = lambda _keys: None  # type: ignore[method-assign]
    service.bindings.build_binding = lambda **kwargs: kwargs  # type: ignore[method-assign]
    service.bindings.put_personal_binding = AsyncMock(return_value={"ok": True})  # type: ignore[method-assign]

    await service.bind_personal(
        vault_id=VAULT_ID, item_id=ITEM_ID, provider="aws", instance_id=INSTANCE["id"],
        hostname="198.51.100.7", port=22, login="deploy", host_keys=["ssh-ed25519 AAAA"],
    )

    assert service.take_lost_team_key(INSTANCE) is False

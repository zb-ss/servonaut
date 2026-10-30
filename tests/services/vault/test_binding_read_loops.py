"""Fleet-wide binding reads through the real vault service: reused, fresh for deletion, stopped by refusals."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault.binding_reads import BindingReadsPaused
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.errors import vault_failure_reason
from servonaut.services.vault.identity_store import IdentityStore

VAULT_ID = "11111111-1111-4111-8111-111111111111"
ITEM_ID = "22222222-2222-4222-8222-222222222222"
# The service reads at most this many bindings at once (command_service._KEY_USAGE_FETCHES).
PARALLEL_READS = 6


def _config() -> SimpleNamespace:
    return SimpleNamespace(vault=SimpleNamespace(
        allow_file_key_store=False, request_timeout_seconds=30.0, strict_verification=False,
        auto_grant=True, agent_key_ttl_seconds=60, poll_after_seconds=300,
        approval_poll_initial_seconds=0.01, approval_poll_max_seconds=0.01,
        binding_read_cache_seconds=60.0, binding_read_backoff_seconds=60.0,
    ))


class _Api:
    """Answers every signed binding GET with *answer* (an exception is raised), counting them."""

    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.gets: list[str] = []

    async def request_signed(self, method: str, path: str, **_kwargs: object) -> object:
        assert method == "GET" and path.endswith("/credential-binding")
        self.gets.append(path)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _service(tmp_path, answer: object) -> tuple[VaultCommandService, _Api]:
    store = IdentityStore(
        tmp_path / "vault_keys.json",
        environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    )
    store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    api = _Api(answer)
    service = VaultCommandService(api, SimpleNamespace(user_id=1, access_token="token-1"), _config(), store=store)
    service._resolve_ca_ssh = AsyncMock(return_value=None)  # type: ignore[method-assign]
    service._ssh_key_record = AsyncMock(return_value={  # type: ignore[method-assign]
        "item_id": ITEM_ID, "type": "ssh_key", "revision": 3, "bound_server_ids": [],
    })
    service._ssh_key_display_name = AsyncMock(return_value="deploy key")  # type: ignore[method-assign]
    service.list_exposures = AsyncMock(return_value={"data": []})  # type: ignore[method-assign]
    service.items.delete_item = AsyncMock()  # type: ignore[method-assign]
    return service, api


def _fleet(count: int) -> list[dict]:
    return [{"id": f"i-{n:04d}", "name": f"web-{n}", "public_ip": "198.51.100.7"} for n in range(count)]


def _not_found() -> APIError:
    return APIError(code="not_found", message="No credential binding for this instance.", status=404)


@pytest.mark.asyncio
async def test_a_second_review_reuses_the_reads_and_a_deletion_reads_again(tmp_path) -> None:
    service, api = _service(tmp_path, _not_found())
    servers = _fleet(5)

    await service.ssh_key_usage(vault_id=VAULT_ID, item_id=ITEM_ID, servers=servers)
    await service.ssh_key_usage(vault_id=VAULT_ID, item_id=ITEM_ID, servers=servers)
    assert len(api.gets) == 5

    assert await service.delete_ssh_key(vault_id=VAULT_ID, item_id=ITEM_ID, servers=servers) == {
        "item_id": ITEM_ID, "deleted": True,
    }
    assert len(api.gets) == 10


@pytest.mark.asyncio
async def test_a_rate_limited_review_stops_at_the_first_refusal(tmp_path) -> None:
    refused = APIError(code="rate_limited", message="opaque", status=429, response_headers={"retry-after": "30"})
    service, api = _service(tmp_path, refused)
    servers = _fleet(20)

    with pytest.raises(BindingReadsPaused) as caught:
        await service.ssh_key_usage(vault_id=VAULT_ID, item_id=ITEM_ID, servers=servers)
    assert "limiting requests" in vault_failure_reason(caught.value)
    assert 1 <= len(api.gets) <= PARALLEL_READS
    sent = len(api.gets)

    # While paused nothing more is sent: not a connection, not a deletion pass.
    with pytest.raises(BindingReadsPaused):
        await service.resolve_ssh(servers[0])
    results = await service.delete_ssh_keys(vault_id=VAULT_ID, item_ids=[ITEM_ID], servers=servers)
    assert [result.deleted for result in results] == [False]
    assert isinstance(results[0].error, BindingReadsPaused)
    assert len(api.gets) == sent
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_refused_sign_in_stops_the_review_and_says_to_sign_in(tmp_path) -> None:
    service, api = _service(tmp_path, APIError(code="unauthorized", message="opaque", status=401))

    with pytest.raises(BindingReadsPaused, match="servonaut login"):
        await service.ssh_keys_usage(vault_id=VAULT_ID, item_ids=[ITEM_ID], servers=_fleet(20))
    assert 1 <= len(api.gets) <= PARALLEL_READS


@pytest.mark.asyncio
async def test_binding_a_server_reads_its_binding_fresh_and_forgets_the_old_answer(tmp_path) -> None:
    service, api = _service(tmp_path, _not_found())
    server = _fleet(1)[0]
    service.vaults.get_vault = AsyncMock(return_value={"scope": "user:1"})  # type: ignore[method-assign]
    service.items.get_item = AsyncMock(return_value={"item_id": ITEM_ID})  # type: ignore[method-assign]
    service.items.read_item = MagicMock(return_value={"public_fingerprint": "SHA256:abc"})  # type: ignore[method-assign]
    service.bindings._validate_host_keys = MagicMock()  # type: ignore[method-assign]
    service.bindings.build_binding = MagicMock(side_effect=lambda **kwargs: kwargs)  # type: ignore[method-assign]
    service.bindings.put_personal_binding = AsyncMock(return_value={"valid": True})  # type: ignore[method-assign]

    assert await service.personal_binding(server) is None
    await service.bind_personal(
        vault_id=VAULT_ID, item_id=ITEM_ID, provider="aws", instance_id=server["id"],
        hostname="198.51.100.7", port=22, login="deploy", host_keys=["ssh-ed25519 AAAA"],
    )
    assert len(api.gets) == 2  # the bind read the binding again before advancing its revision

    api.answer = {"credential_binding": {"source": "servonaut_vault", "vault_item_id": ITEM_ID}}
    assert await service.personal_binding(server) == {"source": "servonaut_vault", "vault_item_id": ITEM_ID}
    assert len(api.gets) == 3

from __future__ import annotations

import asyncio

import datetime as datetime_module
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault.command_service import VaultCommandService, VaultSshLease
from servonaut.services.vault.identity_store import IdentityStore
from servonaut.services.vault.team_vault_client import VaultStateError
from servonaut.utils.validation import ValidationError


def _config(*, auto_grant: bool = True) -> SimpleNamespace:
    return SimpleNamespace(vault=SimpleNamespace(
        allow_file_key_store=False,
        request_timeout_seconds=30.0,
        strict_verification=False,
        auto_grant=auto_grant,
        agent_key_ttl_seconds=60,
        poll_after_seconds=300,
        approval_poll_initial_seconds=0.01,
        approval_poll_max_seconds=0.02,
    ))


class _Api:
    def __init__(self, result: object) -> None:
        self.result = result
        self.called = False

    async def get(self, _path: str, **_kwargs: object) -> dict[str, object]:
        self.called = True
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


def test_closing_one_ca_lease_does_not_delete_shared_cache_or_other_lease_files(tmp_path) -> None:
    cache = tmp_path / "cached.cert.pub"
    cache.write_text("cached certificate\n", encoding="ascii")
    first_certificate = tmp_path / "first.cert.pub"
    second_certificate = tmp_path / "second.cert.pub"
    first_certificate.write_text(cache.read_text(encoding="ascii"), encoding="ascii")
    second_certificate.write_text(cache.read_text(encoding="ascii"), encoding="ascii")
    first_identity, second_identity = tmp_path / "first.pub", tmp_path / "second.pub"
    first_pins, second_pins = tmp_path / "first.known_hosts", tmp_path / "second.known_hosts"
    for path in (first_identity, second_identity, first_pins, second_pins):
        path.write_text("public\n", encoding="ascii")
    first_agent, second_agent = MagicMock(), MagicMock()
    first = VaultSshLease("ca", "/agent-1", str(first_certificate), str(first_pins), "deploy", (), "key", str(first_identity), None, None, None, first_agent)
    second = VaultSshLease("ca", "/agent-2", str(second_certificate), str(second_pins), "deploy", (), "key", str(second_identity), None, None, None, second_agent)

    first.close()

    assert cache.exists()
    assert second_certificate.exists()
    assert second_identity.exists()
    assert second_pins.exists()
    second.close()


@pytest.mark.asyncio
async def test_discover_only_hides_explicit_feature_disable() -> None:
    api = _Api(APIError(code="feature_disabled", message="off", status=503))
    service = VaultCommandService(api, SimpleNamespace(user_id=1), _config())

    assert await service.discover() is False


@pytest.mark.asyncio
async def test_discover_updates_server_poll_interval() -> None:
    api = _Api({"settings": {"poll_after_seconds": 17}})
    service = VaultCommandService(api, SimpleNamespace(user_id=1), _config())

    assert await service.discover() is True
    assert service.poll_interval_seconds == 17


@pytest.mark.asyncio
async def test_auto_grants_are_disabled_without_a_vault_read() -> None:
    api = _Api({})
    service = VaultCommandService(api, SimpleNamespace(user_id=1), _config(auto_grant=False))

    assert await service.process_grants() == []
    assert api.called is False


@pytest.mark.asyncio
async def test_async_confirmation_is_supported() -> None:
    async def confirmation(value: str) -> bool:
        return value == "safety"

    assert await VaultCommandService._confirmed(confirmation, "safety") is True


@pytest.mark.asyncio
async def test_add_device_returns_server_deadline_and_discards_on_bad_registration() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    expiry = (datetime_module.datetime.now(datetime_module.timezone.utc) + datetime_module.timedelta(minutes=5)).isoformat()
    pending = SimpleNamespace(device=SimpleNamespace(device_id="11111111-1111-4111-8111-111111111111"))
    identity = MagicMock()
    identity.begin_pending_device.return_value = pending
    identity.register_pending_device = AsyncMock(return_value={
        "identity": {"identity_id": "11111111-1111-4111-8111-111111111111"},
        "approval": {"state": "pending", "expires_at": expiry},
    })
    service.identity = identity

    result = await service.add_device(device_name="new device", platform="linux")

    assert result["device_id"] == pending.device.device_id
    assert result["expires_at"] == expiry
    identity.discard_pending_device.assert_not_called()

    identity.register_pending_device.return_value = {"identity": {}, "approval": {"expires_at": "not-a-date"}}
    with pytest.raises(Exception, match="expiry"):
        await service.add_device(device_name="new device", platform="linux")
    identity.discard_pending_device.assert_called_once()


@pytest.mark.asyncio
async def test_poll_pending_device_reveals_once_and_returns_safety_number() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    expiry = (datetime_module.datetime.now(datetime_module.timezone.utc) + datetime_module.timedelta(minutes=5)).isoformat()
    identity = MagicMock()
    identity.pending_approval_status = AsyncMock(return_value={"state": "challenged"})
    identity.pending_sas.return_value = "123 456"
    identity.reveal_pending_nonce = AsyncMock(return_value={"state": "revealed"})
    service.identity = identity

    result = await service.poll_pending_device(identity={"public": "identity"}, expires_at=expiry)

    assert result == {"state": "revealed", "safety_number": "123 456"}
    identity.reveal_pending_nonce.assert_awaited_once()


@pytest.mark.asyncio
async def test_setup_identity_exists_race_discards_only_generated_custody(tmp_path) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    store = IdentityStore(path, environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    identity = MagicMock()
    identity.status = AsyncMock(return_value={"identity": None})
    identity.enroll = AsyncMock(side_effect=APIError(
        code="identity_exists", message="already created", status=409,
    ))
    service.identity = identity

    with pytest.raises(RuntimeError, match="add this device"):
        await service.setup(
            device_name="new device", platform="linux", recovery_confirmation=lambda _key: True,
        )

    assert store.identity is None
    assert not path.exists()


def _setup_service(tmp_path, *, status_after_failure):
    path = tmp_path / "vault" / "vault_keys.json"
    store = IdentityStore(path, environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    identity = MagicMock()
    calls = {"n": 0}

    async def status():
        calls["n"] += 1
        if calls["n"] == 1:
            return {"identity": None}  # the setup preflight
        return status_after_failure(store)

    identity.status = status
    identity.enroll = AsyncMock(side_effect=APIError(code="server_error", message="temporary", status=500))
    service.identity = identity
    return service, store, path


@pytest.mark.asyncio
async def test_setup_enrolment_error_retains_custody_the_service_already_holds(tmp_path) -> None:
    service, store, path = _setup_service(
        tmp_path, status_after_failure=lambda store: {"identity": {"identity_id": store.identity.identity_id}},
    )

    with pytest.raises(APIError, match="temporary"):
        await service.setup(device_name="new device", platform="linux", recovery_confirmation=lambda _key: True)

    assert store.identity is not None
    assert path.exists()


@pytest.mark.asyncio
async def test_setup_enrolment_error_retains_custody_when_the_outcome_is_unknown(tmp_path) -> None:
    def unreachable(_store):
        raise APIError(code="server_error", message="down", status=503)

    service, store, path = _setup_service(tmp_path, status_after_failure=unreachable)

    with pytest.raises(APIError, match="temporary"):
        await service.setup(device_name="new device", platform="linux", recovery_confirmation=lambda _key: True)

    assert store.identity is not None
    assert path.exists()


@pytest.mark.asyncio
async def test_setup_enrolment_error_discards_custody_the_service_never_received(tmp_path) -> None:
    service, store, path = _setup_service(tmp_path, status_after_failure=lambda _store: {"identity": None})

    with pytest.raises(APIError, match="temporary"):
        await service.setup(device_name="new device", platform="linux", recovery_confirmation=lambda _key: True)

    assert store.identity is None
    assert not path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [asyncio.CancelledError(), RuntimeError("modal failed")])
async def test_setup_forgets_the_generated_identity_when_confirmation_does_not_finish(tmp_path, failure) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    store = IdentityStore(path, environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    identity = MagicMock()
    identity.status = AsyncMock(return_value={"identity": None})
    identity.enroll = AsyncMock(return_value={"confirmation": {"state": "confirmed"}})
    service.identity = identity

    async def interrupted(_key):
        raise failure

    with pytest.raises(type(failure)):
        await service.setup(device_name="d", platform="linux", recovery_confirmation=interrupted)

    assert store.identity is None
    assert not path.exists()
    # A second attempt is not refused as "already unlocked".
    result = await service.setup(device_name="d", platform="linux", recovery_confirmation=lambda _key: True)
    assert result == {"confirmation": {"state": "confirmed"}}


@pytest.mark.asyncio
async def test_setup_locked_existing_custody_is_never_overwritten_by_identity_race(tmp_path) -> None:
    path = tmp_path / "custom" / "existing-vault.json"
    key = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
    original = IdentityStore(path, environment_key=key)
    prior = original.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    original.save()
    before = path.read_bytes()

    locked = IdentityStore(path, environment_key=key)
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=locked)
    identity = MagicMock()
    identity.status = AsyncMock(return_value={"identity": None})
    identity.enroll = AsyncMock(side_effect=APIError(
        code="identity_exists", message="already created", status=409,
    ))
    service.identity = identity

    with pytest.raises(RuntimeError, match="local vault identity already exists"):
        await service.setup(
            device_name="new device", platform="linux", recovery_confirmation=lambda _key: True,
        )

    assert path.read_bytes() == before
    assert locked.identity is not None and locked.identity.fingerprint == prior.fingerprint
    identity.status.assert_not_awaited()
    identity.enroll.assert_not_awaited()
    reloaded = IdentityStore(path, environment_key=key).load()
    assert reloaded.fingerprint == prior.fingerprint


def test_approval_poll_delay_uses_validated_exponential_config() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    assert service.approval_poll_delay(0) == 0.01
    assert service.approval_poll_delay(1) == 0.02
    assert service.approval_poll_delay(4) == 0.02
    with pytest.raises(ValueError):
        service.approval_poll_delay(True)


@pytest.mark.asyncio
async def test_device_pending_event_rereads_rest_before_notifying() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    received = []

    async def callback(device):
        received.append(dict(device))

    service.identity.list_devices = AsyncMock(return_value=[{
        "device_id": "11111111-1111-4111-8111-111111111111",
        "name": "verified device", "status": "pending",
    }])
    service.set_device_pending_callback(callback)
    await service.handle_event({
        "type": "vault.device_pending",
        "data": {"device_id": "11111111-1111-4111-8111-111111111111", "name": "untrusted"},
    })

    assert received == [{
        "device_id": "11111111-1111-4111-8111-111111111111",
        "name": "verified device", "status": "pending",
    }]
    assert service.drain_device_pending_events() == []


@pytest.mark.asyncio
async def test_device_pending_event_queues_once_without_callback() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    device = {
        "device_id": "11111111-1111-4111-8111-111111111111",
        "name": "verified device", "status": "pending",
    }
    service.identity.list_devices = AsyncMock(return_value=[device])
    event = {"type": "vault.device_pending", "data": {"device_id": device["device_id"]}}

    await service.handle_event(event)
    await service.handle_event(event)

    assert service.drain_device_pending_events() == [device]


@pytest.mark.asyncio
async def test_device_pending_callback_failure_queues_verified_fallback() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    device = {
        "device_id": "11111111-1111-4111-8111-111111111111",
        "name": "verified device", "status": "pending",
    }
    service.identity.list_devices = AsyncMock(return_value=[device])

    def callback(_device):
        raise RuntimeError("screen unavailable")

    service.set_device_pending_callback(callback)
    with pytest.raises(RuntimeError, match="screen unavailable"):
        await service.handle_event({"type": "vault.device_pending", "data": {"device_id": device["device_id"]}})

    assert service.drain_device_pending_events() == [device]


@pytest.mark.asyncio
async def test_reset_poll_preserves_old_custody_until_confirmed(tmp_path) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    key = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
    store = IdentityStore(path, environment_key=key)
    old = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    store.save()
    old_fingerprint = old.fingerprint
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    expiry = (datetime_module.datetime.now(datetime_module.timezone.utc) + datetime_module.timedelta(minutes=5)).isoformat()
    replacement = IdentityStore.generate_identity(identity_id="22222222-2222-4222-8222-222222222222", user_id=1)
    identity = MagicMock()
    identity.request_reset = AsyncMock(return_value={"expires_at": expiry})
    identity.status = AsyncMock(return_value={"pending_reset": {"expires_at": expiry}})
    identity.discard_reset_replacement = MagicMock()
    service.identity = identity
    store.generate_identity = MagicMock(return_value=replacement)

    started = await service.reset_identity(reason="rotate", recovery_confirmation=lambda _key: True)
    pending = await service.poll_reset_identity()

    assert started["expires_at"] == expiry
    assert pending == {"state": "pending_reset", "expires_at": expiry}
    assert store.identity is old
    assert store.load().fingerprint == old.fingerprint

    identity.status.return_value = {"identity": {}}
    identity.finish_confirmed_reset.return_value = replacement
    completed = await service.poll_reset_identity()
    assert completed["state"] == "confirmed"
    identity.finish_confirmed_reset.assert_called_once()


@pytest.mark.asyncio
async def test_reset_poll_failure_discards_replacement_and_preserves_old_custody(tmp_path) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    key = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
    store = IdentityStore(path, environment_key=key)
    old = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    store.save()
    old_fingerprint = old.fingerprint
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    expiry = (datetime_module.datetime.now(datetime_module.timezone.utc) + datetime_module.timedelta(minutes=5)).isoformat()
    replacement = IdentityStore.generate_identity(identity_id="22222222-2222-4222-8222-222222222222", user_id=1)
    identity = MagicMock()
    identity.request_reset = AsyncMock(return_value={"expires_at": expiry})
    identity.status = AsyncMock(side_effect=RuntimeError("reset read failed"))
    identity.discard_reset_replacement = MagicMock()
    service.identity = identity
    store.generate_identity = MagicMock(return_value=replacement)

    await service.reset_identity(reason="rotate", recovery_confirmation=lambda _key: True)
    with pytest.raises(RuntimeError, match="reset read failed"):
        await service.poll_reset_identity()

    identity.discard_reset_replacement.assert_called_once_with(replacement)
    assert service._pending_identity_reset is None
    assert store.load().fingerprint == old.fingerprint


@pytest.mark.asyncio
async def test_reset_close_zeros_pending_replacement_and_preserves_old_custody(tmp_path) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    key = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
    store = IdentityStore(path, environment_key=key)
    old = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    store.save()
    old_fingerprint = old.fingerprint
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    expiry = (datetime_module.datetime.now(datetime_module.timezone.utc) + datetime_module.timedelta(minutes=5)).isoformat()
    service.identity.request_reset = AsyncMock(return_value={"expires_at": expiry})

    await service.reset_identity(reason="rotate", recovery_confirmation=lambda _key: True)
    replacement = service._pending_identity_reset.replacement
    service.close()

    assert service._pending_identity_reset is None
    assert not any(replacement.signing_seed)
    assert not any(replacement.encryption_secret_key)
    assert IdentityStore(path, environment_key=key).load().fingerprint == old_fingerprint


@pytest.mark.asyncio
async def test_reset_declined_confirmation_zeros_unstored_replacement(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    old = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    store.save()
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    replacement = IdentityStore.generate_identity(identity_id="22222222-2222-4222-8222-222222222222", user_id=1)
    store.generate_identity = MagicMock(return_value=replacement)
    service.identity.request_reset = AsyncMock()

    with pytest.raises(RuntimeError, match="recovery key was not confirmed"):
        await service.reset_identity(reason="rotate", recovery_confirmation=lambda _key: False)

    assert not any(replacement.signing_seed)
    service.identity.request_reset.assert_not_awaited()
    assert store.identity is old


def test_unlock_foreign_identity_locks_memory_on_every_attempt(tmp_path) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    key = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
    store = IdentityStore(path, environment_key=key)
    foreign = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=2)
    store.save()
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)

    for _ in range(2):
        with pytest.raises(Exception, match="different account"):
            service.unlock_existing_identity()
        assert store.identity is None

    assert not any(foreign.signing_seed)
    assert IdentityStore(path, environment_key=key).load().user_id == 2


def test_unlock_invalid_account_locks_already_loaded_identity(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    local = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    store.save()
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=True), _config(), store=store)

    for _ in range(2):
        with pytest.raises(Exception, match="account id"):
            service.unlock_existing_identity()
        assert store.identity is None

    assert not any(local.signing_seed)


@pytest.mark.parametrize("expiry", ["not-a-date", "2020-01-01T00:00:00Z", "2026-10-02T00:00:00"])
def test_pending_device_expiry_must_be_future_and_timezone_aware(expiry: str) -> None:
    with pytest.raises(Exception, match="expiry|expired"):
        VaultCommandService._approval_deadline(expiry)


@pytest.mark.asyncio
async def test_personal_binding_is_read_from_signed_canonical_endpoint() -> None:
    class SignedApi(_Api):
        def __init__(self) -> None:
            super().__init__({})
            self.requests: list[tuple[str, str]] = []

        async def request_signed(self, method: str, path: str, **_kwargs: object) -> dict[str, object]:
            self.requests.append((method, path))
            return {"credential_binding": {"source": "servonaut_vault"}}

    api = SignedApi()
    service = VaultCommandService(api, SimpleNamespace(user_id=1), _config())
    service.store.signer = lambda: object()  # type: ignore[method-assign]

    binding, target = await service._credential_binding({"provider": "AWS", "id": "i-abc_123"})

    assert binding == {"source": "servonaut_vault"}
    assert target == "instance:aws:i-abc_123"
    assert api.requests == [("GET", "/api/v1/me/instances/aws/i-abc_123/credential-binding")]


@pytest.mark.asyncio
async def test_unconfigured_ssh_returns_to_legacy_tiers_when_vault_is_locked(tmp_path) -> None:
    store = IdentityStore(
        tmp_path / "vault_keys.json",
        environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    )
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    service._resolve_ca_ssh = AsyncMock(return_value=None)  # type: ignore[method-assign]

    lease = await service.resolve_ssh({
        "provider": "aws", "id": "i-abc_123", "public_ip": "192.0.2.10",
    })

    assert lease is None
    service._resolve_ca_ssh.assert_not_awaited()


@pytest.mark.asyncio
async def test_explicit_native_binding_stays_fail_closed_when_vault_is_locked(tmp_path) -> None:
    store = IdentityStore(
        tmp_path / "vault_keys.json",
        environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    )
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    service._resolve_ca_ssh = AsyncMock(return_value=None)  # type: ignore[method-assign]

    with pytest.raises(VaultStateError, match="requires an unlocked"):
        await service.resolve_ssh({
            "provider": "aws", "id": "i-abc_123", "public_ip": "192.0.2.10",
            "credential_binding": {"source": "servonaut_vault"},
        })

    service._resolve_ca_ssh.assert_not_awaited()


@pytest.mark.asyncio
async def test_unbound_custom_ssh_returns_to_local_resolution_when_vault_is_unlocked(tmp_path) -> None:
    store = IdentityStore(
        tmp_path / "vault_keys.json",
        environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    )
    store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    service._resolve_ca_ssh = AsyncMock(return_value=None)  # type: ignore[method-assign]
    service._credential_binding = AsyncMock()  # type: ignore[method-assign]

    lease = await service.resolve_ssh({
        "provider": "colo", "id": "web-1", "is_custom": True,
        "public_ip": "192.0.2.10",
    })

    assert lease is None
    service._resolve_ca_ssh.assert_not_awaited()
    service._credential_binding.assert_not_awaited()


@pytest.mark.asyncio
async def test_explicit_native_custom_binding_remains_fail_closed_when_unlocked(tmp_path) -> None:
    store = IdentityStore(
        tmp_path / "vault_keys.json",
        environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    )
    store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    service._resolve_ca_ssh = AsyncMock(return_value=None)  # type: ignore[method-assign]

    with pytest.raises(ValidationError, match="Unknown provider"):
        await service.resolve_ssh({
            "provider": "colo", "id": "web-1", "is_custom": True,
            "public_ip": "192.0.2.10",
            "credential_binding": {"source": "servonaut_vault"},
        })

    service._resolve_ca_ssh.assert_awaited_once()


@pytest.mark.asyncio
async def test_native_provider_uses_cached_references_before_vault_scan() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    vault_id = "11111111-1111-1111-1111-111111111111"
    item_id = "22222222-2222-2222-2222-222222222222"

    service.cache_secret_reference("deploy_token", {"vault_id": vault_id, "item_id": item_id})

    assert await service._secret_reference("deploy_token") == {"vault_id": vault_id, "item_id": item_id}


@pytest.mark.asyncio
async def test_ssh_rotation_proves_all_hosts_before_removing_old_key() -> None:
    vault_id = "11111111-1111-1111-1111-111111111111"
    item_id = "22222222-2222-2222-2222-222222222222"
    old_public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJpbmRpbmdUZXN0S2V5MTIzNDU2Nzg5MDE="
    old_fingerprint = "SHA256:old"
    calls: list[str] = []

    class Lease:
        def close(self) -> None:
            calls.append("close")

    class Executor:
        proof_ok = True

        async def append_authorized_key(self, _login: str, _key: str) -> None:
            calls.append("append")

        async def verify_new_key(self, _login: str, _key: bytes) -> bool:
            calls.append("verify")
            return self.proof_ok

        async def remove_authorized_key(self, _login: str, key: str) -> None:
            calls.append("remove-old" if key == old_public else "remove-new")

    class Vaults:
        async def get_vault(self, _vault_id: str) -> dict[str, object]:
            return {"vault_id": vault_id, "scope": "team:example"}

    class Items:
        fail_write = False
        last_payload: dict[str, object] | None = None

        async def get_item(self, _vault_id: str, _item_id: str) -> dict[str, object]:
            return {"type": "ssh_key", "revision": 1}

        def read_item(self, _vault: object, _item: object) -> dict[str, object]:
            return {"name": "deploy", "notes": "", "public_key": old_public,
                    "public_fingerprint": old_fingerprint, "private_key_openssh": "old"}

        async def write_item(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            calls.append("write")
            if self.fail_write:
                raise RuntimeError("write failed")
            self.last_payload = dict(_args[3])
            return {"revision": 2}

    class Bindings:
        fail_put = False

        def verify_binding(self, binding: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
            return binding

        def build_binding(self, **kwargs: object) -> dict[str, object]:
            return dict(kwargs)

        async def put_team_binding(self, *_args: object) -> dict[str, object]:
            calls.append("rebind")
            if self.fail_put:
                raise RuntimeError("binding failed")
            return {"ok": True}

    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    service.vaults = Vaults()  # type: ignore[assignment]
    items = Items()
    service.items = items  # type: ignore[assignment]
    bindings = Bindings()
    service.bindings = bindings  # type: ignore[assignment]
    binding = {"vault_id": vault_id, "vault_item_id": item_id, "public_fingerprint": old_fingerprint,
               "login_user": "deploy", "host_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJpbmRpbmdUZXN0S2V5MTIzNDU2Nzg5MDE="],
               "binding_revision": 1}

    async def shared(_team: str, _server: str) -> dict[str, object]:
        return {"id": "server-1", "hostname": "host", "port": 22, "credential_binding": binding}

    async def lease(_instance: object) -> Lease:
        return Lease()

    service._shared_server = shared  # type: ignore[method-assign]
    service.resolve_ssh = lease  # type: ignore[method-assign]
    service._remote_executor = lambda *_args: Executor()  # type: ignore[method-assign]
    service._new_ed25519_private_key = lambda: b"-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid"  # type: ignore[method-assign]
    service._public_key_from_private = lambda *_args: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE5ld0tleTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="  # type: ignore[method-assign]
    import servonaut.services.vault.command_service as module
    old_fingerprint_fn = module.crypto.ssh_public_fingerprint
    module.crypto.ssh_public_fingerprint = lambda key: old_fingerprint if key == old_public else "SHA256:new"  # type: ignore[assignment]
    try:
        result = await service.rotate_ssh_key(vault_id=vault_id, item_id=item_id, team="example", servers=["server-1"])
    finally:
        module.crypto.ssh_public_fingerprint = old_fingerprint_fn  # type: ignore[assignment]

    assert result["rotated"] is True, result
    assert calls.index("verify") < calls.index("write") < calls.index("rebind") < calls.index("remove-old")

    calls.clear()
    items.fail_write = True
    old_fingerprint_fn = module.crypto.ssh_public_fingerprint
    module.crypto.ssh_public_fingerprint = lambda key: old_fingerprint if key == old_public else "SHA256:new"  # type: ignore[assignment]
    try:
        failed = await service.rotate_ssh_key(vault_id=vault_id, item_id=item_id, team="example", servers=["server-1"])
    finally:
        module.crypto.ssh_public_fingerprint = old_fingerprint_fn  # type: ignore[assignment]

    assert failed["rotated"] is False
    assert "append" in calls and "verify" in calls and "write" in calls
    assert "remove-old" not in calls

    calls.clear()
    items.fail_write = False
    bindings.fail_put = True
    old_fingerprint_fn = module.crypto.ssh_public_fingerprint
    module.crypto.ssh_public_fingerprint = lambda key: old_fingerprint if key == old_public else "SHA256:new"  # type: ignore[assignment]
    try:
        failed_binding = await service.rotate_ssh_key(vault_id=vault_id, item_id=item_id, team="example", servers=["server-1"])
    finally:
        module.crypto.ssh_public_fingerprint = old_fingerprint_fn  # type: ignore[assignment]

    assert failed_binding["rotated"] is False
    assert "write" in calls and "rebind" in calls
    assert "remove-old" not in calls
    assert items.last_payload is not None
    assert items.last_payload["public_fingerprint"] == "SHA256:new"

    # A host whose new-key proof fails gets its appended key removed and its
    # lease closed, even though it never joined the prepared set.
    calls.clear()
    bindings.fail_put = False
    Executor.proof_ok = False
    old_fingerprint_fn = module.crypto.ssh_public_fingerprint
    module.crypto.ssh_public_fingerprint = lambda key: old_fingerprint if key == old_public else "SHA256:new"  # type: ignore[assignment]
    try:
        failed_proof = await service.rotate_ssh_key(vault_id=vault_id, item_id=item_id, team="example", servers=["server-1"])
    finally:
        module.crypto.ssh_public_fingerprint = old_fingerprint_fn  # type: ignore[assignment]

    assert failed_proof["rotated"] is False
    assert calls == ["append", "verify", "remove-new", "close"]


def test_native_known_hosts_requires_private_real_directory_and_formats_port(tmp_path) -> None:
    service = object.__new__(VaultCommandService)
    directory = tmp_path / "known-hosts"
    service._vault_known_hosts_directory = lambda: directory  # type: ignore[method-assign]

    path = service._write_known_hosts("server.example.test", ["ssh-ed25519 AAAA"], port=2222)

    assert path.read_text(encoding="ascii") == "[server.example.test]:2222 ssh-ed25519 AAAA\n"
    assert path.stat().st_mode & 0o777 == 0o600

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "linked-known-hosts"
    link.symlink_to(target, target_is_directory=True)
    service._vault_known_hosts_directory = lambda: link  # type: ignore[method-assign]
    with pytest.raises(Exception, match="real directory"):
        service._write_known_hosts("server.example.test", ["ssh-ed25519 AAAA"])

    insecure = tmp_path / "insecure-known-hosts"
    insecure.mkdir(mode=0o755)
    service._vault_known_hosts_directory = lambda: insecure  # type: ignore[method-assign]
    with pytest.raises(Exception, match="unsafe ownership or permissions"):
        service._write_known_hosts("server.example.test", ["ssh-ed25519 AAAA"])


@pytest.mark.asyncio
async def test_escrow_confirmation_happens_before_any_registration_request() -> None:
    calls: list[str] = []

    class Vaults:
        async def get_vault(self, _vault_id: str) -> dict[str, object]:
            calls.append("get")
            return {}

        async def _signed(self, *_args: object) -> dict[str, object]:
            calls.append("post")
            return {}

    service = object.__new__(VaultCommandService)
    service.vaults = Vaults()
    service.store = SimpleNamespace(identity=SimpleNamespace(identity_id="identity"))

    with pytest.raises(RuntimeError, match="not confirmed"):
        await service.setup_escrow(
            vault_id="11111111-1111-4111-8111-111111111111", label="offline",
            recovery_confirmation=lambda _key: False,
        )

    assert calls == ["get"]


@pytest.mark.asyncio
async def test_personal_binding_uses_canonical_target_and_advances_verified_revision() -> None:
    vault_id = "11111111-1111-4111-8111-111111111111"
    item_id = "22222222-2222-4222-8222-222222222222"
    captured: dict[str, object] = {}

    class Vaults:
        async def get_vault(self, _vault_id: str) -> dict[str, object]:
            return {"scope": "user:1"}

    class Items:
        async def get_item(self, _vault_id: str, _item_id: str) -> dict[str, object]:
            return {"type": "ssh_key"}

        def read_item(self, _vault: object, _item: object) -> dict[str, object]:
            return {"public_fingerprint": "SHA256:fixture"}

    class Bindings:
        @staticmethod
        def _validate_host_keys(keys):
            assert keys == ["ssh-ed25519 AAAA"]

        @staticmethod
        def verify_binding(binding, _vault, **kwargs):
            assert kwargs["target"] == "instance:aws:i-abc"
            return binding

        @staticmethod
        def build_binding(**kwargs):
            captured["binding"] = kwargs
            return kwargs

        async def put_personal_binding(self, provider, instance_id, binding):
            captured.update(provider=provider, instance_id=instance_id, sent=binding)
            return {"valid": True}

    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    service.vaults = Vaults()  # type: ignore[assignment]
    service.items = Items()  # type: ignore[assignment]
    service.bindings = Bindings()  # type: ignore[assignment]

    async def existing(_instance):
        return ({"binding_revision": 4}, "instance:aws:i-abc")

    service._credential_binding = existing  # type: ignore[method-assign]
    result = await service.bind_personal(
        vault_id=vault_id, item_id=item_id, provider="AWS", instance_id="i-abc",
        hostname="server.example.test", port=2222, login="deploy", host_keys=["ssh-ed25519 AAAA"],
    )

    assert result == {"valid": True}
    assert captured["provider"] == "aws"
    assert captured["instance_id"] == "i-abc"
    assert captured["binding"]["target"] == "instance:aws:i-abc"
    assert captured["binding"]["binding_revision"] == 5


@pytest.mark.asyncio
async def test_personal_binding_rejects_missing_host_pins() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())

    with pytest.raises(ValueError, match="host pins"):
        await service.bind_personal(
            vault_id="11111111-1111-4111-8111-111111111111",
            item_id="22222222-2222-4222-8222-222222222222",
            provider="aws", instance_id="i-abc", hostname="server.example.test",
            port=22, login="deploy", host_keys=[],
        )


@pytest.mark.asyncio
async def test_imported_bitwarden_ref_is_cleared_only_after_native_proof() -> None:
    calls: list[str] = []

    class Teams:
        async def get_team_server_ssh_ref(self, _team, _server):
            calls.append("read-legacy")
            return {"ssh_credential_provider": "bitwarden_pm", "ssh_credential_ref": {"item_id": "bw-item"}}

        async def delete_team_server_ssh_ref(self, _team, _server):
            calls.append("clear-legacy")
            return True

    class Lease:
        source = "vault"

        def close(self):
            calls.append("close")

    class Executor:
        async def run(self, argv):
            assert argv == ("true",)
            calls.append("prove")
            return SimpleNamespace(returncode=0)

    service = object.__new__(VaultCommandService)
    service.teams = Teams()

    async def shared(_team, _server):
        return {"id": "server-1", "hostname": "server.example.test", "port": 22}

    async def bind(**_kwargs):
        calls.append("bind")
        return {"source": "servonaut_vault"}

    async def resolve(_instance):
        calls.append("resolve")
        return Lease()

    service._shared_server = shared  # type: ignore[method-assign]
    service.bind = bind  # type: ignore[method-assign]
    service.resolve_ssh = resolve  # type: ignore[method-assign]
    service._remote_executor = lambda *_args: Executor()  # type: ignore[method-assign]

    result = await service.bind_imported_bitwarden_ref(
        vault_id="11111111-1111-4111-8111-111111111111",
        item_id="22222222-2222-4222-8222-222222222222", team="example", server_id="server-1",
        source_ref="bw-item", clear_legacy=True,
    )

    assert result == {"bound": True, "verified": True, "legacy_cleared": True}
    assert calls.index("bind") < calls.index("prove") < calls.index("clear-legacy")


@pytest.mark.asyncio
async def test_imported_bitwarden_ref_failed_native_proof_keeps_legacy_ref() -> None:
    calls: list[str] = []

    class Teams:
        async def get_team_server_ssh_ref(self, _team, _server):
            return {"ssh_credential_provider": "bitwarden_pm", "ssh_credential_ref": {"item_id": "bw-item"}}

        async def delete_team_server_ssh_ref(self, _team, _server):
            calls.append("clear-legacy")
            return True

    class Lease:
        source = "vault"

        def close(self):
            calls.append("close")

    class Executor:
        async def run(self, _argv):
            calls.append("prove")
            return SimpleNamespace(returncode=1)

    async def shared(*_args):
        return {"id": "server-1"}

    async def bind(**_kwargs):
        return {"source": "servonaut_vault"}

    async def resolve(_instance):
        return Lease()

    service = object.__new__(VaultCommandService)
    service.teams = Teams()
    service._shared_server = shared  # type: ignore[method-assign]
    service.bind = bind  # type: ignore[method-assign]
    service.resolve_ssh = resolve  # type: ignore[method-assign]
    service._remote_executor = lambda *_args: Executor()  # type: ignore[method-assign]

    result = await service.bind_imported_bitwarden_ref(
        vault_id="11111111-1111-4111-8111-111111111111",
        item_id="22222222-2222-4222-8222-222222222222", team="example", server_id="server-1",
        source_ref="bw-item", clear_legacy=True,
    )

    assert result["verified"] is False
    assert result["legacy_cleared"] is False
    assert "clear-legacy" not in calls


class _ApprovalServer:
    """Signed device-approval routes returning the real server's payload shapes.

    The approver-side read never includes ``approver_nonce``: the approving
    device keeps its own nonce, and only the pending device is told it.
    """

    def __init__(self, pending, user_id: int) -> None:
        from servonaut.services.vault.crypto import device_registration_message, sign

        self.pending = pending
        self.device_id = pending.device.device_id
        self.registration = sign(bytes(pending.device.signing_seed), device_registration_message(
            self.device_id, user_id, pending.device.signing_public_key,
            pending.device.encryption_public_key, pending.commitment,
        ))
        self.approver_nonce: bytes | None = None
        self.calls: list[tuple[str, str, object]] = []

    @staticmethod
    def _b64(raw: bytes) -> str:
        import base64

        return base64.b64encode(raw).decode()

    def _approval_for_approver(self) -> dict[str, object]:
        revealed = self.approver_nonce is not None
        return {
            "state": "revealed" if revealed else "pending",
            "device": {
                "device_id": self.device_id,
                "device_sig_public_key": self._b64(self.pending.device.signing_public_key),
                "device_enc_public_key": self._b64(self.pending.device.encryption_public_key),
            },
            "commitment": self._b64(self.pending.commitment),
            "registration_signature": self._b64(self.registration),
            "device_nonce": self._b64(bytes(self.pending.device_nonce)) if revealed else None,
        }

    async def request_signed(self, method: str, path: str, **kwargs: object) -> dict[str, object]:
        import base64

        body = kwargs.get("json")
        self.calls.append((method, path, body))
        base = f"/api/v1/vault/devices/{self.device_id}"
        if (method, path) == ("GET", f"{base}/approval"):
            return self._approval_for_approver()
        if (method, path) == ("POST", f"{base}/approval/challenge"):
            assert isinstance(body, dict)
            self.approver_nonce = base64.b64decode(body["approver_nonce"])
            return {"state": "challenged"}
        if (method, path) == ("POST", f"{base}/approve"):
            return {"state": "approved"}
        if (method, path) == ("POST", f"{base}/reject"):
            return {"state": "rejected"}
        raise AssertionError(f"unexpected request {method} {path}")


def _approval_pair(tmp_path):
    import base64

    from servonaut.services.vault.crypto import self_signature
    from servonaut.services.vault.identity_client import IdentityClient

    key = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
    store = IdentityStore(tmp_path / "approver.json", environment_key=key)
    approver = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=7)
    pending_client = IdentityClient(None, IdentityStore(tmp_path / "pending.json", environment_key=key), timeout=1)  # type: ignore[arg-type]
    pending = pending_client.begin_pending_device()
    server = _ApprovalServer(pending, user_id=7)
    service = VaultCommandService(server, SimpleNamespace(user_id=7), _config(), store=store)
    public_identity = {
        "identity_id": approver.identity_id, "user_id": approver.user_id,
        "fingerprint": approver.fingerprint,
        "sig_public_key": base64.b64encode(approver.signing_public_key).decode(),
        "enc_public_key": base64.b64encode(approver.encryption_public_key).decode(),
        "self_signature": base64.b64encode(self_signature(
            bytes(approver.signing_seed), approver.identity_id, approver.user_id,
            approver.signing_public_key, approver.encryption_public_key,
        )).decode(),
    }

    def pending_side_sas() -> str:
        # What the new device shows: the server tells IT the approver nonce.
        assert server.approver_nonce is not None
        return pending_client.pending_sas(
            {"approver_nonce": base64.b64encode(server.approver_nonce).decode()}, identity=public_identity,
        )

    return service, server, pending_side_sas


@pytest.mark.asyncio
async def test_approve_device_matches_pending_sas_without_server_echo_of_approver_nonce(tmp_path) -> None:
    service, server, pending_side_sas = _approval_pair(tmp_path)
    shown: list[str] = []

    def confirm(safety_number: str) -> bool:
        shown.append(safety_number)
        return safety_number == pending_side_sas()

    result = await service.approve_device(device_id=server.device_id, confirmation=confirm)

    assert result == {"state": "approved"}
    assert shown and shown[0] == pending_side_sas()
    paths = [path for _method, path, _body in server.calls]
    assert paths[-1].endswith("/approve")
    assert not any(path.endswith("/reject") for path in paths)


@pytest.mark.asyncio
async def test_approve_device_declined_safety_number_rejects_as_mismatch(tmp_path) -> None:
    service, server, _pending_side_sas = _approval_pair(tmp_path)

    with pytest.raises(RuntimeError, match="not confirmed"):
        await service.approve_device(device_id=server.device_id, confirmation=lambda _value: False)

    method, path, body = server.calls[-1]
    assert (method, path.rsplit("/", 1)[-1]) == ("POST", "reject")
    assert body == {"reason": "sas_mismatch"} or (isinstance(body, dict) and body.get("reason") == "sas_mismatch")
    assert not any(call_path.endswith("/approve") for _m, call_path, _b in server.calls)


def _bind_service(monkeypatch, trusted: list[str]) -> VaultCommandService:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    service.bindings = MagicMock()
    monkeypatch.setattr(
        "servonaut.services.vault.command_service.trusted_host_keys", lambda *_args: list(trusted),
    )
    return service


_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk"


def test_first_team_binding_pins_explicit_host_keys_over_trusted_ones(monkeypatch) -> None:
    service = _bind_service(monkeypatch, trusted=["ssh-rsa AAAA"])

    pins, revision = service._binding_pins({"id": "s1"}, {}, "127.0.0.1", 2222, False, (_HOST_KEY,))

    assert pins == (_HOST_KEY,) and revision == 1


def test_first_team_binding_falls_back_to_locally_trusted_host_keys(monkeypatch) -> None:
    service = _bind_service(monkeypatch, trusted=[_HOST_KEY])

    pins, _revision = service._binding_pins({"id": "s1"}, {}, "127.0.0.1", 2222, True)

    assert pins == (_HOST_KEY,)


def test_first_team_binding_without_any_trusted_key_says_what_to_do(monkeypatch) -> None:
    from servonaut.services.vault.errors import VaultUserError

    service = _bind_service(monkeypatch, trusted=[])

    with pytest.raises(VaultUserError, match="servonaut ssh.*--host-key"):
        service._binding_pins({"id": "s1"}, {}, "127.0.0.1", 2222, True)
    with pytest.raises(ValueError, match="--pin-host-key or --host-key"):
        service._binding_pins({"id": "s1"}, {}, "127.0.0.1", 2222, False)


@pytest.mark.asyncio
async def test_claimed_enrollment_that_fails_is_reported_so_the_job_closes() -> None:
    from servonaut.services.vault.ca_enrollment import EnrollmentError

    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    client = MagicMock()
    client.get_status = AsyncMock(return_value=SimpleNamespace(host_ca_public_key="ssh-ed25519 AAAA"))
    client.create_enrollment = AsyncMock(return_value={"enrollment_id": "job-1"})
    params = {"server": {"hostname": "web-1.example.com"}}
    client.get_enrollment = AsyncMock(return_value={"params": params})
    client.claim_enrollment = AsyncMock(return_value={"params": params})
    client.report_enrollment_result = AsyncMock(return_value={"status": "failed"})
    service._ca = lambda _team: client  # type: ignore[method-assign]
    service._shared_server = AsyncMock(return_value={"id": "server-1", "hostname": "web-1.example.com"})  # type: ignore[method-assign]
    service._validate_enrollment_ca_keys = lambda *_args: None  # type: ignore[method-assign]

    def broken_executor(*_args):
        raise EnrollmentError("A safe existing known_hosts file is required for host enrollment")

    service._remote_executor = broken_executor  # type: ignore[method-assign]

    with pytest.raises(EnrollmentError):
        await service.ca_enroll(
            team="team-a", server="server-1", break_glass_item_id=None,
            confirmation=lambda summary: summary["hostname"],
        )

    job_id, report = client.report_enrollment_result.await_args.args
    assert job_id == "job-1"
    assert report["status"] == "failed"
    assert "known_hosts" in report["error_code"]



@pytest.mark.asyncio
async def test_ca_tier_is_skipped_for_a_shared_server_that_is_not_enrolled() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    client = MagicMock()
    client.get_status = AsyncMock(side_effect=AssertionError("must not ask the CA for an unenrolled host"))
    service._ca = lambda _team: client  # type: ignore[method-assign]
    row = {"id": "server-1", "is_shared": True, "team_slug": "team-a", "hostname": "web-1.example.com"}

    assert await service._resolve_ca_ssh({**row, "ssh_ca": None}) is None
    assert await service._resolve_ca_ssh({**row, "ssh_ca": {"enrolled": False, "status": "enrolling"}}) is None
    client.get_status.assert_not_called()


@pytest.mark.asyncio
async def test_break_glass_import_stores_root_login_and_normalised_source_networks(tmp_path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    from servonaut.services.vault.errors import VaultUserError

    key_path = tmp_path / "break_glass"
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    service.items = MagicMock()
    service.items.write_item = AsyncMock(return_value={"revision": 1})

    result = await service.import_keys(
        source="ssh", vault_id="11111111-1111-4111-8111-111111111111", path=str(key_path),
        break_glass_from_cidrs=["10.0.0.7/8", "10.0.0.0/8", "2001:db8::/32"],
    )

    _vault, _item, item_type, payload = service.items.write_item.await_args.args
    assert item_type == "break_glass" and result["type"] == "break_glass"
    assert payload["logins"] == ["root"]
    assert payload["from_cidrs"] == ["10.0.0.0/8", "2001:db8::/32"]
    with pytest.raises(VaultUserError, match="not a valid CIDR"):
        await service.import_keys(source="ssh", vault_id="11111111-1111-4111-8111-111111111111",
                                  path=str(key_path), break_glass_from_cidrs=["not-a-network"])
    with pytest.raises(VaultUserError, match="at least one"):
        await service.import_keys(source="ssh", vault_id="11111111-1111-4111-8111-111111111111",
                                  path=str(key_path), break_glass_from_cidrs=[])


def _break_glass_service(item_payload: dict, *, item_type: str = "break_glass") -> VaultCommandService:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    service.vaults = MagicMock()
    service.vaults.list_vaults = AsyncMock(return_value=[
        {"vault_id": "v-other", "kind": "team", "team": {"slug": "other-team"}},
        {"vault_id": "v-team", "kind": "team", "team": {"slug": "team-a"}},
    ])
    service.vaults.get_vault = AsyncMock(return_value={"vault_id": "v-team"})
    service.items = MagicMock()
    service.items.get_item = AsyncMock(return_value={"type": item_type})
    service.items.read_item = MagicMock(return_value=item_payload)
    return service


_BG_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk"


@pytest.mark.asyncio
async def test_enrollment_fills_break_glass_details_from_the_decrypted_item() -> None:
    from servonaut.services.vault import crypto as vault_crypto

    fingerprint = vault_crypto.ssh_public_fingerprint(_BG_KEY)
    service = _break_glass_service({
        "public_key": _BG_KEY + " emergency", "public_fingerprint": fingerprint,
        "logins": ["root"], "from_cidrs": ["10.0.0.0/8"],
    })
    params = {"break_glass": {"item_id": "22222222-2222-4222-8222-222222222222", "public_fingerprint": fingerprint,
                              "public_key": None, "login": None, "from_cidrs": None}}

    filled = await service._fill_break_glass("team-a", params)

    assert filled["break_glass"] == {
        "item_id": "22222222-2222-4222-8222-222222222222", "public_fingerprint": fingerprint,
        "public_key": _BG_KEY, "login": "root", "from_cidrs": ["10.0.0.0/8"],
    }
    service.items.get_item.assert_awaited_once_with("v-team", "22222222-2222-4222-8222-222222222222")


@pytest.mark.asyncio
async def test_enrollment_refuses_a_break_glass_item_that_does_not_match_the_server_fingerprint() -> None:
    from servonaut.services.vault.errors import VaultUserError

    service = _break_glass_service({
        "public_key": _BG_KEY, "public_fingerprint": "SHA256:other", "logins": ["root"], "from_cidrs": ["10.0.0.0/8"],
    })
    params = {"break_glass": {"item_id": "22222222-2222-4222-8222-222222222222", "public_fingerprint": "SHA256:named"}}

    with pytest.raises(VaultUserError, match="does not match"):
        await service._fill_break_glass("team-a", params)


@pytest.mark.asyncio
async def test_break_glass_scan_reports_each_new_in_window_login_once(tmp_path) -> None:
    from datetime import datetime, timedelta, timezone

    from servonaut.services.vault.local_state import VaultLocalState

    recent = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S+0000")
    old = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S+0000")
    log = (
        f"{recent} web-1 sshd[1]: Accepted publickey for root from 10.0.0.5 port 1 ssh2: ED25519 SHA256:bg\n"
        f"{recent} web-1 sshd[1]: Accepted publickey for root from 10.0.0.5 port 1 ssh2: ED25519 SHA256:bg\n"
        f"{old} web-1 sshd[1]: Accepted publickey for root from 10.0.0.6 port 1 ssh2: ED25519 SHA256:bg\n"
    )
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    service.state = VaultLocalState(tmp_path / "state.json")
    service.store = MagicMock()
    service._team_break_glass_fingerprints = AsyncMock(return_value={"SHA256:bg"})  # type: ignore[method-assign]
    service.ca_hosts = AsyncMock(return_value={"hosts": [  # type: ignore[method-assign]
        {"server_id": "server-1", "status": "enrolled"}, {"server_id": "server-2", "status": "enrolling"},
    ]})
    service._shared_server = AsyncMock(return_value={"id": "server-1"})  # type: ignore[method-assign]
    executor = MagicMock()
    executor.read_auth_log = AsyncMock(return_value=log)
    service._remote_executor = lambda *_args: executor  # type: ignore[method-assign]
    service.api = MagicMock()
    service.api.request_signed = AsyncMock(return_value={"event_id": "e-1"})

    first = await service.ca_break_glass_scan(team="team-a", since_hours=24)
    second = await service.ca_break_glass_scan(team="team-a", since_hours=24)

    assert first["reported"] == 1 and second["reported"] == 0
    method, path = service.api.request_signed.await_args.args
    body = service.api.request_signed.await_args.kwargs["json"]
    assert (method, path) == ("POST", "/api/v1/teams/team-a/ssh-ca/break-glass-events")
    assert body["server_id"] == "server-1" and body["source_ip"] == "10.0.0.5" and body["observed_at"].endswith("+00:00")
    executor.read_auth_log.assert_awaited_with(24)


@pytest.mark.asyncio
async def test_enrollment_proof_never_reuses_a_cached_certificate() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    client = MagicMock()
    client.get_status = AsyncMock(return_value=SimpleNamespace(
        enabled=True, host_ca_public_key="ssh-ed25519 AAAA", logins_by_server={"server-1": ("deploy",)},
    ))
    client.load_cached_certificate = MagicMock(return_value=MagicMock())
    client.register_device_key = AsyncMock(side_effect=RuntimeError("stop after the cache decision"))
    service._ca = lambda _team: client  # type: ignore[method-assign]
    row = {"id": "server-1", "is_shared": True, "team_slug": "team-a", "hostname": "web-1.example.com"}

    with pytest.raises(RuntimeError, match="stop after the cache decision"):
        await service._resolve_ca_ssh(row, purpose="automation", require_enrolled=False, fresh=True)

    client.load_cached_certificate.assert_not_called()
    client.register_device_key.assert_awaited_once()


@pytest.mark.asyncio
async def test_ca_revoke_reports_the_revoked_serial_and_new_krl_version() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    client = MagicMock()
    client.revoke_certificate = AsyncMock(return_value={
        "certificate": {"serial": 28, "cert_type": "user", "key_id": "u:50", "revoked_at": "2026-10-06T01:40:00Z"},
        "krl_version": 2, "host_krl_version": 1,
    })
    service._ca = lambda _team: client  # type: ignore[method-assign]

    result = await service.ca_revoke(team="team-a", serial=28, note="lost laptop")

    client.revoke_certificate.assert_awaited_once_with(28, note="lost laptop")
    assert result == {"serial": 28, "cert_type": "user", "key_id": "u:50",
                      "revoked_at": "2026-10-06T01:40:00Z", "krl_version": 2}


@pytest.mark.asyncio
async def test_ca_revoke_refuses_a_response_about_another_serial() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    client = MagicMock()
    client.revoke_certificate = AsyncMock(return_value={"certificate": {"serial": 27}, "krl_version": 2})
    service._ca = lambda _team: client  # type: ignore[method-assign]

    with pytest.raises(VaultStateError, match="requested serial"):
        await service.ca_revoke(team="team-a", serial=28)


class _KrlApi:
    def __init__(self, revocations: dict[str, object]) -> None:
        self.revocations = revocations
        self.gets: list[str] = []
        self.signed: list[tuple[str, str, object]] = []

    async def get(self, path: str, **_kwargs: object) -> dict[str, object]:
        self.gets.append(path)
        return self.revocations

    async def request_signed(self, method: str, path: str, *, json: object, **_kwargs: object) -> dict[str, object]:
        self.signed.append((method, path, json))
        return {"accepted": 1}


def _revocations(version: int = 2) -> dict[str, object]:
    import base64
    import hashlib

    from servonaut.services.vault.crypto import build_krl

    krl = build_krl(b"k" * 32, version, 1_700_000_000, [28])
    return {"krl_version": version, "generated_at": "2026-10-06T01:40:06+00:00", "serials": [28],
            "krl": base64.b64encode(krl).decode(), "sha256": base64.b64encode(hashlib.sha256(krl).digest()).decode()}


@pytest.mark.asyncio
async def test_ca_deliver_krl_writes_the_revocations_krl_and_reports_its_version() -> None:
    import base64

    api = _KrlApi(_revocations())
    host = MagicMock()
    host.write_atomic = AsyncMock()
    teams = MagicMock()
    teams.list_shared_servers = AsyncMock(return_value=[
        {"id": "server-1", "name": "web-1", "ssh_ca": {"enrolled": True}},
        {"id": "server-2", "name": "web-2", "ssh_ca": {"enrolled": True}},
    ])
    service = VaultCommandService(
        api, SimpleNamespace(user_id=1), _config(), team_service=teams,
        remote_executor_factory=lambda _row, _lease: host,
    )
    service.store = MagicMock()

    result = await service.ca_deliver_krl(team="team-a", servers=["web-1"])

    assert api.gets == ["/api/v1/teams/team-a/ssh-ca/revocations"]
    written = host.write_atomic.await_args.args
    assert str(written[0]).endswith("/revoked.krl")
    assert written[1] == base64.b64decode(_revocations()["krl"])  # type: ignore[arg-type]
    assert api.signed == [("POST", "/api/v1/teams/team-a/ssh-ca/krl-deliveries",
                           {"krl_version": 2, "results": [{"server_id": "server-1", "status": "delivered"}]})]
    assert result["krl_version"] == 2


@pytest.mark.asyncio
async def test_ca_deliver_krl_refuses_a_revocations_response_without_a_version() -> None:
    payload = _revocations()
    payload["krl_version"] = None
    teams = MagicMock()
    teams.list_shared_servers = AsyncMock(return_value=[{"id": "server-1", "ssh_ca": {"enrolled": True}}])
    host = MagicMock()
    host.write_atomic = AsyncMock()
    service = VaultCommandService(
        _KrlApi(payload), SimpleNamespace(user_id=1), _config(), team_service=teams,
        remote_executor_factory=lambda _row, _lease: host,
    )

    with pytest.raises(VaultStateError, match="no valid version"):
        await service.ca_deliver_krl(team="team-a", servers=None)
    host.write_atomic.assert_not_called()


@pytest.mark.asyncio
async def test_ca_deliver_krl_goes_only_to_enrolled_hosts_and_never_reports_an_empty_list() -> None:
    from servonaut.services.vault.errors import VaultUserError

    api = _KrlApi(_revocations())
    host = MagicMock()
    host.write_atomic = AsyncMock()
    teams = MagicMock()
    teams.list_shared_servers = AsyncMock(return_value=[
        {"id": "server-1", "name": "web-1", "ssh_ca": {"enrolled": True}},
        {"id": "server-2", "name": "web-2", "ssh_ca": {"enrolled": False, "status": "failed"}},
        {"id": "server-3", "name": "web-3"},
    ])
    written_to: list[str] = []

    def executor(row, _lease):
        written_to.append(str(row["id"]))
        return host

    service = VaultCommandService(
        api, SimpleNamespace(user_id=1), _config(), team_service=teams, remote_executor_factory=executor,
    )
    service.store = MagicMock()

    await service.ca_deliver_krl(team="team-a", servers=None)
    assert written_to == ["server-1"]

    with pytest.raises(VaultUserError, match="'web-2' is not enrolled"):
        await service.ca_deliver_krl(team="team-a", servers=["web-2"])
    with pytest.raises(VaultUserError, match="'nope' was not found"):
        await service.ca_deliver_krl(team="team-a", servers=["nope"])

    teams.list_shared_servers = AsyncMock(return_value=[{"id": "server-3", "name": "web-3"}])
    with pytest.raises(VaultUserError, match="no hosts enrolled"):
        await service.ca_deliver_krl(team="team-a", servers=None)
    assert len(api.signed) == 1


@pytest.mark.asyncio
async def test_krl_updated_event_delivers_only_to_enrolled_hosts_that_drifted() -> None:
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config())
    service.ca_hosts = AsyncMock(return_value={"hosts": [  # type: ignore[method-assign]
        {"server_id": "server-1", "status": "enrolled", "krl_drift": True},
        {"server_id": "server-2", "status": "failed", "krl_drift": True},
        {"server_id": "server-3", "status": "enrolled", "krl_drift": False},
    ]})
    service.ca_deliver_krl = AsyncMock()  # type: ignore[method-assign]

    await service.handle_event({"type": "ssh_ca.krl_updated", "data": {"team_slug": "team-a"}})

    service.ca_deliver_krl.assert_awaited_once_with(team="team-a", servers=["server-1"])


@pytest.mark.asyncio
async def test_next_step_reads_vaults_only_once_the_identity_is_confirmed() -> None:
    auth = SimpleNamespace(user_id=1, has_feature=lambda feature: feature == "personal_vault")
    service = VaultCommandService(_Api({}), auth, _config())
    service.list_vaults = AsyncMock(return_value=[])  # type: ignore[method-assign]
    pending = {"remote": {"identity": {"trust_status": "pending_confirmation"}}, "local_identity": "fp"}
    confirmed = {"remote": {"identity": {"trust_status": "confirmed"}}, "local_identity": "fp"}

    assert (await service.next_step(pending))["code"] == "confirm_identity"
    service.list_vaults.assert_not_awaited()
    assert (await service.next_step(confirmed))["code"] == "create_vault"


@pytest.mark.asyncio
async def test_creatable_vaults_offer_personal_and_teams_the_user_runs_without_a_vault() -> None:
    auth = SimpleNamespace(user_id=1, has_feature=lambda feature: feature == "personal_vault")
    teams = MagicMock()
    teams.list_teams = AsyncMock(return_value=[
        {"slug": "ops", "name": "Ops", "role": "owner"},
        {"slug": "web", "name": "Web", "role": "admin"},
        {"slug": "data", "name": "Data", "role": "member"},
    ])
    service = VaultCommandService(_Api({}), auth, _config(), team_service=teams)

    options = await service.creatable_vaults([{"kind": "team", "team": {"slug": "web"}}])

    assert options == [{"team": None, "label": "Personal vault"}, {"team": "ops", "label": "Team vault for Ops"}]


@pytest.mark.asyncio
async def test_creatable_vaults_skip_personal_when_the_plan_lacks_it_or_one_exists() -> None:
    teams = MagicMock()
    teams.list_teams = AsyncMock(return_value=[])
    no_plan = VaultCommandService(_Api({}), SimpleNamespace(user_id=1, has_feature=lambda _f: False), _config(), team_service=teams)
    has_one = VaultCommandService(_Api({}), SimpleNamespace(user_id=1, has_feature=lambda _f: True), _config(), team_service=teams)

    assert await no_plan.creatable_vaults([]) == []
    assert await has_one.creatable_vaults([{"kind": "personal"}]) == []


@pytest.mark.asyncio
async def test_create_vault_for_an_unknown_team_names_the_team() -> None:
    from servonaut.services.vault.errors import VaultUserError

    teams = MagicMock()
    teams.get_team = AsyncMock(side_effect=APIError(code="not_found", message="x", status=404))
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), team_service=teams)

    with pytest.raises(VaultUserError, match="team 'no-such-team' was not found among your teams"):
        await service.create_vault(team="no-such-team", name=None, grant_policy="auto")


@pytest.mark.asyncio
async def test_setup_can_be_retried_after_custody_could_not_be_saved(tmp_path) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    store = IdentityStore(path, environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), _config(), store=store)
    identity = MagicMock()
    identity.status = AsyncMock(return_value={"identity": None})
    identity.enroll = AsyncMock(return_value={"confirmation": {"state": "confirmed"}})
    service.identity = identity
    save = store.save
    store.save = MagicMock(side_effect=RuntimeError("No trusted OS keyring is available"))  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="keyring"):
        await service.setup(device_name="d", platform="linux", recovery_confirmation=lambda _key: True)

    assert store.identity is None
    identity.enroll.assert_not_awaited()
    store.save = save  # type: ignore[method-assign]
    assert await service.setup(device_name="d", platform="linux", recovery_confirmation=lambda _key: True) == {
        "confirmation": {"state": "confirmed"}
    }


def test_file_key_storage_setting_applies_without_a_restart() -> None:
    config = _config()
    config.vault.allow_file_key_store = False
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), config)
    assert service.store.allow_file_key_store is False

    config.vault.allow_file_key_store = True  # Settings > Team Vault saved in the running app
    service.unlock_existing_identity()

    assert service.store.allow_file_key_store is True


def test_an_injected_store_keeps_its_own_key_storage_policy(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault" / "vault_keys.json", allow_file_key_store=True)
    config = _config()
    config.vault.allow_file_key_store = False
    service = VaultCommandService(_Api({}), SimpleNamespace(user_id=1), config, store=store)

    service.unlock_existing_identity()

    assert store.allow_file_key_store is True

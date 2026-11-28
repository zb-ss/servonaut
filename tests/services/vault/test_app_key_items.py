"""Memory Sync and config sync key items in the personal vault."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault import crypto
from servonaut.services.vault.app_keys import AppKeyItems, AppKeyRef
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.errors import (
    NO_LOCAL_IDENTITY,
    RECOVERY_KEY_NOT_A_KEY,
    RECOVERY_KEY_TYPO,
    VaultUserError,
    vault_failure_reason,
)
from servonaut.services.vault.identity_store import IdentityStore
from servonaut.services.vault.items import (
    APP_KEY_LABELS,
    CONFIG_SYNC_KEY,
    MEMORY_KEY,
    VaultItemService,
)
from servonaut.services.vault.roster_pins import RosterPins
from servonaut.services.vault.team_vault_client import TeamVaultClient, VaultStateError


VAULT_ID = "22222222-2222-4222-8222-222222222222"  # leak-guard:allow (synthetic id)
IDENTITY_ID = "11111111-1111-4111-8111-111111111111"  # leak-guard:allow (synthetic id)
_B64 = lambda raw: base64.b64encode(raw).decode()  # noqa: E731


def _config() -> SimpleNamespace:
    return SimpleNamespace(vault=SimpleNamespace(
        allow_file_key_store=False, request_timeout_seconds=30.0, binding_read_cache_seconds=60.0,
        binding_read_backoff_seconds=60.0, strict_verification=False, auto_grant=True,
        agent_key_ttl_seconds=60, poll_after_seconds=300,
        approval_poll_initial_seconds=0.01, approval_poll_max_seconds=0.02,
    ))


def memory_payload(seed: bytes = b"m" * 32, **changes):
    public = crypto.x25519_public(seed)
    payload = {
        "v": 1, "name": APP_KEY_LABELS[MEMORY_KEY], "user_id": 1,
        "public_key": _B64(public), "private_key": _B64(seed),
        "public_fingerprint": hashlib.sha256(public).hexdigest(),
        "created_at": "2026-11-28T10:00:00Z",
    }
    payload.update(changes)
    return payload


def config_payload(key_bytes: bytes = b"c" * 32, **changes):
    payload = {
        "v": 1, "name": APP_KEY_LABELS[CONFIG_SYNC_KEY], "key": _B64(key_bytes),
        "public_fingerprint": hmac.new(key_bytes, b"servonaut-config-sync-key-id-v1", hashlib.sha256).hexdigest(),
        "created_at": "2026-11-28T10:00:00+00:00",
    }
    payload.update(changes)
    return payload


def validate(item_type, payload, fingerprint="__use_payload__"):
    if fingerprint == "__use_payload__":
        fingerprint = payload.get("public_fingerprint")
    VaultItemService._validate_payload(item_type, payload, fingerprint)


# --- payload validation -------------------------------------------------------

def test_valid_payloads_pass() -> None:
    validate(MEMORY_KEY, memory_payload())
    validate(CONFIG_SYNC_KEY, config_payload())


@pytest.mark.parametrize("changes", [
    {"v": 2}, {"v": True}, {"name": ""}, {"user_id": 0}, {"user_id": True}, {"user_id": "1"},
    {"public_key": _B64(b"x" * 31)}, {"public_key": "not base64!"}, {"private_key": _B64(b"y" * 33)},
    {"private_key": _B64(b"y" * 32)},  # does not derive the public key
    {"public_fingerprint": "0" * 64},  # not sha256(public_key)
    {"public_fingerprint": "ABCDEF" + "0" * 58},
    {"created_at": "yesterday"}, {"created_at": 5},
])
def test_memory_key_payload_checks(changes) -> None:
    with pytest.raises(ValueError):
        validate(MEMORY_KEY, memory_payload(**changes))


@pytest.mark.parametrize("changes", [
    {"v": 2}, {"key": _B64(b"x" * 31)}, {"key": 5}, {"public_fingerprint": "0" * 64},
    {"public_fingerprint": "g" * 64}, {"created_at": "later"},
])
def test_config_sync_key_payload_checks(changes) -> None:
    with pytest.raises(ValueError):
        validate(CONFIG_SYNC_KEY, config_payload(**changes))


@pytest.mark.parametrize("fingerprint", [None, "", "SHA256:abc", "A" * 64, "a" * 63])
def test_fingerprint_must_be_64_lowercase_hex(fingerprint) -> None:
    with pytest.raises(ValueError, match="64 lowercase hex"):
        validate(MEMORY_KEY, memory_payload(), fingerprint)


def test_item_fingerprint_must_equal_the_payload_fingerprint() -> None:
    with pytest.raises(ValueError, match="does not match the item"):
        validate(CONFIG_SYNC_KEY, config_payload(), "f" * 64)


def test_validation_messages_never_hold_key_material() -> None:
    payload = memory_payload(public_fingerprint="0" * 64)
    with pytest.raises(ValueError) as caught:
        validate(MEMORY_KEY, payload)
    assert payload["private_key"] not in str(caught.value)


def test_other_item_types_still_refuse_a_public_fingerprint() -> None:
    with pytest.raises(ValueError, match="only SSH"):
        VaultItemService._validate_payload("secret", {"name": "x", "notes": ""}, "a" * 64)


# --- a vault service double with real item crypto -------------------------------

class _State:
    def __init__(self) -> None:
        self.data = {"vault_heads": {}}

    def load(self):
        return self.data

    def record_vault_head(self, vault_id, version, record_hash) -> None:
        self.data["vault_heads"][vault_id] = {"version": version, "record_hash": record_hash}

    def record_item_revision(self, _item_id, _revision) -> None:
        pass


class _World:
    """A personal vault and an in-memory item store behind ``request_signed``."""

    def __init__(self, *, with_vault: bool = True) -> None:
        signing_seed, encryption_secret, vault_secret = b"a" * 32, b"b" * 32, b"v" * 32
        signing_public = crypto.public_from_seed(signing_seed)
        encryption_public = crypto.x25519_public(encryption_secret)
        fingerprint = crypto.identity_fingerprint(signing_public, encryption_public)
        self.identity = SimpleNamespace(
            identity_id=IDENTITY_ID, user_id=1, signing_seed=signing_seed,
            encryption_secret_key=encryption_secret, fingerprint=fingerprint.hex(),
        )
        version_public = crypto.x25519_public(vault_secret)
        message = crypto.version_message(VAULT_ID, "user:1", 1, version_public, crypto.ZERO_HASH, IDENTITY_ID)
        signature = crypto.sign(signing_seed, message)
        sealed = crypto.seal(vault_secret, encryption_public)
        grant = crypto.sign(signing_seed, crypto.grant_message(
            VAULT_ID, "user:1", 1, version_public, 1, IDENTITY_ID, fingerprint, sealed, IDENTITY_ID))
        self.vault = {
            "vault_id": VAULT_ID, "kind": "personal", "scope": "user:1", "owner_user_id": 1,
            "current_version": 1,
            "versions": [{
                "version": 1, "public_key": _B64(version_public), "prev_hash": _B64(crypto.ZERO_HASH),
                "record_hash": _B64(crypto.record_hash(message, signature)),
                "creator_identity_id": IDENTITY_ID, "signature": _B64(signature),
            }],
            "identities": {}, "roster": [],
            "my_grant": {"version": 1, "sealed_private_key": _B64(sealed),
                         "granter_identity_id": IDENTITY_ID, "signature": _B64(grant)},
        }
        self.with_vault = with_vault
        self.items: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.refuse_delete: APIError | None = None
        store = SimpleNamespace(identity=self.identity, signer=lambda: "device")
        self.vaults = TeamVaultClient(self, store, RosterPins(lambda: {}, lambda _v: None), _State())
        self.items_service = VaultItemService(self, self.vaults)
        self.keys = AppKeyItems(self.vaults, self.items_service, lambda: True)

    async def request_signed(self, method, path, *, json=None, device=None):
        self.calls.append((method, path))
        route = path.split("?")[0]
        if route == "/api/v1/vaults":
            return {"data": [{"vault_id": VAULT_ID, "kind": "personal"}] if self.with_vault else [], "meta": {}}
        if route == f"/api/v1/vaults/{VAULT_ID}":
            return self.vault
        if route == f"/api/v1/vaults/{VAULT_ID}/items":
            return {"data": list(self.items.values()), "meta": {"next_cursor": None}}
        item_id = route.rsplit("/", 1)[1]
        if method == "GET":
            return self.items[item_id]
        if method == "PUT":
            self.items[item_id] = {
                "item_id": item_id, "ciphertext_sha256": _B64(crypto.sha256(base64.b64decode(json["ciphertext"]))),
                **{key: value for key, value in json.items() if key != "expected_revision"},
            }
            return {"item_id": item_id, "revision": json["revision"]}
        if self.refuse_delete is not None:
            raise self.refuse_delete
        del self.items[item_id]
        return {"ok": True}


@pytest.mark.asyncio
async def test_create_then_read_back_round_trips_both_types() -> None:
    world = _World()
    memory, config = memory_payload(), config_payload()
    memory_ref = await world.keys.create(MEMORY_KEY, memory)
    config_ref = await world.keys.create(CONFIG_SYNC_KEY, config)

    assert memory_ref == AppKeyRef(memory_ref.item_id, 1, memory["public_fingerprint"])
    assert config_ref.public_fingerprint == config["public_fingerprint"]
    assert await world.keys.read(MEMORY_KEY, memory["public_fingerprint"]) == memory
    assert await world.keys.read(CONFIG_SYNC_KEY, config["public_fingerprint"]) == config
    # The stored row carries the fingerprint only: no key bytes outside the ciphertext.
    assert memory["private_key"] not in json.dumps(world.items[memory_ref.item_id])


@pytest.mark.asyncio
async def test_create_sends_a_fresh_uuid_with_expected_revision_zero() -> None:
    world = _World()
    sent: list[dict] = []
    original = world.request_signed

    async def spy(method, path, *, json=None, device=None):
        if method == "PUT":
            sent.append(json)
        return await original(method, path, json=json, device=device)

    world.request_signed = spy  # type: ignore[method-assign]
    first = await world.keys.create(MEMORY_KEY, memory_payload())
    second = await world.keys.create(MEMORY_KEY, memory_payload(b"n" * 32))

    assert first.item_id != second.item_id
    assert all(re.fullmatch(r"[0-9a-f-]{36}", ref.item_id) for ref in (first, second))
    assert [body["expected_revision"] for body in sent] == [0, 0]
    assert [body["type"] for body in sent] == [MEMORY_KEY, MEMORY_KEY]


@pytest.mark.asyncio
async def test_list_filters_by_type_and_skips_deleted_rows() -> None:
    world = _World()
    memory_a, memory_b = memory_payload(b"1" * 32), memory_payload(b"2" * 32)
    await world.keys.create(MEMORY_KEY, memory_a)
    await world.keys.create(MEMORY_KEY, memory_b)
    await world.keys.create(CONFIG_SYNC_KEY, config_payload())
    gone = await world.keys.create(MEMORY_KEY, memory_payload(b"3" * 32))
    world.items[gone.item_id]["deleted_at"] = "2026-11-28T00:00:00Z"
    world.items["99999999-9999-4999-8999-999999999999"] = {  # leak-guard:allow (synthetic id)
        "item_id": "99999999-9999-4999-8999-999999999999", "type": "secret", "revision": 1,  # leak-guard:allow (synthetic id)
        "public_fingerprint": None,
    }

    refs = await world.keys.list(MEMORY_KEY)

    assert {ref.public_fingerprint for ref in refs} == {memory_a["public_fingerprint"], memory_b["public_fingerprint"]}
    assert len(await world.keys.list(CONFIG_SYNC_KEY)) == 1
    with pytest.raises(ValueError):
        await world.keys.list("secret")


@pytest.mark.asyncio
async def test_read_is_fresh_and_returns_none_for_an_unknown_fingerprint() -> None:
    world = _World()
    payload = memory_payload()
    await world.keys.create(MEMORY_KEY, payload)
    world.calls.clear()

    assert await world.keys.read(MEMORY_KEY, "e" * 64) is None
    assert not any(path.startswith(f"/api/v1/vaults/{VAULT_ID}/items/") for _m, path in world.calls)
    assert await world.keys.read(MEMORY_KEY, payload["public_fingerprint"]) == payload
    assert (("GET", f"/api/v1/vaults/{VAULT_ID}")) in world.calls
    assert any(path.startswith(f"/api/v1/vaults/{VAULT_ID}/items/") for _m, path in world.calls)


@pytest.mark.asyncio
async def test_read_refuses_an_item_whose_payload_disagrees_with_its_row() -> None:
    world = _World()
    payload = memory_payload()
    ref = await world.keys.create(MEMORY_KEY, payload)
    world.items[ref.item_id]["public_fingerprint"] = "a" * 64  # a row swapped by the service

    with pytest.raises(Exception):
        await world.keys.read(MEMORY_KEY, "a" * 64)


@pytest.mark.asyncio
async def test_delete_removes_only_the_matching_item() -> None:
    world = _World()
    keep, drop = memory_payload(b"1" * 32), memory_payload(b"2" * 32)
    await world.keys.create(MEMORY_KEY, keep)
    await world.keys.create(MEMORY_KEY, drop)

    assert await world.keys.delete(MEMORY_KEY, drop["public_fingerprint"]) is True
    assert await world.keys.delete(MEMORY_KEY, drop["public_fingerprint"]) is False
    assert [ref.public_fingerprint for ref in await world.keys.list(MEMORY_KEY)] == [keep["public_fingerprint"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("code,expected", [
    ("memory_key_in_use", "still in use"), ("config_key_in_use", "snapshots still use it"),
])
async def test_delete_in_use_refusal_surfaces_the_actionable_text(code, expected) -> None:
    world = _World()
    payload = memory_payload()
    await world.keys.create(MEMORY_KEY, payload)
    world.refuse_delete = APIError(code=code, message="service wording", status=409)

    with pytest.raises(APIError) as caught:
        await world.keys.delete(MEMORY_KEY, payload["public_fingerprint"])

    reason = vault_failure_reason(caught.value)
    assert expected in reason and "service wording" not in reason
    assert len(await world.keys.list(MEMORY_KEY)) == 1


@pytest.mark.asyncio
async def test_no_personal_vault_means_empty_results_and_no_creation_unless_asked() -> None:
    world = _World(with_vault=False)
    world.vaults.create_personal = AsyncMock(return_value={"vault_id": VAULT_ID})

    assert await world.keys.personal_vault_id() is None
    assert await world.keys.list(MEMORY_KEY) == []
    assert await world.keys.read(MEMORY_KEY, "a" * 64) is None
    assert await world.keys.delete(MEMORY_KEY, "a" * 64) is False
    world.vaults.create_personal.assert_not_awaited()

    assert await world.keys.personal_vault_id(create=True) == VAULT_ID
    world.vaults.create_personal.assert_awaited_once()


@pytest.mark.asyncio
async def test_creation_is_refused_when_the_plan_has_no_personal_vault() -> None:
    world = _World(with_vault=False)
    world.vaults.create_personal = AsyncMock()
    keys = AppKeyItems(world.vaults, world.items_service, lambda: False)

    assert await keys.personal_vault_id(create=True) is None
    with pytest.raises(VaultUserError, match="no personal vault"):
        await keys.create(MEMORY_KEY, memory_payload())
    world.vaults.create_personal.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_validates_the_payload_before_sending_anything() -> None:
    world = _World()
    world.calls.clear()

    with pytest.raises(ValueError):
        await world.keys.create(MEMORY_KEY, memory_payload(public_fingerprint="0" * 64))

    assert not [call for call in world.calls if call[0] == "PUT"]
    assert world.items == {}


# --- personal vault only -------------------------------------------------------

@pytest.mark.asyncio
async def test_writing_to_a_team_vault_is_refused() -> None:
    world = _World()
    team = {**world.vault, "kind": "team", "scope": "team:5"}

    with pytest.raises(ValueError, match="personal vault"):
        await world.items_service._write_once(
            VAULT_ID, "33333333-3333-4333-8333-333333333333", MEMORY_KEY, memory_payload(),  # leak-guard:allow (synthetic id)
            expected_revision=0, vault=team,
        )
    assert world.items == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [{"scope": "team:5"}, {"owner_user_id": 2}, {"owner_user_id": None}])
async def test_write_refuses_a_vault_the_service_relabelled_as_personal(changes) -> None:
    world = _World()
    relabelled = {**world.vault, "kind": "personal", **changes}

    with pytest.raises(ValueError, match="personal vault"):
        await world.items_service._write_once(
            VAULT_ID, "33333333-3333-4333-8333-333333333333", MEMORY_KEY, memory_payload(),  # leak-guard:allow (synthetic id)
            expected_revision=0, vault=relabelled,
        )
    assert world.items == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [{"scope": "team:5"}, {"owner_user_id": 2}])
async def test_personal_vault_id_ignores_a_relabelled_vault(changes) -> None:
    world = _World()
    verified = {**world.vault, **changes}  # a verified team vault whose list row says kind=personal
    world.vaults.get_vault = AsyncMock(return_value=verified)
    world.vaults.create_personal = AsyncMock(return_value={"vault_id": "44444444-4444-4444-8444-444444444444"})  # leak-guard:allow (synthetic id)

    assert await world.keys.personal_vault_id() is None
    assert await world.keys.list(MEMORY_KEY) == []
    assert await world.keys.personal_vault_id(create=True) == "44444444-4444-4444-8444-444444444444"  # leak-guard:allow (synthetic id)
    assert not [call for call in world.calls if call[0] == "PUT"]


@pytest.mark.asyncio
async def test_reading_from_a_team_vault_is_refused_before_it_is_opened() -> None:
    world = _World()
    ref = await world.keys.create(MEMORY_KEY, memory_payload())
    team = {**world.vault, "kind": "team"}
    world.vaults.verify_vault = MagicMock(side_effect=AssertionError("vault must not be opened"))

    with pytest.raises(VaultStateError, match="personal vault"):
        world.items_service.read_item(team, world.items[ref.item_id])


# --- command service ------------------------------------------------------------

def _service(tmp_path, *, user_id: int = 1) -> tuple[VaultCommandService, IdentityStore]:
    store = IdentityStore(
        tmp_path / "vault" / "vault_keys.json", environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    )
    api = MagicMock()
    service = VaultCommandService(api, SimpleNamespace(user_id=user_id, has_feature=lambda _f: True), _config(), store=store)
    return service, store


def test_app_keys_is_exposed_and_wired_to_the_plan_check(tmp_path) -> None:
    service, _store = _service(tmp_path)

    assert isinstance(service.app_keys, AppKeyItems)
    assert service.app_keys._can_create_personal_vault() is True


def test_device_signer_when_locked_is_a_user_error(tmp_path) -> None:
    service, store = _service(tmp_path)

    with pytest.raises(VaultUserError) as caught:
        service.device_signer()
    assert str(caught.value) == NO_LOCAL_IDENTITY

    local = store.create(identity_id=IDENTITY_ID, user_id=1)
    assert service.device_signer() is local.device


def test_unlock_listener_fires_once_per_locked_to_unlocked_transition(tmp_path) -> None:
    service, store = _service(tmp_path)
    calls: list[int] = []
    service.add_unlock_listener(lambda: calls.append(1))

    store.create(identity_id=IDENTITY_ID, user_id=1)
    store.save()
    assert service.unlock_existing_identity() is True
    assert service.unlock_existing_identity() is True  # already unlocked: no second call
    service._remember_local_custody()
    assert calls == [1]

    store.lock()
    assert service.unlock_existing_identity() is True
    assert service.unlock_existing_identity() is True
    assert calls == [1, 1]


def test_a_failing_unlock_listener_does_not_stop_the_others_or_the_unlock(tmp_path) -> None:
    service, store = _service(tmp_path)
    calls: list[int] = []

    def broken() -> None:
        raise RuntimeError("boom")

    service.add_unlock_listener(broken)
    service.add_unlock_listener(lambda: calls.append(1))
    store.create(identity_id=IDENTITY_ID, user_id=1)
    store.save()

    assert service.unlock_existing_identity() is True
    assert calls == [1]


def test_unlock_listener_is_not_called_while_the_vault_stays_locked(tmp_path) -> None:
    service, _store = _service(tmp_path)
    calls: list[int] = []
    service.add_unlock_listener(lambda: calls.append(1))

    assert service.unlock_existing_identity() is False
    service._remember_local_custody()
    assert calls == []


@pytest.mark.asyncio
async def test_has_remote_identity_reads_the_status(tmp_path) -> None:
    service, _store = _service(tmp_path)
    service.identity = MagicMock()
    service.identity.status = AsyncMock(side_effect=[{"identity": {"identity_id": IDENTITY_ID}}, {"identity": None}, {}])

    assert await service.has_remote_identity() is True
    assert await service.has_remote_identity() is False
    assert await service.has_remote_identity() is False


async def _recovery_service(tmp_path):
    service, store = _service(tmp_path)
    local = store.create(identity_id=IDENTITY_ID, user_id=1)
    recovery = crypto.format_recovery_key(b"r" * 32)
    blob = crypto.seal_wrap(
        crypto.recovery_kek(b"r" * 32, IDENTITY_ID),
        crypto.encode_bundle(bytes(local.signing_seed), bytes(local.encryption_secret_key)),
        crypto.wrap_aad("recovery", IDENTITY_ID, 1, local.fingerprint_raw),
    )
    service.identity = MagicMock()
    service.identity.fetch_recovery_wrap = AsyncMock(return_value={"blob": _B64(blob)})
    return service, recovery


@pytest.mark.asyncio
async def test_verify_recovery_key_true_for_the_right_key_and_writes_nothing(tmp_path) -> None:
    service, recovery = await _recovery_service(tmp_path)

    assert await service.verify_recovery_key(recovery) is True
    assert await service.verify_recovery_key(recovery.lower()) is True
    service.identity.fetch_recovery_wrap.assert_awaited()
    assert not service.api.method_calls  # no request of any kind besides the read above


@pytest.mark.asyncio
async def test_verify_recovery_key_false_for_another_well_formed_key(tmp_path) -> None:
    service, _recovery = await _recovery_service(tmp_path)

    assert await service.verify_recovery_key(crypto.format_recovery_key(b"z" * 32)) is False


@pytest.mark.asyncio
async def test_verify_recovery_key_false_when_the_bundle_belongs_to_another_identity(tmp_path) -> None:
    service, recovery = await _recovery_service(tmp_path)
    other = crypto.seal_wrap(
        crypto.recovery_kek(b"r" * 32, IDENTITY_ID),
        crypto.encode_bundle(b"s" * 32, b"t" * 32),
        crypto.wrap_aad("recovery", IDENTITY_ID, 1, service.store.identity.fingerprint_raw),
    )
    service.identity.fetch_recovery_wrap = AsyncMock(return_value={"blob": _B64(other)})

    assert await service.verify_recovery_key(recovery) is False


@pytest.mark.asyncio
async def test_verify_recovery_key_typos_are_user_errors_without_a_request(tmp_path) -> None:
    service, recovery = await _recovery_service(tmp_path)
    typo = recovery[:-1] + ("0" if recovery[-1] != "0" else "1")

    with pytest.raises(VaultUserError) as caught:
        await service.verify_recovery_key(typo)
    assert str(caught.value) == RECOVERY_KEY_TYPO
    with pytest.raises(VaultUserError) as caught:
        await service.verify_recovery_key("not a key")
    assert str(caught.value) == RECOVERY_KEY_NOT_A_KEY
    service.identity.fetch_recovery_wrap.assert_not_awaited()


@pytest.mark.asyncio
async def test_verify_recovery_key_needs_a_local_identity(tmp_path) -> None:
    service, _store = _service(tmp_path)

    with pytest.raises(VaultUserError, match="no vault identity"):
        await service.verify_recovery_key(crypto.format_recovery_key(b"r" * 32))


@pytest.mark.asyncio
async def test_verify_recovery_key_unreadable_wrap_is_a_state_error(tmp_path) -> None:
    service, recovery = await _recovery_service(tmp_path)
    service.identity.fetch_recovery_wrap = AsyncMock(return_value={"blob": "!!"})

    with pytest.raises(VaultStateError):
        await service.verify_recovery_key(recovery)


@pytest.mark.asyncio
@pytest.mark.parametrize("item_type", [MEMORY_KEY, CONFIG_SYNC_KEY])
async def test_show_item_refuses_to_reveal_app_keys_but_shows_metadata(tmp_path, item_type) -> None:
    service, _store = _service(tmp_path)
    item = {"item_id": "x", "type": item_type, "revision": 1, "public_fingerprint": "a" * 64, "ciphertext": "c"}
    service.items.get_item = AsyncMock(return_value=item)
    service.vaults.get_vault = AsyncMock()
    service.items.read_item = MagicMock()

    with pytest.raises(VaultUserError, match="holds a Servonaut key and cannot be shown"):
        await service.show_item(vault_id=VAULT_ID, item_id="x", reveal=True)
    service.vaults.get_vault.assert_not_awaited()
    service.items.read_item.assert_not_called()

    shown = await service.show_item(vault_id=VAULT_ID, item_id="x", reveal=False)
    assert shown["type"] == item_type and "ciphertext" not in shown


@pytest.mark.asyncio
@pytest.mark.parametrize("item_type", [MEMORY_KEY, CONFIG_SYNC_KEY])
async def test_app_keys_cannot_be_renamed_or_deleted_as_ssh_keys(tmp_path, item_type) -> None:
    service, _store = _service(tmp_path)
    service.items.get_item = AsyncMock(return_value={"item_id": "x", "type": item_type, "revision": 1})
    service.items.write_item = AsyncMock()
    service.items.delete_item = AsyncMock()

    with pytest.raises(VaultUserError, match="only SSH key items"):
        await service.rename_ssh_key(vault_id=VAULT_ID, item_id="x", name="new")
    with pytest.raises(VaultUserError, match="only SSH key items"):
        await service._ssh_key_record(VAULT_ID, "x")
    service.items.write_item.assert_not_awaited()
    service.items.delete_item.assert_not_awaited()


# --- error codes -----------------------------------------------------------------

@pytest.mark.parametrize("code", ["item_type_exists", "memory_key_in_use", "config_key_in_use", "device_signature_required"])
def test_app_key_codes_use_client_text_not_the_services_wording(code) -> None:
    reason = vault_failure_reason(APIError(code=code, message="The service's own wording.", status=409))

    assert "service's own wording" not in reason
    assert reason == reason.lower() or reason[0].islower()
    assert not reason.endswith(".")


@pytest.mark.parametrize("field", ["type", "public_fingerprint"])
def test_validation_failed_reports_the_field(field) -> None:
    exc = APIError(code="validation_failed", message="x", status=422, details={"field": field})

    assert field in vault_failure_reason(exc)


def test_labels_are_the_documented_text() -> None:
    assert APP_KEY_LABELS == {
        MEMORY_KEY: "Servonaut Memory Sync key", CONFIG_SYNC_KEY: "Servonaut config sync key",
    }

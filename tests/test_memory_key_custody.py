"""MemoryKeyCustody: where the Memory Sync key is kept and how it is loaded or enrolled."""

from __future__ import annotations

import base64
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.api_client import (
    APIClient, APIError, FeatureDisabledError, NotFoundError, RateLimitedError,
)
from servonaut.services.memory import crypto
from servonaut.services.memory.interfaces import VaultCustodyLocked, VaultCustodyUnavailable
from servonaut.services.memory.key_custody import (
    MODE_NEEDS_VAULT_DEVICE, MODE_PASSPHRASE, MODE_VAULT,
    MemoryKeyCustody, ResolutionKind, parse_key_record,
)
from servonaut.services.memory.rate_limiter import RateLimiter
from servonaut.services.vault.app_keys import AppKeyRef
from servonaut.services.vault.errors import VaultUserError

USER_ID = 7
NOW = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc).timestamp()
HOUR = 3600.0


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _payload(pair, user_id=USER_ID):
    return {
        "v": 1, "name": "Servonaut Memory Sync key", "user_id": user_id,
        "public_key": _b64(pair.public_key), "private_key": _b64(pair.private_key),
        "public_fingerprint": pair.fingerprint, "created_at": "2026-11-28T00:00:00+00:00",
    }


class FakeItems:
    """In-memory stand-in for the vault's AppKeyItems (same public surface)."""

    def __init__(self) -> None:
        self.payloads: dict[str, dict] = {}
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.list_error: Exception | None = None
        self.create_error: Exception | None = None
        self.corrupt_read_back = False

    async def list(self, item_type):
        if self.list_error:
            raise self.list_error
        return [AppKeyRef(f"i-{fp[:6]}", 1, fp) for fp in self.payloads]

    async def read(self, item_type, fingerprint):
        payload = self.payloads.get(fingerprint)
        if payload is not None and self.corrupt_read_back:
            payload = {**payload, "private_key": _b64(b"x" * 32)}
        return payload

    async def create(self, item_type, payload):
        if self.create_error:
            raise self.create_error
        self.payloads[payload["public_fingerprint"]] = dict(payload)
        self.created.append(payload["public_fingerprint"])
        return AppKeyRef("i-new", 1, payload["public_fingerprint"])

    async def delete(self, item_type, fingerprint):
        self.deleted.append(fingerprint)
        return self.payloads.pop(fingerprint, None) is not None


class Env:
    def __init__(self, tmp_path: Path, *, writable=True, unlocked=True, clock=lambda: NOW,
                 identity=None, interval_hours=24.0) -> None:
        self.api = MagicMock(spec=APIClient)
        self.api.get = AsyncMock(side_effect=NotFoundError(code="not_found", message="x", status=404))
        self.api.request_signed = AsyncMock(return_value={})
        self.auth = SimpleNamespace(fetch_user_id=AsyncMock(return_value=USER_ID))
        self.items = FakeItems()
        self.unlocked = unlocked
        self.signer = object()
        self.locked_signer = False
        self.marker_path = tmp_path / "memory" / "key_custody.json"
        self.keys_json = self.marker_path.parent / "keys.json"
        self.detected = MagicMock()
        self.identity = AsyncMock(return_value=bool(identity)) if identity is not None else None
        config = MemoryConfig(custody_check_interval_hours=interval_hours)
        self.custody = MemoryKeyCustody(
            self.api, self.auth, RateLimiter(),
            lambda: self.items if self.unlocked else None,
            self._signer, self.marker_path, writable,
            remote_identity_provider=self.identity,
            memory_config_provider=lambda: config,
            on_vault_detected=self.detected,
            clock=clock,
        )

    def _signer(self):
        if self.locked_signer:
            raise VaultUserError("locked")
        return self.signer

    def keys_me(self, **record):
        self.api.get = AsyncMock(return_value=record)

    def with_item(self, pair=None, user_id=USER_ID):
        pair = pair or crypto.generate_keypair()
        self.items.payloads[pair.fingerprint] = _payload(pair, user_id)
        return pair

    def marker(self):
        return json.loads(self.marker_path.read_text())

    def write_marker(self, custody, fingerprint, user_id=USER_ID, checked_at=None):
        self.marker_path.parent.mkdir(parents=True, exist_ok=True)
        self.marker_path.write_text(json.dumps({
            "user_id": user_id, "custody": custody, "fingerprint": fingerprint,
            "public_key": "", "checked_at": checked_at or datetime.fromtimestamp(NOW, timezone.utc).isoformat(),
        }))


def _record(pair, **extra):
    return {"id": 1, "fingerprint": pair.fingerprint, "public_key": _b64(pair.public_key), **extra}


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# --- parse_key_record ---------------------------------------------------

@pytest.mark.parametrize(
    ("data", "custody"),
    [
        ({"custody": "vault", "wrapped_private_key": "{}"}, "vault"),
        ({"wrapped_private_key": None}, "vault"),
        ({"custody": "vault", "wrapped_private_key": None}, "vault"),
        ({}, "vault"),
        ({"wrapped_private_key": ""}, "vault"),
        ({"wrapped_private_key": "{}"}, "passphrase"),
        ({"custody": "passphrase", "wrapped_private_key": "{}"}, "passphrase"),
        ({"custody": "passphrase", "wrapped_private_key": None}, "vault"),
        ({"custody": "something-new", "wrapped_private_key": "{}"}, "vault"),
    ],
)
def test_parse_fails_closed(data, custody) -> None:
    assert parse_key_record({"fingerprint": "f", "public_key": "p", **data}).custody == custody


def test_parse_keeps_wrap_only_for_passphrase_and_allows_null_changed_at() -> None:
    vault = parse_key_record({"custody": "vault", "wrapped_private_key": "x", "custody_changed_at": None})
    assert vault.wrapped_private_key is None and vault.custody_changed_at is None
    assert parse_key_record({"wrapped_private_key": "x"}).wrapped_private_key == "x"


def test_parse_rejects_a_non_object() -> None:
    with pytest.raises(VaultCustodyUnavailable):
        parse_key_record(["nope"])


# --- resolve: vault branch ----------------------------------------------

@pytest.mark.asyncio
async def test_marker_match_adopts_the_item_without_a_keys_me_call(env) -> None:
    pair = env.with_item()
    env.write_marker("vault", pair.fingerprint)
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.VAULT_KEY
    assert result.material.private_key == pair.private_key and result.material.user_id == USER_ID
    env.api.get.assert_not_called()


@pytest.mark.asyncio
async def test_no_marker_writable_checks_the_service_once_and_writes_the_marker(env) -> None:
    pair = env.with_item()
    env.keys_me(**_record(pair, custody="vault", wrapped_private_key=None))
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.VAULT_KEY
    assert env.api.get.await_count == 1
    assert env.marker()["fingerprint"] == pair.fingerprint
    assert env.marker()["custody"] == "vault"
    assert stat.S_IMODE(os.stat(env.marker_path).st_mode) == 0o600
    assert "private" not in env.marker_path.read_text()


@pytest.mark.asyncio
async def test_writable_with_an_orphan_item_that_is_not_the_active_key_does_not_adopt(env) -> None:
    env.with_item()  # orphan
    active = crypto.generate_keypair()
    env.keys_me(**_record(active, custody="vault", wrapped_private_key=None))
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.VAULT_LOCKED
    assert result.material is None


@pytest.mark.asyncio
async def test_orphan_item_and_a_passphrase_account_resolves_to_passphrase(env) -> None:
    env.with_item()
    active = crypto.generate_keypair()
    env.keys_me(**_record(active, wrapped_private_key="{}"))
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.PASSPHRASE
    assert result.record.fingerprint == active.fingerprint


@pytest.mark.asyncio
async def test_item_without_a_service_key_is_not_enrolled(env) -> None:
    env.with_item()
    assert (await env.custody.resolve()).kind is ResolutionKind.NOT_ENROLLED


@pytest.mark.asyncio
async def test_two_items_writable_always_asks_the_service_even_with_a_marker(env) -> None:
    old, new = env.with_item(), env.with_item()
    env.write_marker("vault", old.fingerprint)
    env.keys_me(**_record(new, custody="vault", wrapped_private_key=None))
    result = await env.custody.resolve()
    assert result.fingerprint == new.fingerprint
    assert env.api.get.await_count == 1


@pytest.mark.asyncio
async def test_two_items_read_only_picks_the_marker_fingerprint(tmp_path) -> None:
    env = Env(tmp_path, writable=False)
    old, new = env.with_item(), env.with_item()
    env.write_marker("vault", new.fingerprint)
    result = await env.custody.resolve()
    assert result.fingerprint == new.fingerprint
    env.api.get.assert_not_called()


@pytest.mark.asyncio
async def test_read_only_with_one_item_adopts_without_a_call_and_writes_nothing(tmp_path) -> None:
    env = Env(tmp_path, writable=False)
    pair = env.with_item()
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.VAULT_KEY and result.fingerprint == pair.fingerprint
    env.api.get.assert_not_called()
    assert not env.marker_path.exists()


@pytest.mark.asyncio
async def test_an_item_of_another_account_is_never_adopted(env) -> None:
    pair = env.with_item(user_id=USER_ID + 1)
    env.write_marker("vault", pair.fingerprint)
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.UNAVAILABLE and result.reason == "vault_key_invalid"


@pytest.mark.asyncio
async def test_an_item_whose_private_key_does_not_match_is_never_adopted(env) -> None:
    pair = env.with_item()
    env.items.payloads[pair.fingerprint]["private_key"] = _b64(b"z" * 32)
    env.write_marker("vault", pair.fingerprint)
    assert (await env.custody.resolve()).kind is ResolutionKind.UNAVAILABLE


@pytest.mark.asyncio
async def test_vault_read_failure_is_unavailable_not_a_prompt(env) -> None:
    env.items.list_error = APIError(code="x", message="m", status=500)
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.UNAVAILABLE and result.error is env.items.list_error


# --- resolve: no item / locked --------------------------------------------

@pytest.mark.asyncio
async def test_locked_vault_with_a_vault_marker_is_vault_locked(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.write_marker("vault", "a" * 64)
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.VAULT_LOCKED
    env.api.get.assert_not_called()


@pytest.mark.asyncio
async def test_locked_listing_is_treated_like_an_absent_vault(env) -> None:
    env.items.list_error = VaultUserError("locked")
    env.write_marker("vault", "a" * 64)
    assert (await env.custody.resolve()).kind is ResolutionKind.VAULT_LOCKED


@pytest.mark.asyncio
async def test_keys_json_gives_the_passphrase_fast_path_with_no_call(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.write_marker("passphrase", "a" * 64)
    env.keys_json.write_text("{}")
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.PASSPHRASE and result.record is None
    env.api.get.assert_not_called()


@pytest.mark.asyncio
async def test_no_marker_no_keys_json_asks_the_service(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    pair = crypto.generate_keypair()
    env.keys_me(**_record(pair, custody="vault", wrapped_private_key=None))
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.VAULT_LOCKED
    assert env.marker()["custody"] == "vault"


@pytest.mark.asyncio
async def test_service_passphrase_record_is_returned_for_reuse(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    pair = crypto.generate_keypair()
    env.keys_me(**_record(pair, wrapped_private_key="{}"))
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.PASSPHRASE and result.record.wrapped_private_key == "{}"
    assert env.api.get.await_count == 1


@pytest.mark.asyncio
async def test_service_404_is_not_enrolled(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    assert (await env.custody.resolve()).kind is ResolutionKind.NOT_ENROLLED


@pytest.mark.asyncio
async def test_rate_limit_is_unavailable_and_ratchets_the_limiter(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    error = RateLimitedError(code="rate_limited", message="m", status=429)
    env.api.get = AsyncMock(side_effect=error)
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.UNAVAILABLE and result.error is error


@pytest.mark.asyncio
async def test_marker_of_another_user_is_ignored(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.write_marker("vault", "a" * 64, user_id=USER_ID + 1)
    assert (await env.custody.resolve()).kind is ResolutionKind.NOT_ENROLLED
    assert env.api.get.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("garbage", ["not json", "[]", json.dumps({"user_id": USER_ID, "custody": "vault", "fingerprint": "short"})])
async def test_unreadable_marker_is_ignored(tmp_path, garbage) -> None:
    env = Env(tmp_path, unlocked=False)
    env.marker_path.parent.mkdir(parents=True)
    env.marker_path.write_text(garbage)
    assert (await env.custody.resolve()).kind is ResolutionKind.NOT_ENROLLED


@pytest.mark.asyncio
async def test_user_id_failure_is_unavailable(env) -> None:
    env.auth.fetch_user_id = AsyncMock(return_value=None)
    assert (await env.custody.resolve()).kind is ResolutionKind.UNAVAILABLE


# --- throttled check on the keys.json fast path ----------------------------

@pytest.mark.asyncio
async def test_check_not_due_makes_no_call(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.keys_json.parent.mkdir(parents=True)
    env.keys_json.write_text("{}")
    env.write_marker("passphrase", "a" * 64)
    await env.custody.resolve()
    env.api.get.assert_not_called()


@pytest.mark.asyncio
async def test_check_due_after_the_interval_and_a_vault_answer_runs_cleanup(tmp_path) -> None:
    clock = [NOW]
    env = Env(tmp_path, unlocked=False, clock=lambda: clock[0], interval_hours=24)
    env.keys_json.parent.mkdir(parents=True)
    env.keys_json.write_text("{}")
    env.write_marker("passphrase", "a" * 64)
    pair = crypto.generate_keypair()
    env.keys_me(**_record(pair, custody="vault", wrapped_private_key=None))
    clock[0] = NOW + 25 * HOUR
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.VAULT_LOCKED
    env.detected.assert_called_once()
    assert env.marker()["custody"] == "vault"
    assert (await env.custody.resolve()).kind is ResolutionKind.VAULT_LOCKED  # marker now decides
    assert env.api.get.await_count == 1


@pytest.mark.asyncio
async def test_check_with_a_passphrase_answer_keeps_the_fast_path_and_resets_the_throttle(tmp_path) -> None:
    clock = [NOW]
    env = Env(tmp_path, unlocked=False, clock=lambda: clock[0])
    env.keys_json.parent.mkdir(parents=True)
    env.keys_json.write_text("{}")
    pair = crypto.generate_keypair()
    env.keys_me(**_record(pair, wrapped_private_key="{}"))
    first = await env.custody.resolve()  # no marker: due
    assert first.kind is ResolutionKind.PASSPHRASE and first.record is None
    await env.custody.resolve()
    clock[0] = NOW + 23 * HOUR
    await env.custody.resolve()
    assert env.api.get.await_count == 1
    clock[0] = NOW + 25 * HOUR
    await env.custody.resolve()
    assert env.api.get.await_count == 2
    env.detected.assert_not_called()


@pytest.mark.asyncio
async def test_failed_check_keeps_the_fast_path(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.keys_json.parent.mkdir(parents=True)
    env.keys_json.write_text("{}")
    env.api.get = AsyncMock(side_effect=RateLimitedError(code="rate_limited", message="m", status=429))
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.PASSPHRASE and result.record is None


@pytest.mark.asyncio
async def test_read_only_never_runs_the_throttled_check(tmp_path) -> None:
    env = Env(tmp_path, writable=False, unlocked=False)
    env.keys_json.parent.mkdir(parents=True)
    env.keys_json.write_text("{}")
    await env.custody.resolve()
    env.api.get.assert_not_called()


# --- enrolment mode ---------------------------------------------------------

@pytest.mark.asyncio
async def test_enrolment_mode(tmp_path) -> None:
    assert await Env(tmp_path / "a").custody.enrolment_mode() == MODE_VAULT
    locked_with_identity = Env(tmp_path / "b", unlocked=False, identity=True)
    assert await locked_with_identity.custody.enrolment_mode() == MODE_NEEDS_VAULT_DEVICE
    assert await Env(tmp_path / "c", unlocked=False, identity=False).custody.enrolment_mode() == MODE_PASSPHRASE


@pytest.mark.asyncio
async def test_enrolment_mode_identity_check_failure_is_unavailable(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False, identity=True)
    env.identity.side_effect = APIError(code="x", message="m", status=500)
    with pytest.raises(VaultCustodyUnavailable):
        await env.custody.enrolment_mode()


# --- enrol in vault ---------------------------------------------------------

@pytest.mark.asyncio
async def test_enrol_happy_path_creates_reads_back_then_posts_signed(env) -> None:
    material = await env.custody.enrol_in_vault()
    fingerprint = crypto.fingerprint(material.public_key)
    assert env.items.created == [fingerprint]
    method, path = env.api.request_signed.await_args.args
    assert (method, path) == ("POST", "/api/v1/memory/keys")
    kwargs = env.api.request_signed.await_args.kwargs
    assert kwargs["device"] is env.signer
    assert kwargs["json"] == {"public_key": _b64(material.public_key), "fingerprint": fingerprint, "custody": "vault"}
    assert "private" not in json.dumps(kwargs["json"])
    assert env.marker()["fingerprint"] == fingerprint and env.marker()["custody"] == "vault"
    assert env.items.deleted == []


@pytest.mark.asyncio
async def test_enrol_resumes_from_an_existing_item_when_the_service_has_no_key(env) -> None:
    pair = env.with_item()
    material = await env.custody.enrol_in_vault()
    assert material.private_key == pair.private_key
    assert env.items.created == []
    assert env.api.request_signed.await_args.kwargs["json"]["fingerprint"] == pair.fingerprint
    assert env.items.deleted == []


@pytest.mark.asyncio
async def test_resumed_item_is_kept_when_the_service_refuses(env) -> None:
    env.with_item()
    env.api.request_signed = AsyncMock(side_effect=APIError(code="vault_not_ready", message="m", status=409))
    with pytest.raises(APIError):
        await env.custody.enrol_in_vault()
    assert env.items.deleted == []  # not created by this call; the next run reuses it


@pytest.mark.asyncio
async def test_refusal_deletes_the_item_this_call_created(env) -> None:
    error = APIError(code="vault_not_ready", message="m", status=409)
    env.api.request_signed = AsyncMock(side_effect=error)
    with pytest.raises(APIError) as caught:
        await env.custody.enrol_in_vault()
    assert caught.value is error
    assert len(env.items.deleted) == 1 and env.items.payloads == {}
    assert not env.marker_path.exists()


@pytest.mark.asyncio
async def test_transport_failure_keeps_the_item_for_a_resume(env) -> None:
    env.api.request_signed = AsyncMock(side_effect=OSError("reset"))
    with pytest.raises(OSError):
        await env.custody.enrol_in_vault()
    assert env.items.deleted == [] and len(env.items.payloads) == 1


@pytest.mark.asyncio
async def test_feature_disabled_on_the_post_stops_and_cleans_up(env) -> None:
    env.api.request_signed = AsyncMock(
        side_effect=FeatureDisabledError(code="feature_disabled", message="m", status=503))
    with pytest.raises(FeatureDisabledError):
        await env.custody.enrol_in_vault()
    assert env.items.payloads == {}


@pytest.mark.asyncio
async def test_feature_disabled_on_the_item_write_posts_nothing(env) -> None:
    env.items.create_error = FeatureDisabledError(code="feature_disabled", message="m", status=503)
    with pytest.raises(FeatureDisabledError):
        await env.custody.enrol_in_vault()
    env.api.request_signed.assert_not_called()


@pytest.mark.asyncio
async def test_read_back_mismatch_deletes_the_item_and_posts_nothing(env) -> None:
    env.items.corrupt_read_back = True
    with pytest.raises(VaultCustodyUnavailable):
        await env.custody.enrol_in_vault()
    env.api.request_signed.assert_not_called()
    assert len(env.items.deleted) == 1


@pytest.mark.asyncio
async def test_enrol_refuses_when_the_service_already_has_a_key(env) -> None:
    env.keys_me(**_record(crypto.generate_keypair(), wrapped_private_key="{}"))
    with pytest.raises(VaultCustodyUnavailable):
        await env.custody.enrol_in_vault()
    env.api.request_signed.assert_not_called()
    assert env.items.created == []


@pytest.mark.asyncio
async def test_enrol_with_a_locked_vault_or_signer_raises_locked(tmp_path) -> None:
    locked = Env(tmp_path / "a", unlocked=False)
    with pytest.raises(VaultCustodyLocked):
        await locked.custody.enrol_in_vault()
    no_signer = Env(tmp_path / "b")
    no_signer.locked_signer = True
    with pytest.raises(VaultCustodyLocked) as caught:
        await no_signer.custody.enrol_in_vault()
    assert caught.value.reason == "device_signature_required"
    assert no_signer.items.created == []


@pytest.mark.asyncio
async def test_enrol_with_two_items_is_ambiguous(env) -> None:
    env.with_item(), env.with_item()
    with pytest.raises(VaultCustodyUnavailable):
        await env.custody.enrol_in_vault()


@pytest.mark.asyncio
async def test_read_only_custody_cannot_enrol(tmp_path) -> None:
    with pytest.raises(RuntimeError):
        await Env(tmp_path, writable=False).custody.enrol_in_vault()


# --- leftovers and marker ---------------------------------------------------

def _config_manager(remember=True):
    memory = MemoryConfig(sync_remember_device=remember, sync_remember_expires_at="2026-12-01T00:00:00+00:00" if remember else "")
    manager = MagicMock()
    manager.get.return_value = SimpleNamespace(memory=memory)
    return manager


def test_forget_leftovers_clears_file_keychain_and_flags_and_is_idempotent(env, monkeypatch) -> None:
    cleared = MagicMock()
    monkeypatch.setattr("servonaut.services.memory.passphrase_store.clear_passphrase", cleared)
    sync, manager = MagicMock(), _config_manager()
    env.custody.forget_passphrase_leftovers(sync, manager)
    sync.clear_local_keypair_cache.assert_called_once()
    cleared.assert_called_once()
    updated = manager.update.call_args.kwargs["memory"]
    assert updated.sync_remember_device is False and updated.sync_remember_expires_at == ""
    manager = _config_manager(remember=False)
    env.custody.forget_passphrase_leftovers(sync, manager)
    manager.update.assert_not_called()


def test_forget_leftovers_never_raises_and_read_only_does_nothing(tmp_path, monkeypatch) -> None:
    env = Env(tmp_path)
    sync = MagicMock()
    sync.clear_local_keypair_cache.side_effect = OSError("denied")
    manager = _config_manager()
    manager.update.side_effect = OSError("denied")
    env.custody.forget_passphrase_leftovers(sync, manager)
    read_only = Env(tmp_path / "ro", writable=False)
    sync2 = MagicMock()
    read_only.custody.forget_passphrase_leftovers(sync2, _config_manager())
    sync2.clear_local_keypair_cache.assert_not_called()


def test_clear_marker_deletes_it_only_for_writable_callers(tmp_path) -> None:
    env = Env(tmp_path)
    env.write_marker("vault", "a" * 64)
    Env(tmp_path / "x", writable=False).custody.clear_marker()
    env.custody.clear_marker()
    assert not env.marker_path.exists()
    env.custody.clear_marker()  # idempotent


# --- config fields ------------------------------------------------------------

@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), "24", True, None])
def test_custody_config_falls_back_for_unusable_values(value) -> None:
    config = MemoryConfig(custody_check_interval_hours=value, vault_key_recheck_seconds=value)
    assert config.custody_check_interval_seconds() == 24 * 3600.0
    assert config.vault_key_recheck_wait() == 60.0


def test_custody_config_defaults_and_overrides() -> None:
    assert MemoryConfig().custody_check_interval_hours == 24 and MemoryConfig().vault_key_recheck_seconds == 60
    config = MemoryConfig(custody_check_interval_hours=0, vault_key_recheck_seconds=5)
    assert config.custody_check_interval_seconds() == 0 and config.vault_key_recheck_wait() == 5

"""The Memory Sync passphrase-to-vault move helper: every step, crash and refusal."""

from __future__ import annotations

import base64
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIClient, APIError, NotFoundError
from servonaut.services.memory import crypto, passphrase_store
from servonaut.services.memory.custody_errors import custody_error_message
from servonaut.services.memory.custody_move import (
    MemoryCustodyMover,
    MoveStopped,
)
from servonaut.services.memory.interfaces import KeyMaterial
from servonaut.services.memory.key_custody import MemoryKeyCustody
from servonaut.services.memory.rate_limiter import RateLimiter
from servonaut.services.vault.app_keys import AppKeyRef
from servonaut.services.vault.errors import VaultUserError

pytestmark = pytest.mark.asyncio

USER_ID = 7
PASSPHRASE = "correct horse battery staple 7!"
RECOVERY_KEY = "SVRK1-AAAA-BBBB-CCCC-DDDD"
CONFIRMED = {
    "remote": {"identity": {"trust_status": "confirmed"}},
    "local_identity": "abc", "custody_missing": False,
}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class FakeItems:
    """In-memory stand-in for the vault's AppKeyItems (same public surface)."""

    def __init__(self) -> None:
        self.payloads: dict[str, dict] = {}
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.has_vault = True
        self.can_create = True
        self.create_error: Exception | None = None
        self.corrupt_read_back = False

    async def personal_vault_id(self, create: bool = False):
        if not self.has_vault and create and self.can_create:
            self.has_vault = True
            self.vault_was_created = True
        return "vault-1" if self.has_vault else None

    async def list(self, item_type):
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


@pytest.fixture(scope="module")
def pair():
    return crypto.generate_keypair()


@pytest.fixture(scope="module")
def wrapped_json(pair):
    return crypto.wrap_private_key(pair.private_key, PASSPHRASE).to_json()


class Env:
    def __init__(self, tmp_path: Path, pair, wrapped_json: str) -> None:
        self.pair = pair
        self.wrapped_json = wrapped_json
        self.items = FakeItems()
        self.signer = object()
        self.api = MagicMock(spec=APIClient)
        self.record = self.passphrase_record()
        self.api.get = AsyncMock(side_effect=lambda *a, **k: self.record)
        self.api.request_signed = AsyncMock(return_value={})
        self.auth = SimpleNamespace(
            is_authenticated=True, has_feature=lambda f: True,
            fetch_user_id=AsyncMock(return_value=USER_ID),
        )
        self.vault = SimpleNamespace(
            is_unlocked=True, status=AsyncMock(return_value=CONFIRMED),
            app_keys=self.items, device_signer=lambda: self.signer,
            verify_recovery_key=AsyncMock(return_value=True),
            has_remote_identity=AsyncMock(return_value=True),
        )
        self.sync = MagicMock()
        self.sync.get_key_material.return_value = None
        self.marker_path = tmp_path / "memory" / "key_custody.json"
        self.config_manager = MagicMock()
        self.custody = MemoryKeyCustody(
            self.api, self.auth, RateLimiter(), lambda: self.items,
            lambda: self.signer, self.marker_path, True,
        )
        self.mover = MemoryCustodyMover(
            self.api, self.auth, RateLimiter(), self.vault, self.sync,
            self.custody, self.config_manager,
        )
        self.passphrase_calls = 0
        self.recovery_calls = 0
        self.steps: list[str] = []

    def passphrase_record(self) -> dict:
        return {"id": 1, "fingerprint": self.pair.fingerprint,
                "public_key": _b64(self.pair.public_key),
                "wrapped_private_key": self.wrapped_json, "custody": "passphrase"}

    def vault_record(self) -> dict:
        return {"id": 1, "fingerprint": self.pair.fingerprint,
                "public_key": _b64(self.pair.public_key),
                "wrapped_private_key": None, "custody": "vault"}

    def passphrase(self, value: str = PASSPHRASE):
        def provide() -> str:
            self.passphrase_calls += 1
            return value
        return provide

    def recovery(self):
        def provide() -> str:
            self.recovery_calls += 1
            return RECOVERY_KEY
        return provide

    async def run(self, passphrase: str = PASSPHRASE):
        return await self.mover.run(self.passphrase(passphrase), self.recovery(), self.steps.append)

    def seed_item(self) -> None:
        self.items.payloads[self.pair.fingerprint] = {
            "v": 1, "name": "Servonaut Memory Sync key", "user_id": USER_ID,
            "public_key": _b64(self.pair.public_key), "private_key": _b64(self.pair.private_key),
            "public_fingerprint": self.pair.fingerprint, "created_at": "2026-11-28T00:00:00+00:00",
        }


@pytest.fixture(autouse=True)
def _no_keychain(monkeypatch):
    monkeypatch.setattr(passphrase_store, "clear_passphrase", lambda: None)


@pytest.fixture
def env(tmp_path, pair, wrapped_json):
    return Env(tmp_path, pair, wrapped_json)


def _api_error(code: str, status: int) -> APIError:
    return APIError(code=code, message="service wording that must not be shown", status=status)


async def test_happy_path_moves_the_key_in_order(env):
    report = await env.run()

    assert report.outcome == "moved"
    assert report.item_created is True
    assert report.warnings == []
    assert env.steps == [
        "preflight", "recovery_check", "unlock_key", "vault_item", "switch_custody", "cleanup",
    ]
    assert env.items.created == [env.pair.fingerprint]
    env.api.request_signed.assert_awaited_once_with(
        "POST", "/api/v1/memory/keys/me/custody",
        json={"custody": "vault", "fingerprint": env.pair.fingerprint}, device=env.signer,
    )
    env.sync.adopt_key_material.assert_called_once_with(USER_ID, env.pair.public_key, env.pair.private_key)
    env.sync.clear_local_keypair_cache.assert_called_once()
    assert '"custody": "vault"' in env.marker_path.read_text()
    assert env.passphrase_calls == 1 and env.recovery_calls == 1


async def test_nothing_to_move_without_a_key(env):
    env.api.get = AsyncMock(side_effect=NotFoundError(code="not_found", message="x", status=404))

    report = await env.run()

    assert report.outcome == "nothing_to_move"
    assert env.recovery_calls == 0 and env.passphrase_calls == 0
    env.api.request_signed.assert_not_awaited()


async def test_already_moved_run_only_cleans_up(env):
    env.record = env.vault_record()
    env.seed_item()

    report = await env.run()

    assert report.outcome == "already_vault"
    assert env.steps == ["preflight", "already_vault", "cleanup"]
    assert env.recovery_calls == 0 and env.passphrase_calls == 0
    env.api.request_signed.assert_not_awaited()
    assert env.items.created == []
    env.sync.clear_local_keypair_cache.assert_called_once()
    assert '"custody": "vault"' in env.marker_path.read_text()
    env.sync.adopt_key_material.assert_called_once()


async def test_already_vault_but_item_missing_stops(env):
    env.record = env.vault_record()

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "vault_item_missing"
    env.sync.adopt_key_material.assert_not_called()


async def test_wrong_passphrase_writes_nothing(env):
    with pytest.raises(MoveStopped) as stopped:
        await env.run("another passphrase entirely 9?")

    assert stopped.value.reason == "wrong_passphrase"
    assert env.items.created == []
    env.api.request_signed.assert_not_awaited()
    env.sync.adopt_key_material.assert_not_called()
    assert not env.marker_path.exists()


async def test_wrong_recovery_key_writes_nothing_and_never_asks_for_the_passphrase(env):
    env.vault.verify_recovery_key = AsyncMock(return_value=False)

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "recovery_key_mismatch"
    assert "servonaut vault recovery-key" in stopped.value.message
    assert env.passphrase_calls == 0
    assert env.items.created == [] and env.items.has_vault
    env.api.request_signed.assert_not_awaited()
    assert RECOVERY_KEY not in stopped.value.message


async def test_mistyped_recovery_key_uses_the_vault_sentence(env):
    env.vault.verify_recovery_key = AsyncMock(side_effect=VaultUserError("recovery key is not valid"))

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.message == "recovery key is not valid"
    assert env.passphrase_calls == 0


@pytest.mark.parametrize("break_it", ["locked", "compromised", "no_plan", "signed_out"])
async def test_preflight_refuses_before_any_call(env, break_it):
    if break_it == "locked":
        env.vault.is_unlocked = False
    elif break_it == "compromised":
        env.vault.status = AsyncMock(return_value={
            "remote": {"identity": {"trust_status": "compromised"}},
            "local_identity": "abc", "custody_missing": False,
        })
    elif break_it == "no_plan":
        env.auth.has_feature = lambda f: False
    else:
        env.auth.is_authenticated = False

    with pytest.raises(MoveStopped):
        await env.run()

    env.api.get.assert_not_awaited()
    assert env.recovery_calls == 0


@pytest.mark.parametrize(("break_it", "expected"), [
    ("locked", "Unlock your vault on this device first, then try again. Nothing was changed."),
    ("pending_confirmation", (
        "Confirm your vault identity first: open the link we e-mailed you. If the link "
        "expired, choose Confirm identity on the Vault screen or run "
        "servonaut vault identity confirm to get a new one. Nothing was changed."
    )),
    ("no_identity", (
        "Your vault is not ready for this. Create your vault identity and write down its "
        "recovery key. Nothing was changed."
    )),
])
async def test_preflight_says_which_vault_step_is_missing(env, break_it, expected):
    if break_it == "locked":
        env.vault.is_unlocked = False
    elif break_it == "pending_confirmation":
        env.vault.status = AsyncMock(return_value={
            "remote": {"identity": {"trust_status": "pending_confirmation"}},
            "local_identity": "abc", "custody_missing": False,
        })
    else:
        env.vault.status = AsyncMock(return_value={"remote": {}, "local_identity": None})

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "vault_not_ready"
    assert stopped.value.message == expected
    env.api.get.assert_not_awaited()


async def test_unlocked_sync_material_skips_the_passphrase(env):
    env.sync.get_key_material.return_value = KeyMaterial(
        user_id=USER_ID, public_key=env.pair.public_key, private_key=env.pair.private_key)

    report = await env.run()

    assert report.outcome == "moved"
    assert env.passphrase_calls == 0


async def test_unwrap_runs_off_the_event_loop(env, monkeypatch):
    seen: dict[str, threading.Thread] = {}
    real = crypto.unwrap_private_key

    def spy(wrapped, passphrase):
        seen["thread"] = threading.current_thread()
        return real(wrapped, passphrase)

    monkeypatch.setattr(crypto, "unwrap_private_key", spy)

    await env.run()

    assert seen["thread"] is not threading.main_thread()


async def test_unwrapped_key_that_does_not_match_the_record_stops(env):
    other = crypto.generate_keypair()
    env.record = {**env.passphrase_record(), "public_key": _b64(other.public_key)}

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "key_mismatch"
    assert env.items.created == []


async def test_read_back_mismatch_deletes_the_new_item_and_never_switches(env):
    env.items.corrupt_read_back = True

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "readback_mismatch"
    assert env.items.deleted == [env.pair.fingerprint]
    env.api.request_signed.assert_not_awaited()
    env.sync.adopt_key_material.assert_not_called()


async def test_missing_personal_vault_is_created_and_reported(env):
    env.items.has_vault = False

    report = await env.run()

    assert report.vault_created is True


async def test_no_personal_vault_possible_stops(env):
    env.items.has_vault = False
    env.items.can_create = False

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "no_personal_vault"
    env.api.request_signed.assert_not_awaited()


async def test_crash_after_unlocking_the_key_then_rerun(env):
    env.items.create_error = OSError("disk gone")
    with pytest.raises(MoveStopped) as stopped:
        await env.run()
    assert stopped.value.reason == "unreachable"
    assert env.items.payloads == {}

    env.items.create_error = None
    report = await env.run()

    assert report.outcome == "moved"
    assert len(env.items.created) == 1


async def test_crash_after_the_item_then_rerun_reuses_it(env):
    env.api.request_signed = AsyncMock(side_effect=OSError("connection reset"))
    with pytest.raises(MoveStopped):
        await env.run()
    assert env.items.created == [env.pair.fingerprint]
    env.sync.adopt_key_material.assert_not_called()

    env.api.request_signed = AsyncMock(return_value={})
    report = await env.run()

    assert report.outcome == "moved"
    assert report.item_created is False
    assert env.items.created == [env.pair.fingerprint]
    assert len(env.items.payloads) == 1


async def test_crash_after_the_switch_then_rerun_only_cleans_up(env):
    env.sync.clear_local_keypair_cache.side_effect = RuntimeError("boom")
    env.custody.forget_passphrase_leftovers = MagicMock(side_effect=RuntimeError("boom"))

    report = await env.run()
    assert report.outcome == "moved"
    assert len(report.warnings) == 1
    assert env.api.request_signed.await_count == 1

    env.custody.forget_passphrase_leftovers = MagicMock()
    env.record = env.vault_record()
    again = await env.run()

    assert again.outcome == "already_vault"
    assert env.api.request_signed.await_count == 1
    assert again.warnings == []
    env.custody.forget_passphrase_leftovers.assert_called_once()


@pytest.mark.parametrize(("code", "status"), [
    ("vault_not_ready", 409),
    ("fingerprint_mismatch", 409),
    ("device_signature_required", 403),
    ("feature_disabled", 503),
])
async def test_switch_refusals_stop_with_the_client_text_and_keep_the_item(env, code, status):
    env.api.request_signed = AsyncMock(side_effect=_api_error(code, status))

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == code
    assert stopped.value.message == custody_error_message(SimpleNamespace(code=code))
    assert "service wording" not in stopped.value.message
    assert env.items.created == [env.pair.fingerprint] and env.items.deleted == []
    env.sync.adopt_key_material.assert_not_called()
    assert not env.marker_path.exists()


async def test_switch_entitlement_refusal_is_the_plan_sentence(env):
    env.api.request_signed = AsyncMock(side_effect=_api_error("forbidden_entitlement", 403))

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "forbidden_entitlement"
    assert "plan" in stopped.value.message


async def test_locked_device_signer_stops_with_the_signature_text(env):
    def locked():
        raise VaultUserError("locked")

    env.vault.device_signer = locked

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "device_signature_required"
    env.api.request_signed.assert_not_awaited()


async def test_feature_disabled_on_the_item_write_writes_nothing(env):
    env.items.create_error = _api_error("feature_disabled", 503)

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "feature_disabled"
    assert "not available on this Servonaut service yet" in stopped.value.message
    env.api.request_signed.assert_not_awaited()
    assert env.items.payloads == {}


async def test_item_type_exists_on_the_item_write_uses_the_client_text(env):
    env.items.create_error = _api_error("item_type_exists", 409)

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.message == custody_error_message(SimpleNamespace(code="item_type_exists"))


async def test_no_secret_appears_in_the_report_or_errors(env):
    report = await env.run()

    text = repr(report)
    for secret in (PASSPHRASE, RECOVERY_KEY, _b64(env.pair.private_key)):
        assert secret not in text


async def test_a_caller_gate_replaces_the_prompt_and_still_runs_before_any_write(env):
    gate_calls: list[int] = []

    async def gate() -> None:
        gate_calls.append(len(env.items.created))  # nothing may be written yet

    report = await env.mover.run(
        env.passphrase(PASSPHRASE), env.recovery(), env.steps.append, recovery_gate=gate,
    )

    assert report.outcome == "moved"
    assert gate_calls == [0]
    assert env.recovery_calls == 0  # the provider was never asked: the gate stood in for it


async def test_a_refusing_caller_gate_writes_nothing(env):
    async def gate() -> None:
        raise MoveStopped("recovery_key_mismatch", "refused")

    with pytest.raises(MoveStopped):
        await env.mover.run(env.passphrase(PASSPHRASE), env.recovery(), recovery_gate=gate)

    assert env.items.created == [] and env.passphrase_calls == 0
    env.api.request_signed.assert_not_awaited()


async def test_prove_recovery_is_public_and_checks_the_key(env):
    await env.mover.prove_recovery(env.recovery())
    assert env.recovery_calls == 1
    env.vault.verify_recovery_key = AsyncMock(return_value=False)
    with pytest.raises(MoveStopped) as stopped:
        await env.mover.prove_recovery(env.recovery())
    assert stopped.value.reason == "recovery_key_mismatch"


async def test_read_back_of_another_users_key_item_is_a_mismatch(env):
    original = env.items.read

    async def read_other_owner(item_type, fingerprint):
        payload = await original(item_type, fingerprint)
        return None if payload is None else {**payload, "user_id": USER_ID + 1}

    env.items.read = read_other_owner

    with pytest.raises(MoveStopped) as stopped:
        await env.run()

    assert stopped.value.reason == "readback_mismatch"
    env.api.request_signed.assert_not_awaited()


async def test_custody_code_message_gives_the_shared_wording():
    from servonaut.services.memory.custody_errors import custody_code_message

    assert "your vault" in custody_code_message("device_signature_required")
    assert custody_code_message("not_a_custody_code") is None

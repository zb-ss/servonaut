"""The standalone MCP server reads team-shared memory without an app.

Memory Sync is unlocked there only from what the app left behind: the
passphrase kept on this device ("Remember on this device") and the local
keypair cache. Nothing in that path may enrol, upload, write config or touch
the keychain or the cache.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import servonaut.services.memory.crypto as memory_crypto
import servonaut.services.memory.sync_service as sync_module
from servonaut.config.manager import ConfigManager
from servonaut.services.api_client import APIClient
from servonaut.services.auth_service import AuthService
from servonaut.services.memory import passphrase_store
from servonaut.services.memory.headless_shared import (
    NOT_WIRED_HINT, LockReason, build_headless_shared_memory, locked_hint,
)
from servonaut.services.memory.remembered_passphrase import remember_passphrase_expired
from servonaut.services.memory.shared_view import SharedMemory
from servonaut.services.memory.sync_service import LocalUnlock, MemorySyncService
from tests.test_memory_mcp_tools import _make_memory_service, _make_tools

PASSPHRASE = "violet-anchor-quartz-meadow-2468"
USER_ID = 7

SHARED_ROW = {
    "id": "share-1", "name": "web-1", "provider": "Team ops", "is_shared": True,
    "team_slug": "ops", "team_name": "ops", "instance_id": "i-owner-1",
    "public_ip": "1.2.3.4", "port": 22, "state": "shared",
}


@pytest.fixture(scope="module")
def keypair_cache() -> dict:
    """A real passphrase-wrapped keypair, derived once for the module."""
    pair = memory_crypto.generate_keypair()
    wrapped = memory_crypto.wrap_private_key(pair.private_key, PASSPHRASE)
    return {
        "public_key": base64.b64encode(pair.public_key).decode(),
        "wrapped_private_key": wrapped.to_json(),
        "fingerprint": pair.fingerprint,
        "user_id": USER_ID,
    }


class Env(SimpleNamespace):
    """Everything a test may need to look at."""


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, keypair_cache: dict) -> Env:
    cache_path = tmp_path / "memory" / "keys.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(json.dumps(keypair_cache))
    monkeypatch.setattr(sync_module, "_KEY_CACHE_PATH", cache_path)

    unwraps: list = []
    real_unwrap = sync_module.unwrap_private_key

    def counting_unwrap(wrapped, passphrase):
        unwraps.append(threading.current_thread())
        return real_unwrap(wrapped, passphrase)

    monkeypatch.setattr(sync_module, "unwrap_private_key", counting_unwrap)

    keychain = SimpleNamespace(
        available=True,
        passphrase=PASSPHRASE,
        store=MagicMock(name="store_passphrase"),
        clear=MagicMock(name="clear_passphrase"),
    )
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: keychain.available)
    monkeypatch.setattr(passphrase_store, "get_passphrase", lambda: keychain.passphrase)
    monkeypatch.setattr(passphrase_store, "store_passphrase", keychain.store)
    monkeypatch.setattr(passphrase_store, "clear_passphrase", keychain.clear)

    auth = MagicMock(spec=AuthService)
    auth.is_authenticated = True
    auth.has_feature.return_value = True
    auth.fetch_user_id = AsyncMock(return_value=USER_ID)
    auth.list_teams = AsyncMock(return_value=[{"slug": "ops", "name": "ops"}])

    api = MagicMock(spec=APIClient)

    remember = SimpleNamespace(value=(True, ""))
    config_manager = MagicMock()
    config_manager.read_saved_memory_remember.side_effect = lambda: remember.value
    from servonaut.config.schema import AppConfig
    config_manager.get.return_value = AppConfig()

    return Env(
        cache_path=cache_path, unwraps=unwraps, keychain=keychain, auth=auth,
        api=api, remember=remember, config_manager=config_manager,
    )


def _build(env: Env):
    return build_headless_shared_memory(env.config_manager, env.auth, env.api)


def _shared_copy() -> SharedMemory:
    return SharedMemory("ops", "ops", {
        "os": {"observed": {"distro": "Debian 12"}, "declared": {},
               "probed_at": "2026-10-20T08:00:00+00:00"},
    })


def _tools_for(shared):
    service = _make_memory_service(get_all_modules_return={})
    tools = _make_tools(memory_service=service, instance_to_find=dict(SHARED_ROW))
    tools._shared_server_rows = AsyncMock(return_value=[dict(SHARED_ROW)])
    tools._memory_target = AsyncMock(side_effect=lambda row: row)
    tools.set_shared_memory_reader(shared.reader, shared.check_lock)
    return tools


def _assert_nothing_written(env: Env) -> None:
    env.keychain.store.assert_not_called()
    env.keychain.clear.assert_not_called()
    env.config_manager.save.assert_not_called()
    env.config_manager.update.assert_not_called()
    assert env.api.method_calls == []


# --- the unlock -----------------------------------------------------------


def test_unlock_succeeds_and_get_server_memory_returns_the_team_copy(env: Env):
    shared = _build(env)

    async def read(slug, name, instance_id):
        # The copy is readable only once the key is in memory.
        return _shared_copy() if shared.is_unlocked else None

    shared.reader.read = AsyncMock(side_effect=read)
    out = asyncio.run(_tools_for(shared).get_server_memory("web-1"))

    assert "Shared by ops" in out and "distro: Debian 12" in out
    assert shared.is_unlocked
    _assert_nothing_written(env)


@pytest.mark.parametrize("setup", [
    pytest.param(lambda e: setattr(e.remember, "value", (False, "")), id="not-remembered"),
    pytest.param(
        lambda e: setattr(e.remember, "value", (True, "2020-01-01T00:00:00+00:00")),
        id="remember-expired",
    ),
    pytest.param(lambda e: setattr(e.keychain, "available", False), id="keychain-unavailable"),
    pytest.param(lambda e: setattr(e.keychain, "passphrase", None), id="nothing-stored"),
    pytest.param(lambda e: e.cache_path.unlink(), id="no-keys-json"),
])
def test_stays_locked_without_a_usable_remembered_passphrase(env: Env, setup):
    setup(env)
    shared = _build(env)

    assert asyncio.run(shared.ensure_unlocked()) is False
    assert not shared.is_unlocked
    assert env.unwraps == []
    env.auth.fetch_user_id.assert_not_awaited()
    _assert_nothing_written(env)


def test_a_wrong_stored_passphrase_is_tried_once_then_remembered_as_failed(env: Env):
    env.keychain.passphrase = "an-older-passphrase-that-no-longer-fits"
    shared = _build(env)

    async def attempts():
        return [await shared.ensure_unlocked(), await shared.ensure_unlocked()]

    assert asyncio.run(attempts()) == [False, False]
    assert len(env.unwraps) == 1
    assert env.cache_path.exists()
    _assert_nothing_written(env)

    # The passphrase the app saves next is a different one: tried at once.
    env.keychain.passphrase = PASSPHRASE
    assert asyncio.run(shared.ensure_unlocked()) is True
    assert len(env.unwraps) == 2


def test_unlocking_in_the_app_later_is_picked_up_without_a_restart(env: Env):
    env.remember.value = (False, "")
    shared = _build(env)
    assert asyncio.run(shared.ensure_unlocked()) is False

    env.remember.value = (True, "")
    assert asyncio.run(shared.ensure_unlocked()) is True
    assert shared.is_unlocked


def test_an_unlocked_process_does_not_look_at_the_keychain_again(env: Env):
    shared = _build(env)
    assert asyncio.run(shared.ensure_unlocked()) is True

    env.keychain.available = False
    env.remember.value = (False, "")
    assert asyncio.run(shared.ensure_unlocked()) is True
    assert len(env.unwraps) == 1


def test_a_failed_user_lookup_is_not_held_against_the_passphrase(env: Env):
    env.auth.fetch_user_id = AsyncMock(return_value=None)
    shared = _build(env)
    assert asyncio.run(shared.ensure_unlocked()) is False
    assert env.unwraps == []

    env.auth.fetch_user_id = AsyncMock(return_value=USER_ID)
    assert asyncio.run(shared.ensure_unlocked()) is True


def test_the_key_derivation_runs_off_the_event_loop(env: Env):
    shared = _build(env)

    async def run():
        loop_thread = threading.current_thread()
        assert await shared.ensure_unlocked() is True
        return loop_thread

    loop_thread = asyncio.run(run())
    assert env.unwraps and all(t is not loop_thread for t in env.unwraps)


# --- what gets built ------------------------------------------------------


def test_nothing_is_built_when_signed_out(env: Env):
    env.auth.is_authenticated = False
    assert _build(env) is None


def test_nothing_is_built_without_the_memory_sync_feature(env: Env):
    env.auth.has_feature.return_value = False
    assert _build(env) is None
    env.auth.has_feature.assert_called_with("memory_sync")


def test_nothing_is_built_without_an_api_client(env: Env):
    assert build_headless_shared_memory(env.config_manager, env.auth, None) is None


def test_construction_makes_no_network_call_and_no_unwrap(env: Env):
    shared = _build(env)

    assert shared is not None and not shared.is_unlocked
    assert env.unwraps == []
    assert env.api.method_calls == []
    env.auth.fetch_user_id.assert_not_awaited()
    env.auth.list_teams.assert_not_awaited()
    _assert_nothing_written(env)


def test_the_process_starts_no_uploads(env: Env):
    shared = _build(env)
    assert asyncio.run(shared.ensure_unlocked()) is True
    # No sync service is handed to a memory service, so nothing is enqueued.
    memory_service = MagicMock()
    assert not memory_service.set_sync_service.called


def test_mcp_startup_wires_the_reader_without_network_or_unwrap(env: Env, monkeypatch):
    from servonaut.mcp import server

    monkeypatch.setattr("servonaut.services.api_client.APIClient", lambda auth: env.api)
    tools = MagicMock()
    server._wire_headless_shared_memory(tools, env.config_manager, env.auth)

    reader, unlock = tools.set_shared_memory_reader.call_args.args
    assert reader is not None and asyncio.iscoroutinefunction(unlock)
    assert env.unwraps == []
    _assert_nothing_written(env)


def test_mcp_startup_signed_out_wires_nothing(env: Env):
    from servonaut.mcp import server

    env.auth.is_authenticated = False
    tools = MagicMock()
    server._wire_headless_shared_memory(tools, env.config_manager, env.auth)
    tools.set_shared_memory_reader.assert_not_called()


def test_mcp_startup_survives_a_failing_build(env: Env, monkeypatch):
    from servonaut.mcp import server

    def boom(*_a, **_k):
        raise RuntimeError("no crypto")

    monkeypatch.setattr(
        "servonaut.services.memory.headless_shared.build_headless_shared_memory", boom
    )
    monkeypatch.setattr("servonaut.services.api_client.APIClient", lambda auth: env.api)
    tools = MagicMock()
    server._wire_headless_shared_memory(tools, env.config_manager, env.auth)
    tools.set_shared_memory_reader.assert_not_called()


# --- the locked hint ------------------------------------------------------

LABEL = "\u201cKeep unlocked for 30 days\u201d"


def _hint_for(shared) -> str:
    shared.reader.read = AsyncMock(return_value=None)
    out = asyncio.run(_tools_for(shared).get_server_memory("web-1"))
    error = json.loads(out)["error"]
    assert error["code"] == "missing"
    shared.reader.read.assert_not_awaited()
    return error["hint"]


def test_never_set_up_hint(env: Env):
    env.cache_path.unlink()
    hint = _hint_for(_build(env))
    assert hint == (
        "This server is shared through a team. To read the memory the team shares, "
        f"set up Memory Sync in the Servonaut app and choose {LABEL}. "
        "Servonaut's MCP server then reads it without a restart."
    )


@pytest.mark.parametrize("value", [(False, ""), (True, "2020-01-01T00:00:00+00:00")],
                         ids=["not-kept", "expired"])
def test_not_kept_or_expired_hint(env: Env, value):
    env.remember.value = value
    hint = _hint_for(_build(env))
    assert hint == (
        "This server is shared through a team, and Memory Sync is locked for "
        "Servonaut's MCP server. Unlock Memory Sync in the Servonaut app and "
        f"choose {LABEL}; the MCP server then reads it without a restart."
    )


def test_no_keychain_hint(env: Env):
    env.keychain.available = False
    hint = _hint_for(_build(env))
    assert "no OS keychain is available" in hint
    assert hint.endswith("Read the shared memory in the Servonaut app.")


@pytest.mark.parametrize("setup", [
    pytest.param(lambda e: setattr(e.keychain, "passphrase", "an-older-passphrase-1357"),
                 id="kept-passphrase-no-longer-fits"),
    pytest.param(lambda e: setattr(e.auth, "fetch_user_id", AsyncMock(return_value=99)),
                 id="other-account"),
    pytest.param(lambda e: setattr(e.auth, "fetch_user_id", AsyncMock(return_value=None)),
                 id="account-not-checked"),
])
def test_could_not_unlock_hint(env: Env, setup):
    setup(env)
    hint = _hint_for(_build(env))
    assert hint == (
        "This server is shared through a team, and Servonaut's MCP server could "
        f"not unlock Memory Sync. Unlock it again in the Servonaut app and choose {LABEL}."
    )


def test_reader_not_wired_hint():
    out = asyncio.run(_tools_for_unwired().get_server_memory("web-1"))
    assert json.loads(out)["error"]["hint"] == NOT_WIRED_HINT
    assert "signed in to Servonaut on a plan that includes Memory Sync" in NOT_WIRED_HINT


def _tools_for_unwired():
    service = _make_memory_service(get_all_modules_return={})
    tools = _make_tools(memory_service=service, instance_to_find=dict(SHARED_ROW))
    tools._shared_server_rows = AsyncMock(return_value=[dict(SHARED_ROW)])
    tools._memory_target = AsyncMock(side_effect=lambda row: row)
    return tools


def test_the_label_survives_json_encoding(env: Env):
    env.remember.value = (False, "")
    shared = _build(env)
    shared.reader.read = AsyncMock(return_value=None)
    out = asyncio.run(_tools_for(shared).get_server_memory("web-1"))
    # ensure_ascii escapes are fine: the client decodes them back.
    assert LABEL in json.loads(out)["error"]["hint"]
    assert LABEL in locked_hint(LockReason.NOT_KEPT)


def test_an_unlocked_shared_server_without_a_copy_keeps_the_usual_hint(env: Env):
    shared = _build(env)
    shared.reader.read = AsyncMock(return_value=None)
    out = asyncio.run(_tools_for(shared).get_server_memory("web-1"))

    hint = json.loads(out)["error"]["hint"]
    assert "locked" not in hint
    assert "build_server_memory" in hint


def test_check_lock_reports_none_when_unlocked_and_never_stores_a_reason(env: Env):
    shared = _build(env)
    assert asyncio.run(shared.check_lock()) is None
    assert shared.is_unlocked


# --- MemorySyncService.unlock_from_local_cache ----------------------------


def _sync(env: Env) -> MemorySyncService:
    return MemorySyncService(
        api_client=env.api,
        crypto=memory_crypto,
        memory_service=None,
        config_manager=env.config_manager,
        auth_service=env.auth,
    )


def _forbid_state_changes(monkeypatch) -> list:
    called: list = []
    for name in (
        "bootstrap", "upsert_instance", "upsert_all_instances", "_replay_jsonl",
        "start_background_loop", "clear_local_keypair_cache", "_persist_key_cache",
        "_ensure_keypair", "drain_now",
    ):
        monkeypatch.setattr(
            MemorySyncService, name,
            lambda *a, _n=name, **k: called.append(_n),
        )
    return called


def test_unlock_from_local_cache_unlocks_and_announces_the_key(env: Env, monkeypatch):
    called = _forbid_state_changes(monkeypatch)
    sync = _sync(env)
    heard: list = []
    sync.set_key_material_listener(lambda: heard.append(sync.get_key_material()))
    before = env.cache_path.read_bytes()

    assert asyncio.run(sync.unlock_from_local_cache(PASSPHRASE)) is True

    assert sync.is_configured
    assert heard and heard[0].user_id == USER_ID
    assert called == []
    assert env.api.method_calls == []
    assert env.cache_path.read_bytes() == before


@pytest.mark.parametrize("passphrase, uid, expected", [
    pytest.param("not-the-passphrase-at-all-1357", USER_ID, LocalUnlock.BAD_PASSPHRASE, id="wrong"),
    pytest.param(PASSPHRASE, None, LocalUnlock.UNAVAILABLE, id="user-unknown"),
    pytest.param(PASSPHRASE, 99, LocalUnlock.OTHER_ACCOUNT, id="other-account"),
])
def test_a_failed_unlock_changes_nothing(env: Env, monkeypatch, passphrase, uid, expected):
    called = _forbid_state_changes(monkeypatch)
    env.auth.fetch_user_id = AsyncMock(return_value=uid)
    sync = _sync(env)
    listener = MagicMock()
    sync.set_key_material_listener(listener)
    before = env.cache_path.read_bytes()

    assert asyncio.run(sync.unlock_local(passphrase)) is expected
    assert asyncio.run(sync.unlock_from_local_cache(passphrase)) is False

    assert not sync.is_configured and sync.get_key_material() is None
    listener.assert_not_called()
    assert called == []
    assert env.api.method_calls == []
    assert env.cache_path.read_bytes() == before


def test_unlock_without_a_cache_file_fails_quietly(env: Env):
    env.cache_path.unlink()
    sync = _sync(env)
    assert asyncio.run(sync.unlock_local(PASSPHRASE)) is LocalUnlock.NO_CACHE


def test_a_cache_with_a_mismatched_public_key_is_rejected(env: Env, keypair_cache):
    other = memory_crypto.generate_keypair()
    env.cache_path.write_text(json.dumps(
        {**keypair_cache, "public_key": base64.b64encode(other.public_key).decode()}
    ))
    sync = _sync(env)
    assert asyncio.run(sync.unlock_from_local_cache(PASSPHRASE)) is False
    assert not sync.is_configured


# --- shared helpers -------------------------------------------------------


@pytest.mark.parametrize("value, expected", [
    ("", False),
    ("not a date", False),
    ("2020-01-01T00:00:00+00:00", True),
    ("2020-01-01T00:00:00", True),
    ("2999-01-01T00:00:00+00:00", False),
])
def test_remember_expiry_rule(value, expected):
    assert remember_passphrase_expired(value) is expected


def test_the_app_uses_the_shared_expiry_rule():
    from servonaut.app import ServonautApp

    cfg = SimpleNamespace(memory=SimpleNamespace(sync_remember_expires_at="2020-01-01T00:00:00+00:00"))
    assert ServonautApp._remember_passphrase_expired(MagicMock(), cfg) is True


def test_read_saved_memory_remember_reads_the_file_without_writing(tmp_path: Path):
    path = tmp_path / "config.json"
    manager = ConfigManager(config_path=path)
    manager.get()
    assert manager.read_saved_memory_remember() == (False, "")

    path.write_text(json.dumps({
        "version": 4,
        "memory": {"sync_remember_device": True,
                   "sync_remember_expires_at": "2999-01-01T00:00:00+00:00"},
    }))
    before = path.read_bytes()
    assert manager.read_saved_memory_remember() == (True, "2999-01-01T00:00:00+00:00")
    assert path.read_bytes() == before
    # The loaded copy is left as it was.
    assert manager.get().memory.sync_remember_device is False


def test_read_saved_memory_remember_ignores_a_broken_file(tmp_path: Path):
    path = tmp_path / "config.json"
    manager = ConfigManager(config_path=path)
    manager.get()
    path.write_text("{not json")
    assert manager.read_saved_memory_remember() == (False, "")

"""Custody review round 1: offline, rate limit, interrupted move, 5xx, malformed answers, wording."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from servonaut.services.api_client import (
    APIError, FeatureDisabledError, NotFoundError, RateLimitedError,
)
from servonaut.services.memory import crypto
from servonaut.services.memory.custody_errors import (
    CONTEXT_GENERAL, custody_error_message,
)
from servonaut.services.memory.interfaces import VaultCustodyUnavailable
from servonaut.services.memory.key_custody import (
    DEFAULT_MARKER_PATH, ResolutionKind, parse_key_record,
)
from servonaut.services.memory.rate_limiter import RateLimiter, RateLimitKey
from servonaut.services.memory.sync_errors import describe_sync_error
from servonaut.services.memory.sync_service import (
    KEY_SOURCE_VAULT_PENDING, MemorySyncService, VaultUnlock,
)
from tests.test_memory_key_custody import Env, USER_ID, _record

OFFLINE = httpx.ConnectError("offline")


def _sync_with(env: Env) -> MemorySyncService:
    sync = MemorySyncService(
        api_client=env.api, crypto=crypto, memory_service=None,
        config_manager=MagicMock(), auth_service=env.auth, rate_limiter=RateLimiter(),
    )
    sync.set_key_custody(env.custody)
    return sync


# --- A1: a transport error is not an OSError ---------------------------------

def test_httpx_connect_error_is_not_an_os_error() -> None:
    """The reason every ``except OSError`` missed an offline start."""
    assert not isinstance(OFFLINE, OSError)


@pytest.mark.asyncio
async def test_offline_vault_listing_is_unavailable(tmp_path) -> None:
    env = Env(tmp_path)
    env.items.list_error = OFFLINE
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.UNAVAILABLE and result.reason == "vault_unreadable"


@pytest.mark.asyncio
async def test_offline_item_read_is_unavailable(tmp_path) -> None:
    env = Env(tmp_path)
    pair = env.with_item()
    env.write_marker("vault", pair.fingerprint)

    async def offline_read(item_type, fingerprint):
        raise OFFLINE

    env.items.read = offline_read
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.UNAVAILABLE and result.reason == "vault_unreadable"


@pytest.mark.asyncio
async def test_offline_keys_me_is_unavailable_with_and_without_an_item(tmp_path) -> None:
    for unlocked in (True, False):
        env = Env(tmp_path / str(unlocked), unlocked=unlocked)
        if unlocked:
            env.with_item()
        env.api.get = AsyncMock(side_effect=OFFLINE)
        result = await env.custody.resolve()
        assert result.kind is ResolutionKind.UNAVAILABLE and result.reason == "keys_me_unavailable"


@pytest.mark.asyncio
async def test_offline_user_id_lookup_is_unavailable(tmp_path) -> None:
    env = Env(tmp_path)
    env.auth.fetch_user_id = AsyncMock(side_effect=OFFLINE)
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.UNAVAILABLE and result.reason == "user_id_unavailable"


@pytest.mark.asyncio
async def test_offline_identity_check_is_unavailable(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False, identity=True)
    env.identity.side_effect = OFFLINE
    with pytest.raises(VaultCustodyUnavailable):
        await env.custody.enrolment_mode()


@pytest.mark.asyncio
async def test_offline_throttled_check_keeps_the_fast_path(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.keys_json.parent.mkdir(parents=True)
    env.keys_json.write_text("{}")
    env.api.get = AsyncMock(side_effect=OFFLINE)
    assert (await env.custody.resolve()).kind is ResolutionKind.PASSPHRASE


@pytest.mark.asyncio
async def test_offline_cleanup_never_raises(tmp_path) -> None:
    env = Env(tmp_path)
    old, new = env.with_item(), env.with_item()
    env.api.get = AsyncMock(side_effect=OFFLINE)
    assert await env.custody.retry_pending_item_cleanup() is False
    assert sorted(env.items.payloads) == sorted([old.fingerprint, new.fingerprint])


@pytest.mark.asyncio
async def test_a_delete_that_goes_offline_keeps_the_item(tmp_path) -> None:
    env = Env(tmp_path)
    old, new = env.with_item(), env.with_item()
    env.keys_me(**_record(new, custody="vault", wrapped_private_key=None))
    env.items.delete_errors[old.fingerprint] = OFFLINE
    assert await env.custody.retry_pending_item_cleanup() is False
    assert old.fingerprint in env.items.payloads


@pytest.mark.asyncio
async def test_unlock_from_vault_offline_is_unavailable_even_if_resolve_raises(tmp_path) -> None:
    env = Env(tmp_path)
    sync = _sync_with(env)
    env.custody.resolve = AsyncMock(side_effect=OFFLINE)
    assert await sync.unlock_from_vault() is VaultUnlock.UNAVAILABLE


@pytest.mark.asyncio
async def test_unlock_from_vault_with_a_vault_user_offline(tmp_path) -> None:
    env = Env(tmp_path)
    env.items.list_error = OFFLINE
    assert await _sync_with(env).unlock_from_vault() is VaultUnlock.UNAVAILABLE


@pytest.mark.asyncio
async def test_bootstrap_offline_shows_a_plain_message(tmp_path) -> None:
    env = Env(tmp_path)
    env.items.list_error = OFFLINE
    sync = _sync_with(env)
    with pytest.raises(VaultCustodyUnavailable) as caught:
        await sync._ensure_keypair(AsyncMock())
    text = describe_sync_error(caught.value, failure_prefix="Setup failed")
    assert "vault_unreadable" not in text and text.startswith("Your vault could not be read")


# --- A2: the lookup never waits for the limiter -------------------------------

def _fill_keys_me(limiter: RateLimiter) -> None:
    """Use up the whole ``/keys/me`` window, whatever size it is configured to."""
    capacity = limiter._limits[RateLimitKey.KEYS_ME].capacity
    for _ in range(capacity):
        limiter._timestamps[RateLimitKey.KEYS_ME].append(__import__("time").monotonic())


@pytest.mark.asyncio
async def test_a_full_keys_me_window_answers_unavailable_without_waiting(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    limiter = env.custody._limiter
    _fill_keys_me(limiter)
    result = await asyncio.wait_for(env.custody.resolve(), timeout=1.0)  # a hang fails here
    assert result.kind is ResolutionKind.UNAVAILABLE and result.reason == "keys_me_unavailable"
    assert isinstance(result.error, VaultCustodyUnavailable) and str(result.error) == "keys_me_limited"
    env.api.get.assert_not_called()


@pytest.mark.asyncio
async def test_a_429_ratchet_does_not_block_the_lookup_either(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.api.get = AsyncMock(side_effect=RateLimitedError(code="rate_limited", message="m", status=429))
    await env.custody.resolve()
    second = await asyncio.wait_for(env.custody.resolve(), timeout=1.0)
    assert second.kind is ResolutionKind.UNAVAILABLE
    assert env.api.get.await_count == 1


@pytest.mark.asyncio
async def test_set_up_after_the_screen_check_does_not_hang_on_the_fourth_lookup(tmp_path) -> None:
    """Start-up x2, the screen's resolve, then Set up's own checks: all within the window."""
    env = Env(tmp_path)  # open vault, nothing enrolled
    sync = _sync_with(env)
    await env.custody.resolve(quiet=True)
    await env.custody.resolve(quiet=True)
    assert (await asyncio.wait_for(env.custody.resolve(), 1.0)).kind is ResolutionKind.NOT_ENROLLED
    await asyncio.wait_for(env.custody.enrol_in_vault(), 1.0)  # _require_no_service_key
    assert env.api.get.await_count == 1  # one lookup shared by all of them
    assert sync.key_source is None


@pytest.mark.asyncio
async def test_the_kept_answer_expires_after_the_recheck_interval(tmp_path) -> None:
    clock = [1_000_000.0]
    env = Env(tmp_path, unlocked=False, clock=lambda: clock[0])
    await env.custody.resolve()
    await env.custody.resolve()
    assert env.api.get.await_count == 1
    clock[0] += 61
    await env.custody.resolve()
    assert env.api.get.await_count == 2


@pytest.mark.asyncio
async def test_rotation_reads_the_service_fresh(tmp_path) -> None:
    env = Env(tmp_path)
    old = env.with_item()
    env.keys_me(**_record(old, custody="vault", wrapped_private_key=None))
    env.write_marker("vault", old.fingerprint)
    await env.custody.resolve()
    await env.custody.rotate_in_vault(AsyncMock(return_value=None))
    assert env.api.get.await_count >= 1


@pytest.mark.asyncio
async def test_quiet_never_asks_the_service_when_nothing_local_says_there_is_a_key(tmp_path) -> None:
    for unlocked in (True, False):
        env = Env(tmp_path / str(unlocked), unlocked=unlocked)
        assert (await env.custody.resolve(quiet=True)).kind is ResolutionKind.NOT_ENROLLED
        env.api.get.assert_not_called()


@pytest.mark.asyncio
async def test_quiet_with_a_key_file_makes_no_call_even_when_the_check_is_due(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.keys_json.parent.mkdir(parents=True)
    env.keys_json.write_text("{}")
    result = await env.custody.resolve(quiet=True)
    assert result.kind is ResolutionKind.PASSPHRASE
    env.api.get.assert_not_called()


@pytest.mark.asyncio
async def test_quiet_bootstrap_never_enrols(tmp_path) -> None:
    env = Env(tmp_path)
    sync = _sync_with(env)
    with pytest.raises(VaultCustodyUnavailable):
        await sync._ensure_keypair(AsyncMock(), quiet=True)
    assert env.items.created == []
    env.api.request_signed.assert_not_called()


# --- A3: an interrupted move is not vault custody ------------------------------

@pytest.mark.asyncio
async def test_item_matching_a_passphrase_custody_key_is_pending_not_vault(tmp_path) -> None:
    env = Env(tmp_path)
    pair = env.with_item()
    env.keys_me(**_record(pair, wrapped_private_key="{}"))  # service: still passphrase
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.VAULT_KEY and result.custody == "passphrase"
    assert env.marker()["custody"] == "passphrase"
    sync = _sync_with(env)
    assert await sync.unlock_from_vault() is VaultUnlock.OK
    assert sync.key_source == KEY_SOURCE_VAULT_PENDING


@pytest.mark.asyncio
async def test_bootstrap_with_a_pending_item_marks_the_source_pending(tmp_path) -> None:
    env = Env(tmp_path)
    pair = env.with_item()
    env.keys_me(**_record(pair, wrapped_private_key="{}"))
    sync = _sync_with(env)
    await sync._ensure_keypair(AsyncMock())
    assert sync.key_source == KEY_SOURCE_VAULT_PENDING


@pytest.mark.asyncio
async def test_confirmed_vault_custody_is_the_vault_source(tmp_path) -> None:
    env = Env(tmp_path)
    pair = env.with_item()
    env.keys_me(**_record(pair, custody="vault", wrapped_private_key=None))
    sync = _sync_with(env)
    await sync.unlock_from_vault()
    assert sync.key_source == "vault"


@pytest.mark.asyncio
async def test_a_passphrase_marker_is_not_trusted_for_an_item(tmp_path) -> None:
    env = Env(tmp_path)
    pair = env.with_item()
    env.write_marker("passphrase", pair.fingerprint)
    env.keys_me(**_record(pair, wrapped_private_key="{}"))
    result = await env.custody.resolve()
    assert env.api.get.await_count == 1  # the service decided, not the marker
    assert result.custody == "passphrase"


@pytest.mark.asyncio
async def test_a_vault_marker_still_skips_the_lookup(tmp_path) -> None:
    env = Env(tmp_path)
    pair = env.with_item()
    env.write_marker("vault", pair.fingerprint)
    result = await env.custody.resolve()
    assert result.custody == "vault"
    env.api.get.assert_not_called()


def _app_stub(sync):
    from types import SimpleNamespace
    import types

    from servonaut.app import ServonautApp

    stub = SimpleNamespace(
        memory_sync_service=sync, memory_key_custody=MagicMock(),
        config_manager=MagicMock(),
    )
    stub._forget_memory_passphrase_leftovers = MagicMock()
    stub._after_memory_unlock = types.MethodType(ServonautApp._after_memory_unlock, stub)
    return stub


@pytest.mark.asyncio
async def test_no_passphrase_cleanup_for_a_pending_key(tmp_path) -> None:
    sync = MagicMock()
    sync.key_source = KEY_SOURCE_VAULT_PENDING
    sync.retry_pending_item_cleanup = AsyncMock()
    stub = _app_stub(sync)
    await stub._after_memory_unlock()
    stub._forget_memory_passphrase_leftovers.assert_not_called()
    sync.retry_pending_item_cleanup.assert_not_called()


@pytest.mark.asyncio
async def test_passphrase_cleanup_runs_for_a_confirmed_vault_key(tmp_path) -> None:
    sync = MagicMock()
    sync.key_source = "vault"
    sync.retry_pending_item_cleanup = AsyncMock()
    stub = _app_stub(sync)
    await stub._after_memory_unlock()
    stub._forget_memory_passphrase_leftovers.assert_called_once()


# --- A8: cleanup follows the service, not the marker ---------------------------

@pytest.mark.asyncio
async def test_cleanup_deletes_by_the_service_active_key_not_a_stale_marker(tmp_path) -> None:
    env = Env(tmp_path)
    stale, active = env.with_item(), env.with_item()
    env.write_marker("vault", stale.fingerprint)  # another device rotated since
    env.keys_me(**_record(active, custody="vault", wrapped_private_key=None))
    assert await env.custody.retry_pending_item_cleanup() is True
    assert env.items.deleted == [stale.fingerprint]
    assert list(env.items.payloads) == [active.fingerprint]


@pytest.mark.asyncio
async def test_cleanup_does_nothing_when_the_service_does_not_say_vault(tmp_path) -> None:
    env = Env(tmp_path)
    one, two = env.with_item(), env.with_item()
    env.write_marker("vault", one.fingerprint)
    env.keys_me(**_record(one, wrapped_private_key="{}"))
    assert await env.custody.retry_pending_item_cleanup() is False
    assert env.items.deleted == []


# --- A9: only a definite refusal deletes the new item --------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("status", [500, 502, 503, 504, 408])
async def test_enrol_keeps_the_item_when_the_post_may_have_been_applied(tmp_path, status) -> None:
    env = Env(tmp_path)
    env.api.request_signed = AsyncMock(side_effect=APIError(code="server_error", message="m", status=status))
    with pytest.raises(APIError):
        await env.custody.enrol_in_vault()
    assert env.items.deleted == [] and len(env.items.payloads) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 403, 409, 422, 429])
async def test_enrol_deletes_the_item_on_a_definite_refusal(tmp_path, status) -> None:
    env = Env(tmp_path)
    env.api.request_signed = AsyncMock(side_effect=APIError(code="refused", message="m", status=status))
    with pytest.raises(APIError):
        await env.custody.enrol_in_vault()
    assert len(env.items.deleted) == 1 and env.items.payloads == {}


@pytest.mark.asyncio
async def test_the_kill_switch_503_is_a_definite_refusal(tmp_path) -> None:
    env = Env(tmp_path)
    env.api.request_signed = AsyncMock(
        side_effect=FeatureDisabledError(code="feature_disabled", message="m", status=503))
    with pytest.raises(FeatureDisabledError):
        await env.custody.enrol_in_vault()
    assert env.items.payloads == {}


@pytest.mark.asyncio
async def test_rotation_keeps_the_next_item_on_a_5xx_and_drops_it_on_a_4xx(tmp_path) -> None:
    for status, kept in ((502, True), (409, False)):
        env = Env(tmp_path / str(status))
        old = env.with_item()
        env.keys_me(**_record(old, custody="vault", wrapped_private_key=None))
        env.write_marker("vault", old.fingerprint)
        env.api.request_signed = AsyncMock(side_effect=APIError(code="x", message="m", status=status))
        with pytest.raises(APIError):
            await env.custody.rotate_in_vault(AsyncMock(return_value=None))
        assert (len(env.items.payloads) == 2) is kept


# --- A10: a malformed answer is not vault custody ------------------------------

@pytest.mark.parametrize("data", [{}, {"fingerprint": "f"}, {"public_key": "p"},
                                  {"fingerprint": "", "public_key": "p"}, {"fingerprint": 1, "public_key": "p"}])
def test_a_record_without_an_identity_is_unreadable(data) -> None:
    with pytest.raises(VaultCustodyUnavailable):
        parse_key_record(data)


@pytest.mark.asyncio
async def test_empty_200_is_unavailable_and_runs_no_cleanup(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.api.get = AsyncMock(return_value={})
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.UNAVAILABLE and result.reason == "keys_me_unavailable"
    assert not env.marker_path.exists()
    env.detected.assert_not_called()


@pytest.mark.asyncio
async def test_empty_200_on_the_key_file_check_runs_no_cleanup(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    env.keys_json.parent.mkdir(parents=True)
    env.keys_json.write_text("{}")
    env.api.get = AsyncMock(return_value={})
    result = await env.custody.resolve()
    assert result.kind is ResolutionKind.PASSPHRASE
    env.detected.assert_not_called()
    assert not env.marker_path.exists()


# --- A12: plain wording ----------------------------------------------------------

@pytest.mark.parametrize("reason", [
    "vault_unreadable", "vault_key_invalid", "keys_me_unavailable", "keys_me_limited",
    "user_id_unavailable",
])
def test_unavailable_reasons_map_to_plain_sentences(reason) -> None:
    text = custody_error_message(VaultCustodyUnavailable(reason))
    assert text and reason not in text and text[0].isupper() and text.endswith(".")
    assert describe_sync_error(VaultCustodyUnavailable(reason), failure_prefix="Setup failed") == text


def test_an_unmapped_unavailable_text_is_left_to_the_caller() -> None:
    assert custody_error_message(VaultCustodyUnavailable("Could not check your vault.")) is None


def test_feature_disabled_has_vault_wording_only_for_vault_calls() -> None:
    error = FeatureDisabledError(code="feature_disabled", message="m", status=503)
    assert "in the vault" in custody_error_message(error)  # custody callers (default context)
    assert custody_error_message(error, CONTEXT_GENERAL) is None
    assert "vault" not in describe_sync_error(error, failure_prefix="Sync failed").lower()


@pytest.mark.asyncio
async def test_the_enrolment_kill_switch_keeps_the_vault_wording_in_set_up(tmp_path) -> None:
    env = Env(tmp_path)
    env.api.request_signed = AsyncMock(
        side_effect=FeatureDisabledError(code="feature_disabled", message="svc", status=503))
    sync = _sync_with(env)
    with pytest.raises(VaultCustodyUnavailable) as caught:
        await sync._ensure_keypair(AsyncMock())
    assert "vault" in describe_sync_error(caught.value, failure_prefix="Setup failed")


@pytest.mark.asyncio
async def test_a_rate_limited_lookup_reads_as_a_rate_limit_in_set_up(tmp_path) -> None:
    env = Env(tmp_path, unlocked=False)
    _fill_keys_me(env.custody._limiter)
    sync = _sync_with(env)
    with pytest.raises(Exception) as caught:
        await asyncio.wait_for(sync._ensure_keypair(AsyncMock()), 1.0)
    assert "rate limit" in describe_sync_error(caught.value, failure_prefix="Setup failed").lower()


# --- B7 support: one marker path ---------------------------------------------------

def test_the_default_marker_path_is_public_and_beside_the_key_file() -> None:
    assert DEFAULT_MARKER_PATH.name == "key_custody.json"
    assert DEFAULT_MARKER_PATH.parent.name == "memory"
    assert DEFAULT_MARKER_PATH.parent.parent.name == ".servonaut"


def test_the_marker_never_holds_a_private_key(tmp_path) -> None:
    env = Env(tmp_path)
    pair = env.with_item()
    env.keys_me(**_record(pair, custody="vault", wrapped_private_key=None))
    asyncio.run(env.custody.resolve())
    raw = env.marker_path.read_text()
    assert base64.b64encode(pair.private_key).decode() not in raw
    assert set(json.loads(raw)) <= {"v", "user_id", "custody", "fingerprint", "public_key", "checked_at"}

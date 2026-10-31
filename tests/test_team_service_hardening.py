"""The member directory and the pre-revoke check refuse what cannot be sealed for."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock

import pytest

from servonaut.services.memory import crypto as crypto_module
from servonaut.services.memory.team_service import TeamMemberKey, UnusableMemberKeyError
from tests.test_team_key_confirmation import SLUG, OWNER, _member, _pair, _service, run
from tests.test_team_wraps_hardening import LOW_ORDER_KEYS


def _row(uid, member, **extra):
    row = {"user_id": uid, "fingerprint": member.fingerprint,
           "public_key_b64": member.public_key_b64, "role": "member", "name": "Lee",
           "key_changed": False}
    row.update(extra)
    return row


def test_a_directory_row_without_a_key_is_dropped_alone(tmp_path):
    svc, api, _ = _service(tmp_path)
    good, _p = _member(2)
    api.get.return_value = {"members": [
        {"user_id": 3, "fingerprint": None, "public_key_b64": None, "role": "member"},
        {"user_id": 4, "role": "member"},
        _row(2, good),
    ]}
    assert [m.user_id for m in run(svc.list_team_member_keys(SLUG))] == [2]


@pytest.mark.parametrize("bad", ["[/bold]", "[link=https://x", "A" * 64, "a" * 63, 7])
def test_a_malformed_previous_fingerprint_in_the_directory_is_dropped(tmp_path, bad):
    svc, api, _ = _service(tmp_path)
    member, _p = _member(2, flagged=True)
    api.get.return_value = {"members": [_row(2, member, key_changed=True, previous_fingerprint=bad)]}
    [lee] = run(svc.list_team_member_keys(SLUG))
    assert lee.previous_fingerprint is None


def test_a_directory_row_with_a_malformed_fingerprint_is_dropped(tmp_path):
    svc, api, _ = _service(tmp_path)
    member, _p = _member(2)
    api.get.return_value = {"members": [dict(_row(2, member), fingerprint="[bold]x")]}
    assert run(svc.list_team_member_keys(SLUG)) == []


def _low_order_member(key):
    return TeamMemberKey(2, crypto_module.fingerprint(key), base64.b64encode(key).decode(),
                         "member", "Lee")


@pytest.mark.parametrize("key", LOW_ORDER_KEYS, ids=lambda k: k[:2].hex())
def test_share_again_refuses_a_low_order_key_before_it_revokes(tmp_path, key):
    svc, api, pins = _service(tmp_path)
    lee = _low_order_member(key)
    pins.set_many({(SLUG, 2): lee.fingerprint})  # even a confirmed pin cannot make it sealable
    fine, _p = _member(3, "Kim")
    with pytest.raises(UnusableMemberKeyError):
        run(svc.reshare_instance(SLUG, "g", OWNER, "member", ["os"], [fine, lee]))
    api.delete.assert_not_awaited()
    api.post.assert_not_awaited()


# --- top-up: data keys come only from the caller's own envelope ----------

import nacl.public  # noqa: E402

from servonaut.services.api_client import APIError  # noqa: E402
from servonaut.services.memory.interfaces import MemoryBackendError  # noqa: E402
from servonaut.services.memory.team_service import (  # noqa: E402
    ServiceBusyError,
    ShareGoneError,
)
from servonaut.services.memory.team_wraps import KeyChange, pinned_fingerprint  # noqa: E402
from tests.test_team_key_confirmation import _coverage, _descriptor  # noqa: E402

STORED = {"wraps_stored": 1, "wraps_unchanged": 0, "skipped_recipients": []}


def _top_up(svc, modules=("os",), instance=OWNER):
    return run(svc.top_up_grant(SLUG, "g", instance, None if modules is None else list(modules)))


@pytest.mark.parametrize("override", [{"grant_id": "other"}, {"instance_id": "other"},
                                      {"grant_id": None}, {"instance_id": None}])
def test_a_coverage_reply_for_another_share_is_refused_before_any_crypto(tmp_path, override):
    svc, api, _ = _service(tmp_path)
    api.get.return_value = dict(_coverage(svc, [_descriptor(3, _pair())]), **override)
    with pytest.raises(MemoryBackendError):
        _top_up(svc)
    api.post.assert_not_awaited()
    svc._retrieval_service.get_module_envelope_raw.assert_not_awaited()


def test_an_envelope_that_is_not_the_callers_latest_is_skipped(tmp_path):
    svc, api, _ = _service(tmp_path)
    payload = _coverage(svc, [_descriptor(3, _pair())])
    payload["envelopes"][0]["envelope_id"] = "e-foreign"
    api.get.return_value = payload
    _top_up(svc)
    api.post.assert_not_awaited()


def test_a_module_outside_the_share_is_not_resealed(tmp_path):
    svc, api, _ = _service(tmp_path)
    api.get.return_value = _coverage(svc, [_descriptor(3, _pair())])
    _top_up(svc, modules=("services",))
    api.post.assert_not_awaited()
    api.post.return_value = STORED
    _top_up(svc, modules=None)  # None means every module
    api.post.assert_awaited_once()


def _dek_of(wrapped_b64, private_key):
    return nacl.public.SealedBox(nacl.public.PrivateKey(private_key)).decrypt(
        base64.b64decode(wrapped_b64))


def test_the_data_key_is_the_one_in_the_callers_own_envelope_not_the_replys(tmp_path):
    svc, api, _ = _service(tmp_path)
    own_wrap = svc.own_wrap()
    foreign_wrap = svc.own_wrap()  # a different data key, wrapped for the owner too
    owner_private = svc._key_store_provider().private_key
    svc._retrieval_service.get_module_envelope_raw = AsyncMock(
        return_value={"id": "e-os", "wrapped_dek": own_wrap})
    member = _pair()
    api.get.return_value = _coverage(svc, [_descriptor(3, member)], wrapped=foreign_wrap)
    api.post.return_value = STORED
    _top_up(svc)
    [wrap] = api.post.await_args.kwargs["json"]["wraps"]
    dek = _dek_of(wrap["wrapped_dek"], member.private_key)
    assert dek == _dek_of(own_wrap, owner_private)
    assert dek != _dek_of(foreign_wrap, owner_private)


@pytest.mark.parametrize("raw", [{"id": "e-os"}, {"wrapped_dek": "x"}, {"id": "e-os", "wrapped_dek": "!!"}])
def test_an_own_envelope_without_a_usable_wrap_is_skipped(tmp_path, raw):
    svc, api, _ = _service(tmp_path)
    svc._retrieval_service.get_module_envelope_raw = AsyncMock(return_value=raw)
    api.get.return_value = _coverage(svc, [_descriptor(3, _pair())])
    _top_up(svc)
    api.post.assert_not_awaited()


# --- top-up: report and pin only what the service stored -----------------

def test_a_wrap_the_service_skipped_is_neither_reported_nor_pinned(tmp_path):
    svc, api, pins = _service(tmp_path)
    kept, skipped = _pair(), _pair()
    api.get.return_value = _coverage(svc, [_descriptor(3, kept, name="Kim"),
                                           _descriptor(4, skipped, name="Lee")])
    api.post.return_value = {"wraps_stored": 1, "wraps_unchanged": 0,
                             "skipped_recipients": [{"user_id": 4, "reason": "key_changed"}]}
    result = _top_up(svc)
    assert result.sealed_names == ("Kim",)
    assert result.skipped_names == ("Lee",)
    assert pinned_fingerprint(pins, SLUG, 3) == kept.fingerprint
    assert pinned_fingerprint(pins, SLUG, 4) is None


@pytest.mark.parametrize("answer", [
    {"wraps_stored": 1}, None, [], "ok",
    {"wraps_stored": "1", "wraps_unchanged": 0, "skipped_recipients": []},
    {"wraps_stored": 1, "wraps_unchanged": 0, "skipped_recipients": "x"},
    {"wraps_stored": 1, "wraps_unchanged": 0, "skipped_recipients": [{"user_id": "4"}]},
    {"wraps_stored": 0, "wraps_unchanged": 0, "skipped_recipients": []},
])
def test_a_response_that_cannot_be_read_counts_every_wrap_as_not_stored(tmp_path, answer):
    svc, api, pins = _service(tmp_path)
    pair = _pair()
    api.get.return_value = _coverage(svc, [_descriptor(3, pair, name="Kim")])
    api.post.return_value = answer
    result = _top_up(svc)
    assert result.sealed_names == () and result.skipped_names == ("Kim",)
    assert pinned_fingerprint(pins, SLUG, 3) is None


def test_unchanged_wraps_count_as_stored(tmp_path):
    svc, api, pins = _service(tmp_path)
    pair = _pair()
    api.get.return_value = _coverage(svc, [_descriptor(3, pair, name="Kim")])
    api.post.return_value = {"wraps_stored": 0, "wraps_unchanged": 1, "skipped_recipients": []}
    assert _top_up(svc).sealed_names == ("Kim",)
    assert pinned_fingerprint(pins, SLUG, 3) == pair.fingerprint


# --- grant create carries the fingerprint --------------------------------

def test_share_sends_the_derived_fingerprint_with_every_wrap(tmp_path):
    svc, api, _ = _service(tmp_path)
    lee, _p = _member(2, "Lee")
    run(svc.share_instance(SLUG, OWNER, "member", ["os"], [lee]))
    [call] = api.post.await_args_list
    [wrap] = call.kwargs["json"]["wraps"]
    assert wrap["recipient_fingerprint"] == lee.fingerprint


# --- which 409 means the share is gone -----------------------------------

def _conflict(code):
    return APIError(code=code, message="m", status=409)


def test_grant_not_live_means_the_share_is_gone_on_coverage_and_top_up(tmp_path):
    svc, api, _ = _service(tmp_path)
    api.get.side_effect = _conflict("grant_not_live")
    with pytest.raises(ShareGoneError):
        run(svc.grant_coverage(SLUG, "g"))
    api.get.side_effect = None
    api.get.return_value = _coverage(svc, [_descriptor(3, _pair())])
    api.post.side_effect = _conflict("grant_not_live")
    with pytest.raises(ShareGoneError):
        _top_up(svc)


def test_conflict_retry_is_a_retryable_busy_error_not_a_gone_share(tmp_path):
    svc, api, _ = _service(tmp_path)
    api.get.return_value = _coverage(svc, [_descriptor(3, _pair())])
    api.post.side_effect = _conflict("conflict_retry")
    with pytest.raises(ServiceBusyError) as err:
        _top_up(svc)
    assert not isinstance(err.value, ShareGoneError)
    assert "Try again" in str(err.value)
    api.get.side_effect = _conflict("conflict_retry")
    with pytest.raises(ServiceBusyError):
        run(svc.grant_coverage(SLUG, "g"))


def test_an_unknown_409_is_neither_gone_nor_busy(tmp_path):
    svc, api, _ = _service(tmp_path)
    api.get.side_effect = _conflict("something_else")
    with pytest.raises(APIError) as err:
        run(svc.grant_coverage(SLUG, "g"))
    assert not isinstance(err.value, (ShareGoneError, ServiceBusyError))


# --- confirming keeps to the team and to real user ids -------------------

def test_a_confirmation_for_another_team_or_a_bad_user_id_writes_nothing(tmp_path):
    svc, _, pins = _service(tmp_path)
    good = KeyChange(SLUG, 2, "Lee", "a" * 64)
    for bad in (KeyChange("team-b", 3, "Kim", "a" * 64),
                KeyChange(SLUG, 0, "Kim", "a" * 64), KeyChange(SLUG, -4, "Kim", "a" * 64),
                KeyChange(SLUG, True, "Kim", "a" * 64), KeyChange(SLUG, "3", "Kim", "a" * 64)):
        with pytest.raises(ValueError):
            svc.confirm_member_keys(SLUG, [good, bad])
    assert pinned_fingerprint(pins, SLUG, 2) is None

"""Confirming a changed member key unblocks Share, Share again and the top-up."""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock

import nacl.public
import pytest

import servonaut.services.memory.crypto as crypto_module
from servonaut.services.api_client import APIClient, APIError
from servonaut.services.memory.team_service import (
    KeyChangedError,
    ShareGoneError,
    TeamMemberKey,
    TeamMemoryService,
    UnusableMemberKeyError,
)
from servonaut.services.memory.team_wraps import KeyChange, WrapPinStore, pinned_fingerprint

SLUG = "team-a"
OWNER = "i-owner-1"
GRANT = {"id": "g", "instance_id": OWNER, "required_role": "member", "modules": ["os"],
         "created_at": "2026-10-01T10:00:00Z", "skipped_recipients": []}


def run(coro):
    return asyncio.run(coro)


def _pair():
    return crypto_module.generate_keypair()


def _member(uid, name="Kim", *, flagged=False, pair=None, **extra):
    pair = pair or _pair()
    return TeamMemberKey(uid, pair.fingerprint, base64.b64encode(pair.public_key).decode(),
                         "member", name, key_changed=flagged, **extra), pair


def _service(tmp_path):
    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value=dict(GRANT))
    api.delete = AsyncMock(return_value=dict(GRANT, status="revoked"))
    api.get = AsyncMock()
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=True)
    owner = _pair()
    km = MagicMock(user_id=1, private_key=owner.private_key, public_key=owner.public_key)

    def own_wrap():
        env = crypto_module.encrypt_envelope(b"{}", self_public_key=km.public_key,
                                             self_user_id=1).to_dict()
        return env["dek_wraps"][0]["wrapped_dek"]

    async def raw(_i, _m):
        return {"id": "e-os", "wrapped_dek": own_wrap()}

    retrieval = MagicMock(list_instance_modules=AsyncMock(return_value={"modules": ["os"]}),
                          get_module_envelope_raw=AsyncMock(side_effect=raw))
    pins = WrapPinStore(tmp_path / "pins.json")
    svc = TeamMemoryService(api_client=api, auth_service=auth, crypto=crypto_module,
                            key_store_provider=lambda: km, retrieval_service=retrieval,
                            pin_store_provider=lambda: pins)
    svc.own_wrap = own_wrap
    return svc, api, pins


# --- parsing -------------------------------------------------------------

def test_the_member_directory_keeps_the_previous_fingerprint_and_rotation_time(tmp_path):
    svc, api, _ = _service(tmp_path)
    member, _pair_ = _member(2, flagged=True)
    api.get.return_value = {"members": [
        {"user_id": 2, "fingerprint": member.fingerprint, "public_key_b64": member.public_key_b64,
         "role": "member", "name": "Lee", "key_changed": True,
         "previous_fingerprint": "c" * 64, "key_rotated_at": "2026-10-30T10:00:00Z"},
        {"user_id": 3, "fingerprint": member.fingerprint, "public_key_b64": member.public_key_b64,
         "role": "member", "name": "Kim", "key_changed": False,
         "previous_fingerprint": 7, "key_rotated_at": {"x": 1}},
    ]}
    lee, kim = run(svc.list_team_member_keys(SLUG))
    assert (lee.previous_fingerprint, lee.key_rotated_at) == ("c" * 64, "2026-10-30T10:00:00Z")
    assert (kim.previous_fingerprint, kim.key_rotated_at) == (None, None)


# --- Share / Share again -------------------------------------------------

def test_a_flagged_member_without_a_pin_raises_key_changed_with_the_details(tmp_path):
    svc, api, _ = _service(tmp_path)
    lee, _ = _member(2, "Lee", flagged=True, previous_fingerprint="c" * 64,
                     key_rotated_at="2026-10-30T10:00:00Z")
    with pytest.raises(KeyChangedError) as err:
        run(svc.share_instance(SLUG, OWNER, "member", ["os"], [lee]))
    assert err.value.names == ["Lee"]
    [change] = err.value.changes
    assert change == KeyChange(SLUG, 2, "Lee", lee.fingerprint, "c" * 64, "2026-10-30T10:00:00Z")
    api.post.assert_not_awaited()


def test_a_flagged_member_whose_key_was_confirmed_is_shared_with(tmp_path):
    """The service flags a rotated key for good: a confirmed pin must unblock it."""
    svc, api, pins = _service(tmp_path)
    lee, _ = _member(2, "Lee", flagged=True)
    pins.set_many({(SLUG, 2): lee.fingerprint})
    run(svc.share_instance(SLUG, OWNER, "member", ["os"], [lee]))
    [call] = api.post.await_args_list
    assert [w["recipient_user_id"] for w in call.kwargs["json"]["wraps"]] == [2]


def test_confirm_member_keys_pins_and_then_the_share_goes_through(tmp_path):
    svc, api, pins = _service(tmp_path)
    lee, _ = _member(2, "Lee", flagged=True)
    with pytest.raises(KeyChangedError) as err:
        run(svc.reshare_instance(SLUG, "g", OWNER, "member", ["os"], [lee]))
    api.delete.assert_not_awaited()
    svc.confirm_member_keys(SLUG, err.value.changes)
    assert pinned_fingerprint(pins, SLUG, 2) == lee.fingerprint
    run(svc.reshare_instance(SLUG, "g", OWNER, "member", ["os"], [lee]))
    api.delete.assert_awaited_once()


def test_an_unusable_key_is_a_different_error_and_not_confirmable(tmp_path):
    svc, api, _ = _service(tmp_path)
    bad = TeamMemberKey(2, "d" * 64, "not base64!!", "member", "Lee")
    with pytest.raises(UnusableMemberKeyError) as err:
        run(svc.reshare_instance(SLUG, "g", OWNER, "member", ["os"], [bad]))
    assert not isinstance(err.value, KeyChangedError)
    assert err.value.names == ["Lee"]
    assert "does not match" in str(err.value) and "nothing was changed" in str(err.value).lower()
    api.delete.assert_not_awaited()


def test_confirm_member_keys_refuses_a_bad_fingerprint_or_slug(tmp_path):
    svc, _, pins = _service(tmp_path)
    good = KeyChange(SLUG, 2, "Lee", "a" * 64)
    for bad in (KeyChange(SLUG, 2, "Lee", "A" * 64), KeyChange(SLUG, 2, "Lee", "short")):
        with pytest.raises(ValueError):
            svc.confirm_member_keys(SLUG, [good, bad])
    with pytest.raises(ValueError):
        svc.confirm_member_keys("../x", [good])
    assert pinned_fingerprint(pins, SLUG, 2) is None  # nothing written by a refused batch


# --- coverage and top-up -------------------------------------------------

def _descriptor(uid, pair, *, flagged=False, name=None):
    return {"user_id": uid, "name": name or f"member-{uid}", "fingerprint": pair.fingerprint,
            "public_key_b64": base64.b64encode(pair.public_key).decode(),
            "key_changed": flagged, "previous_fingerprint": None, "key_rotated_at": None}


def _coverage(svc, missing, *, wrapped="own"):
    return {"grant_id": "g", "instance_id": OWNER,
            "envelopes": [{"envelope_id": "e-os", "module": "os", "snapshot_version": 3,
                           "wrapped_dek": svc.own_wrap() if wrapped == "own" else wrapped,
                           "missing_recipients": missing}],
            "pending_recipients": [{"user_id": 9, "name": "Sam", "role": "member",
                                    "reason": "no_memory_key"}]}


def test_grant_coverage_parses_strictly_and_drops_bad_entries_whole(tmp_path):
    svc, api, _ = _service(tmp_path)
    pair = _pair()
    payload = _coverage(svc, [_descriptor(2, pair), {"user_id": "x"}, _descriptor(3, _pair())])
    payload["envelopes"].append({"envelope_id": "../bad", "module": "os", "missing_recipients": []})
    payload["envelopes"].append("junk")
    api.get.return_value = payload
    coverage = run(svc.grant_coverage(SLUG, "g"))
    assert [e.envelope_id for e in coverage.envelopes] == ["e-os"]
    assert [r.user_id for r in coverage.envelopes[0].missing] == [2, 3]
    assert coverage.pending[0]["user_id"] == 9
    api.get.assert_awaited_once_with(f"/api/v1/teams/{SLUG}/memory/grant/g/wraps")


@pytest.mark.parametrize("status", [404, 409])
def test_coverage_of_a_gone_share_is_a_typed_error(tmp_path, status):
    svc, api, _ = _service(tmp_path)
    api.get.side_effect = APIError(code="grant_not_live" if status == 409 else "x", message="gone", status=status)
    with pytest.raises(ShareGoneError):
        run(svc.grant_coverage(SLUG, "g"))


def test_top_up_seals_only_for_trusted_or_new_keys_and_pins_what_it_sealed(tmp_path):
    svc, api, pins = _service(tmp_path)
    new_pair, confirmed_pair, waiting_pair = _pair(), _pair(), _pair()
    pins.set_many({(SLUG, 4): confirmed_pair.fingerprint})
    api.get.return_value = _coverage(svc, [
        _descriptor(3, new_pair),
        _descriptor(4, confirmed_pair, flagged=True),
        _descriptor(5, waiting_pair, flagged=True, name="Lee"),
    ])
    api.post.return_value = {"wraps_stored": 2, "wraps_unchanged": 0, "skipped_recipients": []}
    result = run(svc.top_up_grant(SLUG, "g", OWNER, ["os"]))
    [call] = api.post.await_args_list
    assert call.args[0] == f"/api/v1/teams/{SLUG}/memory/grant/g/wraps"
    wraps = call.kwargs["json"]["wraps"]
    assert sorted(w["recipient_user_id"] for w in wraps) == [3, 4]
    assert {w["recipient_user_id"]: w["recipient_fingerprint"] for w in wraps} == {
        3: new_pair.fingerprint, 4: confirmed_pair.fingerprint}
    assert pinned_fingerprint(pins, SLUG, 3) == new_pair.fingerprint
    assert pinned_fingerprint(pins, SLUG, 5) is None
    assert sorted(result.sealed_names) == ["member-3", "member-4"]
    assert [c.name for c in result.waiting] == ["Lee"]


def test_top_up_with_nothing_trusted_posts_nothing(tmp_path):
    svc, api, _ = _service(tmp_path)
    api.get.return_value = _coverage(svc, [_descriptor(5, _pair(), flagged=True, name="Lee")])
    result = run(svc.top_up_grant(SLUG, "g", OWNER, ["os"]))
    api.post.assert_not_awaited()
    assert result.sealed_names == () and [c.user_id for c in result.waiting] == [5]


@pytest.mark.parametrize("status", [404, 409])
def test_top_up_of_a_gone_share_is_a_typed_error_and_pins_nothing(tmp_path, status):
    svc, api, pins = _service(tmp_path)
    pair = _pair()
    api.get.return_value = _coverage(svc, [_descriptor(3, pair)])
    api.post.side_effect = APIError(code="grant_not_live" if status == 409 else "x", message="gone", status=status)
    with pytest.raises(ShareGoneError):
        run(svc.top_up_grant(SLUG, "g", OWNER, ["os"]))
    assert pinned_fingerprint(pins, SLUG, 3) is None


def test_a_wrap_that_opens_with_the_members_own_key(tmp_path):
    svc, api, _ = _service(tmp_path)
    pair = _pair()
    api.get.return_value = _coverage(svc, [_descriptor(3, pair)])
    api.post.return_value = {"wraps_stored": 1, "wraps_unchanged": 0, "skipped_recipients": []}
    run(svc.top_up_grant(SLUG, "g", OWNER, ["os"]))
    wrapped = api.post.await_args.kwargs["json"]["wraps"][0]["wrapped_dek"]
    dek = nacl.public.SealedBox(nacl.public.PrivateKey(pair.private_key)).decrypt(
        base64.b64decode(wrapped))
    assert len(dek) == 32

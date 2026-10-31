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

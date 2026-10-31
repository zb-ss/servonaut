"""One trust rule decides whether a team member's key may be sealed for."""

from __future__ import annotations

import base64

import pytest

from servonaut.services.memory import crypto
from servonaut.services.memory.team_wraps import (
    KeyChange,
    KeyTrust,
    WrapPinStore,
    classify_key,
    parse_missing_team_wraps,
    split_by_trust,
)

KEY = bytes(range(1, 33))  # fixed: parametrize ids must match across xdist workers
KEY_B64 = base64.b64encode(KEY).decode()
FP = crypto.fingerprint(KEY)
OTHER_FP = "b" * 64


@pytest.mark.parametrize(
    "key_b64, claimed, flagged, pinned, expected",
    [
        # the key itself is not usable
        ("not base64!!", FP, False, None, KeyTrust.UNUSABLE),
        (base64.b64encode(b"short").decode(), FP, False, None, KeyTrust.UNUSABLE),
        (KEY_B64, OTHER_FP, False, None, KeyTrust.UNUSABLE),
        (KEY_B64, OTHER_FP, True, FP, KeyTrust.UNUSABLE),
        # a pin that equals the key wins over the service's flag
        (KEY_B64, FP, True, FP, KeyTrust.TRUSTED),
        (KEY_B64, FP, False, FP, KeyTrust.TRUSTED),
        # a pin that differs
        (KEY_B64, FP, False, OTHER_FP, KeyTrust.CHANGED),
        (KEY_B64, FP, True, OTHER_FP, KeyTrust.CHANGED),
        # no pin
        (KEY_B64, FP, True, None, KeyTrust.CHANGED),
        (KEY_B64, FP, False, None, KeyTrust.NEW),
    ],
)
def test_the_trust_rule(key_b64, claimed, flagged, pinned, expected):
    assert classify_key(key_b64, claimed, flagged=flagged, pinned=pinned) is expected


def _descriptor(uid=7, **overrides):
    pair = crypto.generate_keypair()
    raw = {
        "user_id": uid, "name": f"member-{uid}", "fingerprint": pair.fingerprint,
        "public_key_b64": base64.b64encode(pair.public_key).decode(),
        "key_changed": False, "previous_fingerprint": None, "key_rotated_at": None,
    }
    raw.update(overrides)
    return raw


def _entry(*recipients):
    return {"envelope_id": "env-1", "instance_id": "web-1", "module": "os",
            "team_slug": "team-a", "grant_id": "grant-1", "recipients": list(recipients)}


def test_a_flagged_recipient_is_parsed_with_its_key_and_details():
    raw = _descriptor(key_changed=True, previous_fingerprint="c" * 64,
                      key_rotated_at="2026-10-30T10:00:00Z")
    [entry] = parse_missing_team_wraps([_entry(raw)])
    [recipient] = entry.recipients
    assert recipient.flagged is True
    assert recipient.name == "member-7"
    assert recipient.fingerprint == raw["fingerprint"]
    assert recipient.previous_fingerprint == "c" * 64
    assert recipient.rotated_at == "2026-10-30T10:00:00Z"


def test_a_flagged_recipient_with_a_lying_fingerprint_is_dropped_like_the_others():
    raw = _descriptor(key_changed=True, fingerprint=OTHER_FP)
    [entry] = parse_missing_team_wraps([_entry(raw)])
    assert entry.recipients == ()


def test_malformed_optional_details_are_dropped_not_trusted():
    raw = _descriptor(previous_fingerprint=5, key_rotated_at=["x"], name=None)
    [entry] = parse_missing_team_wraps([_entry(raw)])
    [recipient] = entry.recipients
    assert recipient.previous_fingerprint is None and recipient.rotated_at is None
    assert recipient.name == ""


def test_split_by_trust_separates_sealable_from_changed(tmp_path):
    pins = WrapPinStore(tmp_path / "pins.json")
    fresh, flagged, swapped, confirmed = (
        _descriptor(1), _descriptor(2, key_changed=True), _descriptor(3), _descriptor(4, key_changed=True),
    )
    pins.set_many({("team-a", 3): OTHER_FP, ("team-a", 4): confirmed["fingerprint"]})
    [entry] = parse_missing_team_wraps([_entry(fresh, flagged, swapped, confirmed)])
    split = split_by_trust(pins, entry)
    assert [r.user_id for r in split.sealable] == [1, 4]
    assert [c.user_id for c in split.changed] == [2, 3]
    assert all(isinstance(c, KeyChange) for c in split.changed)
    swapped_change = split.changed[1]
    assert swapped_change.previous_fingerprint == OTHER_FP  # the pin, when it differs
    assert split.changed[0].team_slug == "team-a"

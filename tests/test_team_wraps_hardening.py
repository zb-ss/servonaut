"""Malformed service data and unusable keys never get past the parsers."""

from __future__ import annotations

import base64
import logging

import pytest

from servonaut.services.memory import crypto
from servonaut.services.memory.team_wraps import (
    KeyTrust,
    classify_key,
    derive_fingerprint,
    parse_grant_coverage,
    parse_missing_team_wraps,
)

# Encodings libsodium refuses to seal to (small-order points of curve25519).
LOW_ORDER_KEYS = [
    bytes([1]) + bytes(31),
    bytes([0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE, 0x16, 0x56, 0xE3, 0xFA, 0xF1,
           0x9F, 0xC4, 0x6A, 0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD, 0x86, 0x62,
           0x05, 0x16, 0x5F, 0x49, 0xB8, 0x00]),
    bytes([0x5F, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24, 0xB1, 0xD0, 0xB1, 0x55, 0x9C,
           0x83, 0xEF, 0x5B, 0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86, 0xD8, 0x22,
           0x4E, 0xDD, 0xD0, 0x9F, 0x11, 0x57]),
    bytes([0xEC]) + bytes([0xFF] * 30) + bytes([0x7F]),
    bytes([0xED]) + bytes([0xFF] * 30) + bytes([0x7F]),
    bytes([0xEE]) + bytes([0xFF] * 30) + bytes([0x7F]),
]


@pytest.mark.parametrize("key", LOW_ORDER_KEYS, ids=lambda k: k[:2].hex())
def test_a_low_order_key_is_unusable_even_with_its_own_fingerprint(key):
    key_b64 = base64.b64encode(key).decode()
    assert derive_fingerprint(key_b64) is None
    for flagged, pinned in ((False, None), (True, None), (False, crypto.fingerprint(key))):
        assert classify_key(
            key_b64, crypto.fingerprint(key), flagged=flagged, pinned=pinned
        ) is KeyTrust.UNUSABLE


def _recipient(uid=7, **overrides):
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
            "team_slug": "team-a", "grant_id": "g-1", "recipients": list(recipients)}


def _coverage(*recipients):
    return {"envelopes": [{"envelope_id": "env-1", "module": "os", "snapshot_version": 1,
                           "wrapped_dek": "x", "missing_recipients": list(recipients)}]}


NULL_PAIRS = [
    {"user_id": 9, "key_changed": False},
    {"user_id": 9, "key_changed": False, "fingerprint": None, "public_key_b64": None},
    {"user_id": 9, "key_changed": False, "fingerprint": None},
]


@pytest.mark.parametrize("bad", NULL_PAIRS)
def test_a_recipient_without_key_and_fingerprint_is_dropped_alone(bad):
    good = _recipient(2)
    [entry] = parse_missing_team_wraps([_entry(bad, good)])
    assert [r.user_id for r in entry.recipients] == [2]
    [envelope] = parse_grant_coverage(_coverage(bad, good)).envelopes
    assert [r.user_id for r in envelope.missing] == [2]


@pytest.mark.parametrize(
    "previous", ["[/bold]", "[link=https://x", "A" * 64, "a" * 63, "a" * 65, 7, "", " " + "a" * 63]
)
def test_a_malformed_previous_fingerprint_is_dropped(previous):
    raw = _recipient(2, previous_fingerprint=previous, key_changed=True)
    [entry] = parse_missing_team_wraps([_entry(raw)])
    assert entry.recipients[0].previous_fingerprint is None
    [envelope] = parse_grant_coverage(_coverage(raw)).envelopes
    assert envelope.missing[0].previous_fingerprint is None


def test_a_well_formed_previous_fingerprint_is_kept():
    raw = _recipient(2, previous_fingerprint="ab" * 32, key_changed=True)
    [entry] = parse_missing_team_wraps([_entry(raw)])
    assert entry.recipients[0].previous_fingerprint == "ab" * 32


def test_parsers_log_nothing_about_the_dropped_recipient(caplog):
    caplog.set_level(logging.DEBUG)
    parse_missing_team_wraps([_entry(NULL_PAIRS[0])])
    assert "user_id" not in caplog.text

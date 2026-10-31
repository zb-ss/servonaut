"""The pin store never raises on odd stored data and only holds positive user ids."""

from __future__ import annotations

import base64
import json

import pytest

from servonaut.services.memory.team_wraps import (
    UNREADABLE_PIN,
    WrapPinStore,
    acknowledge_wraps,
    parse_grant_coverage,
    parse_missing_team_wraps,
    read_skips,
)
from tests.test_memory_sync_team_topup import _missing, _recipient

FP = "a" * 64


def test_a_huge_stored_user_id_makes_the_store_unreadable_not_an_error(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"team-a:" + "9" * 5000: FP}))
    store = WrapPinStore(path)
    assert store.get("team-a", 1) == UNREADABLE_PIN


def test_a_huge_stored_user_id_can_still_be_recovered_by_confirming(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"team-a:" + "9" * 5000: FP}))
    store = WrapPinStore(path)
    store.set_many({("team-a", 2): FP})
    assert store.get("team-a", 2) == FP
    assert list(tmp_path.glob("pins.json.unreadable-*"))


@pytest.mark.parametrize("user_id", [0, -3])
def test_a_non_positive_user_id_is_never_written(tmp_path, user_id):
    path = tmp_path / "pins.json"
    store = WrapPinStore(path)
    store.set_many({("team-a", 5): FP})
    store.set_many({("team-a", user_id): FP})
    seen = {("team-a", user_id, FP): None}
    assert store.set_if_seen({("team-a", user_id): FP}, seen) == set()
    assert store.get("team-a", 5) == FP


def test_a_non_positive_user_id_is_dropped_from_member_payloads():
    raw, _ = _recipient(0)
    negative, _ = _recipient(-4)
    entry = parse_missing_team_wraps([_missing([raw, negative])])
    assert entry and entry[0].recipients == ()
    coverage = parse_grant_coverage(
        {"envelopes": [{
            "envelope_id": "env-1", "module": "os", "snapshot_version": 1,
            "wrapped_dek": None, "missing_recipients": [raw],
        }]}
    )
    assert coverage.envelopes[0].missing == ()


def test_a_non_positive_user_id_in_a_skip_list_is_malformed():
    assert read_skips([{"user_id": 0, "reason": "key_changed"}]) is None
    assert read_skips([{"user_id": -1, "reason": "key_changed"}]) is None


def test_an_acknowledgement_for_user_zero_stores_nothing():
    wraps = [{"recipient_user_id": 0, "envelope_id": "e1", "recipient_fingerprint": FP}]
    ack = acknowledge_wraps(wraps, {"wraps_stored": 1, "wraps_unchanged": 0, "skipped_recipients": []})
    assert ack.stored == ()

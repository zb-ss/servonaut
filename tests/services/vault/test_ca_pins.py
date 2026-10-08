"""CA trust anchors must never be loaded from attacker-controlled filesystem objects."""

from __future__ import annotations

import os

import pytest

from servonaut.services.vault.ca_pins import CaPinMismatchError, CaPinStore, CaPins


PINS = CaPins("SHA256:user", "SHA256:host")


def test_refuses_symlinked_pin_file_without_following_it(tmp_path):
    target = tmp_path / "attacker-pins.json"
    target.write_text('{"format": 1, "teams": {}}', encoding="utf-8")
    pin_path = tmp_path / "ca_pins.json"
    pin_path.symlink_to(target)

    with pytest.raises(CaPinMismatchError, match="real private file"):
        CaPinStore(pin_path).verify_or_pin("team", PINS)
    assert target.read_text(encoding="utf-8") == '{"format": 1, "teams": {}}'


def test_refuses_group_readable_pin_file(tmp_path):
    pin_path = tmp_path / "ca_pins.json"
    pin_path.write_text('{"format": 1, "teams": {}}', encoding="utf-8")
    os.chmod(pin_path, 0o640)

    with pytest.raises(CaPinMismatchError, match="ownership or permissions"):
        CaPinStore(pin_path).verify_or_pin("team", PINS)


def test_creates_owner_only_regular_pin_file(tmp_path):
    pin_path = tmp_path / "private" / "ca_pins.json"
    CaPinStore(pin_path).verify_or_pin("team", PINS)

    assert pin_path.is_file() and not pin_path.is_symlink()
    assert pin_path.stat().st_mode & 0o777 == 0o600
    assert pin_path.parent.stat().st_mode & 0o777 == 0o700


GEN2 = "SHA256:user-gen2"


def test_a_completed_rollover_re_pins_when_the_pinned_ca_is_listed_as_retired(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    store.verify_or_pin("team", PINS)

    store.verify_or_pin("team", CaPins(GEN2, "SHA256:host"), previous_user_fingerprints=["SHA256:user"])

    # Re-pinned: the new generation is accepted on its own from now on.
    assert store.pinned("team") == CaPins(GEN2, "SHA256:host")
    store.verify_or_pin("team", CaPins(GEN2, "SHA256:host"))


def test_a_rollover_this_device_saw_announced_is_accepted_after_the_old_ca_ages_out(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    store.verify_or_pin("team", PINS)
    store.verify_or_pin("team", PINS, next_user_fingerprint=GEN2)  # rollover started

    # Completed, and the retired generation is no longer listed.
    store.verify_or_pin("team", CaPins(GEN2, "SHA256:host"))

    assert store.pinned("team") == CaPins(GEN2, "SHA256:host")


def test_an_unannounced_user_ca_change_is_refused_with_the_way_to_trust_it(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    store.verify_or_pin("team", PINS)

    with pytest.raises(CaPinMismatchError, match=r"servonaut ca trust --team team"):
        store.verify_or_pin("team", CaPins(GEN2, "SHA256:host"), previous_user_fingerprints=["SHA256:other"])
    assert store.pinned("team") == PINS


def test_a_host_ca_change_is_refused_even_during_a_user_ca_rollover(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    store.verify_or_pin("team", PINS, next_user_fingerprint=GEN2)

    with pytest.raises(CaPinMismatchError, match="changed"):
        store.verify_or_pin(
            "team", CaPins(GEN2, "SHA256:host-2"), previous_user_fingerprints=["SHA256:user"],
        )
    assert store.pinned("team") == PINS


def test_reading_unchanged_pins_does_not_rewrite_the_file(tmp_path):
    path = tmp_path / "ca_pins.json"
    store = CaPinStore(path)
    store.verify_or_pin("team", PINS)
    before = path.stat().st_mtime_ns

    store.verify_or_pin("team", PINS)

    assert path.stat().st_mtime_ns == before


def test_a_pin_mismatch_is_shown_to_the_user_as_is():
    from servonaut.services.vault.errors import vault_failure_reason

    assert vault_failure_reason(CaPinMismatchError("The team SSH CA changed")) == "The team SSH CA changed"


def test_a_rollover_must_move_forward_and_a_retired_key_cannot_return(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    store.verify_or_pin("team", PINS, user_ca_generation=1)
    store.verify_or_pin("team", CaPins(GEN2, "SHA256:host"), user_ca_generation=2,
                        previous_user_fingerprints=["SHA256:user"])

    # Back to generation 1's key, even listed as a newer generation with a retired key.
    with pytest.raises(CaPinMismatchError):
        store.verify_or_pin("team", PINS, user_ca_generation=3, previous_user_fingerprints=[GEN2])
    # A new key that claims an older generation.
    with pytest.raises(CaPinMismatchError):
        store.verify_or_pin("team", CaPins("SHA256:user-x", "SHA256:host"), user_ca_generation=2,
                            previous_user_fingerprints=[GEN2])
    assert store.pinned("team") == CaPins(GEN2, "SHA256:host")


def test_two_rollovers_in_a_row_are_followed_through_the_announced_key(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    store.verify_or_pin("team", PINS, user_ca_generation=1, next_user_fingerprint=GEN2)

    # B was completed and replaced by C while this device was away; only B is still listed.
    store.verify_or_pin("team", CaPins("SHA256:user-gen3", "SHA256:host"), user_ca_generation=3,
                        previous_user_fingerprints=[GEN2])

    assert store.pinned("team") == CaPins("SHA256:user-gen3", "SHA256:host")


def test_a_withdrawn_announcement_is_forgotten_and_other_fields_are_kept(tmp_path):
    import json

    path = tmp_path / "ca_pins.json"
    store = CaPinStore(path)
    store.verify_or_pin("team", PINS, next_user_fingerprint=GEN2)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["teams"]["team"]["added_later"] = "keep me"
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)

    store.verify_or_pin("team", PINS)  # the rollover was cancelled

    record = json.loads(path.read_text(encoding="utf-8"))["teams"]["team"]
    assert "user_ca_next_fingerprint" not in record
    assert record["added_later"] == "keep me"
    # Without the announcement the new key is no longer continuous.
    with pytest.raises(CaPinMismatchError):
        store.verify_or_pin("team", CaPins(GEN2, "SHA256:host"))


def test_teams_are_pinned_independently(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    store.verify_or_pin("team-a", PINS, next_user_fingerprint=GEN2)
    store.verify_or_pin("team-b", CaPins("SHA256:b-user", "SHA256:b-host"))

    store.verify_or_pin("team-a", CaPins(GEN2, "SHA256:host"))

    assert store.pinned("team-b") == CaPins("SHA256:b-user", "SHA256:b-host")
    with pytest.raises(CaPinMismatchError):
        store.verify_or_pin("team-b", CaPins(GEN2, "SHA256:b-host"))


def test_a_key_first_seen_as_retired_cannot_later_return_as_active(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    # First sight mid-rollover: B is active, A already retired.
    store.verify_or_pin("team", CaPins(GEN2, "SHA256:host"), user_ca_generation=2,
                        previous_user_fingerprints=["SHA256:user"])

    with pytest.raises(CaPinMismatchError):
        store.verify_or_pin("team", PINS, user_ca_generation=3, previous_user_fingerprints=[GEN2])


def test_a_pinned_key_cannot_move_to_another_generation(tmp_path):
    store = CaPinStore(tmp_path / "ca_pins.json")
    store.verify_or_pin("team", PINS, user_ca_generation=5)

    with pytest.raises(CaPinMismatchError):
        store.verify_or_pin("team", PINS, user_ca_generation=1)

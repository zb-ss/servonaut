from __future__ import annotations

from servonaut.services.vault.duplicates import copy_state, created_time, duplicate_copies

FREE = {"team_servers": [], "own_servers": [], "unchecked": []}
USED = {"team_servers": ["web-1"], "own_servers": [], "unchecked": []}


def item(item_id, fingerprint="SHA256:aaa", created=None):
    data = {"item_id": item_id, "public_fingerprint": fingerprint}
    if created:
        data["created_at"] = created
    return data


def test_no_duplicates():
    result = duplicate_copies([item("k1"), item("k2", "SHA256:bbb")], {"k1": FREE, "k2": FREE})
    assert result.selected == () and result.fingerprints == 0


def test_newer_unused_copy_selected_any_order():
    old, new = "2024-01-01T00:00:00Z", "2025-01-01T00:00:00Z"
    usages = {"k1": FREE, "k2": FREE}
    assert duplicate_copies([item("k1", created=old), item("k2", created=new)], usages).selected == ("k2",)
    assert duplicate_copies([item("k1", created=new), item("k2", created=old)], usages).selected == ("k1",)


def test_no_dates_first_listed_stays():
    result = duplicate_copies([item("k1"), item("k2")], {"k1": FREE, "k2": FREE})
    assert result.selected == ("k2",) and result.fingerprints == 1


def test_undated_after_dated():
    items = [item("k1"), item("k2", created="2025-01-01T00:00:00Z")]
    assert duplicate_copies(items, {"k1": FREE, "k2": FREE}).selected == ("k1",)


def test_one_in_use_two_unused():
    result = duplicate_copies([item("k1"), item("k2"), item("k3")], {"k1": FREE, "k2": USED, "k3": FREE})
    assert result.selected == ("k1", "k3") and result.several_in_use == ()


def test_two_in_use_one_unused():
    result = duplicate_copies([item("k1"), item("k2"), item("k3")], {"k1": USED, "k2": USED, "k3": FREE})
    assert result.selected == ("k3",) and result.several_in_use == (("k1", "k2"),)


def test_two_in_use_only():
    result = duplicate_copies([item("k1"), item("k2")], {"k1": USED, "k2": USED})
    assert result.selected == () and result.several_in_use == (("k1", "k2"),)


def test_unknown_states_never_selected():
    for bad in ({**FREE, "error": "boom"}, {**FREE, "unchecked": ["host"]}, None, {"team_servers": []}):
        usages = {"k1": FREE} if bad is None else {"k1": FREE, "k2": bad}
        result = duplicate_copies([item("k1"), item("k2")], usages)
        assert "k2" not in result.selected and result.unchecked == ("k2",)


def test_unknown_plus_two_unused():
    result = duplicate_copies(
        [item("k1"), item("k2"), item("k3")], {"k1": {**FREE, "error": "x"}, "k2": FREE, "k3": FREE}
    )
    assert result.selected == ("k2", "k3") and result.unchecked == ("k1",)


def test_usages_none():
    result = duplicate_copies([item("k1"), item("k2")], None)
    assert result.selected == () and result.unchecked == ("k1", "k2")


def test_other_members_count_as_in_use():
    other = {**FREE, "other_members": {"members": 1, "servers": 2}}
    assert copy_state(other) == "in_use"
    result = duplicate_copies([item("k1"), item("k2")], {"k1": other, "k2": FREE})
    assert result.selected == ("k2",)


def test_items_without_fingerprint_ignored():
    items = [{"item_id": "k1"}, {"item_id": "k2", "public_fingerprint": ""}, item("k3")]
    assert duplicate_copies(items, {}).fingerprints == 0


def test_timestamps_compare():
    assert created_time({"created_at": "2025-01-01T00:00:00Z"}) is not None
    assert created_time({"created_at": "2025-01-01T00:00:00"}) is not None
    assert created_time({"created_at": "nope"}) is None
    items = [item("k1", created="2025-01-01T00:00:00"), item("k2", created="2024-01-01T00:00:00Z")]
    assert duplicate_copies(items, {"k1": FREE, "k2": FREE}).selected == ("k1",)


def test_usage_by_lowercased_id():
    result = duplicate_copies([item("AB"), item("CD")], {"ab": USED, "cd": FREE})
    assert result.selected == ("CD",)


def test_in_use_wins_over_a_failed_read():
    assert copy_state({**USED, "unchecked": [["aws", "", "i-1"]]}) == "in_use"
    assert copy_state({**USED, "error": "boom"}) == "in_use"
    assert copy_state({**FREE, "unchecked": [["aws", "", "i-1"]]}) == "unknown"
    assert copy_state({**FREE, "error": "boom"}) == "unknown"
    assert copy_state(FREE) == "unused"


def test_in_use_copy_with_a_failed_read_is_kept_and_not_reported_unchecked():
    partial = {**USED, "unchecked": [["aws", "", "i-1"]]}
    result = duplicate_copies([item("k1"), item("k2")], {"k1": partial, "k2": FREE})
    assert result.selected == ("k2",) and result.unchecked == ()


def test_in_use_or_unknown_copy_is_never_selected():
    partial = {**USED, "unchecked": [["aws", "", "i-1"]]}
    for usages in ({"k1": partial, "k2": partial}, {"k1": {"error": "x"}, "k2": {"error": "x"}}):
        assert duplicate_copies([item("k1"), item("k2")], usages).selected == ()


def test_selected_keys_counts_only_keys_that_contributed_a_copy():
    items = [item("k1"), item("k2"), item("k3", "SHA256:bbb"), item("k4", "SHA256:bbb")]
    result = duplicate_copies(items, {"k1": FREE, "k2": FREE, "k3": USED, "k4": USED})
    assert result.selected == ("k2",)
    assert result.fingerprints == 2 and result.selected_keys == 1


def test_selected_keys_is_zero_when_nothing_is_selected():
    result = duplicate_copies([item("k1"), item("k2")], {"k1": USED, "k2": USED})
    assert result.fingerprints == 1 and result.selected_keys == 0

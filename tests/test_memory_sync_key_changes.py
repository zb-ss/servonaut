"""A catch-up that skips a changed key remembers it so it can be confirmed."""
from __future__ import annotations

from tests.test_memory_sync_team_topup import (  # noqa: F401  (fixture re-export)
    _Server,
    _drain,
    _missing,
    _no_pause,
    _recipient,
    _service,
)


def test_a_skipped_changed_key_is_recorded_once_and_announced_once(tmp_path):
    keep, _ = _recipient(7)
    changed, _ = _recipient(8, key_changed=True, previous_fingerprint="c" * 64,
                            key_rotated_at="2026-10-30T10:00:00Z")
    server = _Server(lambda uploads: [_missing([keep, changed], envelope_id=f"env-{len(uploads)}")])
    svc = _service(tmp_path, server)
    heard = []
    svc.set_key_change_listener(heard.append)

    _drain(svc)
    _drain(svc)  # the same key again: no second announcement

    [pending] = svc.pending_key_changes()
    assert pending.instance_id == "web-1"
    assert (pending.change.team_slug, pending.change.user_id) == ("team-a", 8)
    assert pending.change.previous_fingerprint == "c" * 64
    assert len(heard) == 1 and heard[0] == pending
    sent = [w["recipient_user_id"] for p in server.wrap_posts for w in p["json"]["wraps"]]
    assert 8 not in sent


def test_a_member_key_that_differs_from_the_pin_is_recorded_too(tmp_path):
    first, _ = _recipient(7)
    server = _Server(lambda uploads: [_missing([first], envelope_id=f"env-{len(uploads)}")])
    svc = _service(tmp_path, server)
    _drain(svc)
    swapped, _ = _recipient(7)
    server.missing = lambda uploads: [_missing([swapped], envelope_id="env-2")]
    _drain(svc)
    [pending] = svc.pending_key_changes()
    assert pending.change.fingerprint == swapped["fingerprint"]
    assert pending.change.previous_fingerprint == first["fingerprint"]


def test_a_confirmed_key_leaves_the_registry_and_is_sealed_for_next_time(tmp_path):
    changed, _ = _recipient(8, key_changed=True)
    server = _Server(lambda uploads: [_missing([changed], envelope_id=f"env-{len(uploads)}")])
    svc = _service(tmp_path, server)
    _drain(svc)
    [pending] = svc.pending_key_changes()
    svc._pin_store().set_many({("team-a", 8): pending.change.fingerprint})
    assert svc.pending_key_changes() == []
    _drain(svc)
    assert [w["recipient_user_id"] for w in server.wrap_posts[-1]["json"]["wraps"]] == [8]


def test_a_failing_listener_never_breaks_the_upload(tmp_path):
    changed, _ = _recipient(8, key_changed=True)
    server = _Server([_missing([changed])])
    svc = _service(tmp_path, server)

    def boom(_pending):
        raise RuntimeError("toast failed")

    svc.set_key_change_listener(boom)
    result = _drain(svc)
    assert len(result.accepted) == 1 and svc.status.last_error is None


def _change(user_id, fp, team="team-a"):
    from servonaut.services.memory.team_wraps import KeyChange

    return KeyChange(team, user_id, f"member-{user_id}", fp)


def test_a_newer_changed_key_replaces_the_older_entry_for_the_member(tmp_path):
    svc = _service(tmp_path, _Server([]))
    for index in range(50):
        svc._record_key_changes("web-1", [_change(8, f"{index:064x}")])
    assert len(svc._key_changes) == 1
    [pending] = svc.pending_key_changes()
    assert pending.change.fingerprint == f"{49:064x}"


def test_a_superseded_key_never_comes_back_as_waiting(tmp_path):
    svc = _service(tmp_path, _Server([]))
    svc._record_key_changes("web-1", [_change(8, "b" * 64)])
    svc._pin_store().set_many({("team-a", 8): "b" * 64})
    assert svc.pending_key_changes() == []
    svc._record_key_changes("web-1", [_change(8, "c" * 64)])
    svc._pin_store().set_many({("team-a", 8): "c" * 64})
    assert svc.pending_key_changes() == []
    assert len(svc._key_changes) <= 1


def test_pending_keys_that_were_pinned_are_pruned_from_the_registry(tmp_path):
    svc = _service(tmp_path, _Server([]))
    svc._record_key_changes("web-1", [_change(8, "b" * 64), _change(9, "d" * 64)])
    svc._pin_store().set_many({("team-a", 8): "b" * 64})
    assert [p.change.user_id for p in svc.pending_key_changes()] == [9]
    assert len(svc._key_changes) == 1


def test_the_registry_survives_readers_racing_writers(tmp_path):
    import threading

    svc = _service(tmp_path, _Server([]))
    failures = []

    def writer(base):
        try:
            for index in range(300):
                svc._record_key_changes("web-1", [_change(base + index, f"{index:064x}")])
        except Exception as exc:  # noqa: BLE001
            failures.append(exc)

    def reader():
        try:
            for _ in range(300):
                svc.pending_key_changes()
        except Exception as exc:  # noqa: BLE001
            failures.append(exc)

    threads = [threading.Thread(target=writer, args=(b * 1000,)) for b in range(1, 4)]
    threads += [threading.Thread(target=reader) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert failures == []


def test_a_listener_may_read_the_registry_without_deadlocking(tmp_path):
    import threading

    svc = _service(tmp_path, _Server([]))
    seen = []
    svc.set_key_change_listener(lambda pending: seen.append(svc.pending_key_changes()))
    worker = threading.Thread(target=svc._record_key_changes, args=("web-1", [_change(8, "b" * 64)]))
    worker.start()
    worker.join(10)
    assert not worker.is_alive()
    assert len(seen) == 1 and len(seen[0]) == 1

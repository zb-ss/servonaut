"""The team-copy merge never waits on a record lock; user-driven writes still do."""
from __future__ import annotations

import hashlib
import time

import pytest

from servonaut.services.memory.store import LOCKS_DIR, MemoryStore, RecordLockTimeout
from servonaut.utils.file_lock import FileLock
from tests.test_memory_team_merge import (
    FIRST, OLD, OWN_ID, SHARE_ID, _own, _put_copy, _run, _service, _shared,
)

WAIT_SECONDS = 5.0


def _hold(root, instance_id):
    digest = hashlib.sha256(instance_id.encode("utf-8")).hexdigest()
    lock = FileLock(root / LOCKS_DIR / f"{digest}.lock", private_dir=True)
    assert lock.try_acquire()
    return lock


def _patient_service(tmp_path):
    service = _service(tmp_path)
    service._store.set_record_lock_wait(WAIT_SECONDS, 0.05)
    return service


def test_a_non_waiting_lock_raises_a_specific_error_at_once(tmp_path):
    from servonaut.services.memory.store import RecordBusy  # noqa: PLC0415
    store = MemoryStore(root=tmp_path)
    store.set_record_lock_wait(WAIT_SECONDS, 0.05)
    other = _hold(tmp_path, "web-1")
    started = time.monotonic()
    with pytest.raises(RecordBusy) as caught:
        with store.annotation_lock("web-1", wait=False):
            pass
    assert time.monotonic() - started < 1
    assert isinstance(caught.value, RecordLockTimeout) and isinstance(caught.value, OSError)
    other.release()
    with store.annotation_lock("web-1", wait=False):
        pass


@pytest.mark.parametrize("part", ["notes", "findings"])
def test_a_merge_over_a_busy_record_returns_at_once_and_keeps_the_copy(tmp_path, part):
    service = _patient_service(tmp_path)
    if part == "notes":
        _put_copy(service, notes="local note")
    else:
        _put_copy(service, findings=[{"id": FIRST, "title": "local", "created_at": OLD}])
    other = _hold(tmp_path, OWN_ID)
    started = time.monotonic()
    report = _run(service, [_own(), _shared()])
    assert time.monotonic() - started < 2
    assert report.copies == 0 and report.kept == [SHARE_ID]
    assert service.read_annotations(OWN_ID, "aws") == ""
    assert service._store.read_merge_marker(SHARE_ID, "team team a") is None
    other.release()
    again = _run(service, [_own(), _shared()])
    assert again.copies == 1


def test_a_user_write_still_waits_for_the_bounded_time(tmp_path):
    store = MemoryStore(root=tmp_path)
    store.set_record_lock_wait(0.3, 0.02)
    other = _hold(tmp_path, "web-1")
    started = time.monotonic()
    with pytest.raises(RecordLockTimeout):
        store.write_annotations("web-1", "x", "aws")
    assert time.monotonic() - started >= 0.25
    other.release()

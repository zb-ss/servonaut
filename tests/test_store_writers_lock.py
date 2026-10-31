"""Every writer of a server's record takes the record lock."""
from __future__ import annotations

import hashlib
import threading
import time

import pytest

from servonaut.services.memory.store import LOCKS_DIR, MemoryStore, RecordLockTimeout
from servonaut.utils.file_lock import FileLock

ID = "web-1"
RECORD = {"id": "f_aaaaaaaaaaaaaaaa", "title": "t", "created_at": "2026-01-01T00:00:00+00:00"}
MODULE = {"module": "os", "instance_id": ID, "probed_at": "2026-01-01T00:00:00+00:00", "observed": {}}


def _held(root):
    digest = hashlib.sha256(ID.encode("utf-8")).hexdigest()
    lock = FileLock(root / LOCKS_DIR / f"{digest}.lock", private_dir=True)
    assert lock.try_acquire()
    return lock


def _store(tmp_path):
    store = MemoryStore(root=tmp_path)
    store.set_record_lock_wait(0.1, 0.01)
    store.write_annotations(ID, "note", "aws")
    store.save_finding(ID, RECORD, "aws")
    store.save_module(ID, "os", MODULE, "aws")
    return store


WRITERS = {
    "save_finding": lambda s: s.save_finding(ID, {**RECORD, "title": "new"}, "aws"),
    "delete_finding": lambda s: s.delete_finding(ID, RECORD["id"], "aws"),
    "clear": lambda s: s.clear(ID, None, "aws"),
    "save_module": lambda s: s.save_module(ID, "os", MODULE, "aws"),
}


@pytest.mark.parametrize("name", sorted(WRITERS))
def test_a_writer_waits_for_the_lock_then_gives_up_without_changing_anything(tmp_path, name):
    store = _store(tmp_path)
    other = _held(tmp_path)
    started = time.monotonic()
    with pytest.raises(RecordLockTimeout):
        WRITERS[name](store)
    assert time.monotonic() - started >= 0.08
    other.release()
    assert store.read_annotations_strict(ID, "aws") == "note"
    assert store.get_finding(ID, RECORD["id"], "aws")["title"] == "t"
    assert not list((tmp_path / "aws" / ID).glob("annotations.unsaved-*"))


def test_a_clear_waits_for_a_holder_and_then_wins(tmp_path):
    store = _store(tmp_path)
    store.set_record_lock_wait(5.0, 0.01)
    done = threading.Event()
    with store.annotation_lock(ID):
        thread = threading.Thread(target=lambda: (store.clear(ID, None, "aws"), done.set()))
        thread.start()
        assert not done.wait(0.2)
        store.write_annotations(ID, "note\nwriter edit", "aws")
    thread.join(5)
    assert done.is_set()
    assert not store.get_annotations_path(ID, "aws").exists()
    assert store.get_finding(ID, RECORD["id"], "aws") is None

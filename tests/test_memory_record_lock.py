"""The per-server record lock excludes other processes, not just threads."""
from __future__ import annotations

import hashlib
import multiprocessing
import os
import stat
import sys

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore, RecordLockTimeout
from servonaut.utils.file_lock import FileLock

ID = "web-1"


def _lock_file(root, instance_id=ID):
    digest = hashlib.sha256(instance_id.encode("utf-8")).hexdigest()
    return root / ".locks" / f"{digest}.lock"


def _hold_record(root, instance_id, ready, release):
    store = MemoryStore(root=root)
    with store.annotation_lock(instance_id):
        ready.set()
        release.wait(20)


def _store(tmp_path, timeout=0.3):
    store = MemoryStore(root=tmp_path / "root")
    store.set_record_lock_wait(timeout, 0.02)
    return store


def test_the_lock_takes_an_os_lock_on_a_file_named_by_the_id_hash(tmp_path):
    store = _store(tmp_path)
    with store.annotation_lock(ID):
        assert FileLock(_lock_file(tmp_path / "root")).try_acquire() is False
    probe = FileLock(_lock_file(tmp_path / "root"))
    assert probe.try_acquire()
    probe.release()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_the_lock_folder_is_private(tmp_path):
    store = _store(tmp_path)
    with store.annotation_lock(ID):
        pass
    locks = tmp_path / "root" / ".locks"
    assert stat.S_IMODE(os.stat(locks).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(_lock_file(tmp_path / "root")).st_mode) == 0o600


def test_nested_acquisition_in_one_process_still_works(tmp_path):
    store = _store(tmp_path)
    with store.annotation_lock(ID):
        with store.annotation_lock(ID):
            store.write_annotations(ID, "x", "aws")
        assert FileLock(_lock_file(tmp_path / "root")).try_acquire() is False
    probe = FileLock(_lock_file(tmp_path / "root"))
    assert probe.try_acquire()
    probe.release()


def test_another_process_holding_the_record_times_out_with_a_specific_oserror(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    root = tmp_path / "root"
    child = ctx.Process(target=_hold_record, args=(root, ID, ready, release))
    child.start()
    try:
        assert ready.wait(30)
        store = _store(tmp_path)
        with pytest.raises(RecordLockTimeout) as caught:
            store.write_annotations(ID, "x", "aws")
        assert isinstance(caught.value, OSError)
        assert not (root / "aws" / ID / "annotations.md").exists()
        release.set()
        child.join(20)
        store.write_annotations(ID, "x", "aws")
    finally:
        release.set()
        child.join(5)
        if child.is_alive():
            child.kill()


def test_different_servers_do_not_wait_for_each_other(tmp_path):
    store = _store(tmp_path)
    with store.annotation_lock("web-1"):
        with store.annotation_lock("web-2"):
            pass


def test_merge_findings_runs_under_the_record_lock(tmp_path):
    store = _store(tmp_path)
    service = MemoryService(store=store, config=MemoryConfig())
    seen = []
    original = store.get_finding

    def spy(*args, **kwargs):
        probe = FileLock(_lock_file(tmp_path / "root"))
        free = probe.try_acquire()
        if free:
            probe.release()
        seen.append(free)
        return original(*args, **kwargs)

    store.get_finding = spy
    record = {"id": "f_aaaaaaaaaaaaaaaa", "title": "t", "created_at": "2026-01-01T00:00:00+00:00"}
    service.merge_findings(ID, [record], "aws")
    assert seen == [False]


def test_remember_finding_runs_its_supersede_under_the_record_lock(tmp_path):
    store = _store(tmp_path)
    service = MemoryService(store=store, config=MemoryConfig())
    old = service.remember_finding({"id": ID, "name": ID, "provider": "aws"}, title="a", body="b")
    seen = []
    original = store.get_finding

    def spy(*args, **kwargs):
        probe = FileLock(_lock_file(tmp_path / "root"))
        free = probe.try_acquire()
        if free:
            probe.release()
        seen.append(free)
        return original(*args, **kwargs)

    store.get_finding = spy
    service.remember_finding(
        {"id": ID, "name": ID, "provider": "aws"}, title="c", body="d",
        supersede_id=old["finding_id"],
    )
    assert seen == [False]


def test_the_service_hands_the_configured_wait_to_its_store(tmp_path):
    store = MemoryStore(root=tmp_path / "root")
    MemoryService(store=store, config=MemoryConfig(record_lock_timeout_seconds=1.5, record_lock_poll_seconds=0.01))
    assert store.record_lock_wait == (1.5, 0.01)


@pytest.mark.parametrize("bad", [-1, "soon", None, float("nan"), True])
def test_an_unusable_wait_falls_back_to_the_default(bad):
    timeout, _ = MemoryConfig(record_lock_timeout_seconds=bad).record_lock_wait()
    assert timeout == 5.0


def test_defaults_are_documented_values():
    assert MemoryConfig().record_lock_wait() == (5.0, 0.05)

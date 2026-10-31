"""Lock folders and lock files are checked before use (POSIX)."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import stat
import sys

import pytest

from servonaut.services.memory.store import LOCKS_DIR, TEAM_MERGE_LOCK, MemoryStore
from servonaut.services.memory.team_merge import merge_team_copies
from servonaut.utils import file_lock
from servonaut.utils.file_lock import FileLock

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes and links")

ID = "web-1"


@pytest.fixture(autouse=True)
def _fresh_warnings():
    file_lock._WARNED.clear()
    yield
    file_lock._WARNED.clear()


def _store(tmp_path):
    store = MemoryStore(root=tmp_path / "root")
    store.set_record_lock_wait(0.05, 0.01)
    return store


def _lock_file(root):
    digest = hashlib.sha256(ID.encode("utf-8")).hexdigest()
    return root / LOCKS_DIR / f"{digest}.lock"


def _take(store):
    with store.annotation_lock(ID):
        pass


def test_a_lock_folder_that_is_a_link_is_refused_and_nothing_is_created_behind_it(tmp_path):
    store = _store(tmp_path)
    victim = tmp_path / "elsewhere"
    victim.mkdir()
    (tmp_path / "root").mkdir()
    (tmp_path / "root" / LOCKS_DIR).symlink_to(victim)
    with pytest.raises(OSError):
        _take(store)
    assert list(victim.iterdir()) == []


def test_a_lock_folder_that_is_a_file_is_refused(tmp_path):
    store = _store(tmp_path)
    (tmp_path / "root").mkdir()
    (tmp_path / "root" / LOCKS_DIR).write_text("x")
    with pytest.raises(OSError):
        _take(store)


def test_a_wide_open_lock_folder_is_tightened(tmp_path):
    store = _store(tmp_path)
    locks = tmp_path / "root" / LOCKS_DIR
    locks.mkdir(parents=True)
    os.chmod(locks, 0o777)
    _take(store)
    assert stat.S_IMODE(os.stat(locks).st_mode) == 0o700


def test_a_lock_folder_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    store = _store(tmp_path)
    (tmp_path / "root" / LOCKS_DIR).mkdir(parents=True)
    monkeypatch.setattr(file_lock, "_owner_uid", lambda: os.geteuid() + 1)
    with pytest.raises(OSError):
        _take(store)


def test_an_existing_lock_file_is_tightened_to_private(tmp_path):
    store = _store(tmp_path)
    path = _lock_file(tmp_path / "root")
    path.parent.mkdir(parents=True)
    path.write_text("")
    os.chmod(path, 0o666)
    _take(store)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_lock_file_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "locks" / "a.lock"
    lock = FileLock(path)
    assert lock.try_acquire()
    lock.release()
    monkeypatch.setattr(file_lock, "_owner_uid", lambda: os.geteuid() + 1)
    with pytest.raises(OSError):
        FileLock(path).try_acquire()


def test_a_lock_file_that_is_a_link_is_refused_and_warned_about_once(tmp_path, caplog):
    path = tmp_path / "locks" / "a.lock"
    path.parent.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("keep")
    path.symlink_to(victim)
    with caplog.at_level(logging.WARNING, logger="servonaut.utils.file_lock"):
        for _ in range(3):
            with pytest.raises(OSError):
                FileLock(path).try_acquire()
    assert victim.read_text() == "keep"
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1


def test_a_linked_merge_lock_is_refused_with_one_warning_across_passes(tmp_path, caplog):
    from tests.test_memory_team_merge import _own, _put_copy, _service, _shared
    service = _service(tmp_path)
    _put_copy(service, notes="local")
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / TEAM_MERGE_LOCK).symlink_to(victim)
    with caplog.at_level(logging.WARNING):
        reports = [
            asyncio.run(merge_team_copies(service, None, [_own(), _shared()], today="2026-10-31"))
            for _ in range(3)
        ]
    assert all(report.skipped for report in reports)
    assert victim.read_text() == "keep"
    unsafe = [r for r in caplog.records if r.levelno >= logging.WARNING and "lock" in r.getMessage().lower()]
    assert len(unsafe) == 1

"""Pulling the service's notes decides and writes under the record lock."""
from __future__ import annotations

import asyncio
import hashlib
import time

from servonaut.services.memory.store import LOCKS_DIR
from servonaut.utils.file_lock import FileLock
from tests.test_memory_team_merge import OWN_ID, _service
from tests.test_memory_team_merge_v3 import Retrieval, _sync

OLD = "2026-01-01T00:00:00+00:00"
NEWER = "2026-02-01T00:00:00+00:00"


class _Dated(Retrieval):
    async def get_module(self, instance_id, module):
        envelope = await super().get_module(instance_id, module)
        envelope.probed_at = NEWER
        return envelope


def _lock_file(root):
    digest = hashlib.sha256(OWN_ID.encode("utf-8")).hexdigest()
    return root / LOCKS_DIR / f"{digest}.lock"


def _pull(tmp_path, service, text="remote"):
    sync = _sync(tmp_path, service, _Dated(notes={"content": text}))
    return sync, lambda: asyncio.run(sync.pull_annotations(OWN_ID, provider="aws"))


def _aged(service):
    service.write_annotations(OWN_ID, "old", "aws", modified_at=OLD)


def test_the_comparison_and_the_write_happen_while_the_record_is_locked(tmp_path):
    service = _service(tmp_path)
    _aged(service)
    sync, pull = _pull(tmp_path, service)
    seen = []
    original = sync._parse_iso

    def watching(value):
        probe = FileLock(_lock_file(tmp_path), private_dir=True)
        seen.append(not probe.try_acquire())
        probe.release()
        return original(value)

    sync._parse_iso = watching
    assert pull() == "updated"
    assert seen and all(seen)
    assert service.read_annotations(OWN_ID, "aws") == "remote"


def test_a_record_busy_elsewhere_keeps_the_local_text_without_waiting(tmp_path):
    service = _service(tmp_path)
    service._store.set_record_lock_wait(5.0, 0.05)
    _aged(service)
    sync, pull = _pull(tmp_path, service)
    other = FileLock(_lock_file(tmp_path), private_dir=True)
    assert other.try_acquire()
    started = time.monotonic()
    assert pull() == "local_newer"
    assert time.monotonic() - started < 2
    other.release()
    assert service.read_annotations(OWN_ID, "aws") == "old"
    assert pull() == "updated"


def test_a_local_edit_made_after_the_fetch_is_kept(tmp_path):
    service = _service(tmp_path)
    _aged(service)
    sync = _sync(tmp_path, service, _Dated(notes={"content": "remote"}))
    fetch = sync._retrieval_service.get_module

    async def edit_then_return(instance_id, module):
        envelope = await fetch(instance_id, module)
        service.write_annotations(OWN_ID, "newest local edit", "aws")
        service.set_annotations_meta(OWN_ID, annotations_modified_at="2026-03-01T00:00:00+00:00")
        return envelope

    sync._retrieval_service.get_module = edit_then_return
    assert asyncio.run(sync.pull_annotations(OWN_ID, provider="aws")) == "local_newer"
    assert service.read_annotations(OWN_ID, "aws") == "newest local edit"

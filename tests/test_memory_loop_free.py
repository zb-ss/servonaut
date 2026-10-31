"""Blocking record transactions stay off the event loop; the sync queue stays on it."""
from __future__ import annotations

import asyncio
import hashlib
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import LOCKS_DIR, MemoryStore, RecordLockTimeout
from servonaut.utils.file_lock import FileLock
from tests.test_mcp_findings_tools import _make_tools
from tests.test_memory_service import _MockProber
from tests.test_memory_team_merge import OWN_ID, FIRST, _own, _service
from tests.test_memory_team_merge_v3 import Retrieval, _sync


def _hold(root, instance_id=OWN_ID):
    digest = hashlib.sha256(instance_id.encode("utf-8")).hexdigest()
    lock = FileLock(root / LOCKS_DIR / f"{digest}.lock", private_dir=True)
    assert lock.try_acquire()
    return lock


async def _ticks_while(coro, interval=0.02):
    ticks = []

    async def ticker():
        while True:
            ticks.append(time.monotonic())
            await asyncio.sleep(interval)

    task = asyncio.create_task(ticker())
    try:
        outcome = await coro
    finally:
        task.cancel()
    return outcome, len(ticks)


def _build_service(tmp_path, names=("os",)):
    service = _service(tmp_path)
    service._probers = [_MockProber(n) for n in names]
    service._store.set_record_lock_wait(0.3, 0.01)
    service._make_ssh_runner = lambda *a, **k: SimpleNamespace(prepare=AsyncMock(), close=AsyncMock())
    return service


def test_a_busy_record_does_not_stall_the_loop_while_a_probe_is_saved(tmp_path):
    service = _build_service(tmp_path)
    lock = _hold(tmp_path)
    try:
        report, ticks = asyncio.run(_ticks_while(service.build_report(_own(), ["os"])))
    finally:
        lock.release()
    assert ticks >= 8  # the 0.3 s wait did not freeze the timer
    assert report is not None


def test_a_busy_record_marks_the_module_partial_with_a_reason_and_keeps_the_rest(tmp_path):
    service = _build_service(tmp_path, names=("os", "runtimes"))
    real_save = service._store.save_module
    calls = []

    def flaky(instance_id, module, data, provider="custom"):
        calls.append(module)
        if module == "os":
            raise RecordLockTimeout("busy")
        return real_save(instance_id, module, data, provider)

    service._store.save_module = flaky
    report = asyncio.run(service.build_report(_own(), ["os", "runtimes"]))
    assert set(calls) == {"os", "runtimes"}
    assert service._store.get_module(OWN_ID, "runtimes", "aws") is not None
    assert service._store.get_module(OWN_ID, "os", "aws") is None
    assert report.successes["os"].partial is True
    assert report.successes["runtimes"].partial is False
    assert [(f.module, f.reason) for f in report.failures] == [("os", "record_busy")]


def test_pulling_findings_does_not_stall_the_loop_and_reports_busy(tmp_path):
    service = _service(tmp_path)
    service._store.set_record_lock_wait(0.3, 0.01)
    sync = _sync(tmp_path / "s", service, Retrieval(
        findings={"findings": [{"id": FIRST, "title": "t", "created_at": "2026-01-01"}]}))
    lock = _hold(tmp_path)
    try:
        outcome, ticks = asyncio.run(_ticks_while(sync.pull_findings(OWN_ID, provider="aws")))
    finally:
        lock.release()
    assert outcome == "busy"
    assert ticks >= 8


def test_remembering_a_finding_saves_in_a_worker_and_queues_on_the_loop(tmp_path):
    store = MemoryStore(root=tmp_path)
    queue_threads = []
    sync = MagicMock()
    sync.enqueue_findings.side_effect = lambda *a, **k: queue_threads.append(threading.get_ident())
    service = MemoryService(store=store, config=MemoryConfig(enabled=True), probers=[])
    service.set_sync_service(sync)
    save_threads = []
    real_save = store.save_finding

    def spying(*args, **kwargs):
        save_threads.append(threading.get_ident())
        return real_save(*args, **kwargs)

    store.save_finding = spying
    tools = _make_tools(memory_service=service)

    async def scenario():
        loop_thread = threading.get_ident()
        result = await tools.remember_server_finding("i-abc123", "t", "b")
        return loop_thread, result

    loop_thread, result = asyncio.run(scenario())
    assert result.startswith("finding_id:")
    assert save_threads and all(t != loop_thread for t in save_threads)
    assert queue_threads == [loop_thread]

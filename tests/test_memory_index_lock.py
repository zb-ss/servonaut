"""Every change to ``index.json`` is serialised, in this process and across processes."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

from servonaut.services.memory.store import LOCKS_DIR, MemoryStore, RecordLockTimeout
from servonaut.utils.file_lock import FileLock

import pytest

ITERATIONS = 300
TRIALS = 5


def _instances(root: Path) -> dict:
    return json.loads((root / "index.json").read_text())["instances"]


def test_index_writers_on_two_threads_lose_no_entry(tmp_path):
    for trial in range(TRIALS):
        root = tmp_path / f"trial-{trial}"
        store = MemoryStore(root)
        # The race is the subject, not the wait: a loaded machine must not time out.
        store.set_record_lock_wait(120.0, 0.005)

        def bookkeeping():
            for i in range(ITERATIONS):
                store.set_findings_meta("web-meta", findings_count=i)
                store.set_annotations_meta("web-notes", annotations_hash=str(i))

        worker = threading.Thread(target=bookkeeping)
        worker.start()
        for i in range(ITERATIONS):
            store.update_index(f"web-{i}", "web", "AWS", ["os"])
        worker.join()

        expected = {f"web-{i}" for i in range(ITERATIONS)} | {"web-meta", "web-notes"}
        assert expected - set(_instances(root)) == set()


def test_index_writers_in_two_processes_lose_no_entry(tmp_path):
    script = textwrap.dedent(
        """
        import sys
        from pathlib import Path
        from servonaut.services.memory.store import MemoryStore
        store = MemoryStore(Path(sys.argv[1]))
        store.set_record_lock_wait(120.0, 0.005)
        for i in range(int(sys.argv[3])):
            store.update_index(f"{sys.argv[2]}-{i}", "web", "AWS", ["os"])
        """
    )
    count = 80
    children = [
        subprocess.Popen([sys.executable, "-c", script, str(tmp_path), prefix, str(count)])
        for prefix in ("alpha", "beta")
    ]
    for child in children:
        assert child.wait(timeout=120) == 0
    expected = {f"{p}-{i}" for p in ("alpha", "beta") for i in range(count)}
    assert expected - set(_instances(tmp_path)) == set()


def test_index_change_waits_a_bounded_time_for_another_process(tmp_path):
    store = MemoryStore(tmp_path)
    store.set_record_lock_wait(0.2, 0.02)
    lock = FileLock(tmp_path / LOCKS_DIR / "index.lock", private_dir=True)
    assert lock.try_acquire()
    try:
        with pytest.raises(RecordLockTimeout):
            store.update_index("web-1", "web", "AWS", ["os"])
    finally:
        lock.release()
    store.update_index("web-1", "web", "AWS", ["os"])
    assert "web-1" in _instances(tmp_path)


def test_record_lock_then_index_lock_nests(tmp_path):
    store = MemoryStore(tmp_path)
    with store.annotation_lock("web-1"):
        store.update_index("web-1", "web", "AWS", ["os"])
        store.set_annotations_meta("web-1", annotations_hash="x")
    assert _instances(tmp_path)["web-1"]["annotations_hash"] == "x"

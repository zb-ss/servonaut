"""A share filed in two folders is still imported into its target once."""
from __future__ import annotations

from tests.test_memory_team_merge import (
    FIRST, OWN_ID, SECOND, SHARE_ID, _own, _put_copy, _run, _service, _shared,
)
from tests.test_memory_team_merge_v3 import Retrieval, _sync

ROWS = [_own(), _shared()]
NOTE = "note from the canonical folder"


def _two_folders(tmp_path):
    service = _service(tmp_path)
    _put_copy(
        service, notes="note from the older label folder",
        findings=[{"id": FIRST, "title": "old", "created_at": "2026-01-01"}],
    )
    store = service._store
    store.write_annotations(SHARE_ID, NOTE, "shared")
    store.save_finding(SHARE_ID, {"id": SECOND, "title": "canonical", "created_at": "2026-01-01"}, "shared")
    locked = _sync(tmp_path, service, configured=False, enrolled=True)
    first = _run(service, ROWS, locked)
    return service, first


def test_a_note_deleted_after_a_locked_pass_stays_deleted_with_two_folders(tmp_path):
    service, first = _two_folders(tmp_path)
    assert first.copies == 2
    store = service._store
    service.write_annotations(OWN_ID, "", "aws")
    store.delete_finding(OWN_ID, SECOND, "aws")
    remote = Retrieval(
        notes={"content": NOTE},
        findings={"findings": [{"id": SECOND, "title": "canonical", "created_at": "2026-01-01"}]},
    )
    _run(service, ROWS, _sync(tmp_path / "ready", service, remote))
    assert service.read_annotations(OWN_ID, "aws") == ""
    assert store.get_finding(OWN_ID, SECOND, "aws") is None


def test_service_only_content_is_still_imported_once_with_two_folders(tmp_path):
    service, _ = _two_folders(tmp_path)
    remote = Retrieval(
        notes={"content": f"{NOTE}\nonly the service has this"},
        findings={"findings": [{"id": "f_cccccccccccccccc", "title": "remote", "created_at": "2026-01-01"}]},
    )
    _run(service, ROWS, _sync(tmp_path / "ready", service, remote))
    notes = service.read_annotations(OWN_ID, "aws")
    assert notes.count("only the service has this") == 1
    assert service._store.get_finding(OWN_ID, "f_cccccccccccccccc", "aws") is not None

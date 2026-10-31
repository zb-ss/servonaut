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


def test_nobody_can_edit_the_target_between_the_merge_and_the_marker(tmp_path):
    """The target stays locked from the merge through the marker write."""
    import threading
    from unittest.mock import patch

    from servonaut.services.memory.store import RecordLockTimeout
    from servonaut.services.memory.team_merge import TeamCopyMerger
    from tests.test_memory_team_merge import SHARE_ID as share
    from tests.test_memory_team_merge_v3 import _marker

    service = _service(tmp_path)
    _put_copy(service, notes="team note")
    service._store.set_record_lock_wait(0.1, 0.01)
    outcomes = []
    original = TeamCopyMerger.mark_merged

    def delete_from_elsewhere_then_mark(merger, *args, **kwargs):
        def other_writer():
            try:
                service.write_annotations(OWN_ID, "", "aws")
                outcomes.append("deleted")
            except RecordLockTimeout:
                outcomes.append("blocked")

        thread = threading.Thread(target=other_writer)
        thread.start()
        thread.join(3)
        return original(merger, *args, **kwargs)

    with patch.object(TeamCopyMerger, "mark_merged", delete_from_elsewhere_then_mark):
        first = _run(service, ROWS, _sync(tmp_path, service, configured=False, enrolled=True))
    assert outcomes == ["blocked"]
    assert first.copies == 1 and not first.kept
    assert _marker(tmp_path) is not None
    # An edit after the marker is the user's and is not undone.
    service.write_annotations(OWN_ID, "", "aws")
    again = _run(service, ROWS, _sync(tmp_path, service, configured=False, enrolled=True))
    assert service.read_annotations(OWN_ID, "aws") == ""
    assert again.copies == 0 and share

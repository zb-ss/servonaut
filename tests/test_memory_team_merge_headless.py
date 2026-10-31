"""A locked Memory Sync merges the local part once; the service part follows later."""
from __future__ import annotations

from tests.test_memory_team_merge import (
    FIRST,
    NEW,
    OLD,
    OWN_ID,
    SHARE_ID,
    _module,
    _own,
    _put_copy,
    _service,
    _shared,
)
from tests.test_memory_team_merge_v3 import Retrieval, _copy_dir, _marker, _run, _sync
from servonaut.utils.file_lock import FileLock

ROWS = [_own(), _shared()]


def _locked(tmp_path, service, retrieval=None):
    return _sync(tmp_path, service, retrieval, configured=False, enrolled=True)


def _ready(tmp_path, service, retrieval=None):
    return _sync(tmp_path / "ready", service, retrieval)


class TestLockedPass:
    def test_marks_the_copy_and_records_that_the_service_part_is_owed(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        report = _run(service, ROWS, _locked(tmp_path, service))
        assert service.read_annotations(OWN_ID, "aws") == "team note"
        assert report.copies == 1
        marker = _marker(tmp_path)
        assert marker["remote_pending"] is True and marker["target_id"] == OWN_ID

    def test_a_note_deleted_from_the_own_record_does_not_come_back(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note", findings=[{"id": FIRST, "title": "t", "created_at": OLD}])
        sync = _locked(tmp_path, service)
        _run(service, ROWS, sync)
        service.write_annotations(OWN_ID, "", "aws")
        second = _run(service, ROWS, sync)
        assert service.read_annotations(OWN_ID, "aws") == "" and second.copies == 0
        assert _copy_dir(tmp_path, "team team a").joinpath("annotations.md").read_text() == "team note"

    def test_with_no_sync_service_at_all_the_local_merge_is_final(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        assert _run(service, ROWS, None).copies == 1
        assert not _marker(tmp_path).get("remote_pending")

    def test_sync_not_set_up_owes_nothing_remote(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        _run(service, ROWS, _sync(tmp_path, service, configured=False, enrolled=False))
        assert not _marker(tmp_path).get("remote_pending")

    def test_an_unverified_local_merge_writes_no_marker(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        monkeypatch.setattr(
            "servonaut.services.memory.team_merge.TeamCopyMerger.is_contained", lambda *a: False
        )
        report = _run(service, ROWS, _locked(tmp_path, service))
        assert _marker(tmp_path) is None and SHARE_ID in report.kept


class TestLaterReadyPass:
    def test_reads_the_service_merges_it_clears_the_flag_and_queues_uploads(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        _run(service, ROWS, _locked(tmp_path, service))
        retrieval = Retrieval(notes={"content": "cloud note"}, findings=None)
        ready = _ready(tmp_path, service, retrieval)
        report = _run(service, ROWS, ready)
        merged = service.read_annotations(OWN_ID, "aws")
        assert "team note" in merged and "cloud note" in merged
        assert retrieval.calls, "the service is read"
        marker = _marker(tmp_path)
        assert marker["remote_pending"] is False and marker["upload_pending"] is False
        assert ready.pending_count(OWN_ID) >= 1
        assert report.notes == 1

    def test_a_note_deleted_while_locked_stays_deleted_but_the_service_part_arrives(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        locked = _locked(tmp_path, service)
        _run(service, ROWS, locked)
        service.write_annotations(OWN_ID, "", "aws")
        _run(service, ROWS, locked)
        _run(service, ROWS, _ready(tmp_path, service, Retrieval(notes={"content": "cloud note"})))
        merged = service.read_annotations(OWN_ID, "aws")
        assert "team note" not in merged and "cloud note" in merged

    def test_the_service_is_not_read_again_once_the_flag_is_clear(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        _run(service, ROWS, _locked(tmp_path, service))
        retrieval = Retrieval(notes={"content": "cloud note"})
        ready = _ready(tmp_path, service, retrieval)
        _run(service, ROWS, ready)
        calls = len(retrieval.calls)
        _run(service, ROWS, ready)
        assert len(retrieval.calls) == calls

    def test_a_read_that_is_unavailable_keeps_the_flag(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        _run(service, ROWS, _locked(tmp_path, service))
        broken = Retrieval(notes=RuntimeError("offline"), findings=RuntimeError("offline"))
        _run(service, ROWS, _ready(tmp_path, service, broken))
        assert _marker(tmp_path)["remote_pending"] is True
        working = Retrieval(notes={"content": "cloud note"})
        _run(service, ROWS, _ready(tmp_path / "again", service, working))
        assert _marker(tmp_path)["remote_pending"] is False
        assert "cloud note" in service.read_annotations(OWN_ID, "aws")

    def test_a_ready_first_pass_whose_read_is_unavailable_marks_with_the_flag(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        broken = Retrieval(notes=RuntimeError("offline"), findings=RuntimeError("offline"))
        report = _run(service, ROWS, _sync(tmp_path, service, broken))
        assert report.copies == 1 and _marker(tmp_path)["remote_pending"] is True

    def test_findings_from_the_service_are_merged_into_the_marked_target(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        _run(service, ROWS, _locked(tmp_path, service))
        remote = {"findings": [{"id": FIRST, "title": "remote", "created_at": NEW}]}
        _run(service, ROWS, _ready(tmp_path, service, Retrieval(notes=None, findings=remote)))
        ids = {r["id"] for r in service.list_findings(OWN_ID, "aws", include_superseded=True)}
        assert ids == {FIRST}

    def test_a_member_row_completes_into_the_shared_row_and_uploads_nothing(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        member = [_shared(instance_id=None, hostname="5.6.7.8")]
        _run(service, member, _locked(tmp_path, service))
        ready = _ready(tmp_path, service, Retrieval(notes={"content": "cloud note"}))
        _run(service, member, ready)
        assert _marker(tmp_path)["remote_pending"] is False
        assert ready.pending_count(SHARE_ID) == 0


class TestEarlierMarkers:
    def test_a_marker_without_the_flag_reads_as_false(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        service._store.write_merge_marker(SHARE_ID, "team team a", {
            "target_provider": "aws", "target_id": OWN_ID,
            "merged_at": "2026-10-01T00:00:00+00:00", "upload_pending": False,
        })
        retrieval = Retrieval(notes={"content": "cloud note"})
        report = _run(service, ROWS, _ready(tmp_path, service, retrieval))
        assert retrieval.calls == [] and report.copies == 0
        assert service.read_annotations(OWN_ID, "aws") == ""


class TestCloudOnlyPlans:
    def test_locked_pass_writes_nothing_and_a_ready_pass_imports(self, tmp_path):
        service = _service(tmp_path)
        rows = [_own(), _shared()]
        _run(service, rows, _locked(tmp_path, service))
        assert not _copy_dir(tmp_path, "team team a").exists()
        retrieval = Retrieval(notes={"content": "cloud note"})
        _run(service, rows, _ready(tmp_path, service, retrieval))
        assert "cloud note" in service.read_annotations(OWN_ID, "aws")


class TestOnePassAtATime:
    def test_a_busy_pass_lock_skips_the_pass(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        holder = FileLock(service._store.root / "team_merge.lock")
        assert holder.try_acquire()
        try:
            report = _run(service, ROWS, _locked(tmp_path, service))
        finally:
            holder.release()
        assert report.skipped is True and report.copies == 0
        assert service.read_annotations(OWN_ID, "aws") == "" and _marker(tmp_path) is None
        assert _run(service, ROWS, _locked(tmp_path, service)).copies == 1

    def test_the_lock_is_released_after_a_pass(self, tmp_path):
        service = _service(tmp_path)
        _run(service, ROWS, _locked(tmp_path, service))
        probe = FileLock(service._store.root / "team_merge.lock")
        assert probe.try_acquire()
        probe.release()

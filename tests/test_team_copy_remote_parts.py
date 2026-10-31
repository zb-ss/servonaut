"""The service's part of a team copy is merged beyond what the copy already held."""
from __future__ import annotations

import logging

from tests.test_memory_team_merge import (
    FIRST, NEW, OLD, OWN_ID, SECOND, SHARE_ID, _own, _put_copy, _service, _shared,
)
from tests.test_memory_team_merge_v3 import Retrieval, _marker, _run, _sync

ROWS = [_own(), _shared()]
LEGACY = "team team a"


def _locked(tmp_path, service):
    return _sync(tmp_path, service, configured=False, enrolled=True)


def _ready(tmp_path, service, retrieval):
    return _sync(tmp_path / "ready", service, retrieval)


def _finding(fid, title, at=OLD):
    return {"id": fid, "title": title, "created_at": at, "updated_at": at}


class TestNoResurrection:
    def test_text_the_copy_holds_is_not_brought_back_after_the_user_deleted_it(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="local note")
        _run(service, ROWS, _locked(tmp_path, service))
        service.write_annotations(OWN_ID, "", "aws")
        retrieval = Retrieval(notes={"content": "local note"})
        _run(service, ROWS, _ready(tmp_path, service, retrieval))
        assert service.read_annotations(OWN_ID, "aws") == ""

    def test_text_only_the_service_holds_is_still_merged(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="local note")
        _run(service, ROWS, _locked(tmp_path, service))
        service.write_annotations(OWN_ID, "", "aws")
        retrieval = Retrieval(notes={"content": "local note\nremote only note"})
        _run(service, ROWS, _ready(tmp_path, service, retrieval))
        merged = service.read_annotations(OWN_ID, "aws")
        assert merged == "remote only note"

    def test_a_finding_the_copy_holds_is_not_brought_back_but_a_new_one_is(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, findings=[_finding(FIRST, "local")])
        _run(service, ROWS, _locked(tmp_path, service))
        service._store.delete_finding(OWN_ID, FIRST, "aws")
        remote = {"findings": [_finding(FIRST, "local"), _finding(SECOND, "remote", NEW)]}
        _run(service, ROWS, _ready(tmp_path, service, Retrieval(findings=remote)))
        ids = {r["id"] for r in service.list_findings(OWN_ID, "aws", include_superseded=True)}
        assert ids == {SECOND}


class TestPartsAreSettledSeparately:
    def test_notes_settle_while_findings_are_retried(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="local note")
        _run(service, ROWS, _locked(tmp_path, service))
        retrieval = Retrieval(notes={"content": "remote only note"}, findings=RuntimeError("offline"))
        ready = _ready(tmp_path, service, retrieval)
        _run(service, ROWS, ready)
        marker = _marker(tmp_path)
        assert marker["remote_notes_pending"] is False and marker["remote_findings_pending"] is True
        assert "remote only note" in service.read_annotations(OWN_ID, "aws")
        service.write_annotations(OWN_ID, "mine", "aws")
        retrieval.answers.update(findings={"findings": [_finding(SECOND, "remote", NEW)]})
        _run(service, ROWS, ready)
        assert service.read_annotations(OWN_ID, "aws") == "mine"
        assert {r["id"] for r in service.list_findings(OWN_ID, "aws")} == {SECOND}
        marker = _marker(tmp_path)
        assert marker["remote_notes_pending"] is False and marker["remote_findings_pending"] is False

    def test_a_marker_with_the_old_single_flag_owes_both_parts(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="local note")
        _run(service, ROWS, _locked(tmp_path, service))
        legacy = {k: v for k, v in _marker(tmp_path).items()
                  if k not in ("remote_notes_pending", "remote_findings_pending")}
        legacy["remote_pending"] = True
        service._store.write_merge_marker(SHARE_ID, LEGACY, legacy)
        remote = {"findings": [_finding(SECOND, "remote", NEW)]}
        _run(service, ROWS, _ready(tmp_path, service, Retrieval(notes={"content": "remote only"}, findings=remote)))
        assert "remote only" in service.read_annotations(OWN_ID, "aws")
        assert {r["id"] for r in service.list_findings(OWN_ID, "aws")} == {SECOND}
        assert not _marker(tmp_path)["remote_pending"]


class TestOneTarget:
    def _changed_twin(self, tmp_path, *, remote_pending):
        service = _service(tmp_path)
        _put_copy(service, notes="local note")
        _run(service, ROWS, _locked(tmp_path, service))
        if not remote_pending:
            marker = _marker(tmp_path)
            marker.update(remote_pending=False, remote_notes_pending=False,
                          remote_findings_pending=False, upload_pending=True)
            service._store.write_merge_marker(SHARE_ID, LEGACY, marker)
        before = _marker(tmp_path)
        new_id = "i-new"
        rows = [_own(id=new_id), _shared(instance_id=new_id)]
        retrieval = Retrieval(notes={"content": "remote note"})
        sync = _ready(tmp_path, service, retrieval)
        return service, rows, sync, retrieval, before, new_id

    def test_service_part_is_not_merged_into_a_different_target(self, tmp_path, caplog):
        service, rows, sync, retrieval, before, new_id = self._changed_twin(tmp_path, remote_pending=True)
        with caplog.at_level(logging.INFO, logger="servonaut.services.memory.team_merge"):
            report = _run(service, rows, sync)
        assert _marker(tmp_path) == before
        assert SHARE_ID in report.kept and report.copies == 0
        assert service.read_annotations(new_id, "aws") == ""
        assert "remote note" not in service.read_annotations(OWN_ID, "aws")
        mismatch = [r.getMessage() for r in caplog.records if "target" in r.getMessage().lower()]
        assert len(mismatch) == 1 and SHARE_ID not in mismatch[0] and OWN_ID not in mismatch[0]

    def test_uploads_are_not_retried_for_a_different_target(self, tmp_path):
        service, rows, sync, retrieval, before, new_id = self._changed_twin(tmp_path, remote_pending=False)
        report = _run(service, rows, sync)
        assert _marker(tmp_path) == before
        assert SHARE_ID in report.kept
        assert sync.pending_count(new_id) == 0 and sync.pending_count(OWN_ID) == 0

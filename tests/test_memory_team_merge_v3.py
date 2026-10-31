"""The team-copy merge is non-destructive: it reads, merges, verifies, then marks.

Runs through the real sync service and the real store; only the retrieval
boundary (what the service answers) is scripted.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from servonaut.services.memory.interfaces import MemoryNotFound
from servonaut.services.memory.store import TEAM_MERGED_MARKER, MemoryStore
from servonaut.services.memory.team_merge import merge_team_copies, share_identity
from tests.test_memory_sync_service import _make_config_manager, _make_service
from tests.test_memory_team_merge import (
    FIRST,
    NEW,
    OLD,
    OWN_ID,
    SECOND,
    SHARE_ID,
    _module,
    _own,
    _put_copy,
    _service,
    _shared,
)

LEGACY = "team team a"
OTHER = "88888888-aaaa-bbbb-cccc-000000000008"  # leak-guard:allow


class Retrieval:
    """What the service answers: payload, exception, or MemoryNotFound per module."""

    def __init__(self, notes: Any = None, findings: Any = None) -> None:
        self.answers = {"annotations": notes, "findings": findings}
        self.calls: List[tuple] = []

    async def get_module(self, instance_id: str, module: str):
        self.calls.append((instance_id, module))
        answer = self.answers[module]
        if answer is None:
            raise MemoryNotFound("access_revoked")
        if isinstance(answer, BaseException):
            raise answer
        return SimpleNamespace(plaintext=answer, probed_at="", created_at="")


def _sync(tmp_path, service, retrieval=None, *, configured=True, enrolled=False):
    cfg = _make_config_manager()
    cfg.get.return_value.memory.findings_sync_enabled = True
    svc = _make_service(memory_service=service, config_manager=cfg, tmp_path=tmp_path / "sync",
                        configured=configured)
    svc.set_retrieval_service(retrieval or Retrieval())
    if enrolled:
        svc._key_cache_path.parent.mkdir(parents=True, exist_ok=True)
        svc._key_cache_path.write_text("{}")
    return svc


def _ids(*ids):
    async def listing():
        return list(ids)
    return listing


def _run(service, rows, sync, *ids):
    listing = None if sync is None else _ids(*ids)
    return asyncio.run(merge_team_copies(
        service, sync, rows, today="2026-10-31"))


def _copy_dir(root, slug=LEGACY, share=SHARE_ID):
    return root / slug / share


def _marker(root, slug=LEGACY, share=SHARE_ID):
    path = _copy_dir(root, slug, share) / TEAM_MERGED_MARKER
    return json.loads(path.read_text()) if path.is_file() else None


class TestRemoteIsReadNotWritten:
    @pytest.mark.parametrize("local_modified", [
        "2000-01-01T00:00:00+00:00",   # the copy's note is older than the service's
        "2999-01-01T00:00:00+00:00",   # ... or newer
    ])
    def test_both_texts_reach_the_own_row_and_the_copy_is_untouched(self, tmp_path, local_modified):
        service = _service(tmp_path)
        _put_copy(service, notes="LOCAL ONLY NOTE")
        service.set_annotations_meta(SHARE_ID, annotations_modified_at=local_modified)
        sync = _sync(tmp_path, service, Retrieval(notes={"content": "CLOUD ONLY NOTE"}, findings=None))
        report = _run(service, [_own(), _shared()], sync, SHARE_ID)
        merged = service.read_annotations(OWN_ID, "aws")
        assert merged.count("LOCAL ONLY NOTE") == 1 and merged.count("CLOUD ONLY NOTE") == 1
        assert (_copy_dir(tmp_path) / "annotations.md").read_text() == "LOCAL ONLY NOTE"
        assert report.copies == 1

    def test_a_cancel_while_reading_the_service_loses_nothing(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="LOCAL ONLY NOTE")
        retrieval = Retrieval(notes={"content": "CLOUD ONLY NOTE"}, findings=asyncio.CancelledError())
        sync = _sync(tmp_path, service, retrieval)
        with pytest.raises(asyncio.CancelledError):
            _run(service, [_own(), _shared()], sync, SHARE_ID)
        assert (_copy_dir(tmp_path) / "annotations.md").read_text() == "LOCAL ONLY NOTE"
        assert _marker(tmp_path) is None
        retrieval.answers["findings"] = None
        report = _run(service, [_own(), _shared()], sync, SHARE_ID)
        merged = service.read_annotations(OWN_ID, "aws")
        assert "LOCAL ONLY NOTE" in merged and "CLOUD ONLY NOTE" in merged and report.copies == 1

    def test_remote_findings_are_merged_with_the_local_ones(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, findings=[{"id": FIRST, "title": "local", "created_at": OLD}])
        remote = {"findings": [{"id": SECOND, "title": "remote", "created_at": NEW}]}
        sync = _sync(tmp_path, service, Retrieval(notes=None, findings=remote))
        _run(service, [_own(), _shared()], sync, SHARE_ID)
        ids = {r["id"] for r in service.list_findings(OWN_ID, "aws", include_superseded=True)}
        assert ids == {FIRST, SECOND}


class TestMarker:
    def test_an_unreadable_service_leaves_no_marker_and_a_later_pass_finishes(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="local")
        retrieval = Retrieval(notes=RuntimeError("offline"), findings=RuntimeError("offline"))
        sync = _sync(tmp_path, service, retrieval)
        first = _run(service, [_own(), _shared()], sync, SHARE_ID)
        assert service.read_annotations(OWN_ID, "aws") == "local"        # merged locally
        assert first.copies == 0 and SHARE_ID in first.kept and _marker(tmp_path) is None
        retrieval.answers.update(annotations={"content": "cloud"}, findings=None)
        second = _run(service, [_own(), _shared()], sync, SHARE_ID)
        assert second.copies == 1 and "cloud" in service.read_annotations(OWN_ID, "aws")
        assert _marker(tmp_path)["target_id"] == OWN_ID

    def test_a_verified_absence_is_settled(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="local")
        sync = _sync(tmp_path, service, Retrieval(notes=None, findings=None))
        assert _run(service, [_own(), _shared()], sync, SHARE_ID).copies == 1

    def test_the_copy_is_never_moved_and_a_deleted_note_is_not_resurrected(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note", module=_module(NEW, distro="team"))
        sync = _sync(tmp_path, service)
        rows = [_own(), _shared()]
        _run(service, rows, sync)
        assert (_copy_dir(tmp_path) / "annotations.md").read_text() == "team note"
        service.write_annotations(OWN_ID, "", "aws")     # the user clears the note
        second = _run(service, rows, sync)
        assert second.copies == 0 and service.read_annotations(OWN_ID, "aws") == ""

    def test_a_failed_marker_write_is_retried(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        sync = _sync(tmp_path, service)
        real = MemoryStore.write_merge_marker
        monkeypatch.setattr(MemoryStore, "write_merge_marker",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
        first = _run(service, [_own(), _shared()], sync)
        assert first.copies == 0 and SHARE_ID in first.kept
        monkeypatch.setattr(MemoryStore, "write_merge_marker", real)
        assert _run(service, [_own(), _shared()], sync).copies == 1

    def test_a_locked_sync_merges_locally_and_marks_nothing(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        sync = _sync(tmp_path, service, configured=False, enrolled=True)
        report = _run(service, [_own(), _shared()], sync)
        assert service.read_annotations(OWN_ID, "aws") == "team note"
        assert report.copies == 0 and _marker(tmp_path) is None

    def test_sync_not_set_up_marks_after_the_local_merge(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        sync = _sync(tmp_path, service, configured=False, enrolled=False)
        assert _run(service, [_own(), _shared()], sync).copies == 1


class TestUploads:
    def test_a_refused_upload_leaves_the_flag_and_the_copys_queue(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        sync = _sync(tmp_path, service)
        from tests.test_memory_sync_service import _make_module_result
        sync.enqueue_module({"id": SHARE_ID, "name": "web-1"}, "os", _make_module_result())
        sync.set_folded_instance_ids({SHARE_ID})
        monkeypatch.setattr("servonaut.services.memory.sync_service._QUEUE_CAP", 1)  # full
        _run(service, [_own(), _shared()], sync)
        assert _marker(tmp_path)["upload_pending"] is True
        assert sync.pending_count(SHARE_ID) == 1                  # the copy's queue is kept
        monkeypatch.setattr("servonaut.services.memory.sync_service._QUEUE_CAP", 100)
        _run(service, [_own(), _shared()], sync)
        assert _marker(tmp_path)["upload_pending"] is False
        assert sync.pending_count(SHARE_ID) == 0 and sync.pending_count(OWN_ID) == 1

    def test_a_member_keeps_their_queue_and_owes_no_upload(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        sync = _sync(tmp_path, service)
        from tests.test_memory_sync_service import _make_module_result
        sync.enqueue_module({"id": SHARE_ID, "name": "web-1"}, "os", _make_module_result())
        _run(service, [_member_row()], sync)
        assert sync.pending_count(SHARE_ID) == 1
        assert _marker(tmp_path)["upload_pending"] is False


def _member_row():
    return _shared(instance_id=None, hostname="8.8.8.8")


class TestDiscovery:
    def test_a_copy_is_found_without_the_index_and_after_a_failed_first_attempt(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        store = service._store
        store.save_finding(SHARE_ID, {"id": FIRST, "title": "t", "created_at": NEW}, "former team")
        service.update_index(SHARE_ID, "web-1", "Former Team", [])
        real = MemoryStore.save_finding

        def failing(self, instance_id, record, provider="custom"):
            if instance_id == OWN_ID:
                raise OSError("disk full")
            return real(self, instance_id, record, provider)

        monkeypatch.setattr(MemoryStore, "save_finding", failing)
        sync = _sync(tmp_path, service)
        assert _run(service, [_own(), _shared()], sync).copies == 0
        monkeypatch.setattr(MemoryStore, "save_finding", real)
        store._remove_from_index(SHARE_ID)               # the index no longer helps
        report = _run(service, [_own(), _shared()], sync)
        assert report.copies == 1
        assert [r["id"] for r in service.list_findings(OWN_ID, "aws")] == [FIRST]

    def test_a_members_legacy_entry_moves_to_the_shared_key_and_stays_in_place(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="hand written", module=_module(NEW, distro="team"),
                  findings=[{"id": FIRST, "title": "t", "created_at": NEW}])
        sync = _sync(tmp_path, service)
        _run(service, [_member_row()], sync)
        assert service.read_annotations(SHARE_ID, "shared") == "hand written"
        assert "os" in service._store.get_all_modules(SHARE_ID, "shared")
        assert service._store.get_index_entry(SHARE_ID)["provider"] == "shared"
        assert (_copy_dir(tmp_path) / "annotations.md").is_file()
        assert _marker(tmp_path)["target_provider"] == "shared"



class TestUnsafeData:
    def test_a_symlinked_note_is_never_read_and_other_copies_still_merge(self, tmp_path):
        service = _service(tmp_path)
        outside = tmp_path / "private.md"
        outside.write_text("PRIVATE")
        _put_copy(service, notes="x")
        (_copy_dir(tmp_path) / "annotations.md").unlink()
        os.symlink(outside, _copy_dir(tmp_path) / "annotations.md")
        service._store.write_annotations(OTHER, "second copy note", LEGACY)
        service.update_index(OTHER, "web-2", "Team Team A", [])
        rows = [_own(), _shared(), _shared(id=OTHER, instance_id="i-0def0def0def0def0", hostname="8.8.4.4")]
        rows.append(_own(id="i-0def0def0def0def0", name="web-2", public_ip="8.8.4.4"))
        report = _run(service, rows, _sync(tmp_path, service))
        assert "PRIVATE" not in service.read_annotations(OWN_ID, "aws")
        assert SHARE_ID in report.kept and report.copies == 1
        assert service.read_annotations("i-0def0def0def0def0", "aws") == "second copy note"

    def test_valid_json_of_the_wrong_shape_keeps_that_copy_and_the_pass_goes_on(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="x")
        (_copy_dir(tmp_path) / "findings").mkdir()
        (_copy_dir(tmp_path) / "findings" / f"{FIRST}.json").write_text("null")
        service._store.write_annotations(OTHER, "second", LEGACY)
        service.update_index(OTHER, "web-2", "Team Team A", [])
        rows = [_own(), _shared(), _own(id="i-0def0def0def0def0", name="web-2", public_ip="8.8.4.4"),
                _shared(id=OTHER, instance_id="i-0def0def0def0def0", hostname="8.8.4.4")]
        report = _run(service, rows, _sync(tmp_path, service))
        assert SHARE_ID in report.kept and report.copies == 1


class TestCloudOnly:
    def test_a_share_with_no_folder_is_merged_from_the_service_and_recorded_on_the_target(self, tmp_path):
        service = _service(tmp_path)
        retrieval = Retrieval(notes={"content": "only in the cloud"}, findings=None)
        sync = _sync(tmp_path, service, retrieval)
        rows = [_own(), _shared()]
        assert _run(service, rows, sync).copies == 1
        assert service.read_annotations(OWN_ID, "aws") == "only in the cloud"
        assert not (tmp_path / "shared").exists()                    # no folder made for the share
        assert service._store.get_cloud_import(OWN_ID, SHARE_ID)["state"] == "imported"
        calls = len(retrieval.calls)
        _run(service, rows, sync)
        assert len(retrieval.calls) == calls                         # recorded: not read again

    def test_a_verified_absence_is_remembered_for_the_run_only(self, tmp_path):
        service = _service(tmp_path)
        retrieval = Retrieval(notes=None, findings=None)
        sync = _sync(tmp_path, service, retrieval)
        absent = set()
        asyncio.run(merge_team_copies(service, sync, [_own(), _shared()], absent_ids=absent))
        assert absent == {SHARE_ID} and service._store.get_cloud_import(OWN_ID, SHARE_ID) is None
        calls = len(retrieval.calls)
        asyncio.run(merge_team_copies(service, sync, [_own(), _shared()], absent_ids=absent))
        assert len(retrieval.calls) == calls

    def test_an_unreadable_service_records_nothing(self, tmp_path):
        service = _service(tmp_path)
        retrieval = Retrieval(notes=RuntimeError("offline"), findings=RuntimeError("offline"))
        sync = _sync(tmp_path, service, retrieval)
        absent = set()
        asyncio.run(merge_team_copies(service, sync, [_own(), _shared()], absent_ids=absent))
        assert absent == set() and service._store.get_cloud_import(OWN_ID, SHARE_ID) is None

    def test_locked_or_unset_sync_reads_nothing_for_a_share_with_no_folder(self, tmp_path):
        service = _service(tmp_path)
        retrieval = Retrieval(notes={"content": "x"}, findings=None)
        for kwargs in ({"configured": False, "enrolled": True}, {"configured": False, "enrolled": False}):
            sync = _sync(tmp_path, service, retrieval, **kwargs)
            assert _run(service, [_own(), _shared()], sync).copies == 0
        assert retrieval.calls == []

    def test_a_members_canonical_folder_is_not_a_copy_of_itself(self, tmp_path):
        service = _service(tmp_path)
        service._store.write_annotations(SHARE_ID, "canonical", "shared")
        retrieval = Retrieval(notes={"content": "cloud"}, findings=None)
        sync = _sync(tmp_path, service, retrieval)
        report = _run(service, [_member_row()], sync)
        assert report.copies == 0 and retrieval.calls == []
        assert service.read_annotations(SHARE_ID, "shared") == "canonical"
        assert not (tmp_path / "shared" / SHARE_ID / TEAM_MERGED_MARKER).exists()

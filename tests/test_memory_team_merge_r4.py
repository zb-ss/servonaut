"""Marked copies stay merged, uploads retry on strict reads, and unsafe or malformed data is contained."""
from __future__ import annotations

import asyncio
import json
import os
import threading

import pytest

from servonaut.services.memory.store import TEAM_MERGED_MARKER, MemoryStore
from servonaut.services.memory.team_merge import TeamCopyMerger, MemoryKey, merge_team_copies
from tests.test_memory_team_merge import FIRST, NEW, OLD, OWN_ID, SECOND, SHARE_ID, _module, _own, _put_copy, _service, _shared
from tests.test_memory_team_merge_v3 import LEGACY, OTHER, Retrieval, _copy_dir, _marker, _member_row, _run, _sync

BAD = b"\xff\xfe not utf-8 \xc3\x28"
OTHER_OWN = "i-0def0def0def0def0"


def _second_pair():
    """A second own server with its own team copy, to show the pass goes on."""
    return [
        _own(id=OTHER_OWN, name="web-2", public_ip="8.8.4.4"),
        _shared(id=OTHER, name="web-2", instance_id=OTHER_OWN, hostname="8.8.4.4"),
    ]


def _second_copy(service):
    service._store.write_annotations(OTHER, "second copy note", LEGACY)
    service.update_index(OTHER, "web-2", "Team Team A", [])


class TestMarkedCopiesStayMerged:
    def test_a_member_who_gains_an_own_twin_never_gets_deleted_text_back(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="OLD TEXT")
        sync = _sync(tmp_path, service, configured=False, enrolled=False)
        _run(service, [_member_row()], sync)
        assert service.read_annotations(SHARE_ID, "shared") == "OLD TEXT"
        service.write_annotations(SHARE_ID, "CURRENT TEXT", "shared")        # the user edits it
        report = _run(service, [_own(), _shared()], sync)                    # now an own twin exists
        own = service.read_annotations(OWN_ID, "aws")
        assert "CURRENT TEXT" in own and "OLD TEXT" not in own
        assert _marker(tmp_path, "shared") is not None                       # the canonical record is marked too
        assert report.copies == 1

    def test_a_marked_copy_is_skipped_even_when_its_recorded_target_is_gone(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="OLD TEXT")
        sync = _sync(tmp_path, service, configured=False, enrolled=False)
        _run(service, [_member_row()], sync)
        import shutil
        shutil.rmtree(tmp_path / "shared" / SHARE_ID)
        _run(service, [_member_row()], sync)
        assert not (tmp_path / "shared" / SHARE_ID).exists()
        assert (_copy_dir(tmp_path) / "annotations.md").read_text() == "OLD TEXT"


class TestUploadRetryReadsStrictly:
    def _pending(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        _put_copy(service, notes="NEEDS UPLOAD")
        sync = _sync(tmp_path, service)
        from tests.test_memory_sync_service import _make_module_result
        sync.enqueue_module({"id": SHARE_ID, "name": "web-1"}, "os", _make_module_result())
        sync.set_folded_instance_ids({SHARE_ID})
        monkeypatch.setattr("servonaut.services.memory.sync_service._QUEUE_CAP", 1)
        _run(service, [_own(), _shared()], sync)
        monkeypatch.setattr("servonaut.services.memory.sync_service._QUEUE_CAP", 100)
        assert _marker(tmp_path)["upload_pending"] is True
        return service, sync

    def test_an_unreadable_target_note_keeps_the_flag_and_the_copys_queue(self, tmp_path, monkeypatch):
        service, sync = self._pending(tmp_path, monkeypatch)
        notes = tmp_path / "aws" / OWN_ID / "annotations.md"
        good = notes.read_bytes()
        notes.write_bytes(BAD)
        _run(service, [_own(), _shared()], sync)
        assert _marker(tmp_path)["upload_pending"] is True and sync.pending_count(SHARE_ID) == 1
        notes.write_bytes(good)
        _run(service, [_own(), _shared()], sync)
        assert _marker(tmp_path)["upload_pending"] is False
        assert sync.pending_count(SHARE_ID) == 0 and sync.pending_count(OWN_ID) == 1

    def test_a_corrupt_finding_is_a_failure_not_nothing_to_upload(self, tmp_path, monkeypatch):
        service, sync = self._pending(tmp_path, monkeypatch)
        (tmp_path / "aws" / OWN_ID / "findings").mkdir()
        (tmp_path / "aws" / OWN_ID / "findings" / f"{FIRST}.json").write_text("null")
        _run(service, [_own(), _shared()], sync)
        assert _marker(tmp_path)["upload_pending"] is True and sync.pending_count(SHARE_ID) == 1


class TestTargetAndRemoteSafety:
    def test_a_target_folder_that_links_outside_the_root_is_never_touched(self, tmp_path):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "annotations.md").write_text("OUTSIDE PRIVATE")
        (root / "aws").mkdir(parents=True)
        os.symlink(outside, root / "aws" / OWN_ID)
        service = _service(root)
        _put_copy(service, notes="COPY NOTE")
        sync = _sync(tmp_path, service)
        report = _run(service, [_own(), _shared()], sync)
        assert (outside / "annotations.md").read_text() == "OUTSIDE PRIVATE"
        assert report.copies == 0 and SHARE_ID in report.kept
        assert sync.pending_count(OWN_ID) == 0
        assert _marker(root) is None

    def test_a_malformed_target_module_keeps_that_copy_and_the_next_still_merges(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, module=_module(NEW, distro="team"))
        (tmp_path / "aws" / OWN_ID).mkdir(parents=True)
        (tmp_path / "aws" / OWN_ID / "os.json").write_text("[]")
        _second_copy(service)
        rows = [_own(), _shared()] + _second_pair()
        report = _run(service, rows, _sync(tmp_path, service))
        assert SHARE_ID in report.kept and report.copies == 1
        assert service.read_annotations(OTHER_OWN, "aws") == "second copy note"

    def test_a_remote_finding_with_a_wrong_typed_time_is_unavailable_and_nothing_is_marked(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="local")
        service._store.save_finding(OWN_ID, {"id": FIRST, "title": "x", "created_at": OLD}, "aws")
        bad = {"findings": [{"id": FIRST, "title": "y", "created_at": 7}]}
        sync = _sync(tmp_path, service, Retrieval(notes=None, findings=bad))
        _second_copy(service)
        report = _run(service, [_own(), _shared()] + _second_pair(), sync)
        assert _marker(tmp_path) is None and SHARE_ID in report.kept
        assert service.read_annotations(OTHER_OWN, "aws") == "second copy note"

    def test_an_unexpected_error_type_from_one_copy_is_contained(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        _put_copy(service, notes="boom")
        _second_copy(service)
        real = TeamCopyMerger.merge

        def merge(self, source, target, **kwargs):
            if source.instance_id == SHARE_ID:
                raise AttributeError("'list' object has no attribute 'get'")
            return real(self, source, target, **kwargs)

        monkeypatch.setattr(TeamCopyMerger, "merge", merge)
        report = _run(service, [_own(), _shared()] + _second_pair(), _sync(tmp_path, service))
        assert SHARE_ID in report.kept and report.copies == 1


class TestEditorAgainstTheRealMerger:
    @pytest.mark.timeout(60)
    def test_a_merge_that_starts_after_the_editor_compared_waits_and_keeps_both(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        store = service._store
        _put_copy(service, notes="TEAM NOTE")
        service.write_annotations(OWN_ID, "BASE", "aws")
        compared, release = threading.Event(), threading.Event()
        real = MemoryStore._write_annotations_locked

        def paused(self, instance_id, content, provider):
            compared.set()            # the editor has compared; its write has not happened yet
            release.wait(5)
            return real(self, instance_id, content, provider)

        monkeypatch.setattr(MemoryStore, "_write_annotations_locked", paused)
        import hashlib
        outcome = []
        editor = threading.Thread(target=lambda: outcome.append(store.write_annotations_if_unchanged(
            OWN_ID, hashlib.sha256(b"BASE").hexdigest(), "BASE\nUSER EDIT", "aws")))
        merge = threading.Thread(target=lambda: TeamCopyMerger(service)._merge_notes(
            MemoryKey("aws", OWN_ID), "TEAM NOTE", "a team", "2026-10-31"))
        editor.start()
        assert compared.wait(5)
        merge.start()
        merge.join(0.3)
        assert merge.is_alive()                       # blocked on the lock the editor holds
        release.set()
        editor.join(5), merge.join(5)
        assert not editor.is_alive() and not merge.is_alive()
        assert outcome == [True]
        final = service.read_annotations(OWN_ID, "aws")
        assert "USER EDIT" in final and "TEAM NOTE" in final


class TestCloudImportState:
    """A cloud-only import is recorded on the target before anything is written."""

    def _sync_with_cloud(self, tmp_path, service, **answers):
        retrieval = Retrieval(
            notes=answers.get("notes", {"content": "OLD CLOUD NOTE"}), findings=answers.get("findings"),
        )
        return _sync(tmp_path, service, retrieval), retrieval

    def test_a_refused_upload_then_a_user_edit_then_a_retry_keeps_the_edit(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        sync, retrieval = self._sync_with_cloud(tmp_path, service)
        from tests.test_memory_sync_service import _make_module_result
        sync.enqueue_module(_own(), "os", _make_module_result())
        monkeypatch.setattr("servonaut.services.memory.sync_service._QUEUE_CAP", 1)       # full
        rows = [_own(), _shared()]
        _run(service, rows, sync)
        assert service.read_annotations(OWN_ID, "aws") == "OLD CLOUD NOTE"
        assert service._store.get_cloud_import(OWN_ID, SHARE_ID) == {"state": "imported", "upload_pending": True}
        service.write_annotations(OWN_ID, "CURRENT USER NOTE", "aws")
        monkeypatch.setattr("servonaut.services.memory.sync_service._QUEUE_CAP", 100)
        calls = len(retrieval.calls)
        _run(service, rows, sync)
        assert service.read_annotations(OWN_ID, "aws") == "CURRENT USER NOTE"
        assert len(retrieval.calls) == calls                              # the cloud payload is not read again
        assert service._store.get_cloud_import(OWN_ID, SHARE_ID)["upload_pending"] is False
        assert any("CURRENT USER NOTE" in line for line in sync._queue_path.read_text().splitlines())

    def test_a_partial_member_import_is_finished_by_the_next_pass(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        finding = {"findings": [{"id": FIRST, "title": "HAND WRITTEN FINDING", "created_at": NEW}]}
        sync, retrieval = self._sync_with_cloud(tmp_path, service, notes={"content": "CLOUD NOTE"}, findings=finding)
        real = MemoryStore.save_finding
        monkeypatch.setattr(MemoryStore, "save_finding",
                            lambda *a, **k: (_ for _ in ()).throw(PermissionError("denied")))
        first = _run(service, [_member_row()], sync)
        assert first.copies == 0 and service.read_annotations(SHARE_ID, "shared") == "CLOUD NOTE"
        assert service._store.get_cloud_import(SHARE_ID, SHARE_ID)["state"] == "importing"
        monkeypatch.setattr(MemoryStore, "save_finding", real)
        second = _run(service, [_member_row()], sync)           # the canonical folder exists now
        assert second.copies == 1
        assert service._store.get_finding(SHARE_ID, FIRST, "shared")["title"] == "HAND WRITTEN FINDING"
        assert service._store.get_cloud_import(SHARE_ID, SHARE_ID)["state"] == "imported"
        calls = len(retrieval.calls)
        _run(service, [_member_row()], sync)
        assert len(retrieval.calls) == calls

    def test_an_existing_canonical_folder_without_a_pending_import_still_gets_no_plan(self, tmp_path):
        service = _service(tmp_path)
        service._store.write_annotations(SHARE_ID, "canonical", "shared")
        sync, retrieval = self._sync_with_cloud(tmp_path, service)
        _run(service, [_member_row()], sync)
        assert retrieval.calls == []


class TestSymlinkLoop:
    def test_a_looping_target_folder_is_skipped_and_the_pass_goes_on(self, tmp_path):
        root = tmp_path / "root"
        (root / "aws").mkdir(parents=True)
        os.symlink(root / "aws" / OWN_ID, root / "aws" / OWN_ID)       # points at itself
        service = _service(root)
        assert service._store.is_addressable(OWN_ID, "aws") is False
        _put_copy(service, notes="x")
        _second_copy(service)
        report = _run(service, [_own(), _shared()] + _second_pair(), _sync(tmp_path, service))
        assert SHARE_ID in report.kept and report.copies == 1
        assert service.read_annotations(OTHER_OWN, "aws") == "second copy note"

    def test_a_looping_provider_folder_is_not_addressable(self, tmp_path):
        # Python 3.13 stopped raising for a loop in a non-strict resolve().
        root = tmp_path / "root"
        root.mkdir()
        os.symlink(root / "aws", root / "aws")                          # points at itself
        service = _service(root)
        assert service._store.is_addressable(OWN_ID, "aws") is False

    def test_a_folder_that_does_not_exist_yet_is_addressable(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        service = _service(root)
        assert service._store.is_addressable(OWN_ID, "aws") is True

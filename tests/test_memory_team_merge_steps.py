"""Every step of the team-copy merge is safe to repeat, and the copy is moved last."""
from __future__ import annotations

import asyncio
import os
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.memory.store import MemoryStore
from servonaut.services.memory.sync_service import RemoteRead
from servonaut.services.memory.team_merge import merge_team_copies, share_identity
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


def _sync(configured: bool = True, enrolled: bool = True, **overrides: Any) -> MagicMock:
    sync = MagicMock()
    sync.is_configured = configured
    sync.is_enrolled_locally = MagicMock(return_value=enrolled)
    sync.fetch_remote_notes = AsyncMock(return_value=RemoteRead("absent"))
    sync.fetch_remote_findings = AsyncMock(return_value=RemoteRead("absent"))
    for name, value in overrides.items():
        setattr(sync, name, value)
    return sync


def _ids(*ids: str):
    async def listing() -> List[str]:
        return list(ids)
    return listing


def _run(service, rows, sync=None, listing=None, **kwargs):
    return asyncio.run(merge_team_copies(
        service, sync, rows, today="2026-10-31", **kwargs
    ))


class TestOrder:
    def test_the_queue_is_dropped_only_after_a_verified_merge(self, tmp_path):
        service = _service(tmp_path)
        service._config = type(service._config)(per_server_overrides={OWN_ID: {"memory_disabled": True}})
        _put_copy(service, notes="team note")
        sync = _sync()
        _run(service, [_own(), _shared()], sync, _ids())
        sync.drop_pending_for.assert_not_called()



class TestRemoteState:
    def test_sync_not_set_up_merges_and_backs_up(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        report = _run(service, [_own(), _shared()], _sync(configured=False, enrolled=False))
        assert report.copies == 1

    def test_sync_locked_merges_but_backs_up_nothing(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        listing = AsyncMock(return_value=[])
        report = _run(service, [_own(), _shared()], _sync(configured=False, enrolled=True), listing)
        listing.assert_not_awaited()
        assert service.read_annotations(OWN_ID, "aws") == "team note"
        assert report.copies == 0 and SHARE_ID in report.kept
        assert (tmp_path / LEGACY / SHARE_ID / "annotations.md").is_file()



class TestAddressing:
    def test_a_legacy_directory_that_is_a_symlink_out_of_the_root_is_never_read(self, tmp_path):
        root = tmp_path / "root"
        outside = tmp_path / "outside" / SHARE_ID
        outside.mkdir(parents=True)
        (outside / "annotations.md").write_text("outside note")
        (root / LEGACY).mkdir(parents=True)
        os.symlink(outside, root / LEGACY / SHARE_ID)
        service = _service(root)
        service.update_index(SHARE_ID, "web-1", "Team Team A", [])
        report = _run(service, [_own(), _shared()], _sync(configured=False, enrolled=False))
        assert service.read_annotations(OWN_ID, "aws") == ""
        assert (outside / "annotations.md").read_text() == "outside note"
        assert report.copies == 0

    def test_a_traversing_index_provider_is_ignored(self, tmp_path):
        service = _service(tmp_path / "root")
        (tmp_path / "outside" / SHARE_ID).mkdir(parents=True)
        (tmp_path / "outside" / SHARE_ID / "annotations.md").write_text("outside note")
        service.update_index(SHARE_ID, "web-1", "../outside", [])
        _run(service, [_own(), _shared()], _sync(configured=False, enrolled=False))
        assert service.read_annotations(OWN_ID, "aws") == ""


class TestVerifiesContent:
    def test_a_failed_finding_update_keeps_the_copy(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        service._store.save_finding(OWN_ID, {"id": FIRST, "title": "old", "created_at": OLD}, "aws")
        _put_copy(service, findings=[{"id": FIRST, "title": "new", "created_at": NEW}])
        real = MemoryStore.save_finding

        def failing(self, instance_id, record, provider="custom"):
            if instance_id == OWN_ID:
                raise OSError("disk full")
            return real(self, instance_id, record, provider)

        monkeypatch.setattr(MemoryStore, "save_finding", failing)
        report = _run(service, [_own(), _shared()], _sync(), _ids())
        assert report.copies == 0 and SHARE_ID in report.kept
        assert (tmp_path / LEGACY / SHARE_ID / "findings" / f"{FIRST}.json").is_file()

    def test_a_supersession_only_change_is_uploaded(self, tmp_path):
        service = _service(tmp_path)
        service._store.save_finding(
            OWN_ID, {"id": FIRST, "title": "newer text", "created_at": NEW}, "aws"
        )
        _put_copy(service, findings=[
            {"id": FIRST, "title": "older text", "created_at": OLD, "superseded_by": SECOND},
        ])
        sync = _sync()
        report = _run(service, [_own(), _shared()], sync, _ids())
        assert service._store.get_finding(OWN_ID, FIRST, "aws")["superseded_by"] == SECOND
        assert report.findings == 1
        sync.enqueue_findings.assert_called_once()

    def test_a_target_that_lost_a_supersession_is_not_verified(self):
        from servonaut.services.memory.team_merge import finding_contained
        source = {"id": FIRST, "title": "x", "created_at": OLD, "superseded_by": SECOND}
        assert not finding_contained(source, {"id": FIRST, "title": "x", "created_at": OLD})
        older = {"id": FIRST, "created_at": "2025-01-01T00:00:00+00:00", "superseded_by": SECOND}
        assert not finding_contained(source, older)
        assert finding_contained(source, {**source, "created_at": NEW})


class TestIndexAndIdentity:
    def test_a_notes_only_merge_leaves_a_complete_index_entry(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        _run(service, [_own(), _shared()], _sync(), _ids())
        entry = service._store.get_index_entry(OWN_ID)
        assert entry["name"] == "web-1" and entry["provider"] == "aws"

    def test_an_identity_recorded_before_the_entry_exists_lands_on_it(self, tmp_path):
        store = MemoryStore(root=tmp_path)
        identity = share_identity(_shared(instance_id=None, hostname="8.8.8.8"))
        assert store.set_share_identity(SHARE_ID, identity) is False
        store.update_index(SHARE_ID, "web-1", "shared", ["os"])
        assert store.get_index_entry(SHARE_ID)["share_identity"] == identity
        store.update_index(SHARE_ID, "web-1", "shared", ["os", "disk"])
        assert store.get_index_entry(SHARE_ID)["share_identity"] == identity

    def test_a_notes_only_entry_also_gets_the_identity(self, tmp_path):
        store = MemoryStore(root=tmp_path)
        identity = share_identity(_shared(instance_id=None, hostname="8.8.8.8"))
        store.set_share_identity(SHARE_ID, identity)
        store.set_annotations_meta(SHARE_ID, annotations_hash="h")
        assert store.get_index_entry(SHARE_ID)["share_identity"] == identity

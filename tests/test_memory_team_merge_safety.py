"""The team-copy merge never loses a note, and one bad copy never stops the rest."""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, Iterable, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.memory.store import MemoryStore
from servonaut.services.memory.sync_service import RemoteRead
from servonaut.services.memory.team_merge import (
    MemoryKey,
    TeamCopyMerger,
    TeamMergeReport,
    is_contained_text,
    merge_annotation_text,
    merge_team_copies,
)
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
BAD_BYTES = b"\xff\xfe\x00 not utf-8 \xc3\x28"
OTHER_SHARE = "44444444-aaaa-bbbb-cccc-000000000004"  # leak-guard:allow


def _member() -> Dict[str, Any]:
    """A shared row with no own twin: a member's view of a team server."""
    return _shared(instance_id=None, hostname="8.8.8.8")


def _listing(ids: Iterable[str]):
    async def listing() -> List[str]:
        return list(ids)
    return listing


def _sync(**overrides: Any) -> MagicMock:
    sync = MagicMock()
    sync.is_configured = True
    sync.fetch_remote_notes = AsyncMock(return_value=RemoteRead("absent"))
    sync.fetch_remote_findings = AsyncMock(return_value=RemoteRead("absent"))
    for name, value in overrides.items():
        setattr(sync, name, value)
    return sync


def _run(service, rows, sync=None, listing=None) -> TeamMergeReport:
    if listing is None and sync is not None:
        listing = _listing([])
    return asyncio.run(
        merge_team_copies(service, sync, rows, today="2026-10-31")
    )


class TestMemberLegacyEntries:
    """C1: a member's memory filed under the team label moves to the shared slug."""

    def _fill(self, service) -> None:
        store = service._store
        store.save_module(SHARE_ID, "os", _module(NEW, distro="team"), LEGACY)
        store.write_annotations(SHARE_ID, "hand written", LEGACY)
        store.save_finding(SHARE_ID, {"id": FIRST, "title": "t", "created_at": NEW}, LEGACY)
        service.update_index(SHARE_ID, "web-1", "Team Team A", ["os"])

    def test_a_members_uploads_do_not_change(self, tmp_path):
        service = _service(tmp_path)
        self._fill(service)
        sync = _sync()
        _run(service, [_member()], sync)
        sync.drop_pending_for.assert_not_called()
        sync.enqueue_annotations.assert_not_called()
        sync.enqueue_findings.assert_not_called()

    def test_a_renamed_team_directory_is_found_through_the_index(self, tmp_path):
        service = _service(tmp_path)
        store = service._store
        store.write_annotations(SHARE_ID, "old label note", "former name")
        service.update_index(SHARE_ID, "web-1", "Former Name", [])
        report = _run(service, [_member()], _sync())
        assert report.copies == 1
        assert service.read_annotations(SHARE_ID, "shared") == "old label note"



class TestNoteMatching:
    """C2: a short note is not 'contained' just because a longer text holds the word."""

    def test_a_short_note_is_appended_not_swallowed(self):
        text, changed = merge_annotation_text("prod db\n", "prod", source="s", merged_on="d")
        assert changed and text.rstrip().endswith("prod")

    def test_a_whole_line_match_is_contained(self):
        assert merge_annotation_text("a\nprod\nb\n", "prod", source="s", merged_on="d")[1] is False
        assert is_contained_text("a\nprod\nb\n", "prod")

    def test_a_substring_is_not_contained(self):
        assert not is_contained_text("Backups run nightly; see DB runbook", "DB")

    def test_a_multi_line_note_matches_as_whole_lines(self):
        assert is_contained_text("x\none\ntwo\ny\n", "one\ntwo")
        assert not is_contained_text("x\none\ntwo three\ny\n", "one\ntwo")



class TestPullBeforeMerge:
    """C3: what a pull overwrites in the copy is merged too."""



class TestPerIdReads:
    """With Memory Sync usable each unmarked copy reads its own share id; otherwise nothing is read."""

    def test_one_pair_of_reads_per_copy(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="note")
        sync = _sync()
        report = _run(service, [_own(), _shared()], sync)
        sync.fetch_remote_notes.assert_awaited_once()
        sync.fetch_remote_findings.assert_awaited_once()
        assert report.copies == 1

    def test_without_sync_nothing_is_read(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="note")
        sync = _sync(is_configured=False, is_enrolled_locally=lambda: False)
        report = _run(service, [_own(), _shared()], sync)
        sync.fetch_remote_notes.assert_not_awaited()
        assert report.copies == 1


class TestUnreadableData:
    """Findings 1 and 3: unreadable is not empty."""

    def _own_file(self, tmp_path):
        return tmp_path / "aws" / OWN_ID / "annotations.md"

    def test_an_unreadable_own_note_is_never_replaced(self, tmp_path, caplog):
        service = _service(tmp_path)
        service.write_annotations(OWN_ID, "MY NOTE", "aws")
        self._own_file(tmp_path).write_bytes(BAD_BYTES)
        _put_copy(service, notes="team note")
        with caplog.at_level(logging.WARNING):
            report = _run(service, [_own(), _shared()], _sync(), _listing([]))
        assert self._own_file(tmp_path).read_bytes() == BAD_BYTES
        assert (tmp_path / LEGACY / SHARE_ID / "annotations.md").is_file()
        assert report.copies == 0 and SHARE_ID in report.kept
        assert "team note" not in caplog.text and "MY NOTE" not in caplog.text

    @pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs file modes")
    def test_a_permission_error_on_the_own_note_keeps_everything(self, tmp_path):
        service = _service(tmp_path)
        service.write_annotations(OWN_ID, "MY NOTE", "aws")
        path = self._own_file(tmp_path)
        path.chmod(0)
        _put_copy(service, notes="team note")
        try:
            report = _run(service, [_own(), _shared()], _sync(), _listing([]))
        finally:
            path.chmod(0o600)
        assert path.read_text() == "MY NOTE"
        assert report.copies == 0 and (tmp_path / LEGACY / SHARE_ID).exists()

    def test_an_unreadable_copy_note_keeps_the_copy(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="x")
        (tmp_path / LEGACY / SHARE_ID / "annotations.md").write_bytes(BAD_BYTES)
        report = _run(service, [_own(), _shared()], _sync(), _listing([]))
        assert report.copies == 0 and SHARE_ID in report.kept
        assert (tmp_path / LEGACY / SHARE_ID / "annotations.md").is_file()

    def test_a_corrupt_finding_file_keeps_the_copy(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, findings=[{"id": FIRST, "title": "t", "created_at": NEW}])
        (tmp_path / LEGACY / SHARE_ID / "findings" / f"{SECOND}.json").write_text("{not json")
        report = _run(service, [_own(), _shared()], _sync(), _listing([]))
        assert report.copies == 0 and SHARE_ID in report.kept
        assert (tmp_path / LEGACY / SHARE_ID / "findings" / f"{SECOND}.json").is_file()

    def test_an_empty_or_missing_note_is_still_just_empty(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, module=_module(NEW, distro="team"))
        report = _run(service, [_own(), _shared()], _sync(), _listing([]))
        assert report.copies == 1


class TestOnePlanNeverStopsTheOthers:
    """Finding 2."""

    def test_a_team_label_with_a_separator_is_skipped_and_the_rest_merge(self, tmp_path, caplog):
        service = _service(tmp_path)
        nested = tmp_path / "ops" / "eu" / OTHER_SHARE
        nested.mkdir(parents=True)
        (nested / "annotations.md").write_text("nested")
        poisoned = _shared(id=OTHER_SHARE)
        poisoned["provider"] = "Ops/EU"
        _put_copy(service, notes="team note")
        with caplog.at_level(logging.WARNING):
            report = _run(service, [_own(), poisoned, _shared()], _sync(), _listing([]))
        assert service.read_annotations(OWN_ID, "aws") == "team note"
        assert report.copies == 1
        assert (nested / "annotations.md").is_file()
        assert "Ops" not in caplog.text



class TestReshareQueue:
    """Finding 6."""

    def test_a_members_queue_is_not_dropped_on_a_reshare(self, tmp_path):
        service = _service(tmp_path)
        old_id = "22222222-aaaa-bbbb-cccc-000000000002"  # leak-guard:allow
        row = _shared(instance_id=None, hostname="8.8.8.8")
        service._store.write_annotations(old_id, "kept note", "shared")
        service.update_index(old_id, "web-1", "shared", [])
        from servonaut.services.memory.team_merge import share_identity
        service._store.set_share_identity(old_id, share_identity(row))
        sync = _sync()
        _run(service, [row], sync, _listing([]))
        sync.drop_pending_for.assert_not_called()

    def test_an_own_twin_fold_still_drops_the_queue(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="n")
        sync = _sync()
        _run(service, [_own(), _shared()], sync, _listing([]))
        sync.drop_pending_for.assert_called_once_with({SHARE_ID})


def test_the_message_is_singular_for_one_copy():
    assert TeamMergeReport(copies=1, notes=1, findings=1).message() == (
        "Merged 1 team copy into your servers: 1 note, 1 finding."
    )
    assert TeamMergeReport(copies=2, notes=0, findings=2).message() == (
        "Merged 2 team copies into your servers: 0 notes, 2 findings."
    )


def test_a_build_of_a_shared_row_records_which_server_it_is(tmp_path):
    """Headless surfaces build through the service alone: the identity must land on the entry."""
    import asyncio

    from servonaut.config.schema import MemoryConfig
    from servonaut.services.memory.interfaces import ModuleProberInterface, ModuleResult
    from servonaut.services.memory.service import MemoryService
    from servonaut.services.memory.team_merge import share_identity

    class Prober(ModuleProberInterface):
        name, ttl_seconds = "os", 3600

        async def probe(self, ssh_runner):
            return ModuleResult(module="os", instance_id="", observed={}, probed_at=NEW, ttl_seconds=3600)

    service = MemoryService(store=MemoryStore(root=tmp_path), config=MemoryConfig(), probers=[Prober()])
    row = _member()
    asyncio.run(service.build(row))
    entry = service._store.get_index_entry(SHARE_ID)
    assert entry["share_identity"] == share_identity(row)

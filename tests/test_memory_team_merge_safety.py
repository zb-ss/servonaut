"""The team-copy merge never loses a note, and one bad copy never stops the rest."""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, Iterable, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.memory.store import TEAM_COPY_BACKUP_DIR, MemoryStore
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
    sync.pull_annotations = AsyncMock(return_value="not_found")
    sync.pull_findings = AsyncMock(return_value="not_found")
    for name, value in overrides.items():
        setattr(sync, name, value)
    return sync


def _run(service, rows, sync=None, listing=None) -> TeamMergeReport:
    if listing is None and sync is not None:
        listing = _listing([])
    return asyncio.run(
        merge_team_copies(service, sync, rows, today="2026-10-31", list_remote_ids=listing)
    )


class TestMemberLegacyEntries:
    """C1: a member's memory filed under the team label moves to the shared slug."""

    def _fill(self, service) -> None:
        store = service._store
        store.save_module(SHARE_ID, "os", _module(NEW, distro="team"), LEGACY)
        store.write_annotations(SHARE_ID, "hand written", LEGACY)
        store.save_finding(SHARE_ID, {"id": FIRST, "title": "t", "created_at": NEW}, LEGACY)
        service.update_index(SHARE_ID, "web-1", "Team Team A", ["os"])

    def test_everything_is_visible_under_the_rows_current_key(self, tmp_path):
        service = _service(tmp_path)
        self._fill(service)
        sync = _sync()
        report = _run(service, [_member()], sync)
        assert report.copies == 1
        assert service.read_annotations(SHARE_ID, "shared") == "hand written"
        assert "os" in service._store.get_all_modules(SHARE_ID, "shared")
        assert [r["id"] for r in service.list_findings(SHARE_ID, "shared")] == [FIRST]
        assert service._store.get_index_entry(SHARE_ID)["provider"] == "shared"
        assert (tmp_path / TEAM_COPY_BACKUP_DIR / LEGACY / SHARE_ID / "os.json").is_file()
        assert not (tmp_path / LEGACY / SHARE_ID).exists()

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

    def test_the_index_entry_is_kept_when_it_belongs_to_the_target(self, tmp_path):
        store = MemoryStore(root=tmp_path)
        store.write_annotations(SHARE_ID, "x", LEGACY)
        store.write_annotations(SHARE_ID, "y", "shared")
        store.update_index(SHARE_ID, "web-1", "shared", [])
        store.backup_instance_dir(SHARE_ID, LEGACY)
        assert store.get_index_entry(SHARE_ID) is not None


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

    def test_the_short_note_reaches_the_own_row_through_a_pass(self, tmp_path):
        service = _service(tmp_path)
        service.write_annotations(OWN_ID, "prod db\n", "aws")
        _put_copy(service, notes="prod")
        _run(service, [_own(), _shared()], _sync(), _listing([SHARE_ID]))
        assert "\nprod" in service.read_annotations(OWN_ID, "aws").split("prod db")[1]


class TestPullBeforeMerge:
    """C3: what a pull overwrites in the copy is merged too."""

    def test_the_text_a_pull_replaces_is_not_lost(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="local copy note")

        async def pull(instance_id, name, provider):
            service.write_annotations(instance_id, "service copy note", provider)
            return "updated"

        sync = _sync(pull_annotations=pull)
        _run(service, [_own(), _shared()], sync, _listing([SHARE_ID]))
        merged = service.read_annotations(OWN_ID, "aws")
        assert merged.count("local copy note") == 1
        assert merged.count("service copy note") == 1

    def test_local_findings_survive_a_pull(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, findings=[{"id": FIRST, "title": "local", "created_at": OLD}])

        async def pull(instance_id, name, provider):
            service.merge_findings(
                instance_id, [{"id": SECOND, "title": "remote", "created_at": NEW}], provider
            )
            return "updated"

        _run(service, [_own(), _shared()], _sync(pull_findings=pull), _listing([SHARE_ID]))
        ids = {r["id"] for r in service.list_findings(OWN_ID, "aws", include_superseded=True)}
        assert ids == {FIRST, SECOND}


class TestListingFirst:
    """C4: one fleet listing decides which share ids are pulled."""

    def test_only_listed_ids_are_pulled(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="note")
        sync = _sync()
        report = _run(service, [_own(), _shared()], sync, _listing([]))
        sync.pull_annotations.assert_not_awaited()
        sync.pull_findings.assert_not_awaited()
        assert report.copies == 1

    def test_a_listed_id_is_pulled_once_each(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="note")
        sync = _sync()
        _run(service, [_own(), _shared()], sync, _listing([SHARE_ID]))
        sync.pull_annotations.assert_awaited_once()
        sync.pull_findings.assert_awaited_once()

    def test_a_failed_listing_merges_but_backs_up_nothing_and_a_later_pass_finishes(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="note")
        sync = _sync()

        async def broken() -> List[str]:
            raise RuntimeError("offline")

        first = _run(service, [_own(), _shared()], sync, broken)
        assert service.read_annotations(OWN_ID, "aws") == "note"
        assert (tmp_path / LEGACY / SHARE_ID / "annotations.md").is_file()
        assert first.copies == 0 and SHARE_ID in first.kept
        second = _run(service, [_own(), _shared()], sync, _listing([]))
        assert second.copies == 1
        assert not (tmp_path / LEGACY / SHARE_ID).exists()

    def test_a_failed_pull_of_a_listed_id_keeps_the_copy(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="note")
        sync = _sync(pull_annotations=AsyncMock(side_effect=RuntimeError("boom")))
        report = _run(service, [_own(), _shared()], sync, _listing([SHARE_ID]))
        assert report.copies == 0 and SHARE_ID in report.kept
        assert (tmp_path / LEGACY / SHARE_ID / "annotations.md").is_file()

    def test_without_sync_nothing_is_listed_or_pulled(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="note")
        sync = _sync(is_configured=False, is_enrolled_locally=lambda: False)
        listing = AsyncMock(return_value=[])
        report = _run(service, [_own(), _shared()], sync, listing)
        listing.assert_not_awaited()
        sync.pull_annotations.assert_not_awaited()
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

    def test_a_failing_backup_is_kept_and_the_next_copy_still_merges(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        second = _shared(id=OTHER_SHARE)
        calls: List[str] = []
        real = MemoryStore.backup_instance_dir

        def flaky(self, instance_id, provider="custom"):
            calls.append(instance_id)
            if len(calls) == 1:
                raise OSError("disk full")
            return real(self, instance_id, provider)

        monkeypatch.setattr(MemoryStore, "backup_instance_dir", flaky)
        service._store.write_annotations(OTHER_SHARE, "other note", LEGACY)
        service.update_index(OTHER_SHARE, "web-1", "Team Team A", [])
        report = _run(service, [_own(), _shared(), second], _sync(), _listing([]))
        assert len(calls) >= 2
        assert report.copies == 1 and len(report.kept) == 1

    def test_the_store_refuses_an_unsafe_provider_slug(self, tmp_path):
        store = MemoryStore(root=tmp_path)
        for method in (store.has_instance_dir, store.backup_instance_dir):
            for slug in ("a/b", "..", "a\\b"):
                with pytest.raises(ValueError):
                    method(SHARE_ID, slug)


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

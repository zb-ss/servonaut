"""Merging a team's copy of a server's memory into the user's own record.

Nothing a user wrote may be lost: notes are never overwritten, the newer
probe wins, findings merge last-writer-wins, and the copy's directory is
moved to a backup rather than deleted.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.services.memory.sync_service import RemoteRead
from servonaut.services.memory.team_merge import (
    MemoryKey,
    copy_module_wins,
    merge_annotation_text,
    merge_team_copies,
    plan_merges,
    same_share,
)
from servonaut.services.shared_servers import shared_row

TEAM = {"slug": "team-a", "name": "Team A", "id": 7}
OWN_ID = "i-0abc0abc0abc0abc0"
SHARE_ID = "11111111-aaaa-bbbb-cccc-000000000001"  # leak-guard:allow
OLD = "2026-01-01T00:00:00+00:00"
NEW = "2026-02-01T00:00:00+00:00"
FIRST = "f_aaaaaaaaaaaaaaaa"
SECOND = "f_bbbbbbbbbbbbbbbb"


def _own(**changes: Any) -> Dict[str, Any]:
    row = {"id": OWN_ID, "name": "web-1", "state": "running", "public_ip": "9.9.9.9"}
    row.update(changes)
    return row


def _shared(**changes: Any) -> Dict[str, Any]:
    server = {
        "id": SHARE_ID, "name": "web-1", "hostname": "9.9.9.9",
        "instance_id": OWN_ID, "username": "deploy",
    }
    server.update(changes)
    return shared_row(server, TEAM)


def _service(root: Path) -> MemoryService:
    return MemoryService(store=MemoryStore(root=root), config=MemoryConfig(), probers=[])


def _module(probed_at: str, **observed: Any) -> Dict[str, Any]:
    return {"module": "os", "instance_id": SHARE_ID, "probed_at": probed_at, "observed": observed}


def _copy_key() -> Dict[str, Any]:
    return {"instance_id": SHARE_ID, "provider": "team team a"}


def _put_copy(service: MemoryService, **parts: Any) -> None:
    store = service._store
    if "module" in parts:
        store.save_module(SHARE_ID, "os", parts["module"], "team team a")
    if "notes" in parts:
        store.write_annotations(SHARE_ID, parts["notes"], "team team a")
    for record in parts.get("findings", []):
        store.save_finding(SHARE_ID, record, "team team a")
    service.update_index(SHARE_ID, "web-1", "Team Team A", ["os"])


def _run(service: MemoryService, rows: List[Dict[str, Any]], sync: Any = None):
    async def listing():
        return [SHARE_ID]
    return asyncio.run(
        merge_team_copies(service, sync, rows, today="2026-10-31")
    )


class TestRules:
    def test_only_a_newer_probe_replaces_the_own_module(self):
        assert copy_module_wins(None, {"probed_at": OLD})
        assert copy_module_wins({"probed_at": OLD}, {"probed_at": NEW})
        assert not copy_module_wins({"probed_at": NEW}, {"probed_at": OLD})
        assert not copy_module_wins({"probed_at": OLD}, {"probed_at": OLD})
        assert not copy_module_wins({"probed_at": OLD}, {"probed_at": "garbage"})

    def test_notes_only_the_copy_has_move_over(self):
        text, changed = merge_annotation_text("", "disk is tight", source="x", merged_on="d")
        assert (text, changed) == ("disk is tight", True)

    def test_different_notes_keep_the_own_and_append_the_copy_once(self):
        first, changed = merge_annotation_text(
            "mine", "theirs", source="the Team A team's copy", merged_on="2026-10-31",
        )
        assert changed and first.startswith("mine\n\n## Notes from the Team A team's copy, merged 2026-10-31")
        assert first.rstrip().endswith("theirs")
        again, changed_again = merge_annotation_text(
            first, "theirs", source="the Team A team's copy", merged_on="2026-11-01",
        )
        assert (again, changed_again) == (first, False)

    def test_text_the_own_notes_contain_adds_nothing(self):
        assert merge_annotation_text("a\ntheirs\nb", "theirs", source="s", merged_on="d") == (
            "a\ntheirs\nb", False,
        )

    def test_same_share_needs_an_id_or_host_port_and_login(self):
        base = {"instance_id": "", "host": "9.9.9.9", "port": 22, "login": "deploy"}
        assert same_share({**base, "instance_id": "i-1"}, {**base, "instance_id": "i-1"})
        assert not same_share({**base, "instance_id": "i-1"}, {**base, "instance_id": "i-2"})
        assert same_share(base, dict(base))
        assert not same_share(base, {**base, "port": 2222})
        assert not same_share(base, {**base, "login": "root"})
        assert not same_share({**base, "host": ""}, {**base, "host": ""})


class TestMerge:
    def test_annotations_only_on_the_copy_move_to_the_own_row(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="restart nginx after deploys")
        report = _run(service, [_own(), _shared()])
        assert service.read_annotations(OWN_ID, "aws") == "restart nginx after deploys"
        assert (report.copies, report.notes) == (1, 1)

    def test_findings_merge_last_writer_wins_and_keep_superseded_by(self, tmp_path):
        service = _service(tmp_path)
        service._store.save_finding(
            OWN_ID, {"id": FIRST, "title": "mine", "created_at": OLD, "updated_at": OLD}, "aws",
        )
        _put_copy(service, findings=[
            {"id": FIRST, "title": "theirs", "created_at": OLD, "updated_at": NEW, "superseded_by": SECOND},
            {"id": SECOND, "title": "extra", "created_at": NEW},
        ])
        report = _run(service, [_own(), _shared()])
        kept = service._store.get_finding(OWN_ID, FIRST, "aws")
        assert kept["title"] == "theirs" and kept["superseded_by"] == SECOND
        assert service._store.get_finding(OWN_ID, SECOND, "aws")["title"] == "extra"
        assert report.findings == 2

    def test_an_older_copy_module_never_replaces_the_own_one(self, tmp_path):
        service = _service(tmp_path)
        service._store.save_module(OWN_ID, "os", _module(NEW, distro="own") | {"instance_id": OWN_ID}, "aws")
        _put_copy(service, module=_module(OLD, distro="team"))
        _run(service, [_own(), _shared()])
        assert service._store.get_module(OWN_ID, "os", "aws")["observed"]["distro"] == "own"

    def test_an_unconfirmed_twin_is_never_merged(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        other = _shared(instance_id="i-0def0def0def0def0", hostname="8.8.8.8")
        report = _run(service, [_own(), other])
        # Not the user's own server: the note never reaches the own row. The
        # row is a member's view, so its entry moves to the neutral slug.
        assert service.read_annotations(OWN_ID, "aws") == ""
        assert service.read_annotations(SHARE_ID, "shared") == "team note"
        assert report.copies == 1

    def test_a_copy_is_kept_when_the_read_back_finds_something_missing(self, tmp_path, monkeypatch):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        monkeypatch.setattr(
            "servonaut.services.memory.team_merge.TeamCopyMerger.is_contained",
            lambda self, source, target: False,
        )
        report = _run(service, [_own(), _shared()])
        assert report.copies == 0 and report.kept == [SHARE_ID]
        assert (tmp_path / "team team a" / SHARE_ID / "annotations.md").is_file()

    def test_an_own_row_with_memory_off_keeps_the_copy_in_place(self, tmp_path):
        service = _service(tmp_path)
        service._config = MemoryConfig(per_server_overrides={OWN_ID: {"memory_disabled": True}})
        _put_copy(service, notes="team note")
        report = _run(service, [_own(), _shared()])
        assert report.copies == 0
        assert (tmp_path / "team team a" / SHARE_ID / "annotations.md").is_file()

    def test_the_message_names_the_counts(self, tmp_path):
        service = _service(tmp_path)
        _put_copy(service, notes="a note")
        assert _run(service, [_own(), _shared()]).message() == (
            "Merged 1 team copy into your servers: 1 note, 0 findings."
        )


class TestSyncSide:
    def _sync(self) -> MagicMock:
        sync = MagicMock()
        sync.is_configured = True
        sync.fetch_remote_notes = AsyncMock(return_value=RemoteRead("absent"))
        sync.fetch_remote_findings = AsyncMock(return_value=RemoteRead("absent"))
        return sync



class TestReshare:
    def test_an_entry_with_no_recorded_identity_is_left_alone(self, tmp_path):
        service = _service(tmp_path)
        old_id = "22222222-aaaa-bbbb-cccc-000000000002"  # leak-guard:allow
        service._store.write_annotations(old_id, "kept note", "shared")
        service.update_index(old_id, "web-1", "shared", [])
        report = _run(service, [_shared(instance_id=None, hostname="8.8.8.8")])
        assert report.copies == 0
        assert (tmp_path / "shared" / old_id / "annotations.md").is_file()

    def test_an_earlier_share_ids_folder_is_never_touched_even_with_a_recorded_identity(self, tmp_path):
        service = _service(tmp_path)
        old_id = "22222222-aaaa-bbbb-cccc-000000000002"  # leak-guard:allow
        row = _shared(instance_id=None, hostname="8.8.8.8")
        service._store.write_annotations(old_id, "kept note", "shared")
        service.update_index(old_id, "web-1", "shared", [])
        from servonaut.services.memory.team_merge import share_identity
        service._store.set_share_identity(old_id, share_identity(row))
        report = _run(service, [row])
        assert report.copies == 0
        assert (tmp_path / "shared" / old_id / "annotations.md").read_text() == "kept note"
        assert not (tmp_path / "shared" / old_id / "team_merged.marker").exists()

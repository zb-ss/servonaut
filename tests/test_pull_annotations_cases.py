"""Pulling the service's notes copes with every state the local notes can be in."""
from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timezone

import pytest

from tests.test_memory_team_merge import OWN_ID, _service
from tests.test_memory_team_merge_v3 import Retrieval, _sync

OLD = "2026-01-01T00:00:00+00:00"
NEWER = "2026-02-01T00:00:00+00:00"
LONG_AGO = datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp()


class _Dated(Retrieval):
    async def get_module(self, instance_id, module):
        envelope = await super().get_module(instance_id, module)
        envelope.probed_at = NEWER
        return envelope


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Notes:
    """A service with one server's notes, pulling whatever the service holds."""

    def __init__(self, tmp_path, remote="remote"):
        self.service = _service(tmp_path)
        self.sync = _sync(tmp_path, self.service, _Dated(notes={"content": remote}))

    def pull(self, remote=None):
        if remote is not None:
            self.sync._retrieval_service.answers["annotations"] = {"content": remote}
        return asyncio.run(self.sync.pull_annotations(OWN_ID, provider="aws"))

    @property
    def path(self):
        return self.service.get_annotations_path(OWN_ID, "aws")

    def put_file(self, data: bytes, mtime=None):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(data)
        if mtime is not None:
            os.utime(self.path, (mtime, mtime))

    def on_disk(self) -> bytes:
        return self.path.read_bytes()

    def meta(self):
        return self.service.get_annotations_meta(OWN_ID)


@pytest.fixture
def notes(tmp_path):
    return _Notes(tmp_path)


def test_a_new_machine_takes_the_services_notes(notes):
    assert notes.pull() == "updated"
    assert notes.on_disk() == b"remote"


def test_a_recorded_hash_with_the_file_deleted_takes_the_services_notes(notes):
    notes.service.write_annotations(OWN_ID, "mine", "aws", modified_at=OLD)
    notes.path.unlink()
    assert notes.pull() == "updated"
    assert notes.on_disk() == b"remote"
    assert notes.pull() == "unchanged"


def test_a_file_emptied_by_hand_takes_the_services_notes(notes):
    notes.service.write_annotations(OWN_ID, "mine", "aws", modified_at=OLD)
    notes.put_file(b"")
    assert notes.pull() == "updated"
    assert notes.on_disk() == b"remote"


def test_notes_cleared_in_the_app_are_judged_by_their_age(notes):
    notes.service.write_annotations(OWN_ID, "", "aws", modified_at="2026-03-01T00:00:00+00:00")
    assert notes.pull() == "local_newer"
    assert notes.on_disk() == b""
    notes.service.set_annotations_meta(OWN_ID, annotations_modified_at=OLD)
    assert notes.pull() == "updated"


def test_a_file_edited_outside_the_app_is_adopted_and_judged_by_its_modified_time(notes):
    notes.service.write_annotations(OWN_ID, "mine", "aws", modified_at=OLD)
    notes.put_file(b"hand edited")  # modified just now, after the service's copy
    assert notes.pull() == "local_newer"
    assert notes.on_disk() == b"hand edited"
    assert notes.meta()["annotations_hash"] == _digest(b"hand edited")
    assert notes.meta()["annotations_modified_at"] > NEWER


def test_an_edit_older_than_the_services_copy_gives_way_but_is_kept_as_a_draft(notes):
    notes.service.write_annotations(OWN_ID, "mine", "aws", modified_at=OLD)
    notes.put_file(b"hand edited", mtime=LONG_AGO)
    assert notes.pull() == "updated"
    assert notes.on_disk() == b"remote"
    drafts = list(notes.path.parent.glob("annotations.unsaved-*.md"))
    assert [d.read_bytes() for d in drafts] == [b"hand edited"]


def test_an_older_release_with_no_recorded_hash_does_not_lose_its_notes(notes):
    notes.put_file(b"old local notes")
    assert notes.meta()["annotations_hash"] == ""
    assert notes.pull() == "local_newer"
    assert notes.on_disk() == b"old local notes"
    assert notes.meta()["annotations_hash"] == _digest(b"old local notes")


def test_an_older_release_file_older_than_the_services_copy_is_replaced_with_a_draft(notes):
    notes.put_file(b"old local notes", mtime=LONG_AGO)
    assert notes.pull() == "updated"
    assert notes.on_disk() == b"remote"
    drafts = list(notes.path.parent.glob("annotations.unsaved-*.md"))
    assert [d.read_bytes() for d in drafts] == [b"old local notes"]


def test_identical_text_with_no_recorded_hash_is_unchanged(notes):
    notes.put_file(b"remote")
    assert notes.pull() == "unchanged"
    assert list(notes.path.parent.glob("annotations.unsaved-*.md")) == []


@pytest.mark.parametrize("text", ["a\r\nb\r\n", "a\rb", "a\r\nb\nc\r"])
def test_line_endings_survive_a_pull_and_the_next_pull_is_decided_by_time(notes, text):
    assert notes.pull(text) == "updated"
    assert notes.on_disk() == text.encode("utf-8")
    assert notes.service.read_annotations(OWN_ID, "aws") == text
    assert notes.pull(text) == "unchanged"
    assert notes.pull(text + "more") == "updated"
    assert notes.on_disk() == (text + "more").encode("utf-8")


@pytest.mark.parametrize("text", ["a\r\nb\r\n", "a\rb", "a\r\nb\nc\r"])
def test_line_endings_survive_a_save(notes, text):
    notes.service.write_annotations(OWN_ID, text, "aws", modified_at=OLD)
    assert notes.on_disk() == text.encode("utf-8")
    assert notes.service.read_annotations(OWN_ID, "aws") == text
    assert notes.meta()["annotations_hash"] == _digest(text.encode("utf-8"))
    assert notes.pull() == "updated"

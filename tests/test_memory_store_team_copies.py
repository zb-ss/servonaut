"""Store guarantees the team-copy merge relies on."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading

import pytest

from servonaut.services.memory.store import MemoryCorruptError, MemoryStore

ID = "77777777-aaaa-bbbb-cccc-000000000007"  # leak-guard:allow
FID = "f_aaaaaaaaaaaaaaaa"


def _store(tmp_path):
    return MemoryStore(root=tmp_path / "root")


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class TestShapeValidation:
    @pytest.mark.parametrize("body", ["null", "[]", '"x"', "5"])
    def test_a_module_must_be_an_object(self, tmp_path, body):
        store = _store(tmp_path)
        d = tmp_path / "root" / "aws" / ID
        d.mkdir(parents=True)
        (d / "os.json").write_text(body)
        with pytest.raises(MemoryCorruptError):
            store.get_all_modules(ID, "aws", strict=True)

    @pytest.mark.parametrize("record", [
        None, [], {"id": 5}, {"id": FID, "created_at": 5}, {"id": FID, "updated_at": []},
        {"id": FID, "superseded_by": 3},
    ])
    def test_a_finding_must_have_a_string_id_and_string_times(self, tmp_path, record):
        store = _store(tmp_path)
        d = tmp_path / "root" / "aws" / ID / "findings"
        d.mkdir(parents=True)
        (d / f"{FID}.json").write_text(json.dumps(record))
        with pytest.raises(MemoryCorruptError):
            store.list_findings(ID, "aws", include_superseded=True, strict=True)

    def test_the_error_is_a_value_error(self):
        assert issubclass(MemoryCorruptError, ValueError)


class TestNoSymlinks:
    def _dir(self, tmp_path):
        d = tmp_path / "root" / "aws" / ID
        d.mkdir(parents=True)
        return d

    def test_a_symlinked_annotations_file_is_refused(self, tmp_path):
        store = _store(tmp_path)
        d = self._dir(tmp_path)
        outside = tmp_path / "private.md"
        outside.write_text("secret")
        os.symlink(outside, d / "annotations.md")
        with pytest.raises(MemoryCorruptError):
            store.read_annotations_strict(ID, "aws")

    def test_a_symlinked_finding_or_module_file_is_refused(self, tmp_path):
        store = _store(tmp_path)
        d = self._dir(tmp_path)
        outside = tmp_path / "x.json"
        outside.write_text(json.dumps({"id": FID}))
        (d / "findings").mkdir()
        os.symlink(outside, d / "findings" / f"{FID}.json")
        with pytest.raises(MemoryCorruptError):
            store.list_findings(ID, "aws", include_superseded=True, strict=True)
        os.symlink(outside, d / "os.json")
        with pytest.raises(MemoryCorruptError):
            store.get_all_modules(ID, "aws", strict=True)

    def test_a_symlinked_findings_directory_is_refused(self, tmp_path):
        store = _store(tmp_path)
        d = self._dir(tmp_path)
        (tmp_path / "elsewhere").mkdir()
        os.symlink(tmp_path / "elsewhere", d / "findings")
        with pytest.raises(MemoryCorruptError):
            store.list_findings(ID, "aws", include_superseded=True, strict=True)

    def test_a_symlinked_target_directory_is_not_addressable(self, tmp_path):
        store = _store(tmp_path)
        (tmp_path / "root" / "aws").mkdir(parents=True)
        (tmp_path / "outside").mkdir()
        os.symlink(tmp_path / "outside", tmp_path / "root" / "aws" / ID)
        assert not store.is_addressable(ID, "aws")


class TestSourceDiscovery:
    def test_every_provider_folder_holding_the_id_is_found_without_the_index(self, tmp_path):
        store = _store(tmp_path)
        for slug in ("team a", "former team", "shared"):
            store.write_annotations(ID, "x", slug)
        store.write_annotations("other-id", "x", "team a")
        assert sorted(store.find_instance_dirs(ID)) == ["former team", "shared", "team a"]

    def test_symlinks_and_files_are_not_sources(self, tmp_path):
        store = _store(tmp_path)
        root = tmp_path / "root"
        store.write_annotations(ID, "x", "real")
        (root / "linked").mkdir()
        (tmp_path / "outside").mkdir()
        os.symlink(tmp_path / "outside", root / "linked" / ID)
        (root / "a-file").write_text("x")
        assert store.find_instance_dirs(ID) == ["real"]

    def test_an_unsafe_id_finds_nothing(self, tmp_path):
        assert _store(tmp_path).find_instance_dirs("../x") == []


class TestAnnotationLock:
    def test_a_write_with_a_stale_hash_is_refused(self, tmp_path):
        store = _store(tmp_path)
        store.write_annotations(ID, "base", "aws")
        assert store.write_annotations_if_unchanged(ID, _sha("base"), "mine", "aws") is True
        assert store.read_annotations(ID, "aws") == "mine"
        assert store.write_annotations_if_unchanged(ID, _sha("base"), "again", "aws") is False
        assert store.read_annotations(ID, "aws") == "mine"

    def test_an_absent_file_matches_the_hash_of_empty_text(self, tmp_path):
        store = _store(tmp_path)
        assert store.write_annotations_if_unchanged(ID, _sha(""), "first", "aws") is True

    def test_a_merge_that_holds_the_lock_makes_the_editor_write_refuse(self, tmp_path):
        store = _store(tmp_path)
        store.write_annotations(ID, "base", "aws")
        outcome = []
        started = threading.Event()

        def editor():
            started.set()
            outcome.append(store.write_annotations_if_unchanged(ID, _sha("base"), "USER EDIT", "aws"))

        with store.annotation_lock(ID):
            thread = threading.Thread(target=editor)
            thread.start()
            started.wait(2)
            thread.join(0.2)
            assert thread.is_alive()               # blocked on the lock, not yet compared
            store.write_annotations(ID, "base\n\nMERGED", "aws")
        thread.join(2)
        assert outcome == [False]
        assert store.read_annotations(ID, "aws") == "base\n\nMERGED"


class TestDraftsAndMarkers:
    def test_each_draft_has_its_own_private_file(self, tmp_path):
        store = _store(tmp_path)
        store.write_annotations(ID, "base", "aws")
        first = store.write_annotation_draft(ID, "one", "aws")
        second = store.write_annotation_draft(ID, "two", "aws")
        assert first != second and first.read_text() == "one" and second.read_text() == "two"
        assert stat.S_IMODE(first.stat().st_mode) == 0o600
        assert first.name.startswith("annotations.unsaved-") and first.name.endswith(".md")

    def test_a_draft_never_follows_a_symlink(self, tmp_path):
        store = _store(tmp_path)
        store.write_annotations(ID, "base", "aws")
        d = tmp_path / "root" / "aws" / ID
        target = tmp_path / "victim.md"
        target.write_text("keep")
        first = store.write_annotation_draft(ID, "x", "aws")
        first.unlink()
        for path in d.glob("annotations.unsaved-*"):
            path.unlink()
        # Even a pre-planted link at a guessable name is not written through.
        import servonaut.services.memory.store as module
        stamp = "20260101T000000000000Z"
        planted = d / f"annotations.unsaved-{stamp}.md"
        os.symlink(target, planted)
        original = module._draft_stamp
        module._draft_stamp = lambda: stamp
        try:
            draft = store.write_annotation_draft(ID, "new", "aws")
        finally:
            module._draft_stamp = original
        assert target.read_text() == "keep" and draft != planted and draft.read_text() == "new"

    def test_a_marker_is_atomic_private_and_not_a_module(self, tmp_path):
        store = _store(tmp_path)
        store.write_annotations(ID, "x", "team a")
        store.write_merge_marker(ID, "team a", {"target_provider": "aws", "target_id": "i-1"})
        path = tmp_path / "root" / "team a" / ID / "team_merged.marker"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert store.read_merge_marker(ID, "team a")["target_id"] == "i-1"
        assert "team_merged" not in store.get_all_modules(ID, "team a")

    def test_no_marker_reads_as_none_and_a_broken_one_as_corrupt(self, tmp_path):
        store = _store(tmp_path)
        store.write_annotations(ID, "x", "team a")
        assert store.read_merge_marker(ID, "team a") is None
        (tmp_path / "root" / "team a" / ID / "team_merged.marker").write_text("[1]")
        with pytest.raises(MemoryCorruptError):
            store.read_merge_marker(ID, "team a")


class TestFreshTempFiles:
    """Writers create a fresh exclusive temp file; a planted link at the old fixed name is harmless."""

    def _plant(self, tmp_path, name):
        d = tmp_path / "root" / "aws" / ID
        d.mkdir(parents=True, exist_ok=True)
        victim = tmp_path / "victim.txt"
        victim.write_text("KEEP")
        os.symlink(victim, d / name)
        return victim

    def test_annotations(self, tmp_path):
        store = _store(tmp_path)
        victim = self._plant(tmp_path, "annotations.md.tmp")
        store.write_annotations(ID, "new", "aws")
        assert victim.read_text() == "KEEP" and store.read_annotations(ID, "aws") == "new"

    def test_modules_findings_and_the_marker(self, tmp_path):
        store = _store(tmp_path)
        victim = self._plant(tmp_path, "os.json.tmp")
        store.save_module(ID, "os", {"module": "os"}, "aws")
        assert victim.read_text() == "KEEP"
        victim = self._plant(tmp_path, "team_merged.marker.tmp")
        store.write_merge_marker(ID, "aws", {"target_id": "x"})
        assert victim.read_text() == "KEEP" and store.read_merge_marker(ID, "aws")["target_id"] == "x"

    def test_no_temp_file_is_left_behind(self, tmp_path):
        store = _store(tmp_path)
        store.write_annotations(ID, "new", "aws")
        store.save_module(ID, "os", {"module": "os"}, "aws")
        assert not list((tmp_path / "root" / "aws" / ID).glob("*.tmp"))

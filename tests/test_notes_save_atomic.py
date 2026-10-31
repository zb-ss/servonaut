"""A notes save writes the text and its bookkeeping as one record-locked step."""
from __future__ import annotations

import asyncio
import hashlib
from unittest.mock import patch

from servonaut.cli import memory as cli
from tests.test_memory_cli import _make_args, _fake_config  # noqa: F401
from tests.test_memory_team_merge import OWN_ID, _own, _service
from tests.test_memory_team_merge_v3 import _sync
from tests.test_pull_annotations_locking import _Dated

OLD = "2026-01-01T00:00:00+00:00"


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _aged(service, text="old"):
    service.write_annotations(OWN_ID, text, "aws")
    service.set_annotations_meta(
        OWN_ID, annotations_hash=_digest(text), annotations_modified_at=OLD
    )


def _pull(tmp_path, service):
    sync = _sync(tmp_path, service, _Dated(notes={"content": "older remote note"}))
    return asyncio.run(sync.pull_annotations(OWN_ID, provider="aws"))


def test_the_store_records_the_hash_with_the_content_in_one_step(tmp_path):
    service = _service(tmp_path)
    _aged(service)
    seen = []
    original = service._store._write_annotations_locked

    def spying(*args, **kwargs):
        result = original(*args, **kwargs)
        # A pull running between the write and the bookkeeping must be refused.
        seen.append(_pull(tmp_path / "sync", service))
        return result

    with patch.object(service._store, "_write_annotations_locked", spying):
        assert service.write_annotations_if_unchanged(
            OWN_ID, _digest("old"), "new local edit", "aws", modified_at="2026-10-31T00:00:00+00:00"
        )
    assert seen == ["local_newer"]
    meta = service.get_annotations_meta(OWN_ID)
    assert meta["annotations_hash"] == _digest("new local edit")
    assert meta["annotations_modified_at"] == "2026-10-31T00:00:00+00:00"
    assert service.read_annotations(OWN_ID, "aws") == "new local edit"


def test_a_plain_write_can_record_its_bookkeeping_in_the_same_step(tmp_path):
    service = _service(tmp_path)
    service.write_annotations(OWN_ID, "text", "aws", modified_at="2026-10-31T00:00:00+00:00")
    meta = service.get_annotations_meta(OWN_ID)
    assert meta["annotations_hash"] == _digest("text")
    assert meta["annotations_modified_at"] == "2026-10-31T00:00:00+00:00"


def test_a_pull_keeps_notes_whose_hash_differs_from_the_record(tmp_path):
    service = _service(tmp_path)
    _aged(service)
    # Edited on disk after the metadata was written (an editor, a copy).
    service.write_annotations(OWN_ID, "edited elsewhere", "aws")
    assert _pull(tmp_path / "sync", service) == "local_newer"
    assert service.read_annotations(OWN_ID, "aws") == "edited elsewhere"


def test_a_pull_still_updates_when_disk_and_record_agree(tmp_path):
    service = _service(tmp_path)
    _aged(service)
    assert _pull(tmp_path / "sync", service) == "updated"
    assert service.read_annotations(OWN_ID, "aws") == "older remote note"


def test_the_cli_save_leaves_metadata_that_matches_the_text(tmp_path):
    service = _service(tmp_path)
    _aged(service)
    statuses = []
    original = service._store._write_annotations_locked

    def spying(*args, **kwargs):
        result = original(*args, **kwargs)
        statuses.append(_pull(tmp_path / "sync", service))
        return result

    with patch.object(service._store, "_write_annotations_locked", spying):
        code = cli._store_edit(service, None, _own(), OWN_ID, "aws", _digest("old"), "new local edit")
    assert code == 0
    assert statuses == ["local_newer"]
    assert service.read_annotations(OWN_ID, "aws") == "new local edit"
    assert service.get_annotations_meta(OWN_ID)["annotations_hash"] == _digest("new local edit")


def test_the_notes_screen_save_records_the_bookkeeping_with_the_write(tmp_path):
    from servonaut.screens.memory import MemoryScreen

    service = _service(tmp_path)
    _aged(service)
    draft = MemoryScreen._write_unless_changed(
        service, OWN_ID, "aws", "typed in the app", "old", "2026-10-31T00:00:00+00:00"
    )
    assert draft is None
    meta = service.get_annotations_meta(OWN_ID)
    assert meta["annotations_hash"] == _digest("typed in the app")
    assert meta["annotations_modified_at"] == "2026-10-31T00:00:00+00:00"


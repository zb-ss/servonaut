"""Nothing is queued or uploaded for a share that folds into an own row."""
from __future__ import annotations

import json
import logging
from unittest.mock import AsyncMock

import pytest

from tests.test_memory_sync_service import _make_module_result, _make_service

SHARE = {"id": "share-1", "name": "web-1"}
OWN = {"id": "i-0abc0abc0abc0abc0", "name": "web-1"}


def _queue(svc):
    svc.enqueue_module(SHARE, "os", _make_module_result())
    svc.enqueue_module(OWN, "os", _make_module_result())


def test_queued_envelopes_of_a_folded_share_are_dropped_from_memory_and_file(tmp_path):
    svc = _make_service(tmp_path=tmp_path)
    _queue(svc)
    assert svc.set_folded_instance_ids({"share-1"}) == 1
    assert [env.instance_id for env in svc._pending] == [OWN["id"]]
    owners = [json.loads(line)["instance_id"] for line in svc._queue_path.read_text().splitlines()]
    assert owners == [OWN["id"]]


def test_a_folded_share_is_never_queued_again(tmp_path):
    svc = _make_service(tmp_path=tmp_path)
    svc.set_folded_instance_ids({"share-1"})
    svc.enqueue_module(SHARE, "os", _make_module_result())
    svc.enqueue_annotations(SHARE, "note")
    svc.enqueue_findings(SHARE, [{"id": "f_aaaaaaaaaaaaaaaa"}])
    assert svc.pending_count() == 0


def test_a_drain_never_posts_a_folded_share(tmp_path):
    svc = _make_service(tmp_path=tmp_path)
    _queue(svc)
    svc._folded_ids = {"share-1"}  # set late, as when the shares load after a restart
    svc._post_batch = AsyncMock(side_effect=lambda batch: _result(batch))

    async def run():
        return await svc.drain_now()

    import asyncio
    asyncio.run(run())
    posted = [env.instance_id for call in svc._post_batch.await_args_list for env in call.args[0]]
    assert "share-1" not in posted


def test_the_skip_is_logged_once(tmp_path, caplog):
    svc = _make_service(tmp_path=tmp_path)
    svc.set_folded_instance_ids({"share-1"})
    with caplog.at_level(logging.INFO):
        for _ in range(3):
            svc.enqueue_module(SHARE, "os", _make_module_result())
    assert sum("team copy" in r.getMessage() for r in caplog.records) == 1


def test_other_instances_are_untouched(tmp_path):
    svc = _make_service(tmp_path=tmp_path)
    svc.set_folded_instance_ids({"share-1"})
    svc.enqueue_module(OWN, "os", _make_module_result())
    assert svc.pending_count(OWN["id"]) == 1


def _result(batch):
    from servonaut.services.memory.interfaces import SyncBatchResult
    return SyncBatchResult(accepted=[], rejected=[], quota=None)


SHARE_SHAPED = "55555555-aaaa-bbbb-cccc-000000000005"  # leak-guard:allow


def _posted(svc):
    return [env.instance_id for call in svc._post_batch.await_args_list for env in call.args[0]]


def _drain(svc):
    import asyncio
    svc._post_batch = AsyncMock(side_effect=lambda batch: _result(batch))
    asyncio.run(svc.drain_now())
    return _posted(svc)


def test_a_share_shaped_envelope_waits_until_the_folds_are_known(tmp_path):
    svc = _make_service(tmp_path=tmp_path)
    svc.enqueue_module({"id": SHARE_SHAPED, "name": "web-1"}, "os", _make_module_result())
    svc.enqueue_module(OWN, "os", _make_module_result())
    svc.hold_unfolded_shares()
    assert _drain(svc) == [OWN["id"]]
    assert svc.pending_count(SHARE_SHAPED) == 1  # held, not lost


def test_a_held_envelope_is_dropped_when_its_share_turns_out_folded(tmp_path):
    svc = _make_service(tmp_path=tmp_path)
    svc.enqueue_module({"id": SHARE_SHAPED, "name": "web-1"}, "os", _make_module_result())
    svc.hold_unfolded_shares()
    svc.set_folded_instance_ids({SHARE_SHAPED})
    assert _drain(svc) == []
    assert svc.pending_count() == 0


def test_a_held_envelope_of_a_member_goes_out_once_the_hold_is_released(tmp_path):
    svc = _make_service(tmp_path=tmp_path)
    svc.enqueue_module({"id": SHARE_SHAPED, "name": "web-1"}, "os", _make_module_result())
    svc.hold_unfolded_shares()
    svc.release_share_hold()
    assert _drain(svc) == [SHARE_SHAPED]


def test_without_a_hold_nothing_changes(tmp_path):
    svc = _make_service(tmp_path=tmp_path)
    svc.enqueue_module({"id": SHARE_SHAPED, "name": "web-1"}, "os", _make_module_result())
    assert _drain(svc) == [SHARE_SHAPED]

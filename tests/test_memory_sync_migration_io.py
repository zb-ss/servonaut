"""What the team-copy merge needs from the sync service: reads that never write,
enqueues that say whether they were stored, and one dispatch batch."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.memory.interfaces import (
    MemoryBackendError,
    MemoryNotFound,
    UpsellRequired,
)
from servonaut.services.memory.store import MemoryStore
from tests.test_memory_sync_service import _make_config_manager, _make_module_result, _make_service

SHARE = "66666666-aaaa-bbbb-cccc-000000000006"  # leak-guard:allow
OWN = {"id": "i-0abc0abc0abc0abc0", "name": "web-1"}


class _Retrieval:
    """The retrieval boundary: one scripted answer per module."""

    def __init__(self, **answers: Any) -> None:
        self.answers, self.calls = answers, []

    async def get_module(self, instance_id: str, module: str):
        self.calls.append((instance_id, module))
        answer = self.answers[module]
        if isinstance(answer, Exception):
            raise answer
        return SimpleNamespace(plaintext=answer, probed_at="2026-01-01T00:00:00+00:00", created_at="")


def _svc(tmp_path, retrieval=None, findings=True):
    cfg = _make_config_manager()
    cfg.get.return_value.memory.findings_sync_enabled = findings
    svc = _make_service(config_manager=cfg, tmp_path=tmp_path)
    if retrieval is not None:
        svc.set_retrieval_service(retrieval)
    return svc


def _fetch(coro):
    return asyncio.run(coro)


class TestRemoteReads:
    def test_found_notes_are_returned_and_nothing_is_written(self, tmp_path):
        svc = _svc(tmp_path, _Retrieval(annotations={"content": "cloud note"}))
        result = _fetch(svc.fetch_remote_notes(SHARE, "web-1"))
        assert (result.status, result.text) == ("found", "cloud note")
        svc._memory_service.write_annotations.assert_not_called()
        svc._memory_service.set_annotations_meta.assert_not_called()

    def test_only_a_verified_not_found_is_absent(self, tmp_path):
        svc = _svc(tmp_path, _Retrieval(annotations=MemoryNotFound("access_revoked"),
                                        findings=MemoryNotFound("access_revoked")))
        assert _fetch(svc.fetch_remote_notes(SHARE)).status == "absent"
        assert _fetch(svc.fetch_remote_findings(SHARE)).status == "absent"

    @pytest.mark.parametrize("failure", [
        RuntimeError("offline"), MemoryBackendError("rate_limited"), UpsellRequired("solo"),
        {"content": 5}, {"nope": 1},
    ])
    def test_every_other_outcome_is_unavailable(self, tmp_path, failure):
        svc = _svc(tmp_path, _Retrieval(annotations=failure, findings=failure))
        assert _fetch(svc.fetch_remote_notes(SHARE)).status == "unavailable"
        assert _fetch(svc.fetch_remote_findings(SHARE)).status == "unavailable"

    def test_no_retrieval_service_or_an_opted_out_server_is_unavailable(self, tmp_path):
        assert _fetch(_svc(tmp_path).fetch_remote_notes(SHARE)).status == "unavailable"
        svc = _svc(tmp_path, _Retrieval(annotations={"content": "x"}))
        svc._memory_service.is_memory_disabled.return_value = True
        assert _fetch(svc.fetch_remote_notes(SHARE)).status == "unavailable"

    def test_findings_must_be_a_list_of_objects(self, tmp_path):
        svc = _svc(tmp_path, _Retrieval(findings={"findings": [1, 2]}))
        assert _fetch(svc.fetch_remote_findings(SHARE)).status == "unavailable"
        svc = _svc(tmp_path, _Retrieval(findings={"findings": [{"id": "f_aaaaaaaaaaaaaaaa"}]}))
        result = _fetch(svc.fetch_remote_findings(SHARE))
        assert result.status == "found" and result.records == [{"id": "f_aaaaaaaaaaaaaaaa"}]


class TestEnqueueReportsStorage:
    def test_stored_envelopes_return_true(self, tmp_path):
        svc = _svc(tmp_path)
        assert svc.enqueue_annotations(OWN, "note") is True
        assert svc.enqueue_findings(OWN, [{"id": "f_aaaaaaaaaaaaaaaa"}]) is True
        assert svc._queue_path.read_text().count("\n") == 2

    def test_not_configured_returns_false(self, tmp_path):
        svc = _make_service(tmp_path=tmp_path, configured=False)
        assert svc.enqueue_annotations(OWN, "note") is False

    def test_a_full_queue_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.setattr("servonaut.services.memory.sync_service._QUEUE_CAP", 1)
        svc = _svc(tmp_path)
        assert svc.enqueue_annotations(OWN, "one") is True
        assert svc.enqueue_annotations(OWN, "two") is False

    def test_a_failed_file_append_returns_false_and_leaves_nothing_queued(self, tmp_path):
        svc = _svc(tmp_path)
        svc._queue_path.parent.mkdir(parents=True)
        svc._queue_path.mkdir()  # the queue file cannot be opened for append
        assert svc.enqueue_annotations(OWN, "note") is False
        assert svc.pending_count() == 0

    def test_findings_behind_a_closed_gate_have_nothing_due(self, tmp_path):
        svc = _svc(tmp_path, findings=False)
        assert svc.enqueue_findings(OWN, [{"id": "f_aaaaaaaaaaaaaaaa"}]) is True
        assert svc.pending_count() == 0


class TestOneDispatchBatch:
    def _prepare(self, tmp_path, monkeypatch, error):
        monkeypatch.setattr(
            "servonaut.services.memory.sync_service.encrypt_envelope",
            lambda *a, **k: SimpleNamespace(to_dict=lambda: {}),
        )
        svc = _svc(tmp_path)
        svc.enqueue_module({"id": SHARE, "name": "s"}, "os", _make_module_result())
        svc.enqueue_module(OWN, "os", _make_module_result())

        async def acquire(*a, **k):
            svc.set_folded_instance_ids({SHARE})  # folded while the batch waits

        async def post(path, json):
            raise error

        svc._rate_limiter.acquire = acquire
        svc._api.post = post
        return svc

    @pytest.mark.parametrize("error", [
        APIError(code="conflict_retry", message="x", status=409),
        APIError(code="boom", message="x", status=500),
        RuntimeError("network"),
    ])
    def test_no_envelope_is_queued_twice_after_a_failed_post(self, tmp_path, monkeypatch, error):
        svc = self._prepare(tmp_path, monkeypatch, error)
        asyncio.run(svc.drain_now())
        owners = sorted(env.instance_id for env in svc._pending)
        assert owners == sorted([SHARE, OWN["id"]])

    def test_a_cancelled_post_requeues_each_envelope_once(self, tmp_path, monkeypatch):
        svc = self._prepare(tmp_path, monkeypatch, asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(svc.drain_now())
        owners = sorted(env.instance_id for env in svc._pending)
        assert owners == sorted([SHARE, OWN["id"]])
        assert svc._inflight is None

"""The e2e fake's /latest answers the two ``after`` forms as the service does."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from e2e.harness.fake_cloud.routes_memory_summary import FAILURE_REASON, SummaryCloud

pytestmark = [pytest.mark.e2e_pr]

QUEUED = "2026-11-28T10:00:00.400000+00:00"


def _cloud(status: str) -> SummaryCloud:
    cloud = SummaryCloud(MagicMock(), lambda: 7)
    cloud._jobs.append({
        "instance_id": "web-1", "user_id": 7, "queued_at": QUEUED, "status": status,
        "reason": FAILURE_REASON if status == "failed" else None,
        "result": {"id": "new-envelope"} if status == "success" else None,
        "pending_polls": 0, "previous_id": "old-envelope",
    })
    return cloud


def test_failed_body_only_on_the_timestamp_form():
    cloud = _cloud("failed")
    assert FAILURE_REASON == "dek_invalid"
    code, body = cloud.latest("web-1", "2026-11-28T10:00:00+00:00")
    assert code == 200 and body["status"] == "failed" and body["reason"] == "dek_invalid" and body["failed_at"]
    code, body = cloud.latest("web-1", "old-envelope")
    assert code == 202 and body["status"] == "pending"


def test_timestamp_form_is_inclusive_at_one_second_precision_and_pending_before_the_job():
    cloud = _cloud("success")
    assert cloud.latest("web-1", "2026-11-28T10:00:00+00:00")[1]["id"] == "new-envelope"
    code, body = cloud.latest("web-1", "2026-11-28T10:00:01+00:00")
    assert code == 202 and body["status"] == "pending"


def test_id_form_pends_on_the_previous_envelope_and_returns_a_new_one():
    cloud = _cloud("success")
    assert cloud.latest("web-1", "new-envelope")[0] == 202
    assert cloud.latest("web-1", "old-envelope")[1]["id"] == "new-envelope"

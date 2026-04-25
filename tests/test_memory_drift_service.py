"""Tests for DriftService and AnomalyService."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import (
    ForbiddenEntitlementError,
    RateLimitedError,
)
from servonaut.services.memory.interfaces import (
    AnomalyEvent,
    DriftEvent,
    RateLimited,
    UpsellRequired,
)
from servonaut.services.memory.drift_service import AnomalyService, DriftService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_api_client(get_return=None, get_side_effect=None,
                     post_return=None, post_side_effect=None):
    client = MagicMock()
    client.get = AsyncMock(return_value=get_return or {})
    client.post = AsyncMock(return_value=post_return or {})
    if get_side_effect:
        client.get.side_effect = get_side_effect
    if post_side_effect:
        client.post.side_effect = post_side_effect
    return client


def _raw_drift_event(event_id="evt-001") -> Dict[str, Any]:
    return {
        "id": event_id,
        "instance_id": "web-01",
        "module": "os",
        "old_hash": "abc123",
        "new_hash": "def456",
        "probed_at": "2026-04-25T11:00:00+00:00",
        "detected_at": "2026-04-25T12:00:00+00:00",
        "severity": "medium",
        "acknowledged_at": None,
        "old_envelope_id": "old-env-uuid",
        "new_envelope_id": "new-env-uuid",
    }


def _raw_anomaly_event(event_id="ano-001") -> Dict[str, Any]:
    return {
        "id": event_id,
        "instance_id": "web-01",
        "module": "services",
        "rule_key": "drift.os_kernel",
        "severity": "high",
        "summary": "Kernel changed unexpectedly",
        "detected_at": "2026-04-25T12:00:00+00:00",
        "acknowledged_at": None,
    }


# ---------------------------------------------------------------------------
# DriftService tests
# ---------------------------------------------------------------------------

class TestDriftService:

    @pytest.mark.asyncio
    async def test_list_drift_happy_path(self):
        """list_drift returns DriftEvent list on success."""
        api = _make_api_client(get_return={"drift_events": [_raw_drift_event()]})
        svc = DriftService(api)
        events = await svc.list_drift()
        assert len(events) == 1
        assert isinstance(events[0], DriftEvent)
        assert events[0].id == "evt-001"
        assert events[0].instance_id == "web-01"
        assert events[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_list_drift_with_since_and_limit(self):
        """list_drift passes since and limit as query params."""
        api = _make_api_client(get_return={"drift_events": []})
        svc = DriftService(api)
        await svc.list_drift(since="2026-01-01T00:00:00Z", limit=50)
        api.get.assert_called_once_with(
            "/api/v1/memory/drift",
            params={"limit": 50, "since": "2026-01-01T00:00:00Z"},
        )

    @pytest.mark.asyncio
    async def test_list_drift_403_raises_upsell_required(self):
        """list_drift: 403 forbidden_entitlement → UpsellRequired."""
        api = _make_api_client(get_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        svc = DriftService(api)
        with pytest.raises(UpsellRequired):
            await svc.list_drift()

    @pytest.mark.asyncio
    async def test_list_drift_429_raises_rate_limited(self):
        """list_drift: 429 rate_limited → RateLimited."""
        api = _make_api_client(get_side_effect=RateLimitedError(
            code="rate_limited", message="too fast", status=429
        ))
        svc = DriftService(api)
        with pytest.raises(RateLimited):
            await svc.list_drift()

    @pytest.mark.asyncio
    async def test_acknowledge_drift_happy_path(self):
        """acknowledge_drift returns ack dict on success."""
        ack_response = {"id": "evt-001", "acknowledged_at": "2026-04-25T13:00:00+00:00"}
        api = _make_api_client(post_return=ack_response)
        svc = DriftService(api)
        result = await svc.acknowledge_drift("evt-001")
        assert result["id"] == "evt-001"
        assert result["acknowledged_at"] == "2026-04-25T13:00:00+00:00"
        api.post.assert_called_once_with(
            "/api/v1/memory/drift/evt-001/ack", json={}
        )

    @pytest.mark.asyncio
    async def test_acknowledge_drift_403_raises_upsell_required(self):
        """acknowledge_drift: 403 → UpsellRequired."""
        api = _make_api_client(post_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        svc = DriftService(api)
        with pytest.raises(UpsellRequired):
            await svc.acknowledge_drift("evt-001")

    @pytest.mark.asyncio
    async def test_list_drift_skips_malformed_events(self):
        """list_drift skips events that can't be parsed (missing required fields)."""
        bad_event = {"id": "bad", "missing_field": True}
        good_event = _raw_drift_event("good-001")
        api = _make_api_client(get_return={"drift_events": [bad_event, good_event]})
        svc = DriftService(api)
        events = await svc.list_drift()
        # good event should be parsed; bad event silently skipped
        assert len(events) == 1
        assert events[0].id == "good-001"


# ---------------------------------------------------------------------------
# AnomalyService tests
# ---------------------------------------------------------------------------

class TestAnomalyService:

    @pytest.mark.asyncio
    async def test_list_anomalies_happy_path(self):
        """list_anomalies returns AnomalyEvent list on success."""
        api = _make_api_client(get_return={"anomaly_events": [_raw_anomaly_event()]})
        svc = AnomalyService(api)
        events = await svc.list_anomalies()
        assert len(events) == 1
        assert isinstance(events[0], AnomalyEvent)
        assert events[0].id == "ano-001"
        assert events[0].severity == "high"

    @pytest.mark.asyncio
    async def test_list_anomalies_403_raises_upsell_required(self):
        """list_anomalies: 403 → UpsellRequired."""
        api = _make_api_client(get_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        svc = AnomalyService(api)
        with pytest.raises(UpsellRequired):
            await svc.list_anomalies()

    @pytest.mark.asyncio
    async def test_list_anomalies_429_raises_rate_limited(self):
        """list_anomalies: 429 → RateLimited."""
        api = _make_api_client(get_side_effect=RateLimitedError(
            code="rate_limited", message="too fast", status=429
        ))
        svc = AnomalyService(api)
        with pytest.raises(RateLimited):
            await svc.list_anomalies()

    @pytest.mark.asyncio
    async def test_acknowledge_anomaly_happy_path(self):
        """acknowledge_anomaly posts to correct endpoint and returns ack dict."""
        ack_response = {"id": "ano-001", "acknowledged_at": "2026-04-25T14:00:00+00:00"}
        api = _make_api_client(post_return=ack_response)
        svc = AnomalyService(api)
        result = await svc.acknowledge_anomaly("ano-001")
        assert result["id"] == "ano-001"
        api.post.assert_called_once_with(
            "/api/v1/memory/anomalies/ano-001/ack", json={}
        )

    @pytest.mark.asyncio
    async def test_acknowledge_anomaly_403_raises_upsell_required(self):
        """acknowledge_anomaly: 403 → UpsellRequired."""
        api = _make_api_client(post_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        svc = AnomalyService(api)
        with pytest.raises(UpsellRequired):
            await svc.acknowledge_anomaly("ano-001")

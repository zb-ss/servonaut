"""Tests for FleetService — reconciliation matrix, age buckets."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import (
    FeatureDisabledError,
    ForbiddenEntitlementError,
)
from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    RemoteFleet,
    RemoteFleetItem,
    UpsellRequired,
)
from servonaut.services.memory.fleet_service import FleetService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_api_client(get_return=None, get_side_effect=None):
    client = MagicMock()
    client.get = AsyncMock(return_value=get_return or {})
    if get_side_effect:
        client.get.side_effect = get_side_effect
    return client


def _make_memory_service(local_entries: Optional[List[Dict]] = None) -> MagicMock:
    ms = MagicMock()
    ms.list_all.return_value = local_entries or []
    return ms


def _make_fleet_response(instance_ids: List[str]) -> Dict[str, Any]:
    items = []
    for iid in instance_ids:
        items.append({
            "instance": {
                "instance_id": iid,
                "display_name": iid,
                "provider": "aws",
                "last_probe_at": "2026-04-25T12:00:00+00:00",
            },
            "drift_count_7d": 0,
            "memory_age": "green",
        })
    return {
        "total": len(items),
        "by_provider": {"aws": len(items)},
        "oldest_last_probe_at": None,
        "items": items,
    }


# ---------------------------------------------------------------------------
# memory_age_bucket tests
# ---------------------------------------------------------------------------

class TestMemoryAgeBucket:

    def test_none_probed_at_returns_unknown(self):
        assert FleetService.memory_age_bucket(None) == "unknown"

    def test_empty_string_returns_unknown(self):
        assert FleetService.memory_age_bucket("") == "unknown"

    def test_recent_timestamp_returns_green(self):
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat()
        assert FleetService.memory_age_bucket(recent) == "green"

    def test_one_day_old_returns_amber(self):
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        assert FleetService.memory_age_bucket(old) == "amber"

    def test_eight_days_old_returns_red(self):
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        assert FleetService.memory_age_bucket(old) == "red"

    def test_invalid_string_returns_unknown(self):
        assert FleetService.memory_age_bucket("not-a-date") == "unknown"


# ---------------------------------------------------------------------------
# Reconciliation matrix tests
# ---------------------------------------------------------------------------

class TestFleetReconciliation:

    @pytest.mark.asyncio
    async def test_local_only(self):
        """Local instances not in remote → source='local'."""
        local = [
            {"instance_id": "local-01", "name": "local-01", "provider": "custom",
             "modules": ["os"], "probed_at": "2026-04-25T12:00:00+00:00"},
        ]
        api = _make_api_client(get_return=_make_fleet_response([]))
        ms = _make_memory_service(local_entries=local)
        svc = FleetService(api, ms)
        rows = await svc.get_merged_fleet()
        assert len(rows) == 1
        assert rows[0]["source"] == "local"
        assert rows[0]["id"] == "local-01"

    @pytest.mark.asyncio
    async def test_remote_only(self):
        """Remote instances not in local → source='remote'."""
        local = []
        api = _make_api_client(get_return=_make_fleet_response(["remote-01"]))
        ms = _make_memory_service(local_entries=local)
        svc = FleetService(api, ms)
        rows = await svc.get_merged_fleet()
        assert len(rows) == 1
        assert rows[0]["source"] == "remote"
        assert rows[0]["id"] == "remote-01"

    @pytest.mark.asyncio
    async def test_merged_when_both_exist(self):
        """Instance in both local and remote → source='merged'."""
        local = [
            {"instance_id": "shared-01", "name": "shared-01", "provider": "aws",
             "modules": ["os", "runtimes"], "probed_at": "2026-04-25T12:00:00+00:00"},
        ]
        api = _make_api_client(get_return=_make_fleet_response(["shared-01"]))
        ms = _make_memory_service(local_entries=local)
        svc = FleetService(api, ms)
        rows = await svc.get_merged_fleet()
        assert len(rows) == 1
        assert rows[0]["source"] == "merged"

    @pytest.mark.asyncio
    async def test_mixed_providers(self):
        """Local and remote can have different providers — all included."""
        local = [
            {"instance_id": "ovh-01", "name": "OVH VPS", "provider": "ovh",
             "modules": ["os"], "probed_at": "2026-04-25T12:00:00+00:00"},
        ]
        remote_resp = _make_fleet_response(["aws-01"])
        remote_resp["items"][0]["instance"]["provider"] = "aws"
        api = _make_api_client(get_return=remote_resp)
        ms = _make_memory_service(local_entries=local)
        svc = FleetService(api, ms)
        rows = await svc.get_merged_fleet()
        assert len(rows) == 2
        sources = {r["id"]: r["source"] for r in rows}
        assert sources["ovh-01"] == "local"
        assert sources["aws-01"] == "remote"

    @pytest.mark.asyncio
    async def test_backend_maintenance_falls_back_to_local_only(self):
        """BackendMaintenance: return local rows only with remote_error hint."""
        local = [
            {"instance_id": "web-01", "name": "web-01", "provider": "custom",
             "modules": ["os"], "probed_at": ""},
        ]
        api = _make_api_client(get_side_effect=FeatureDisabledError(
            code="feature_disabled", message="maintenance", status=503
        ))
        ms = _make_memory_service(local_entries=local)
        svc = FleetService(api, ms)
        rows = await svc.get_merged_fleet()
        # Should still return local row
        assert len(rows) == 1
        assert rows[0]["id"] == "web-01"
        # remote_error is set
        assert "remote_error" in rows[0]

    @pytest.mark.asyncio
    async def test_upsell_required_falls_back_to_local_only(self):
        """UpsellRequired: return local rows only with remote_error hint."""
        local = [
            {"instance_id": "web-01", "name": "web-01", "provider": "custom",
             "modules": ["os"], "probed_at": ""},
        ]
        api = _make_api_client(get_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        ms = _make_memory_service(local_entries=local)
        svc = FleetService(api, ms)
        rows = await svc.get_merged_fleet()
        assert len(rows) == 1
        assert "remote_error" in rows[0]

    @pytest.mark.asyncio
    async def test_drift_7d_from_remote(self):
        """drift_count_7d from remote fleet shows in merged row."""
        local = [
            {"instance_id": "web-01", "name": "web-01", "provider": "aws",
             "modules": ["os"], "probed_at": "2026-04-25T12:00:00+00:00"},
        ]
        remote_resp = {
            "total": 1,
            "by_provider": {"aws": 1},
            "oldest_last_probe_at": None,
            "items": [{
                "instance": {
                    "instance_id": "web-01",
                    "display_name": "web-01",
                    "provider": "aws",
                    "last_probe_at": "2026-04-25T12:00:00+00:00",
                },
                "drift_count_7d": 3,
                "memory_age": "green",
            }],
        }
        api = _make_api_client(get_return=remote_resp)
        ms = _make_memory_service(local_entries=local)
        svc = FleetService(api, ms)
        rows = await svc.get_merged_fleet()
        assert rows[0]["drift_7d"] == 3

    @pytest.mark.asyncio
    async def test_sort_local_first_then_remote(self):
        """Merged/local rows come before remote-only rows."""
        local = [
            {"instance_id": "local-01", "name": "Z-local", "provider": "custom",
             "modules": [], "probed_at": ""},
        ]
        api = _make_api_client(get_return=_make_fleet_response(["a-remote"]))
        ms = _make_memory_service(local_entries=local)
        svc = FleetService(api, ms)
        rows = await svc.get_merged_fleet()
        # local-01 has source=local → should come first
        assert rows[0]["source"] == "local"
        assert rows[1]["source"] == "remote"


# ---------------------------------------------------------------------------
# get_remote_fleet tests
# ---------------------------------------------------------------------------

class TestGetRemoteFleet:

    @pytest.mark.asyncio
    async def test_happy_path_parses_fleet_response(self):
        api = _make_api_client(get_return=_make_fleet_response(["inst-01", "inst-02"]))
        ms = _make_memory_service()
        svc = FleetService(api, ms)
        fleet = await svc.get_remote_fleet()
        assert isinstance(fleet, RemoteFleet)
        assert fleet.total == 2
        assert len(fleet.items) == 2

    @pytest.mark.asyncio
    async def test_503_raises_backend_maintenance(self):
        api = _make_api_client(get_side_effect=FeatureDisabledError(
            code="feature_disabled", message="maintenance", status=503
        ))
        ms = _make_memory_service()
        svc = FleetService(api, ms)
        with pytest.raises(BackendMaintenance):
            await svc.get_remote_fleet()

    @pytest.mark.asyncio
    async def test_403_raises_upsell_required(self):
        api = _make_api_client(get_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        ms = _make_memory_service()
        svc = FleetService(api, ms)
        with pytest.raises(UpsellRequired):
            await svc.get_remote_fleet()

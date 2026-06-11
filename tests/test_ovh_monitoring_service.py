"""Tests for OVHMonitoringService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_monitoring_service import OVHMonitoringService
from servonaut.services.ovh_service import OVHService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_ovh_client():
    return MagicMock()


@pytest.fixture
def ovh_service(mock_ovh_client):
    """OVHService with a pre-injected mock client."""
    cfg = OVHConfig(
        enabled=True,
        endpoint="ovh-eu",
        application_key="APP_KEY",
        application_secret="APP_SECRET",
        consumer_key="CONSUMER_KEY",
    )
    svc = OVHService(cfg)
    svc._client = mock_ovh_client
    return svc


@pytest.fixture
def monitoring_service(ovh_service):
    return OVHMonitoringService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        svc = OVHMonitoringService(ovh_service)
        assert svc._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# Period validation
# ---------------------------------------------------------------------------

class TestPeriodValidation:

    @pytest.mark.parametrize("period", ["lastday", "lastweek", "lastmonth", "lastyear"])
    def test_valid_periods_accepted_for_vps(self, monitoring_service, mock_ovh_client, period):
        mock_ovh_client.get.return_value = {}
        # Should not raise
        asyncio.run(monitoring_service.get_vps_monitoring("vps-abc123.ovh.net", period))

    @pytest.mark.parametrize("period", ["lastday", "lastweek", "lastmonth", "lastyear"])
    def test_valid_periods_accepted_for_dedicated(self, monitoring_service, mock_ovh_client, period):
        mock_ovh_client.get.return_value = {}
        asyncio.run(monitoring_service.get_dedicated_monitoring("ns12345.ip-1-2-3.eu", period))

    @pytest.mark.parametrize("period", ["lastday", "lastweek", "lastmonth", "lastyear"])
    def test_valid_periods_accepted_for_cloud(self, monitoring_service, mock_ovh_client, period):
        mock_ovh_client.get.return_value = {}
        asyncio.run(monitoring_service.get_cloud_monitoring("proj-123", "inst-abc", period))

    @pytest.mark.parametrize("bad_period", ["last1day", "hour", "1day", "", "LASTDAY", "7d"])
    def test_invalid_period_raises_value_error_for_vps(self, monitoring_service, bad_period):
        with pytest.raises(ValueError, match="Invalid period"):
            asyncio.run(monitoring_service.get_vps_monitoring("vps-abc123.ovh.net", bad_period))

    @pytest.mark.parametrize("bad_period", ["last1day", "hour", "1day", "", "LASTDAY", "7d"])
    def test_invalid_period_raises_value_error_for_dedicated(self, monitoring_service, bad_period):
        with pytest.raises(ValueError, match="Invalid period"):
            asyncio.run(monitoring_service.get_dedicated_monitoring("ns12345.ip-1-2-3.eu", bad_period))

    @pytest.mark.parametrize("bad_period", ["last1day", "hour", "1day", "", "LASTDAY", "7d"])
    def test_invalid_period_raises_value_error_for_cloud(self, monitoring_service, bad_period):
        with pytest.raises(ValueError, match="Invalid period"):
            asyncio.run(monitoring_service.get_cloud_monitoring("proj-123", "inst-abc", bad_period))


# ---------------------------------------------------------------------------
# Instance name / ID validation
# ---------------------------------------------------------------------------

class TestInputValidation:

    @pytest.mark.parametrize("bad_name", ["", "../../etc/passwd", "vps name", "vps;drop"])
    def test_invalid_vps_name_raises_value_error(self, monitoring_service, bad_name):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(monitoring_service.get_vps_monitoring(bad_name))

    @pytest.mark.parametrize("bad_name", ["", "../../etc/passwd", "server name"])
    def test_invalid_server_name_raises_value_error(self, monitoring_service, bad_name):
        with pytest.raises(ValueError, match="Invalid server_name"):
            asyncio.run(monitoring_service.get_dedicated_monitoring(bad_name))

    @pytest.mark.parametrize("bad_id", ["", "../../etc/passwd", "proj id"])
    def test_invalid_project_id_raises_value_error(self, monitoring_service, bad_id):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(monitoring_service.get_cloud_monitoring(bad_id, "inst-abc"))

    @pytest.mark.parametrize("bad_id", ["", "../../etc/passwd", "inst id"])
    def test_invalid_instance_id_raises_value_error(self, monitoring_service, bad_id):
        with pytest.raises(ValueError, match="Invalid instance_id"):
            asyncio.run(monitoring_service.get_cloud_monitoring("proj-123", bad_id))


# ---------------------------------------------------------------------------
# get_vps_monitoring
# ---------------------------------------------------------------------------

class TestGetVpsMonitoring:

    def test_fetches_all_four_stat_types(self, monitoring_service, mock_ovh_client):
        # One API call per statistic type — the endpoint 400s without
        # an explicit `type` parameter.
        mock_ovh_client.get.return_value = {
            "unit": "%",
            "values": [{"timestamp": 1704067200, "value": 12.5}],
        }

        result = asyncio.run(monitoring_service.get_vps_monitoring("vps-abc123.ovh.net"))

        assert mock_ovh_client.get.call_count == 4
        types_called = [
            kwargs["type"] for _, kwargs in mock_ovh_client.get.call_args_list
        ]
        assert types_called == ["cpu:used", "mem:used", "net:rx", "net:tx"]
        assert set(result.keys()) == {"cpu", "ram", "net_in", "net_out"}
        assert result["cpu"][0]["value"] == 12.5

    def test_correct_api_path_and_period(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {"unit": "%", "values": []}

        asyncio.run(monitoring_service.get_vps_monitoring("vps-test.ovh.net", "lastweek"))

        for args, kwargs in mock_ovh_client.get.call_args_list:
            assert args[0] == "/vps/vps-test.ovh.net/monitoring"
            assert kwargs["period"] == "lastweek"

    def test_default_period_is_lastday(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {"unit": "%", "values": []}

        asyncio.run(monitoring_service.get_vps_monitoring("vps-abc123.ovh.net"))

        _, kwargs = mock_ovh_client.get.call_args
        assert kwargs["period"] == "lastday"

    def test_partial_failure_keeps_successful_keys(self, monitoring_service, mock_ovh_client):
        # cpu succeeds, the rest fail — result keeps cpu and empties the
        # failed keys without raising.
        ok = {"unit": "%", "values": [{"timestamp": 1704067200, "value": 12.5}]}
        mock_ovh_client.get.side_effect = [
            ok,
            Exception("500 Internal server error"),
            Exception("500 Internal server error"),
            Exception("500 Internal server error"),
        ]

        result = asyncio.run(monitoring_service.get_vps_monitoring("vps-abc123.ovh.net"))

        assert result["cpu"][0]["value"] == 12.5
        assert result["ram"] == []
        assert result["net_in"] == []
        assert result["net_out"] == []

    def test_all_types_failing_raises_loudly(self, monitoring_service, mock_ovh_client):
        # Silent-empty is indistinguishable from "no load" — when every
        # statistic type fails the caller must see an error.
        mock_ovh_client.get.side_effect = Exception("500 Internal server error")

        with pytest.raises(RuntimeError) as exc_info:
            asyncio.run(monitoring_service.get_vps_monitoring("vps-abc123.ovh.net"))

        msg = str(exc_info.value)
        assert "no monitoring data" in msg
        assert "500 Internal server error" in msg
        assert "legacy /vps monitoring API" in msg

    def test_vps_monitoring_data_shape_normalised(self, monitoring_service, mock_ovh_client):
        # vps.VpsMonitoringData: {"unit": ..., "values": [{timestamp, value}]}
        points = [{"timestamp": 1704067200 + i, "value": float(i)} for i in range(5)]
        mock_ovh_client.get.return_value = {"unit": "%", "values": points}

        result = asyncio.run(monitoring_service.get_vps_monitoring("vps-abc123.ovh.net"))

        assert len(result["cpu"]) == 5
        assert result["cpu"][2] == {"timestamp": 1704067202, "value": 2.0}


# ---------------------------------------------------------------------------
# get_dedicated_monitoring
# ---------------------------------------------------------------------------

class TestGetDedicatedMonitoring:

    def test_fetches_all_four_chart_types(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"timestamp": "2024-01-01T00:00:00Z", "value": 42.0}
        ]

        result = asyncio.run(
            monitoring_service.get_dedicated_monitoring("ns12345.ip-1-2-3.eu")
        )

        assert mock_ovh_client.get.call_count == 4
        assert set(result.keys()) == {"cpu", "ram", "net_rx", "net_tx"}

    def test_correct_chart_types_used(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(monitoring_service.get_dedicated_monitoring("ns12345.ip-1-2-3.eu"))

        called_types = [
            call.kwargs["type"]
            for call in mock_ovh_client.get.call_args_list
        ]
        assert "cpu:user:max" in called_types
        assert "ram:used:max" in called_types
        assert "net:rx:max" in called_types
        assert "net:tx:max" in called_types

    def test_partial_api_failure_returns_empty_list_for_failed_keys(
        self, monitoring_service, mock_ovh_client
    ):
        def side_effect(path, **kwargs):
            chart_type = kwargs.get("type", "")
            if chart_type == "cpu:user:max":
                return [{"timestamp": "2024-01-01T00:00:00Z", "value": 55.0}]
            raise Exception("chart unavailable")

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(
            monitoring_service.get_dedicated_monitoring("ns12345.ip-1-2-3.eu")
        )

        assert len(result["cpu"]) == 1
        assert result["ram"] == []
        assert result["net_rx"] == []
        assert result["net_tx"] == []

    def test_list_response_normalised_to_series(self, monitoring_service, mock_ovh_client):
        points = [{"timestamp": "2024-01-01T00:00:00Z", "value": 10.0}]
        mock_ovh_client.get.return_value = points

        result = asyncio.run(
            monitoring_service.get_dedicated_monitoring("ns12345.ip-1-2-3.eu")
        )

        assert result["cpu"] == points

    def test_dict_response_with_timestamps_and_values_normalised(
        self, monitoring_service, mock_ovh_client
    ):
        mock_ovh_client.get.return_value = {
            "timestamps": ["2024-01-01T00:00:00Z", "2024-01-01T01:00:00Z"],
            "values": [10.0, 20.0],
        }

        result = asyncio.run(
            monitoring_service.get_dedicated_monitoring("ns12345.ip-1-2-3.eu")
        )

        assert result["cpu"][0] == {"timestamp": "2024-01-01T00:00:00Z", "value": 10.0}
        assert result["cpu"][1] == {"timestamp": "2024-01-01T01:00:00Z", "value": 20.0}

    def test_correct_server_name_in_api_path(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(monitoring_service.get_dedicated_monitoring("ns99999.ip-9-9-9.eu"))

        for call in mock_ovh_client.get.call_args_list:
            assert "/dedicated/server/ns99999.ip-9-9-9.eu/statistics/chart" in call.args[0]


# ---------------------------------------------------------------------------
# get_cloud_monitoring
# ---------------------------------------------------------------------------

class TestGetCloudMonitoring:

    def test_returns_structured_data(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "cpu": [{"timestamp": "2024-01-01T00:00:00Z", "value": 30.0}],
            "net_in": [{"timestamp": "2024-01-01T00:00:00Z", "value": 500.0}],
            "net_out": [{"timestamp": "2024-01-01T00:00:00Z", "value": 250.0}],
        }

        result = asyncio.run(
            monitoring_service.get_cloud_monitoring("proj-abc", "inst-xyz")
        )

        assert set(result.keys()) == {"cpu", "net_in", "net_out"}
        assert len(result["cpu"]) == 1
        assert result["cpu"][0]["value"] == 30.0

    def test_correct_api_path_with_composite_id(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(
            monitoring_service.get_cloud_monitoring("my-project", "my-instance", "lastweek")
        )

        mock_ovh_client.get.assert_called_once_with(
            "/cloud/project/my-project/instance/my-instance/monitoring",
            period="lastweek",
        )

    def test_api_error_returns_empty_lists(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("instance not found")

        result = asyncio.run(
            monitoring_service.get_cloud_monitoring("proj-abc", "inst-xyz")
        )

        assert result["cpu"] == []
        assert result["net_in"] == []
        assert result["net_out"] == []

    def test_empty_response_returns_empty_lists(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        result = asyncio.run(
            monitoring_service.get_cloud_monitoring("proj-abc", "inst-xyz")
        )

        assert result["cpu"] == []
        assert result["net_in"] == []
        assert result["net_out"] == []

    def test_default_period_is_lastday(self, monitoring_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(monitoring_service.get_cloud_monitoring("proj-abc", "inst-xyz"))

        _, kwargs = mock_ovh_client.get.call_args
        assert kwargs["period"] == "lastday"

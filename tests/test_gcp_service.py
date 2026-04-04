"""Tests for GCPService."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import GCPConfig
from servonaut.services.gcp_service import GCPService, _STATE_MAP


@pytest.fixture
def gcp_config():
    return GCPConfig(
        enabled=True,
        project_ids=["my-project"],
        zones=["us-central1-a"],
    )


@pytest.fixture
def mock_cache():
    return MagicMock()


@pytest.fixture
def gcp_service(mock_cache, gcp_config):
    return GCPService(mock_cache, gcp_config)


class TestGCPService:
    def test_state_mapping(self):
        assert _STATE_MAP["RUNNING"] == "running"
        assert _STATE_MAP["TERMINATED"] == "stopped"
        assert _STATE_MAP["STAGING"] == "pending"

    def test_to_instance_dict(self, gcp_service):
        mock_instance = MagicMock()
        mock_instance.id = 12345
        mock_instance.name = "test-vm"
        mock_instance.status = "RUNNING"
        mock_instance.machine_type = "zones/us-central1-a/machineTypes/e2-medium"

        # Mock network interface
        mock_iface = MagicMock()
        mock_iface.network_i_p = "10.0.0.1"
        mock_access = MagicMock()
        mock_access.nat_i_p = "35.192.0.1"
        mock_iface.access_configs = [mock_access]
        mock_instance.network_interfaces = [mock_iface]

        result = gcp_service._to_instance_dict(mock_instance, "my-project", "us-central1-a")

        assert result["id"] == "gcp-12345"
        assert result["name"] == "test-vm"
        assert result["type"] == "e2-medium"
        assert result["state"] == "running"
        assert result["public_ip"] == "35.192.0.1"
        assert result["private_ip"] == "10.0.0.1"
        assert result["provider"] == "gcp"
        assert result["region"] == "us-central1-a"

    def test_to_instance_dict_no_ips(self, gcp_service):
        mock_instance = MagicMock()
        mock_instance.id = 99999
        mock_instance.name = "no-ip-vm"
        mock_instance.status = "TERMINATED"
        mock_instance.machine_type = "e2-micro"
        mock_instance.network_interfaces = []

        result = gcp_service._to_instance_dict(mock_instance, "proj", "zone-a")
        assert result["public_ip"] is None
        assert result["private_ip"] is None
        assert result["state"] == "stopped"

    def test_fetch_requires_sdk(self, gcp_service):
        with patch.dict("sys.modules", {"google.cloud": None, "google.cloud.compute_v1": None}):
            # This should raise because google-cloud-compute is not importable
            with pytest.raises(RuntimeError, match="google-cloud-compute"):
                asyncio.run(gcp_service.fetch_instances())

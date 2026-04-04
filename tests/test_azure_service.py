"""Tests for AzureService."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import AzureConfig
from servonaut.services.azure_service import AzureService, _STATE_MAP


@pytest.fixture
def azure_config():
    return AzureConfig(
        enabled=True,
        subscription_ids=["sub-123"],
        resource_groups=["my-rg"],
    )


@pytest.fixture
def mock_cache():
    return MagicMock()


@pytest.fixture
def azure_service(mock_cache, azure_config):
    return AzureService(mock_cache, azure_config)


class TestAzureService:
    def test_state_mapping(self):
        assert _STATE_MAP["PowerState/running"] == "running"
        assert _STATE_MAP["PowerState/deallocated"] == "stopped"
        assert _STATE_MAP["PowerState/starting"] == "pending"

    def test_to_instance_dict(self, azure_service):
        mock_vm = MagicMock()
        mock_vm.vm_id = "vm-123"
        mock_vm.name = "test-vm"
        mock_vm.id = "/subscriptions/sub/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/test-vm"
        mock_vm.location = "eastus"
        mock_vm.hardware_profile.vm_size = "Standard_B2s"
        mock_vm.network_profile.network_interfaces = []

        mock_compute = MagicMock()
        mock_iv = MagicMock()
        status = MagicMock()
        status.code = "PowerState/running"
        mock_iv.statuses = [status]
        mock_compute.virtual_machines.instance_view.return_value = mock_iv

        mock_network = MagicMock()

        result = azure_service._to_instance_dict(
            mock_vm, "sub-123", mock_compute, mock_network
        )

        assert result["id"] == "azure-vm-123"
        assert result["name"] == "test-vm"
        assert result["type"] == "Standard_B2s"
        assert result["state"] == "running"
        assert result["provider"] == "azure"
        assert result["region"] == "eastus"

    def test_fetch_requires_sdk(self, azure_service):
        with patch.dict("sys.modules", {
            "azure": None,
            "azure.identity": None,
            "azure.mgmt": None,
            "azure.mgmt.compute": None,
            "azure.mgmt.network": None,
        }):
            with pytest.raises(RuntimeError, match="azure-identity"):
                asyncio.run(azure_service.fetch_instances())

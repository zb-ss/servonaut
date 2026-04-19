"""Azure VM instance service."""
from __future__ import annotations

import logging
from typing import Dict, List, TYPE_CHECKING

from .interfaces import CloudServiceInterface

if TYPE_CHECKING:
    from servonaut.config.schema import AzureConfig
    from servonaut.services.cache_service import CacheService

logger = logging.getLogger(__name__)

# State mapping: Azure power state → Servonaut standard
_STATE_MAP = {
    "PowerState/running": "running",
    "PowerState/deallocated": "stopped",
    "PowerState/deallocating": "shutting-down",
    "PowerState/stopped": "stopped",
    "PowerState/stopping": "shutting-down",
    "PowerState/starting": "pending",
    "PowerState/unknown": "unknown",
}


class AzureService(CloudServiceInterface):
    """Fetch Azure VM instances."""

    def __init__(self, cache_service: 'CacheService', config: 'AzureConfig') -> None:
        self._cache = cache_service
        self._config = config

    async def fetch_instances(self) -> List[dict]:
        """Fetch instances from Azure across configured subscriptions."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.network import NetworkManagementClient
        except ImportError:
            raise RuntimeError(
                "Azure support requires azure-identity and azure-mgmt-compute. "
                "Install with: pip install 'servonaut[azure]'"
            )

        import asyncio

        loop = asyncio.get_event_loop()
        instances = await loop.run_in_executor(
            None,
            self._fetch_sync,
            DefaultAzureCredential,
            ComputeManagementClient,
            NetworkManagementClient,
        )
        return instances

    def _fetch_sync(
        self, credential_cls, compute_cls, network_cls
    ) -> List[dict]:
        """Synchronous fetch using Azure SDK."""
        credential = credential_cls()
        all_instances: List[dict] = []

        for sub_id in self._config.subscription_ids:
            try:
                compute_client = compute_cls(credential, sub_id)
                network_client = network_cls(credential, sub_id)

                if self._config.resource_groups:
                    vms = []
                    for rg in self._config.resource_groups:
                        vms.extend(compute_client.virtual_machines.list(rg))
                else:
                    vms = list(compute_client.virtual_machines.list_all())

                for vm in vms:
                    instance = self._to_instance_dict(
                        vm, sub_id, compute_client, network_client
                    )
                    all_instances.append(instance)

            except Exception as e:
                logger.error(
                    "Error fetching Azure VMs for subscription %s: %s", sub_id, e
                )

        logger.info("Fetched %d Azure VMs", len(all_instances))
        return all_instances

    def _to_instance_dict(
        self, vm, subscription_id: str, compute_client, network_client
    ) -> dict:
        """Convert Azure VM to standard instance dict format."""
        # Get power state
        rg = vm.id.split('/')[4] if vm.id and '/resourceGroups/' in vm.id else ""
        state = "unknown"
        try:
            iv = compute_client.virtual_machines.instance_view(rg, vm.name)
            for status in (iv.statuses or []):
                if status.code and status.code.startswith("PowerState/"):
                    state = _STATE_MAP.get(status.code, "unknown")
                    break
        except Exception:
            pass

        # Get IPs from network interfaces
        public_ip = None
        private_ip = None
        try:
            for nic_ref in (vm.network_profile.network_interfaces or []):
                nic_name = nic_ref.id.split('/')[-1]
                nic_rg = nic_ref.id.split('/')[4] if '/resourceGroups/' in nic_ref.id else rg
                try:
                    nic = network_client.network_interfaces.get(nic_rg, nic_name)
                    for ip_config in (nic.ip_configurations or []):
                        if ip_config.private_ip_address:
                            private_ip = ip_config.private_ip_address
                        if ip_config.public_ip_address and ip_config.public_ip_address.id:
                            pip_name = ip_config.public_ip_address.id.split('/')[-1]
                            pip_rg = ip_config.public_ip_address.id.split('/')[4]
                            try:
                                pip = network_client.public_ip_addresses.get(pip_rg, pip_name)
                                public_ip = pip.ip_address
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            pass

        location = getattr(vm, 'location', '')
        vm_size = ""
        if vm.hardware_profile and vm.hardware_profile.vm_size:
            vm_size = vm.hardware_profile.vm_size

        return {
            "id": f"azure-{vm.vm_id or vm.name}",
            "name": vm.name or "",
            "type": vm_size,
            "state": state,
            "public_ip": public_ip,
            "private_ip": private_ip,
            "region": location,
            "key_name": "",
            "provider": "azure",
            "azure_subscription": subscription_id,
            "azure_resource_group": rg,
            "is_custom": False,
        }

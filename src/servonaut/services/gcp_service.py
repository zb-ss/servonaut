"""GCP Compute Engine instance service."""
from __future__ import annotations

import logging
from typing import Dict, List, TYPE_CHECKING

from .interfaces import CloudServiceInterface

if TYPE_CHECKING:
    from servonaut.config.schema import GCPConfig
    from servonaut.services.cache_service import CacheService

logger = logging.getLogger(__name__)

# State mapping: GCP status → Servonaut standard
_STATE_MAP = {
    "RUNNING": "running",
    "TERMINATED": "stopped",
    "STOPPED": "stopped",
    "SUSPENDED": "stopped",
    "STAGING": "pending",
    "PROVISIONING": "pending",
    "STOPPING": "shutting-down",
    "SUSPENDING": "shutting-down",
}


class GCPService(CloudServiceInterface):
    """Fetch GCP Compute Engine instances."""

    def __init__(self, cache_service: 'CacheService', config: 'GCPConfig') -> None:
        self._cache = cache_service
        self._config = config

    async def fetch_instances(self) -> List[dict]:
        """Fetch instances from GCP across configured projects/zones."""
        try:
            from google.cloud import compute_v1
        except ImportError:
            raise RuntimeError(
                "GCP support requires google-cloud-compute. "
                "Install with: pip install 'servonaut[gcp]'"
            )

        import asyncio

        loop = asyncio.get_event_loop()
        instances = await loop.run_in_executor(None, self._fetch_sync, compute_v1)
        return instances

    def _fetch_sync(self, compute_v1) -> List[dict]:
        """Synchronous fetch using google-cloud-compute SDK."""
        client = compute_v1.InstancesClient()
        all_instances: List[dict] = []

        credentials_path = self._config.credentials_path
        if credentials_path:
            import os
            os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", credentials_path)

        for project_id in self._config.project_ids:
            try:
                if self._config.zones:
                    for zone in self._config.zones:
                        instances = client.list(project=project_id, zone=zone)
                        for inst in instances:
                            all_instances.append(
                                self._to_instance_dict(inst, project_id, zone)
                            )
                else:
                    # Use aggregated list to get all zones
                    agg = client.aggregated_list(project=project_id)
                    for zone_path, response in agg:
                        if not response.instances:
                            continue
                        # zone_path looks like "zones/us-central1-a"
                        zone = zone_path.split("/")[-1] if "/" in zone_path else zone_path
                        for inst in response.instances:
                            all_instances.append(
                                self._to_instance_dict(inst, project_id, zone)
                            )
            except Exception as e:
                logger.error("Error fetching GCP instances for project %s: %s", project_id, e)

        logger.info("Fetched %d GCP instances", len(all_instances))
        return all_instances

    def _to_instance_dict(self, instance, project_id: str, zone: str) -> dict:
        """Convert GCP instance to standard instance dict format."""
        # Extract IPs from network interfaces
        public_ip = None
        private_ip = None
        for iface in getattr(instance, 'network_interfaces', []) or []:
            if hasattr(iface, 'network_i_p') and iface.network_i_p:
                private_ip = iface.network_i_p
            for access in getattr(iface, 'access_configs', []) or []:
                if hasattr(access, 'nat_i_p') and access.nat_i_p:
                    public_ip = access.nat_i_p

        status = getattr(instance, 'status', 'UNKNOWN')
        machine_type = getattr(instance, 'machine_type', '')
        # machine_type is a URL like "zones/us-central1-a/machineTypes/e2-medium"
        if '/' in machine_type:
            machine_type = machine_type.split('/')[-1]

        return {
            "id": f"gcp-{instance.id}",
            "name": getattr(instance, 'name', ''),
            "type": machine_type,
            "state": _STATE_MAP.get(status, "unknown"),
            "public_ip": public_ip,
            "private_ip": private_ip,
            "region": zone,
            "key_name": "",
            "provider": "gcp",
            "gcp_project": project_id,
            "is_custom": False,
        }

"""OVHcloud instance fetching service with caching support."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from servonaut.config.secrets import resolve_secret

if TYPE_CHECKING:
    from servonaut.config.schema import OVHConfig

logger = logging.getLogger(__name__)

_OVH_CACHE_PATH = Path.home() / '.servonaut' / 'ovh_cache.json'
_OVH_CACHE_TTL_SECONDS = 300  # 5 minutes


class OVHService:
    """Service for fetching OVHcloud instances (dedicated, VPS, Public Cloud)."""

    def __init__(self, config: 'OVHConfig') -> None:
        """Initialize OVH service.

        Args:
            config: OVHConfig dataclass instance.
        """
        self._config = config
        self._client = None  # lazy-initialized

    def _get_client(self):
        """Lazy-initialize the OVH API client.

        Returns:
            ovh.Client instance.

        Raises:
            ImportError: If python-ovh is not installed.
        """
        if self._client is not None:
            return self._client

        try:
            import ovh
        except ImportError:
            raise ImportError(
                "python-ovh is not installed. "
                "Install with: pip install 'servonaut[ovh]'"
            )

        config = self._config
        application_key = resolve_secret(config.application_key)
        application_secret = resolve_secret(config.application_secret)
        consumer_key = resolve_secret(config.consumer_key)
        client_id = resolve_secret(config.client_id)
        client_secret = resolve_secret(config.client_secret)

        if client_id and client_secret:
            # OAuth2 service account auth
            self._client = ovh.Client(
                endpoint=config.endpoint,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            # Classic 3-key auth
            self._client = ovh.Client(
                endpoint=config.endpoint,
                application_key=application_key,
                application_secret=application_secret,
                consumer_key=consumer_key,
            )

        return self._client

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def fetch_instances(self) -> List[dict]:
        """Fetch all OVH instances across configured resource types.

        Returns:
            List of instance dictionaries compatible with app.instances format.
        """
        logger.debug("Fetching instances from OVHcloud")
        instances: List[dict] = []

        if self._config.include_dedicated:
            try:
                dedicated = await asyncio.to_thread(self._fetch_dedicated)
                instances.extend(dedicated)
                logger.debug("Fetched %d OVH dedicated servers", len(dedicated))
            except Exception as e:
                logger.error("Error fetching OVH dedicated servers: %s", e)

        if self._config.include_vps:
            try:
                vps = await asyncio.to_thread(self._fetch_vps)
                instances.extend(vps)
                logger.debug("Fetched %d OVH VPS instances", len(vps))
            except Exception as e:
                logger.error("Error fetching OVH VPS instances: %s", e)

        if self._config.include_cloud:
            for project_id in self._config.cloud_project_ids:
                try:
                    cloud = await asyncio.to_thread(self._fetch_cloud, project_id)
                    instances.extend(cloud)
                    logger.debug(
                        "Fetched %d OVH Cloud instances for project %s",
                        len(cloud), project_id
                    )
                except Exception as e:
                    logger.error(
                        "Error fetching OVH Cloud instances for project %s: %s",
                        project_id, e
                    )

        logger.info("Fetched %d total OVH instances", len(instances))
        return instances

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        """Fetch instances with OVH-specific file cache.

        Args:
            force_refresh: If True, bypass cache and fetch from API.

        Returns:
            List of instance dictionaries.
        """
        if not force_refresh:
            cached = self._load_cache()
            if cached is not None:
                logger.debug("Using cached OVH instances")
                return cached

        instances = await self.fetch_instances()
        self._save_cache(instances)
        return instances

    def get_cached_instances(self) -> List[dict]:
        """Return cached OVH instances synchronously (any age).

        Returns:
            Cached instance list or empty list if no cache exists.
        """
        cached = self._load_cache(ignore_ttl=True)
        return cached if cached is not None else []

    def is_cache_fresh(self) -> bool:
        """Check if OVH cache is within TTL.

        Returns:
            True if cache exists and has not expired.
        """
        if not _OVH_CACHE_PATH.exists():
            return False
        try:
            with open(_OVH_CACHE_PATH, 'r') as f:
                data = json.load(f)
            ts = data.get('timestamp')
            if not ts:
                return False
            age = datetime.now() - datetime.fromisoformat(ts)
            return age < timedelta(seconds=_OVH_CACHE_TTL_SECONDS)
        except Exception:
            return False

    @property
    def client(self):
        """Return the initialized OVH API client.

        Returns:
            ovh.Client instance (lazy-initialized).
        """
        return self._get_client()

    @staticmethod
    def default_username(provider_type: str) -> str:
        """Return the default SSH username for an OVH provider type.

        Args:
            provider_type: One of "dedicated", "vps", "cloud".

        Returns:
            Default SSH username string.
        """
        return {
            'cloud': 'ubuntu',
            'dedicated': 'debian',
            'vps': 'ubuntu',
        }.get(provider_type, 'ubuntu')

    # ------------------------------------------------------------------
    # Power management
    # ------------------------------------------------------------------

    async def reboot_instance(self, instance_id: str, provider_type: str) -> bool:
        """Reboot an OVH instance.

        Args:
            instance_id: OVH instance identifier.
            provider_type: One of "dedicated", "vps", "cloud".

        Returns:
            True if reboot was requested successfully.
        """
        if not re.match(r'^[a-zA-Z0-9._:/-]+$', instance_id):
            raise ValueError(f"Invalid instance_id format: {instance_id!r}")
        client = self._get_client()
        if provider_type == "dedicated":
            await asyncio.to_thread(
                client.post, f"/dedicated/server/{instance_id}/reboot"
            )
        elif provider_type == "vps":
            await asyncio.to_thread(
                client.post, f"/vps/{instance_id}/reboot"
            )
        elif provider_type == "cloud":
            # Cloud reboots need project_id — instance_id is "<project_id>/<id>"
            project_id, _, inst_id = instance_id.partition('/')
            await asyncio.to_thread(
                client.post,
                f"/cloud/project/{project_id}/instance/{inst_id}/reboot",
                type="soft",
            )
        else:
            raise ValueError(f"Unknown OVH provider_type: {provider_type}")
        return True

    async def start_instance(self, instance_id: str, provider_type: str) -> bool:
        """Start an OVH instance (VPS and Cloud only).

        Args:
            instance_id: OVH instance identifier.
            provider_type: One of "vps", "cloud".

        Returns:
            True if start was requested successfully.
        """
        if not re.match(r'^[a-zA-Z0-9._:/-]+$', instance_id):
            raise ValueError(f"Invalid instance_id format: {instance_id!r}")
        client = self._get_client()
        if provider_type == "vps":
            await asyncio.to_thread(
                client.post, f"/vps/{instance_id}/start"
            )
        elif provider_type == "cloud":
            project_id, _, inst_id = instance_id.partition('/')
            await asyncio.to_thread(
                client.post,
                f"/cloud/project/{project_id}/instance/{inst_id}/start",
            )
        else:
            raise ValueError(
                f"Start is not supported for OVH provider_type: {provider_type}"
            )
        return True

    async def stop_instance(self, instance_id: str, provider_type: str) -> bool:
        """Stop an OVH instance (VPS and Cloud only).

        Args:
            instance_id: OVH instance identifier.
            provider_type: One of "vps", "cloud".

        Returns:
            True if stop was requested successfully.
        """
        if not re.match(r'^[a-zA-Z0-9._:/-]+$', instance_id):
            raise ValueError(f"Invalid instance_id format: {instance_id!r}")
        client = self._get_client()
        if provider_type == "vps":
            await asyncio.to_thread(
                client.post, f"/vps/{instance_id}/stop"
            )
        elif provider_type == "cloud":
            project_id, _, inst_id = instance_id.partition('/')
            await asyncio.to_thread(
                client.post,
                f"/cloud/project/{project_id}/instance/{inst_id}/stop",
            )
        else:
            raise ValueError(
                f"Stop is not supported for OVH provider_type: {provider_type}"
            )
        return True

    # ------------------------------------------------------------------
    # Credential validation
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Test OVH API credentials by calling GET /me.

        Returns:
            Dict with keys: success (bool), account (str), message (str).
        """
        try:
            client = self._get_client()
            me = await asyncio.to_thread(client.get, "/me")
            nickname = me.get('nichandle') or me.get('email') or 'unknown'
            return {
                'success': True,
                'account': nickname,
                'message': f"Connected as {nickname}",
            }
        except Exception as e:
            logger.debug("OVH test_connection failed: %s", e)
            return {
                'success': False,
                'account': '',
                'message': "Authentication failed. Check your API credentials.",
            }

    async def request_consumer_key(self) -> dict:
        """Request a new consumer key via the OVH credential flow.

        Returns:
            Dict with keys: consumer_key, validation_url, state.
        """
        try:
            import ovh
        except ImportError:
            raise ImportError("python-ovh is not installed. Install with: pip install 'servonaut[ovh]'")

        config = self._config
        application_secret = resolve_secret(config.application_secret)

        application_key = resolve_secret(config.application_key)

        client = ovh.Client(
            endpoint=config.endpoint,
            application_key=application_key,
            application_secret=application_secret,
        )

        access_rules = [
            # Listing endpoints (/* doesn't match the root list endpoint)
            {'method': 'GET', 'path': '/dedicated/server'},
            {'method': 'GET', 'path': '/vps'},
            {'method': 'GET', 'path': '/cloud/project'},
            # Individual resource access
            {'method': 'GET', 'path': '/dedicated/server/*'},
            {'method': 'GET', 'path': '/vps/*'},
            {'method': 'GET', 'path': '/cloud/project/*'},
            # Power management
            {'method': 'POST', 'path': '/vps/*/reboot'},
            {'method': 'POST', 'path': '/vps/*/start'},
            {'method': 'POST', 'path': '/vps/*/stop'},
            {'method': 'POST', 'path': '/dedicated/server/*/reboot'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/reboot'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/start'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/stop'},
            # Billing and account
            {'method': 'GET', 'path': '/me'},
            {'method': 'GET', 'path': '/me/consumption/*'},
            {'method': 'GET', 'path': '/me/bill'},
            {'method': 'GET', 'path': '/me/bill/*'},
        ]

        result = await asyncio.to_thread(
            client.request_consumerkey,
            access_rules,
        )
        return result

    # ------------------------------------------------------------------
    # Blocking fetch helpers (run inside asyncio.to_thread)
    # ------------------------------------------------------------------

    def _fetch_dedicated(self) -> List[dict]:
        """Fetch all dedicated servers sequentially.

        Returns:
            List of instance dictionaries.
        """
        client = self._get_client()
        try:
            server_names = client.get("/dedicated/server")
        except Exception as e:
            logger.error("Error listing OVH dedicated servers: %s", e)
            return []

        if not server_names:
            return []

        instances = []
        for name in server_names:
            try:
                instance = self._fetch_dedicated_server(name)
                if instance:
                    instances.append(instance)
            except Exception as e:
                logger.error("Error fetching OVH dedicated server %s: %s", name, e)

        return instances

    def _fetch_dedicated_server(self, name: str) -> Optional[dict]:
        """Fetch details for a single dedicated server.

        Args:
            name: Dedicated server hostname/identifier.

        Returns:
            Instance dictionary or None on error.
        """
        client = self._get_client()
        try:
            details = client.get(f"/dedicated/server/{name}")
        except Exception as e:
            logger.error("Error fetching dedicated server details for %s: %s", name, e)
            return None

        # Fetch hardware specs — non-fatal if missing
        try:
            specs = client.get(f"/dedicated/server/{name}/specifications/hardware")
        except Exception:
            specs = {}

        # Fetch IPs — non-fatal if missing
        try:
            ips = client.get(f"/dedicated/server/{name}/ips")
        except Exception:
            ips = []

        return {
            'id': name,
            'name': details.get('reverse') or name,
            'type': specs.get('description') or 'Dedicated',
            'state': self._map_dedicated_state(details.get('state', '')),
            'public_ip': self._find_public_ip(ips) or '',
            'private_ip': self._find_private_ip(ips) or '',
            'region': details.get('datacenter') or '',
            'key_name': '',
            'provider': 'OVH',
            'provider_type': 'dedicated',
            'is_ovh': True,
            'os': details.get('os') or '',
            'cpu': specs.get('numberOfCores') or '',
            'ram_gb': self._bytes_to_gb(specs.get('memorySize', 0)),
            'raw': details,
        }

    def _fetch_vps(self) -> List[dict]:
        """Fetch all VPS instances.

        Returns:
            List of instance dictionaries.
        """
        client = self._get_client()
        try:
            vps_names = client.get("/vps")
        except Exception as e:
            logger.error("Error listing OVH VPS instances: %s", e)
            return []

        if not vps_names:
            return []

        instances = []
        for name in vps_names:
            try:
                details = client.get(f"/vps/{name}")
                model = details.get('model') or {}
                public_ip = ''
                ips = details.get('ips')
                if ips:
                    public_ip = ips[0] if isinstance(ips[0], str) else ''
                instances.append({
                    'id': name,
                    'name': details.get('displayName') or name,
                    'type': model.get('name') or 'VPS',
                    'state': self._map_vps_state(details.get('state', '')),
                    'public_ip': public_ip,
                    'private_ip': '',
                    'region': details.get('zone') or '',
                    'key_name': '',
                    'provider': 'OVH',
                    'provider_type': 'vps',
                    'is_ovh': True,
                    'ram_gb': self._mb_to_gb(model.get('memory')),
                    'raw': details,
                })
            except Exception as e:
                logger.error("Error fetching OVH VPS details for %s: %s", name, e)

        return instances

    def _fetch_cloud(self, project_id: str) -> List[dict]:
        """Fetch all Public Cloud instances for a project.

        Args:
            project_id: OVH Public Cloud project identifier.

        Returns:
            List of instance dictionaries.
        """
        client = self._get_client()
        try:
            cloud_instances = client.get(f"/cloud/project/{project_id}/instance")
        except Exception as e:
            logger.error(
                "Error fetching OVH Cloud instances for project %s: %s",
                project_id, e
            )
            return []

        if not cloud_instances:
            return []

        instances = []
        for inst in cloud_instances:
            inst_id = inst.get('id', '')
            # Encode project_id into the composite ID for power management routing
            composite_id = f"{project_id}/{inst_id}"
            ip_addresses = inst.get('ipAddresses') or []
            instances.append({
                'id': composite_id,
                'name': inst.get('name') or inst_id,
                'type': inst.get('flavor', {}).get('name') or inst.get('flavorId') or '',
                'state': self._map_cloud_state(inst.get('status', '')),
                'public_ip': self._extract_public_ip(ip_addresses),
                'private_ip': self._extract_private_ip(ip_addresses),
                'region': inst.get('region') or '',
                'key_name': '',
                'provider': 'OVH',
                'provider_type': 'cloud',
                'is_ovh': True,
                'raw': inst,
            })

        return instances

    # ------------------------------------------------------------------
    # State mapping helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_dedicated_state(state: str) -> str:
        """Normalize OVH dedicated server state to common format."""
        return {
            'ok': 'running',
            'hacked': 'error',
            'hackedBlocked': 'error',
        }.get(state, state)

    @staticmethod
    def _map_vps_state(state: str) -> str:
        """Normalize OVH VPS state to common format."""
        return {
            'running': 'running',
            'stopped': 'stopped',
            'installing': 'pending',
            'rescueMode': 'running',
        }.get(state, state)

    @staticmethod
    def _map_cloud_state(status: str) -> str:
        """Normalize OVH Public Cloud instance status to common format."""
        return {
            'ACTIVE': 'running',
            'SHUTOFF': 'stopped',
            'BUILD': 'pending',
            'ERROR': 'error',
            'SHELVED': 'stopped',
            'RESCUED': 'running',
            'SUSPENDED': 'stopped',
        }.get(status, status.lower() if status else '')

    # ------------------------------------------------------------------
    # IP extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_public_ip(ips: List[str]) -> str:
        """Extract the first public (non-RFC1918) IP from a list.

        Args:
            ips: List of IP strings from OVH dedicated server API.

        Returns:
            First public IP or empty string.
        """
        import ipaddress
        for ip in ips:
            ip_str = ip.split('/')[0] if '/' in ip else ip
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.version == 4 and not addr.is_private and not addr.is_loopback:
                    return ip_str
            except ValueError:
                continue
        # Fall back to the first entry if no public IP found
        if ips:
            return ips[0].split('/')[0] if '/' in ips[0] else ips[0]
        return ''

    @staticmethod
    def _find_private_ip(ips: List[str]) -> str:
        """Extract the first private (RFC1918) IP from a list.

        Args:
            ips: List of IP strings from OVH dedicated server API.

        Returns:
            First private IP or empty string.
        """
        import ipaddress
        for ip in ips:
            ip_str = ip.split('/')[0] if '/' in ip else ip
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.version == 4 and addr.is_private:
                    return ip_str
            except ValueError:
                continue
        return ''

    @staticmethod
    def _extract_public_ip(ip_addresses: List[dict]) -> str:
        """Extract public IPv4 from OVH Cloud ipAddresses list.

        Args:
            ip_addresses: List of ip-address dicts from Cloud instance API.

        Returns:
            First public IPv4 string or empty string.
        """
        for entry in ip_addresses:
            if entry.get('type') == 'public' and entry.get('version') == 4:
                return entry.get('ip', '')
        # Fallback: any public IP
        for entry in ip_addresses:
            if entry.get('type') == 'public':
                return entry.get('ip', '')
        return ''

    @staticmethod
    def _extract_private_ip(ip_addresses: List[dict]) -> str:
        """Extract private IPv4 from OVH Cloud ipAddresses list.

        Args:
            ip_addresses: List of ip-address dicts from Cloud instance API.

        Returns:
            First private IPv4 string or empty string.
        """
        for entry in ip_addresses:
            if entry.get('type') == 'private' and entry.get('version') == 4:
                return entry.get('ip', '')
        for entry in ip_addresses:
            if entry.get('type') == 'private':
                return entry.get('ip', '')
        return ''

    @staticmethod
    def _bytes_to_gb(value) -> float:
        """Convert bytes to GB.

        Args:
            value: Memory size in bytes (OVH dedicated server memorySize field).

        Returns:
            Size in GB, rounded to 1 decimal place.
        """
        if not value:
            return 0.0
        try:
            v = int(value)
        except (TypeError, ValueError):
            return 0.0
        # OVH dedicated server API returns memorySize in bytes
        return round(v / (1024 ** 3), 1)

    @staticmethod
    def _mb_to_gb(value) -> float:
        """Convert megabytes to GB.

        Args:
            value: Memory size in MB (OVH VPS model.memory field).

        Returns:
            Size in GB, rounded to 1 decimal place.
        """
        if not value:
            return 0.0
        try:
            v = int(value)
        except (TypeError, ValueError):
            return 0.0
        # OVH VPS API returns model.memory in MB
        return round(v / 1024, 1)

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _load_cache(self, ignore_ttl: bool = False) -> Optional[List[dict]]:
        """Load OVH instances from local file cache.

        Args:
            ignore_ttl: If True, return data even if expired.

        Returns:
            List of instance dicts or None if cache invalid/expired.
        """
        if not _OVH_CACHE_PATH.exists():
            return None

        try:
            with open(_OVH_CACHE_PATH, 'r') as f:
                data = json.load(f)

            ts = data.get('timestamp')
            instances = data.get('instances')

            if ts is None or instances is None:
                return None

            if not ignore_ttl:
                age = datetime.now() - datetime.fromisoformat(ts)
                if age >= timedelta(seconds=_OVH_CACHE_TTL_SECONDS):
                    logger.debug("OVH cache expired (age: %s)", age)
                    return None

            logger.debug("Loaded %d OVH instances from cache", len(instances))
            return instances

        except Exception as e:
            logger.error("Error reading OVH cache: %s", e)
            return None

    def _save_cache(self, instances: List[dict]) -> None:
        """Save OVH instances to local file cache with restricted permissions.

        Args:
            instances: List of instance dicts to cache.
        """
        try:
            _OVH_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'timestamp': datetime.now().isoformat(),
                'instances': instances,
            }
            # Write with 0o600 permissions so only the owner can read the cache
            fd = os.open(
                str(_OVH_CACHE_PATH),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug("Saved %d OVH instances to cache", len(instances))
        except Exception as e:
            logger.error("Error saving OVH cache: %s", e)

"""VPS lifecycle operations via OVHcloud API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

_VPS_NAME_RE = re.compile(r'^[a-zA-Z0-9._:/-]+$')
_IMAGE_ID_RE = re.compile(r'^[a-zA-Z0-9._:/-]+$')
_MODEL_RE = re.compile(r'^[a-zA-Z0-9._:/-]+$')
# Accepts IPv4 and IPv6 addresses used in VPS IP endpoints
_IP_RE = re.compile(r'^[a-fA-F0-9:.]+$')
# Reverse DNS hostname: RFC-1123 hostnames
_RDNS_RE = re.compile(r'^[a-zA-Z0-9._-]+$')


class OVHVPSService:
    """VPS lifecycle operations (reinstall, resize) via OVHcloud API."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        """Initialize VPS service.

        Args:
            ovh_service: Shared OVHService instance providing the API client.
        """
        self._ovh_service = ovh_service

    # ------------------------------------------------------------------
    # Image listing
    # ------------------------------------------------------------------

    async def list_images(self, vps_name: str) -> List[dict]:
        """List available OS images for a VPS.

        GET /vps/{serviceName}/availableImages

        Args:
            vps_name: VPS service name (e.g. "vps-abc123.ovh.net").

        Returns:
            List of dicts with keys: id, name, os_type.

        Raises:
            ValueError: If vps_name contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")

        client = self._ovh_service.client
        try:
            raw = await asyncio.to_thread(
                client.get, f"/vps/{vps_name}/availableImages"
            )
        except Exception as e:
            logger.error("Error listing VPS images for %s: %s", vps_name, e)
            return []

        if not raw:
            return []

        images = []
        for item in raw:
            if isinstance(item, str):
                # Some OVH endpoints return a list of IDs; fetch details per ID.
                try:
                    detail = await asyncio.to_thread(
                        client.get, f"/vps/{vps_name}/availableImages/{item}"
                    )
                    images.append({
                        'id': detail.get('id', item),
                        'name': detail.get('name', item),
                        'os_type': detail.get('os', ''),
                    })
                except Exception as e:
                    logger.warning("Could not fetch image detail for %s: %s", item, e)
                    images.append({'id': item, 'name': item, 'os_type': ''})
            elif isinstance(item, dict):
                images.append({
                    'id': item.get('id', ''),
                    'name': item.get('name', ''),
                    'os_type': item.get('os', item.get('os_type', '')),
                })

        return images

    # ------------------------------------------------------------------
    # Reinstall
    # ------------------------------------------------------------------

    async def reinstall(self, vps_name: str, image_id: str) -> bool:
        """Reinstall a VPS with a new OS image.

        POST /vps/{serviceName}/reinstall

        Args:
            vps_name: VPS service name.
            image_id: Image identifier returned by list_images().

        Returns:
            True if the reinstall request was accepted successfully.

        Raises:
            ValueError: If vps_name or image_id contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")
        if not _IMAGE_ID_RE.match(image_id):
            raise ValueError(f"Invalid image_id format: {image_id!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.post,
            f"/vps/{vps_name}/reinstall",
            imageId=image_id,
        )
        logger.info("VPS reinstall requested: vps=%s image=%s", vps_name, image_id)
        return True

    # ------------------------------------------------------------------
    # Upgrade / resize
    # ------------------------------------------------------------------

    async def list_upgrade_models(self, vps_name: str) -> List[dict]:
        """List available upgrade models for a VPS.

        GET /vps/{serviceName}/availableUpgrade

        Args:
            vps_name: VPS service name.

        Returns:
            List of dicts with keys: name, vcpus, ram, disk, price.

        Raises:
            ValueError: If vps_name contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")

        client = self._ovh_service.client
        try:
            raw = await asyncio.to_thread(
                client.get, f"/vps/{vps_name}/availableUpgrade"
            )
        except Exception as e:
            logger.error("Error listing VPS upgrade models for %s: %s", vps_name, e)
            return []

        if not raw:
            return []

        models = []
        for item in raw:
            if isinstance(item, str):
                models.append({
                    'name': item,
                    'vcpus': '',
                    'ram': '',
                    'disk': '',
                    'price': '',
                })
            elif isinstance(item, dict):
                models.append({
                    'name': item.get('name', ''),
                    'vcpus': item.get('vcores', item.get('vcpus', '')),
                    'ram': item.get('memory', item.get('ram', '')),
                    'disk': item.get('disk', ''),
                    'price': item.get('price', ''),
                })

        return models

    async def upgrade(self, vps_name: str, model: str) -> bool:
        """Upgrade a VPS to a new model/plan.

        POST /vps/{serviceName}/change

        Args:
            vps_name: VPS service name.
            model: Model name returned by list_upgrade_models().

        Returns:
            True if the upgrade request was accepted successfully.

        Raises:
            ValueError: If vps_name or model contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")
        if not _MODEL_RE.match(model):
            raise ValueError(f"Invalid model format: {model!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.post,
            f"/vps/{vps_name}/change",
            model=model,
        )
        logger.info("VPS upgrade requested: vps=%s model=%s", vps_name, model)
        return True

    # ------------------------------------------------------------------
    # IP details & reverse DNS
    # ------------------------------------------------------------------

    async def get_ip_details(self, vps_name: str, ip_address: str) -> dict:
        """Get details for a VPS IP including reverse DNS.

        GET /vps/{serviceName}/ips/{ipAddress}

        Args:
            vps_name: VPS service name.
            ip_address: IP address attached to the VPS.

        Returns:
            IP detail dict (includes ``reverse`` field), or empty dict on error.

        Raises:
            ValueError: If vps_name or ip_address contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")
        if not ip_address or not _IP_RE.match(ip_address):
            raise ValueError(f"Invalid ip_address format: {ip_address!r}")

        client = self._ovh_service.client
        try:
            return await asyncio.to_thread(
                client.get, f"/vps/{vps_name}/ips/{ip_address}"
            )
        except Exception as exc:
            logger.error(
                "Error fetching VPS IP details for %s/%s: %s",
                vps_name, ip_address, exc,
            )
            return {}

    async def set_reverse_dns(
        self, vps_name: str, ip_address: str, reverse: str
    ) -> bool:
        """Set or update reverse DNS for a VPS IP.

        PUT /vps/{serviceName}/ips/{ipAddress}

        Args:
            vps_name: VPS service name.
            ip_address: IP address attached to the VPS.
            reverse: Target hostname (e.g. ``"server.example.com"``).

        Returns:
            True on success.

        Raises:
            ValueError: If any argument contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")
        if not ip_address or not _IP_RE.match(ip_address):
            raise ValueError(f"Invalid ip_address format: {ip_address!r}")
        if not reverse or not _RDNS_RE.match(reverse):
            raise ValueError(f"Invalid reverse DNS hostname: {reverse!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.put, f"/vps/{vps_name}/ips/{ip_address}", reverse=reverse
        )
        logger.info(
            "VPS reverse DNS set: vps=%s ip=%s reverse=%s",
            vps_name, ip_address, reverse,
        )
        return True

    async def get_reverse_dns(self, vps_name: str, ip_address: str) -> Optional[str]:
        """Get the reverse DNS hostname for a VPS IP.

        Convenience wrapper around get_ip_details that returns only the
        ``reverse`` field.

        Args:
            vps_name: VPS service name.
            ip_address: IP address attached to the VPS.

        Returns:
            Reverse DNS hostname string, or None if not set or on error.
        """
        details = await self.get_ip_details(vps_name, ip_address)
        reverse = details.get("reverse") if details else None
        return reverse if reverse else None

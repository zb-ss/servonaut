"""Public Cloud instance lifecycle via OVHcloud API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

_INPUT_RE = re.compile(r'^[a-zA-Z0-9._:/-]+$')


def _validate(value: str, field: str) -> None:
    """Validate that a string field matches the allowed character set.

    Args:
        value: The value to validate.
        field: Field name used in the error message.

    Raises:
        ValueError: If value is empty or contains disallowed characters.
    """
    if not value or not _INPUT_RE.match(value):
        raise ValueError(f"Invalid {field} format: {value!r}")


class OVHCloudService:
    """Public Cloud instance lifecycle operations via OVHcloud API."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        """Initialize the Cloud service.

        Args:
            ovh_service: Shared OVHService instance providing the API client.
        """
        self._ovh_service = ovh_service

    # ------------------------------------------------------------------
    # Flavors
    # ------------------------------------------------------------------

    async def list_flavors(self, project_id: str, region: str = "") -> List[dict]:
        """List available instance flavors for a project.

        GET /cloud/project/{pid}/flavor

        Args:
            project_id: OVH Public Cloud project ID.
            region: Optional region filter (e.g. "GRA11"). Empty means all regions.

        Returns:
            List of dicts with keys: id, name, vcpus, ram, disk, region.

        Raises:
            ValueError: If project_id contains invalid characters.
        """
        _validate(project_id, "project_id")

        client = self._ovh_service.client
        try:
            raw: List[dict] = await asyncio.to_thread(
                client.get, f"/cloud/project/{project_id}/flavor"
            )
        except Exception as e:
            logger.error("Error listing flavors for project %s: %s", project_id, e)
            return []

        if not raw:
            return []

        flavors = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            flavor_region = item.get("region") or item.get("region_name") or ""
            if region and flavor_region != region:
                continue
            flavors.append({
                "id": item.get("id", ""),
                "name": item.get("name", ""),
                "vcpus": item.get("vcpus", 0),
                "ram": item.get("ram", 0),
                "disk": item.get("disk", 0),
                "region": flavor_region,
            })

        return flavors

    # ------------------------------------------------------------------
    # Images
    # ------------------------------------------------------------------

    async def list_images(self, project_id: str, region: str = "") -> List[dict]:
        """List available OS images for a project.

        GET /cloud/project/{pid}/image

        Args:
            project_id: OVH Public Cloud project ID.
            region: Optional region filter. Empty means all regions.

        Returns:
            List of dicts with keys: id, name, os_type, min_disk, region.

        Raises:
            ValueError: If project_id contains invalid characters.
        """
        _validate(project_id, "project_id")

        client = self._ovh_service.client
        try:
            raw: List[dict] = await asyncio.to_thread(
                client.get, f"/cloud/project/{project_id}/image"
            )
        except Exception as e:
            logger.error("Error listing images for project %s: %s", project_id, e)
            return []

        if not raw:
            return []

        images = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            image_region = item.get("region") or item.get("region_name") or ""
            if region and image_region != region:
                continue
            images.append({
                "id": item.get("id", ""),
                "name": item.get("name", ""),
                "os_type": item.get("type", item.get("os", "")),
                "min_disk": item.get("minDisk", item.get("min_disk", 0)),
                "region": image_region,
            })

        return images

    # ------------------------------------------------------------------
    # SSH Keys
    # ------------------------------------------------------------------

    async def list_ssh_keys(self, project_id: str) -> List[dict]:
        """List SSH keys registered in a project.

        GET /cloud/project/{pid}/sshkey

        Args:
            project_id: OVH Public Cloud project ID.

        Returns:
            List of dicts with keys: id, name, public_key, fingerprint.

        Raises:
            ValueError: If project_id contains invalid characters.
        """
        _validate(project_id, "project_id")

        client = self._ovh_service.client
        try:
            raw: List[dict] = await asyncio.to_thread(
                client.get, f"/cloud/project/{project_id}/sshkey"
            )
        except Exception as e:
            logger.error("Error listing SSH keys for project %s: %s", project_id, e)
            return []

        if not raw:
            return []

        keys = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            keys.append({
                "id": item.get("id", ""),
                "name": item.get("name", ""),
                "public_key": item.get("publicKey", ""),
                "fingerprint": item.get("fingerPrint", item.get("fingerprint", "")),
            })

        return keys

    async def add_ssh_key(
        self,
        project_id: str,
        name: str,
        public_key: str,
        region: str = "",
    ) -> dict:
        """Add an SSH key to a project.

        POST /cloud/project/{pid}/sshkey

        Args:
            project_id: OVH Public Cloud project ID.
            name: Display name for the key.
            public_key: Full SSH public key string.
            region: Optional region to associate the key with.

        Returns:
            Dict with keys: id, name, public_key, fingerprint.

        Raises:
            ValueError: If project_id or name contains invalid characters.
        """
        _validate(project_id, "project_id")
        _validate(name, "name")

        client = self._ovh_service.client
        kwargs: dict = {"name": name, "publicKey": public_key}
        if region:
            kwargs["region"] = region

        raw: dict = await asyncio.to_thread(
            client.post,
            f"/cloud/project/{project_id}/sshkey",
            **kwargs,
        )

        logger.info("SSH key added: project=%s name=%s", project_id, name)
        return {
            "id": raw.get("id", ""),
            "name": raw.get("name", ""),
            "public_key": raw.get("publicKey", ""),
            "fingerprint": raw.get("fingerPrint", raw.get("fingerprint", "")),
        }

    async def delete_ssh_key(self, project_id: str, key_id: str) -> bool:
        """Delete an SSH key from a project.

        DELETE /cloud/project/{pid}/sshkey/{keyId}

        Args:
            project_id: OVH Public Cloud project ID.
            key_id: SSH key identifier.

        Returns:
            True if the key was deleted successfully.

        Raises:
            ValueError: If project_id or key_id contains invalid characters.
        """
        _validate(project_id, "project_id")
        _validate(key_id, "key_id")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.delete,
            f"/cloud/project/{project_id}/sshkey/{key_id}",
        )

        logger.info("SSH key deleted: project=%s key_id=%s", project_id, key_id)
        return True

    # ------------------------------------------------------------------
    # Instance lifecycle
    # ------------------------------------------------------------------

    async def create_instance(
        self,
        project_id: str,
        name: str,
        flavor_id: str,
        image_id: str,
        region: str,
        ssh_key_id: str = "",
    ) -> dict:
        """Create a new Public Cloud instance.

        POST /cloud/project/{pid}/instance

        Args:
            project_id: OVH Public Cloud project ID.
            name: Display name for the new instance.
            flavor_id: Flavor (plan) identifier from list_flavors().
            image_id: OS image identifier from list_images().
            region: Region code where the instance will be created (e.g. "GRA11").
            ssh_key_id: Optional SSH key identifier from list_ssh_keys().

        Returns:
            Dict with keys: id, name, status, region, flavor_id, image_id.

        Raises:
            ValueError: If any validated parameter contains invalid characters.
        """
        _validate(project_id, "project_id")
        _validate(name, "name")
        _validate(flavor_id, "flavor_id")
        _validate(image_id, "image_id")
        _validate(region, "region")
        if ssh_key_id:
            _validate(ssh_key_id, "ssh_key_id")

        client = self._ovh_service.client
        kwargs: dict = {
            "name": name,
            "flavorId": flavor_id,
            "imageId": image_id,
            "region": region,
        }
        if ssh_key_id:
            kwargs["sshKeyId"] = ssh_key_id

        raw: dict = await asyncio.to_thread(
            client.post,
            f"/cloud/project/{project_id}/instance",
            **kwargs,
        )

        logger.info(
            "Cloud instance created: project=%s name=%s region=%s",
            project_id, name, region,
        )
        return {
            "id": raw.get("id", ""),
            "name": raw.get("name", ""),
            "status": raw.get("status", ""),
            "region": raw.get("region", region),
            "flavor_id": flavor_id,
            "image_id": image_id,
        }

    async def delete_instance(self, project_id: str, instance_id: str) -> bool:
        """Delete a Public Cloud instance.

        DELETE /cloud/project/{pid}/instance/{iid}

        Args:
            project_id: OVH Public Cloud project ID.
            instance_id: Instance identifier.

        Returns:
            True if the instance was deleted successfully.

        Raises:
            ValueError: If project_id or instance_id contains invalid characters.
        """
        _validate(project_id, "project_id")
        _validate(instance_id, "instance_id")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.delete,
            f"/cloud/project/{project_id}/instance/{instance_id}",
        )

        logger.info(
            "Cloud instance deleted: project=%s instance_id=%s",
            project_id, instance_id,
        )
        return True

    async def resize_instance(
        self,
        project_id: str,
        instance_id: str,
        flavor_id: str,
    ) -> dict:
        """Resize a Public Cloud instance to a different flavor.

        POST /cloud/project/{pid}/instance/{iid}/resize

        Args:
            project_id: OVH Public Cloud project ID.
            instance_id: Instance identifier.
            flavor_id: Target flavor identifier from list_flavors().

        Returns:
            Dict with keys: id, name, status, flavor_id.

        Raises:
            ValueError: If any validated parameter contains invalid characters.
        """
        _validate(project_id, "project_id")
        _validate(instance_id, "instance_id")
        _validate(flavor_id, "flavor_id")

        client = self._ovh_service.client
        raw: dict = await asyncio.to_thread(
            client.post,
            f"/cloud/project/{project_id}/instance/{instance_id}/resize",
            flavorId=flavor_id,
        )

        logger.info(
            "Cloud instance resized: project=%s instance_id=%s flavor_id=%s",
            project_id, instance_id, flavor_id,
        )
        return {
            "id": raw.get("id", instance_id),
            "name": raw.get("name", ""),
            "status": raw.get("status", ""),
            "flavor_id": flavor_id,
        }

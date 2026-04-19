"""Cloud block storage management via OVHcloud API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

_PROJECT_ID_RE = re.compile(r'^[a-zA-Z0-9._:/-]+$')
_VOLUME_ID_RE = re.compile(r'^[a-zA-Z0-9._:/-]+$')
_INSTANCE_ID_RE = re.compile(r'^[a-zA-Z0-9._:/-]+$')
_NAME_RE = re.compile(r'^[a-zA-Z0-9 ._:-]{1,64}$')
_REGION_RE = re.compile(r'^[a-zA-Z0-9-]+$')
_VOLUME_TYPE_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


class OVHStorageService:
    """Cloud block storage operations via OVHcloud Public Cloud API."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        """Initialize storage service.

        Args:
            ovh_service: Shared OVHService instance providing the API client.
        """
        self._ovh_service = ovh_service

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_project_id(project_id: str) -> None:
        if not project_id or not _PROJECT_ID_RE.match(project_id):
            raise ValueError(f"Invalid project_id: {project_id!r}")

    @staticmethod
    def _validate_volume_id(volume_id: str) -> None:
        if not volume_id or not _VOLUME_ID_RE.match(volume_id):
            raise ValueError(f"Invalid volume_id: {volume_id!r}")

    @staticmethod
    def _validate_instance_id(instance_id: str) -> None:
        if not instance_id or not _INSTANCE_ID_RE.match(instance_id):
            raise ValueError(f"Invalid instance_id: {instance_id!r}")

    @staticmethod
    def _validate_name(name: str) -> None:
        if not name or not _NAME_RE.match(name):
            raise ValueError(f"Invalid name: {name!r}")

    @staticmethod
    def _validate_region(region: str) -> None:
        if not region or not _REGION_RE.match(region):
            raise ValueError(f"Invalid region: {region!r}")

    @staticmethod
    def _validate_size(size_gb: int) -> None:
        if not isinstance(size_gb, int) or size_gb <= 0:
            raise ValueError(f"Invalid size_gb: {size_gb!r} — must be a positive integer")

    @staticmethod
    def _validate_volume_type(volume_type: str) -> None:
        if not volume_type or not _VOLUME_TYPE_RE.match(volume_type):
            raise ValueError(f"Invalid volume_type: {volume_type!r}")

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def list_volumes(self, project_id: str) -> List[dict]:
        """List all block storage volumes in a Public Cloud project.

        Args:
            project_id: OVH Public Cloud project identifier.

        Returns:
            List of volume dicts from the OVH API.
        """
        self._validate_project_id(project_id)
        client = self._ovh_service.client
        try:
            result = await asyncio.to_thread(
                client.get,
                f"/cloud/project/{project_id}/volume",
            )
            return result if result else []
        except Exception as exc:
            logger.error("list_volumes failed for project %s: %s", project_id, exc)
            return []

    async def create_volume(
        self,
        project_id: str,
        name: str,
        size_gb: int,
        region: str,
        volume_type: str = "classic",
    ) -> dict:
        """Create a new block storage volume.

        Args:
            project_id: OVH Public Cloud project identifier.
            name: Display name for the volume.
            size_gb: Desired volume size in gigabytes (must be > 0).
            region: OVH region (e.g. "GRA11", "BHS5").
            volume_type: Volume type ("classic" or "high-speed").

        Returns:
            New volume dict from the OVH API.

        Raises:
            ValueError: If any argument fails validation.
        """
        self._validate_project_id(project_id)
        self._validate_name(name)
        self._validate_size(size_gb)
        self._validate_region(region)
        self._validate_volume_type(volume_type)

        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.post,
            f"/cloud/project/{project_id}/volume",
            name=name,
            size=size_gb,
            region=region,
            type=volume_type,
        )
        return result

    async def delete_volume(self, project_id: str, volume_id: str) -> bool:
        """Delete a block storage volume.

        Args:
            project_id: OVH Public Cloud project identifier.
            volume_id: Volume identifier.

        Returns:
            True if the deletion request succeeded.

        Raises:
            ValueError: If project_id or volume_id is invalid.
        """
        self._validate_project_id(project_id)
        self._validate_volume_id(volume_id)

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.delete,
            f"/cloud/project/{project_id}/volume/{volume_id}",
        )
        return True

    async def attach_volume(
        self, project_id: str, volume_id: str, instance_id: str
    ) -> dict:
        """Attach a volume to a cloud instance.

        Args:
            project_id: OVH Public Cloud project identifier.
            volume_id: Volume identifier.
            instance_id: Target instance identifier.

        Returns:
            Attachment result dict from the OVH API.

        Raises:
            ValueError: If any identifier is invalid.
        """
        self._validate_project_id(project_id)
        self._validate_volume_id(volume_id)
        self._validate_instance_id(instance_id)

        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.post,
            f"/cloud/project/{project_id}/volume/{volume_id}/attach",
            instanceId=instance_id,
        )
        return result

    async def detach_volume(
        self, project_id: str, volume_id: str, instance_id: str
    ) -> dict:
        """Detach a volume from a cloud instance.

        Args:
            project_id: OVH Public Cloud project identifier.
            volume_id: Volume identifier.
            instance_id: Instance to detach from.

        Returns:
            Detachment result dict from the OVH API.

        Raises:
            ValueError: If any identifier is invalid.
        """
        self._validate_project_id(project_id)
        self._validate_volume_id(volume_id)
        self._validate_instance_id(instance_id)

        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.post,
            f"/cloud/project/{project_id}/volume/{volume_id}/detach",
            instanceId=instance_id,
        )
        return result

    async def create_volume_snapshot(
        self, project_id: str, volume_id: str, name: str
    ) -> dict:
        """Create a snapshot of a block storage volume.

        Args:
            project_id: OVH Public Cloud project identifier.
            volume_id: Volume identifier.
            name: Display name for the snapshot.

        Returns:
            Snapshot dict from the OVH API.

        Raises:
            ValueError: If any argument fails validation.
        """
        self._validate_project_id(project_id)
        self._validate_volume_id(volume_id)
        self._validate_name(name)

        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.post,
            f"/cloud/project/{project_id}/volume/{volume_id}/snapshot",
            name=name,
        )
        return result

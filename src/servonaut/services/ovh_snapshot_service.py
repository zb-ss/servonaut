"""Snapshot and backup management via OVHcloud API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

_VPS_NAME_RE = re.compile(r'^[\w\-.]+$')          # no slashes — rejects path traversal
_SNAPSHOT_ID_RE = re.compile(r'^[a-zA-Z0-9._:-]+$')
_PROJECT_ID_RE = re.compile(r'^[a-zA-Z0-9._:-]+$')
_INSTANCE_ID_RE = re.compile(r'^[a-zA-Z0-9._:-]+$')
_SNAPSHOT_NAME_RE = re.compile(r'^[a-zA-Z0-9._: -]+$')
_SCHEDULE_RE = re.compile(r'^[a-zA-Z0-9 */-]+$')
_RESTORE_POINT_RE = re.compile(r'^[a-zA-Z0-9._:T+Z-]+$')


class OVHSnapshotService:
    """Snapshot and backup management for OVH VPS and Public Cloud instances."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        """Initialize snapshot service.

        Args:
            ovh_service: Shared OVHService instance providing the API client.
        """
        self._ovh_service = ovh_service

    # ------------------------------------------------------------------
    # VPS Snapshots
    # ------------------------------------------------------------------

    async def list_vps_snapshots(self, vps_name: str) -> List[dict]:
        """List snapshots for a VPS.

        GET /vps/{serviceName}/snapshot

        Args:
            vps_name: VPS service name (e.g. "vps-abc123.ovh.net").

        Returns:
            List of snapshot detail dicts. Empty list on error.

        Raises:
            ValueError: If vps_name contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")

        client = self._ovh_service.client
        try:
            raw = await asyncio.to_thread(
                client.get, f"/vps/{vps_name}/snapshot"
            )
        except Exception as e:
            logger.error("Error listing VPS snapshots for %s: %s", vps_name, e)
            return []

        if not raw:
            return []

        # Normalise: API may return a list of IDs or a list of dicts
        snapshots = []
        for item in raw:
            if isinstance(item, dict):
                snapshots.append(item)
            elif isinstance(item, str):
                snapshots.append({'id': item, 'name': item})

        return snapshots

    async def create_vps_snapshot(self, vps_name: str, description: str = "") -> dict:
        """Create a snapshot for a VPS.

        POST /vps/{serviceName}/createSnapshot

        Args:
            vps_name: VPS service name.
            description: Optional snapshot description.

        Returns:
            Task dict returned by OVH API.

        Raises:
            ValueError: If vps_name contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")

        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.post,
            f"/vps/{vps_name}/createSnapshot",
            description=description,
        )
        logger.info("VPS snapshot creation requested: vps=%s", vps_name)
        return result or {}

    async def restore_vps_snapshot(self, vps_name: str, snapshot_id: str) -> bool:
        """Restore a VPS from a snapshot.

        POST /vps/{serviceName}/snapshot/{snapshotId}/revert

        Args:
            vps_name: VPS service name.
            snapshot_id: Snapshot identifier.

        Returns:
            True if the revert request was accepted.

        Raises:
            ValueError: If inputs contain invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")
        if not _SNAPSHOT_ID_RE.match(snapshot_id):
            raise ValueError(f"Invalid snapshot_id format: {snapshot_id!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.post,
            f"/vps/{vps_name}/snapshot/{snapshot_id}/revert",
        )
        logger.info("VPS snapshot revert requested: vps=%s snapshot=%s", vps_name, snapshot_id)
        return True

    async def delete_vps_snapshot(self, vps_name: str) -> bool:
        """Delete the current snapshot for a VPS.

        DELETE /vps/{serviceName}/snapshot

        Args:
            vps_name: VPS service name.

        Returns:
            True if the deletion request was accepted.

        Raises:
            ValueError: If vps_name contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.delete, f"/vps/{vps_name}/snapshot"
        )
        logger.info("VPS snapshot deleted: vps=%s", vps_name)
        return True

    # ------------------------------------------------------------------
    # VPS Automated Backups
    # ------------------------------------------------------------------

    async def get_vps_backup_options(self, vps_name: str) -> dict:
        """Get automated backup configuration for a VPS.

        GET /vps/{serviceName}/automatedBackup

        Args:
            vps_name: VPS service name.

        Returns:
            Backup options dict. Empty dict on error.

        Raises:
            ValueError: If vps_name contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")

        client = self._ovh_service.client
        try:
            raw = await asyncio.to_thread(
                client.get, f"/vps/{vps_name}/automatedBackup"
            )
        except Exception as e:
            logger.error("Error fetching VPS backup options for %s: %s", vps_name, e)
            return {}

        return raw if isinstance(raw, dict) else {}

    async def configure_vps_backup(self, vps_name: str, schedule: str) -> bool:
        """Configure automated backup schedule for a VPS.

        POST /vps/{serviceName}/automatedBackup

        Args:
            vps_name: VPS service name.
            schedule: Cron-style schedule string.

        Returns:
            True if the configuration was accepted.

        Raises:
            ValueError: If inputs contain invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")
        if not schedule or not _SCHEDULE_RE.match(schedule):
            raise ValueError(f"Invalid schedule format: {schedule!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.post,
            f"/vps/{vps_name}/automatedBackup",
            schedule=schedule,
        )
        logger.info("VPS backup configured: vps=%s schedule=%s", vps_name, schedule)
        return True

    async def list_vps_backups(self, vps_name: str) -> List[dict]:
        """List attached automated backups for a VPS.

        GET /vps/{serviceName}/automatedBackup/attachedBackup

        Args:
            vps_name: VPS service name.

        Returns:
            List of backup dicts. Empty list on error.

        Raises:
            ValueError: If vps_name contains invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")

        client = self._ovh_service.client
        try:
            raw = await asyncio.to_thread(
                client.get, f"/vps/{vps_name}/automatedBackup/attachedBackup"
            )
        except Exception as e:
            logger.error("Error listing VPS backups for %s: %s", vps_name, e)
            return []

        if not raw:
            return []

        backups = []
        for item in raw:
            if isinstance(item, dict):
                backups.append(item)
            elif isinstance(item, str):
                backups.append({'restore_point': item})

        return backups

    async def restore_vps_backup(self, vps_name: str, restore_point: str) -> bool:
        """Restore a VPS from an automated backup restore point.

        POST /vps/{serviceName}/automatedBackup/restore

        Args:
            vps_name: VPS service name.
            restore_point: ISO 8601 timestamp string identifying the restore point.

        Returns:
            True if the restore request was accepted.

        Raises:
            ValueError: If inputs contain invalid characters.
        """
        if not _VPS_NAME_RE.match(vps_name):
            raise ValueError(f"Invalid vps_name format: {vps_name!r}")
        if not restore_point or not _RESTORE_POINT_RE.match(restore_point):
            raise ValueError(f"Invalid restore_point format: {restore_point!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.post,
            f"/vps/{vps_name}/automatedBackup/restore",
            restorePoint=restore_point,
        )
        logger.info("VPS backup restore requested: vps=%s restore_point=%s", vps_name, restore_point)
        return True

    # ------------------------------------------------------------------
    # Cloud Snapshots
    # ------------------------------------------------------------------

    async def list_cloud_snapshots(self, project_id: str) -> List[dict]:
        """List snapshots for an OVH Public Cloud project.

        GET /cloud/project/{serviceId}/snapshot

        Args:
            project_id: Public Cloud project identifier.

        Returns:
            List of snapshot dicts. Empty list on error.

        Raises:
            ValueError: If project_id contains invalid characters.
        """
        if not _PROJECT_ID_RE.match(project_id):
            raise ValueError(f"Invalid project_id format: {project_id!r}")

        client = self._ovh_service.client
        try:
            raw = await asyncio.to_thread(
                client.get, f"/cloud/project/{project_id}/snapshot"
            )
        except Exception as e:
            logger.error("Error listing cloud snapshots for project %s: %s", project_id, e)
            return []

        if not raw:
            return []

        return [item for item in raw if isinstance(item, dict)]

    async def create_cloud_snapshot(
        self,
        project_id: str,
        instance_id: str,
        snapshot_name: str,
    ) -> dict:
        """Create a snapshot of a Public Cloud instance.

        POST /cloud/project/{serviceId}/instance/{instanceId}/snapshot

        Args:
            project_id: Public Cloud project identifier.
            instance_id: Instance identifier.
            snapshot_name: Name for the new snapshot.

        Returns:
            Task or snapshot dict from OVH API.

        Raises:
            ValueError: If inputs contain invalid characters.
        """
        if not _PROJECT_ID_RE.match(project_id):
            raise ValueError(f"Invalid project_id format: {project_id!r}")
        if not _INSTANCE_ID_RE.match(instance_id):
            raise ValueError(f"Invalid instance_id format: {instance_id!r}")
        if not snapshot_name or not _SNAPSHOT_NAME_RE.match(snapshot_name):
            raise ValueError(f"Invalid snapshot_name format: {snapshot_name!r}")

        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.post,
            f"/cloud/project/{project_id}/instance/{instance_id}/snapshot",
            snapshotName=snapshot_name,
        )
        logger.info(
            "Cloud snapshot creation requested: project=%s instance=%s name=%s",
            project_id, instance_id, snapshot_name,
        )
        return result or {}

    async def delete_cloud_snapshot(self, project_id: str, snapshot_id: str) -> bool:
        """Delete a Public Cloud snapshot.

        DELETE /cloud/project/{serviceId}/snapshot/{snapshotId}

        Args:
            project_id: Public Cloud project identifier.
            snapshot_id: Snapshot identifier to delete.

        Returns:
            True if the deletion request was accepted.

        Raises:
            ValueError: If inputs contain invalid characters.
        """
        if not _PROJECT_ID_RE.match(project_id):
            raise ValueError(f"Invalid project_id format: {project_id!r}")
        if not _SNAPSHOT_ID_RE.match(snapshot_id):
            raise ValueError(f"Invalid snapshot_id format: {snapshot_id!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.delete,
            f"/cloud/project/{project_id}/snapshot/{snapshot_id}",
        )
        logger.info(
            "Cloud snapshot deleted: project=%s snapshot=%s",
            project_id, snapshot_id,
        )
        return True

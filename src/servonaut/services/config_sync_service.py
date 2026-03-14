"""Cloud config synchronization service."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .interfaces import ConfigSyncServiceInterface

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.config.manager import ConfigManager

logger = logging.getLogger(__name__)

# Fields to strip before uploading (contain secrets or machine-specific paths)
SENSITIVE_FIELDS = {
    "ai_provider.api_key",
    "abuseipdb_api_key",
}

# Fields that are machine-specific and shouldn't sync
LOCAL_ONLY_FIELDS = {
    "instance_keys",
    "keyword_store_path",
    "command_history_path",
    "ip_ban_audit_path",
    "chat_history_path",
}


class ConfigSyncService(ConfigSyncServiceInterface):
    """Sync configuration to/from servonaut.dev cloud."""

    def __init__(self, api_client: 'APIClient', config_manager: 'ConfigManager') -> None:
        self._api = api_client
        self._config_manager = config_manager

    async def push(self) -> dict:
        """Push local config to cloud. Returns version info."""
        config = self._config_manager.get()
        config_data = self._strip_sensitive(asdict(config))
        config_hash = self._compute_hash(config_data)

        result = await self._api.post("/api/v1/configs/snapshots", {
            "config_data": config_data,
            "config_hash": config_hash,
        })
        logger.info("Config pushed, version: %s", result.get("version"))
        return result

    async def pull(self) -> dict:
        """Pull latest config from cloud. Returns config data and metadata."""
        result = await self._api.get("/api/v1/configs/snapshots/latest")
        return result

    async def list_snapshots(self, limit: int = 30) -> List[dict]:
        """List available config snapshots."""
        result = await self._api.get(f"/api/v1/configs/snapshots?limit={limit}")
        return result.get("snapshots", [])

    async def restore(self, version: int) -> dict:
        """Restore config from a specific version."""
        result = await self._api.get(f"/api/v1/configs/snapshots/{version}")
        return result

    def apply_remote_config(self, remote_data: dict) -> None:
        """Apply remote config data to local config, preserving local-only fields."""
        config = self._config_manager.get()
        current = asdict(config)

        # Preserve local-only fields
        for field_name in LOCAL_ONLY_FIELDS:
            if field_name in current:
                remote_data[field_name] = current[field_name]

        # Preserve sensitive fields that are empty in remote
        for field_path in SENSITIVE_FIELDS:
            parts = field_path.split(".")
            remote_val = remote_data
            current_val = current
            for part in parts[:-1]:
                remote_val = remote_val.get(part, {})
                current_val = current_val.get(part, {})
            last_key = parts[-1]
            if isinstance(remote_val, dict) and not remote_val.get(last_key):
                if isinstance(current_val, dict) and current_val.get(last_key):
                    remote_val[last_key] = current_val[last_key]

        # Reload via config manager's deserialize
        new_config = self._config_manager._deserialize(remote_data)
        self._config_manager.save(new_config)
        logger.info("Remote config applied")

    def compute_local_hash(self) -> str:
        """Compute hash of current local config for conflict detection."""
        config = self._config_manager.get()
        config_data = self._strip_sensitive(asdict(config))
        return self._compute_hash(config_data)

    def diff(self, remote_data: dict) -> Dict[str, Any]:
        """Compare remote config with local. Returns dict of changed fields."""
        config = self._config_manager.get()
        local_data = self._strip_sensitive(asdict(config))
        remote_clean = self._strip_sensitive(remote_data)

        changes: Dict[str, Any] = {}
        all_keys = set(local_data.keys()) | set(remote_clean.keys())
        for key in all_keys:
            if key in LOCAL_ONLY_FIELDS:
                continue
            local_val = local_data.get(key)
            remote_val = remote_clean.get(key)
            if local_val != remote_val:
                changes[key] = {"local": local_val, "remote": remote_val}

        return changes

    def _strip_sensitive(self, config_data: dict) -> dict:
        """Remove sensitive and local-only fields from config data."""
        data = dict(config_data)

        # Remove local-only fields
        for field_name in LOCAL_ONLY_FIELDS:
            data.pop(field_name, None)

        # Mask sensitive fields
        for field_path in SENSITIVE_FIELDS:
            parts = field_path.split(".")
            obj = data
            for part in parts[:-1]:
                obj = obj.get(part, {})
            if isinstance(obj, dict):
                obj.pop(parts[-1], None)

        return data

    def _compute_hash(self, config_data: dict) -> str:
        """Compute deterministic hash of config data."""
        serialized = json.dumps(config_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]

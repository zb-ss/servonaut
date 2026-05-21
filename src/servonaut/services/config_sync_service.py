"""Cloud config synchronization service."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import stat
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .interfaces import ConfigSyncServiceInterface
from . import config_crypto

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.config.manager import ConfigManager

logger = logging.getLogger(__name__)

# Secrets that must never leave the device in plaintext form.
# These are stripped before upload AND preserved locally on pull if remote is empty.
SENSITIVE_FIELDS = {
    "ai_provider.api_key",
    "ai_provider.openai_api_key",
    "ai_provider.anthropic_api_key",
    "ai_provider.gemini_api_key",
    "ai_provider.ollama_api_key",
    "abuseipdb_api_key",
    "ovh.application_key",
    "ovh.application_secret",
    "ovh.consumer_key",
    "ovh.client_id",
    "ovh.client_secret",
    "hetzner.api_token",
    # Object-storage S3 credentials — stripped before upload so a leaked
    # passphrase + ciphertext cannot expose live bucket credentials.
    "aws.object_storage.access_key",
    "aws.object_storage.secret_key",
    "ovh.object_storage.access_key",
    "ovh.object_storage.secret_key",
    "hetzner.object_storage.access_key",
    "hetzner.object_storage.secret_key",
}

# Machine-specific fields that shouldn't sync (always kept from local).
LOCAL_ONLY_FIELDS = {
    "instance_keys",
    "keyword_store_path",
    "command_history_path",
    "ip_ban_audit_path",
    "chat_history_path",
}

# User-generated lists that ARE pushed (so they sync) but must be preserved
# locally if the remote snapshot has them empty/missing. This prevents an
# older or empty snapshot from wiping real user data on pull.
PRESERVE_ON_EMPTY_FIELDS = {
    "custom_servers",
    "scan_rules",
    "connection_profiles",
    "connection_rules",
    "ip_ban_configs",
}

PROBE_FILE = Path.home() / ".servonaut" / "sync_key_probe.json"
DEFAULT_SNAPSHOT_NAME = "servonaut-cli"


class ConfigSyncService(ConfigSyncServiceInterface):
    """Sync configuration to/from servonaut.dev cloud."""

    def __init__(self, api_client: 'APIClient', config_manager: 'ConfigManager') -> None:
        self._api = api_client
        self._config_manager = config_manager
        self._cached_passphrase: Optional[str] = None

    async def push(
        self,
        passphrase: Optional[str] = None,
        label: Optional[str] = None,
    ) -> dict:
        """Push local config to cloud as an encrypted snapshot.

        Args:
            passphrase: Sync passphrase. Falls back to cached value.
            label: Human-readable device/snapshot label. Defaults to hostname.

        Returns:
            Server response (version, id, label, etc.).

        Raises:
            ValueError: If no passphrase is available.
            CryptoUnavailableError: If cryptography package is missing.
        """
        effective_passphrase = passphrase or self._cached_passphrase
        if not effective_passphrase:
            raise ValueError("Sync passphrase required")

        effective_label = self._sanitize_label(label) or socket.gethostname() or DEFAULT_SNAPSHOT_NAME

        config = self._config_manager.get()
        config_data = self._strip_sensitive(asdict(config))
        data_json = json.dumps(config_data, sort_keys=True, default=str)
        data_hash = hashlib.sha256(data_json.encode()).hexdigest()

        enc = config_crypto.encrypt(data_json, effective_passphrase)
        payload = {
            "name": DEFAULT_SNAPSHOT_NAME,
            "label": effective_label,
            "data": enc["data"],
            "hash": data_hash,
            "encryption": enc["encryption"],
            "salt": enc["salt"],
            "iv": enc["iv"],
            "tag": enc["tag"],
        }
        result = await self._api.post("/api/v1/configs", json=payload)
        self._cached_passphrase = effective_passphrase
        self._save_probe(effective_passphrase)
        logger.info("Config pushed (encrypted), version: %s, label: %s",
                    result.get("version"), effective_label)
        return result

    async def pull(self, passphrase: Optional[str] = None) -> dict:
        """Pull and decrypt the latest snapshot."""
        result = await self._api.get("/api/v1/configs/latest")
        return self._decrypt_snapshot(result, passphrase)

    async def list_snapshots(self, limit: int = 30) -> List[dict]:
        """List available config snapshots (metadata only, no ciphertext)."""
        result = await self._api.get(f"/api/v1/configs?limit={limit}")
        return result.get("snapshots", [])

    async def restore(self, version: int, passphrase: Optional[str] = None) -> dict:
        """Restore config from a specific version.

        `version` is accepted for compatibility with the service interface — the
        backend endpoint actually takes a snapshot id. When version looks like
        an integer we try both forms so callers can use either.
        """
        result = await self._api.get(f"/api/v1/configs/{version}")
        return self._decrypt_snapshot(result, passphrase)

    async def restore_by_id(self, snapshot_id: str, passphrase: Optional[str] = None) -> dict:
        """Restore config by snapshot id (preferred for the snapshot manager)."""
        result = await self._api.get(f"/api/v1/configs/{snapshot_id}")
        return self._decrypt_snapshot(result, passphrase)


    async def rename_snapshot(self, snapshot_id: str, label: str) -> dict:
        """Rename a snapshot server-side. Label is plaintext by design."""
        clean = self._sanitize_label(label)
        if not clean:
            raise ValueError("Label cannot be empty")
        return await self._api.patch(f"/api/v1/configs/{snapshot_id}", json={"label": clean})

    async def delete_snapshot(self, snapshot_id: str) -> dict:
        """Delete a snapshot server-side."""
        return await self._api.delete(f"/api/v1/configs/{snapshot_id}")

    def _decrypt_snapshot(self, result: dict, passphrase: Optional[str]) -> dict:
        """Decrypt a full-envelope response and return the parsed config dict."""
        if not result.get("encryption"):
            raise config_crypto.DecryptionError(
                "Snapshot is missing the client-encryption envelope. Delete it "
                "and push a fresh one."
            )

        effective_passphrase = passphrase or self._cached_passphrase
        if not effective_passphrase:
            raise ValueError("Sync passphrase required")

        probe_hex = self._load_probe()
        if probe_hex is not None and not config_crypto.verify_probe(effective_passphrase, probe_hex):
            raise config_crypto.DecryptionError("Decryption failed - wrong passphrase or corrupted data")

        plaintext = config_crypto.decrypt(result, effective_passphrase)
        self._cached_passphrase = effective_passphrase
        return json.loads(plaintext)

    @staticmethod
    def _sanitize_label(label: Optional[str]) -> str:
        """Trim whitespace and strip control chars. Max 100 chars."""
        if not label:
            return ""
        cleaned = "".join(ch for ch in label.strip() if ch.isprintable() or ch == " ")
        return cleaned[:100]

    def apply_remote_config(self, remote_data: dict) -> None:
        """Apply remote config data to local config.

        Preservation rules:
        - LOCAL_ONLY_FIELDS: always keep local value (never sync)
        - SENSITIVE_FIELDS (secrets): keep local value if remote is empty/missing
        - PRESERVE_ON_EMPTY_FIELDS (user-data lists): keep local value if remote
          is empty/missing — prevents an older snapshot from wiping real data
        """
        config = self._config_manager.get()
        current = asdict(config)

        # Always-local fields
        for field_name in LOCAL_ONLY_FIELDS:
            if field_name in current:
                remote_data[field_name] = current[field_name]

        # Preserve sensitive (nested) fields that are empty in remote
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

        # Preserve top-level user-data lists that are empty in remote
        for field_name in PRESERVE_ON_EMPTY_FIELDS:
            remote_val = remote_data.get(field_name)
            current_val = current.get(field_name)
            # Treat missing/None/empty-list/empty-dict as "empty"
            if not remote_val and current_val:
                remote_data[field_name] = current_val

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

    def clear_session(self) -> None:
        """Clear the in-memory cached passphrase on logout."""
        self._cached_passphrase = None

    def has_probe(self) -> bool:
        """Return True if a sync passphrase probe is stored locally."""
        return self._load_probe() is not None

    def _save_probe(self, passphrase: str) -> None:
        """Write a passphrase probe to disk for fast pre-flight verification.

        Uses os.open with O_CREAT|O_TRUNC and mode 0o600 so the file is never
        world-readable, even briefly. The umask is bypassed explicitly.
        """
        try:
            PROBE_FILE.parent.mkdir(parents=True, exist_ok=True)
            probe_hex = config_crypto.make_probe(passphrase)
            payload = json.dumps({"probe": probe_hex, "version": 1})
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            mode = stat.S_IRUSR | stat.S_IWUSR
            fd = os.open(str(PROBE_FILE), flags, mode)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
            except Exception:
                os.close(fd)
                raise
            # Pre-existing files preserve their old mode after O_CREAT; re-apply.
            PROBE_FILE.chmod(mode)
        except Exception as exc:
            logger.warning("Could not save sync key probe: %s", exc)

    def _load_probe(self) -> Optional[str]:
        """Load the probe hex from disk, or return None if absent/malformed."""
        try:
            raw = PROBE_FILE.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                return None
            if data.get("version") != 1:
                return None
            probe = data.get("probe")
            if not isinstance(probe, str) or len(probe) != 64:
                return None
            # Defense-in-depth: reject non-hex garbage to avoid silent lockout
            # via hmac.compare_digest never matching.
            try:
                bytes.fromhex(probe)
            except ValueError:
                return None
            return probe
        except Exception:
            return None

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

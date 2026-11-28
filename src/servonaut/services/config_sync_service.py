"""Cloud config synchronization service."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import logging
import os
import socket
import stat
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, TYPE_CHECKING

from .interfaces import ConfigSyncServiceInterface
from . import config_crypto

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.config.manager import ConfigManager
    from servonaut.services.vault.app_keys import AppKeyItems

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
    # Extra provider accounts. "[]" means "in every entry of this list"; on
    # pull, entries are matched to local ones by label.
    "ovh.accounts[].application_key",
    "ovh.accounts[].application_secret",
    "ovh.accounts[].consumer_key",
    "ovh.accounts[].client_id",
    "ovh.accounts[].client_secret",
    "ovh.accounts[].object_storage.access_key",
    "ovh.accounts[].object_storage.secret_key",
    "hetzner.accounts[].api_token",
    "hetzner.accounts[].object_storage.access_key",
    "hetzner.accounts[].object_storage.secret_key",
}

# Key that identifies an entry of a list-scoped secret path across devices.
_LIST_ENTRY_IDENTITY = "label"

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
    # A snapshot pushed by a release without extra accounts has none; pulling
    # it must not delete the accounts configured on this device.
    "aws.accounts",
    "hetzner.accounts",
    "ovh.accounts",
}


def _get_path(data: Any, parts: List[str]) -> Any:
    """Value at a dotted path of plain dict keys, or None."""
    for part in parts:
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _parents(data: Any, parts: List[str]):
    """Every dict that holds the leaf of *parts* (the path minus its leaf).

    A segment ending in ``[]`` fans out over each dict in that list.
    """
    if not parts:
        if isinstance(data, dict):
            yield data
        return
    head, rest = parts[0], parts[1:]
    if not isinstance(data, dict):
        return
    if head.endswith("[]"):
        items = data.get(head[:-2])
        if isinstance(items, list):
            for item in items:
                yield from _parents(item, rest)
        return
    yield from _parents(data.get(head), rest)


def _materialise(data: dict, parts: List[str]) -> dict:
    """The dict at *parts* inside *data*, creating empty dicts on the way."""
    cursor = data
    for part in parts:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[part] = nxt
        cursor = nxt
    return cursor


def _identity(entry: Any) -> Optional[str]:
    """Case-insensitive identity of a list entry, or None without one."""
    if not isinstance(entry, dict):
        return None
    value = entry.get(_LIST_ENTRY_IDENTITY)
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower()

PROBE_FILE = Path.home() / ".servonaut" / "sync_key_probe.json"
DEFAULT_SNAPSHOT_NAME = "servonaut-cli"
CONFIG_KEY_ITEM = "config_sync_key"
CONFIG_KEY_NAME = "Servonaut config sync key"


class ConfigKeyError(config_crypto.DecryptionError):
    """A vault-key problem with the client's own text; ``code`` names the case."""

    def __init__(self, code: str, fallback: str = "The config sync key is not available.") -> None:
        from servonaut.services.memory.custody_errors import custody_code_message

        super().__init__(custody_code_message(code) or fallback)
        self.code = code


_UNKNOWN_KEY_TEXT = (
    "This snapshot was sealed with a vault key that is not in your vault. "
    "Unlock your vault or add this device to it, then try again."
)

KeyItemsProvider = Callable[[], Optional["AppKeyItems"]]


class ConfigSyncService(ConfigSyncServiceInterface):
    """Sync configuration to/from servonaut.dev cloud."""

    def __init__(
        self,
        api_client: 'APIClient',
        config_manager: 'ConfigManager',
        key_items_provider: Optional[KeyItemsProvider] = None,
    ) -> None:
        self._api = api_client
        self._config_manager = config_manager
        # Returns the vault's AppKeyItems, or None while the vault is absent or locked.
        self._key_items_provider = key_items_provider
        self._cached_passphrase: Optional[str] = None

    # -- key custody ---------------------------------------------------

    def _key_items(self) -> Optional["AppKeyItems"]:
        if self._key_items_provider is None:
            return None
        return self._key_items_provider()

    async def key_mode(self) -> str:
        """``"vault"`` or ``"passphrase"``: where the snapshot key is kept.

        Vault when a ``config_sync_key`` item exists, or when the vault is
        ready and the account has no passphrase snapshot and no local probe
        (a new user); passphrase otherwise.
        """
        items = self._key_items()
        if items is None:
            return "passphrase"
        if await items.list(CONFIG_KEY_ITEM):
            return "vault"
        if self.has_probe():
            return "passphrase"
        snapshots = await self.list_snapshots()
        if any(snap.get("key_custody") != "vault" for snap in snapshots):
            return "passphrase"
        return "vault"

    async def _vault_keys(self, items: "AppKeyItems") -> List[Dict[str, Any]]:
        """Payloads of the live config sync key items, newest first."""
        payloads = []
        for ref in await items.list(CONFIG_KEY_ITEM):
            payload = await items.read(CONFIG_KEY_ITEM, ref.public_fingerprint)
            if payload is not None:
                payloads.append(payload)
        payloads.sort(key=lambda p: str(p.get("created_at", "")), reverse=True)
        return payloads

    async def _ensure_vault_key(self, items: "AppKeyItems") -> Dict[str, Any]:
        """The current key payload; created and read back on first use."""
        existing = await self._vault_keys(items)
        if existing:
            return existing[0]
        key = config_crypto.generate_key()
        try:
            payload = {
                "v": 1,
                "name": CONFIG_KEY_NAME,
                "key": base64.b64encode(bytes(key)).decode(),
                "public_fingerprint": config_crypto.key_id(bytes(key)),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            await items.create(CONFIG_KEY_ITEM, payload)
            read_back = await items.read(CONFIG_KEY_ITEM, payload["public_fingerprint"])
            if read_back is None or read_back.get("key") != payload["key"]:
                raise ConfigKeyError("config_key_not_ready")
            return payload
        finally:
            for i in range(len(key)):
                key[i] = 0

    async def _decrypt_vault(self, result: dict) -> dict:
        items = self._key_items()
        if items is None:
            raise ConfigKeyError("config_key_not_ready")
        wanted = result.get("key_id")
        for payload in await self._vault_keys(items):
            if payload.get("public_fingerprint") != wanted:
                continue
            key = bytearray(base64.b64decode(payload["key"]))
            try:
                return json.loads(config_crypto.decrypt_with_key(result, key))
            finally:
                for i in range(len(key)):
                    key[i] = 0
        raise config_crypto.DecryptionError(_UNKNOWN_KEY_TEXT)

    def has_cached_passphrase(self) -> bool:
        """True when a sync passphrase is held in memory for this session."""
        return bool(self._cached_passphrase)

    def _snapshot_payload(self, label: Optional[str]) -> tuple:
        effective_label = self._sanitize_label(label) or socket.gethostname() or DEFAULT_SNAPSHOT_NAME
        config = self._config_manager.get()
        config_data = self._strip_sensitive(asdict(config))
        data_json = json.dumps(config_data, sort_keys=True, default=str)
        return effective_label, data_json, hashlib.sha256(data_json.encode()).hexdigest()

    async def push(
        self,
        passphrase: Optional[str] = None,
        label: Optional[str] = None,
    ) -> dict:
        """Push local config to cloud as an encrypted snapshot.

        In vault mode the key comes from the vault and no passphrase is used.

        Args:
            passphrase: Sync passphrase. Falls back to cached value.
            label: Human-readable device/snapshot label. Defaults to hostname.

        Returns:
            Server response (version, id, label, etc.).

        Raises:
            ValueError: If no passphrase is available (passphrase mode).
            CryptoUnavailableError: If cryptography package is missing.
        """
        if await self.key_mode() == "vault":
            return await self._push_vault(label)

        effective_passphrase = passphrase or self._cached_passphrase
        if not effective_passphrase:
            raise ValueError("Sync passphrase required")

        effective_label, data_json, data_hash = self._snapshot_payload(label)

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

    async def _push_vault(self, label: Optional[str]) -> dict:
        items = self._key_items()
        if items is None:
            raise ConfigKeyError("config_key_not_ready")
        key_payload = await self._ensure_vault_key(items)
        effective_label, data_json, data_hash = self._snapshot_payload(label)
        key = bytearray(base64.b64decode(key_payload["key"]))
        try:
            enc = config_crypto.encrypt_with_key(data_json, key)
        finally:
            for i in range(len(key)):
                key[i] = 0
        payload = {
            "name": DEFAULT_SNAPSHOT_NAME,
            "label": effective_label,
            "data": enc["data"],
            "hash": data_hash,
            "encryption": enc["encryption"],
            "iv": enc["iv"],
            "tag": enc["tag"],
            "key_custody": "vault",
            "key_id": key_payload["public_fingerprint"],
        }
        result = await self._api.post("/api/v1/configs", json=payload)
        logger.info("Config pushed (vault key), version: %s, label: %s",
                    result.get("version"), effective_label)
        return result

    async def pull(self, passphrase: Optional[str] = None) -> dict:
        """Pull and decrypt the newest snapshot this device can open."""
        items = self._key_items()
        if items is not None:
            matched = await self._newest_vault_snapshot(items)
            if matched is not None:
                full = await self._api.get(f"/api/v1/configs/{matched['id']}")
                return await self._decrypt_snapshot(full, passphrase)
        result = await self._api.get("/api/v1/configs/latest")
        return await self._decrypt_snapshot(result, passphrase)

    async def _newest_vault_snapshot(self, items: "AppKeyItems") -> Optional[dict]:
        """Newest vault snapshot under one of our keys; None when there is no vault snapshot.

        Raises DecryptionError when vault snapshots exist but none match a key.
        """
        snapshots = [s for s in await self.list_snapshots() if s.get("key_custody") == "vault"]
        if not snapshots:
            return None
        ids = {p.get("public_fingerprint") for p in await self._vault_keys(items)}
        matching = [s for s in snapshots if s.get("key_id") in ids]
        if not matching:
            raise config_crypto.DecryptionError(_UNKNOWN_KEY_TEXT)
        return max(matching, key=lambda s: (str(s.get("created_at", "")), s.get("version") or 0))

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
        return await self._decrypt_snapshot(result, passphrase)

    async def restore_by_id(self, snapshot_id: str, passphrase: Optional[str] = None) -> dict:
        """Restore config by snapshot id (preferred for the snapshot manager)."""
        result = await self._api.get(f"/api/v1/configs/{snapshot_id}")
        return await self._decrypt_snapshot(result, passphrase)

    async def rename_snapshot(self, snapshot_id: str, label: str) -> dict:
        """Rename a snapshot server-side. Label is plaintext by design."""
        clean = self._sanitize_label(label)
        if not clean:
            raise ValueError("Label cannot be empty")
        return await self._api.patch(f"/api/v1/configs/{snapshot_id}", json={"label": clean})

    async def delete_snapshot(self, snapshot_id: str) -> dict:
        """Delete a snapshot server-side."""
        return await self._api.delete(f"/api/v1/configs/{snapshot_id}")

    async def move_key_to_vault(
        self,
        progress: Optional[Callable[[str], None]] = None,
        *,
        recovery_gate: Callable[[], Awaitable[None]],
    ) -> dict:
        """Switch config sync to a vault-held key; safe to re-run at every step.

        *recovery_gate* is awaited first, before the key item exists: the move
        ends by deleting the passphrase snapshots, so the person must have
        proven they can still recover the vault. It raises to stop the move.

        Order matters: the key item, then a snapshot under it, and only then
        the bulk delete of passphrase snapshots (the service refuses that
        delete without a vault snapshot as a second guard). Local passphrase
        leftovers go last.

        Returns:
            ``{"key_created", "pushed", "deleted"}``.
        """
        say = progress or (lambda _step: None)
        items = self._key_items()
        if items is None:
            raise ConfigKeyError("config_key_not_ready")
        await recovery_gate()
        say("key")
        had_key = bool(await items.list(CONFIG_KEY_ITEM))
        key_payload = await self._ensure_vault_key(items)
        key_id = key_payload["public_fingerprint"]

        say("snapshot")
        has_snapshot = any(
            s.get("key_custody") == "vault" and s.get("key_id") == key_id
            for s in await self.list_snapshots()
        )
        if not has_snapshot:
            await self._push_vault(None)

        say("cleanup")
        response = await self._api.delete(
            "/api/v1/configs", params={"key_custody": "passphrase"},
        )
        self._forget_local_passphrase()
        deleted = response.get("deleted", 0) if isinstance(response, dict) else 0
        return {"key_created": not had_key, "pushed": not has_snapshot, "deleted": deleted}

    def _forget_local_passphrase(self) -> None:
        self._cached_passphrase = None
        try:
            PROBE_FILE.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not remove sync key probe: %s", exc)

    async def _decrypt_snapshot(self, result: dict, passphrase: Optional[str]) -> dict:
        """Decrypt a full-envelope response and return the parsed config dict."""
        if not result.get("encryption"):
            raise config_crypto.DecryptionError(
                "Snapshot is missing the client-encryption envelope. Delete it "
                "and push a fresh one."
            )

        if result.get("key_custody") == "vault":
            return await self._decrypt_vault(result)

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

        # Preserve sensitive (nested) fields that are empty in remote.
        # Walk local config to find the value first; only if a non-empty local
        # value exists, materialise the intermediate path in remote_data and
        # write the leaf.  This avoids orphaned empty dicts when there is
        # nothing to preserve, and correctly handles depth ≥ 2 where the old
        # `.get(part, {})` chain produced orphaned dicts whose leaf assignment
        # was never reflected back into remote_data.
        for field_path in SENSITIVE_FIELDS:
            if "[]" in field_path:
                self._preserve_list_secret(current, remote_data, field_path)
                continue
            parts = field_path.split(".")
            # Walk local config to find the value to preserve.
            local_val: Any = current
            for part in parts:
                if not isinstance(local_val, dict):
                    local_val = None
                    break
                local_val = local_val.get(part)
                if local_val is None:
                    break
            if not local_val:
                continue  # nothing worth preserving (empty string or None)
            # Walk and materialise the path in remote_data; only fill the leaf
            # if remote is empty (avoid clobbering a freshly-rotated
            # server-side secret).
            cursor = remote_data
            for part in parts[:-1]:
                nxt = cursor.get(part)
                if not isinstance(nxt, dict):
                    nxt = {}
                    cursor[part] = nxt
                cursor = nxt
            leaf = parts[-1]
            if not cursor.get(leaf):
                cursor[leaf] = local_val

        # Preserve user-data lists that are empty in remote. A preserved list
        # is the local copy, so it keeps its local secrets as well.
        for field_name in PRESERVE_ON_EMPTY_FIELDS:
            parts = field_name.split(".")
            remote_val = _get_path(remote_data, parts)
            current_val = _get_path(current, parts)
            # Treat missing/None/empty-list/empty-dict as "empty"
            if not remote_val and current_val:
                _materialise(remote_data, parts[:-1])[parts[-1]] = copy.deepcopy(current_val)

        # Reload via config manager's deserialize
        new_config = self._config_manager._deserialize(remote_data)
        self._config_manager.save(new_config)
        logger.info("Remote config applied")

    @staticmethod
    def _preserve_list_secret(current: dict, remote_data: dict, field_path: str) -> None:
        """Keep a local secret of a list entry the remote copy has empty.

        ``hetzner.accounts[].api_token``: every remote account whose label
        matches a local account gets the local token when its own is empty.
        Entries without a label, or only present on one side, are left alone.
        """
        list_path, _, leaf_path = field_path.partition("[].")
        list_parts = list_path.split(".")
        leaf_parts = leaf_path.split(".")
        local_items = _get_path(current, list_parts)
        remote_items = _get_path(remote_data, list_parts)
        if not isinstance(local_items, list) or not isinstance(remote_items, list):
            return
        local_by_id = {}
        for item in local_items:
            key = _identity(item)
            if key is not None:
                local_by_id.setdefault(key, item)
        for remote_item in remote_items:
            local_item = local_by_id.get(_identity(remote_item) or "")
            if local_item is None:
                continue
            local_val = _get_path(local_item, leaf_parts)
            if not local_val:
                continue
            parent = _materialise(remote_item, leaf_parts[:-1])
            if not parent.get(leaf_parts[-1]):
                parent[leaf_parts[-1]] = local_val

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
        data = copy.deepcopy(config_data)

        # Remove local-only fields
        for field_name in LOCAL_ONLY_FIELDS:
            data.pop(field_name, None)

        # Mask sensitive fields, including those inside list entries.
        for field_path in SENSITIVE_FIELDS:
            parts = field_path.split(".")
            for parent in list(_parents(data, parts[:-1])):
                parent.pop(parts[-1], None)

        return data

    def _compute_hash(self, config_data: dict) -> str:
        """Compute deterministic hash of config data."""
        serialized = json.dumps(config_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def vault_key_items_provider(get_vault_service: Callable[[], Any]) -> KeyItemsProvider:
    """A key provider that reads the app's vault service lazily.

    The vault service is rebuilt on login, so the provider asks for it on
    every call and answers None while it is absent or locked.
    """
    def provider() -> Optional["AppKeyItems"]:
        vault = get_vault_service()
        if vault is None or not vault.is_unlocked:
            return None
        return vault.app_keys

    return provider

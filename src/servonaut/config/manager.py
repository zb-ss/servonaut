"""Configuration manager for loading, saving, and validating app configuration."""

from __future__ import annotations

from dataclasses import asdict, fields
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import glob
import json
import logging
import os
import re

from .schema import (
    AIProviderConfig,
    AppConfig,
    AWSConfig,
    AzureConfig,
    CustomServer,
    DBProfile,
    GCPConfig,
    HetznerConfig,
    IPBanConfig,
    MCPConfig,
    MemoryConfig,
    ObjectStorageConfig,
    OVHConfig,
    RelayConfig,
    ScanRule,
    ConnectionProfile,
    ConnectionRule,
    SSHConfig,
    VoiceConfig,
    CONFIG_VERSION,
)
from .migration import migrate_to_latest
from .paths import normalize_config_paths
from .secrets import load_secrets_env

logger = logging.getLogger(__name__)


def _coerce(cls: type, data: Any, label: str) -> Any:
    """Build a config dataclass from a dict, dropping keys not in the schema.

    A field removed from the schema in a newer release would otherwise crash
    ``cls(**data)`` when reading an older on-disk config. That crash makes the
    whole load fall back to defaults, and the next save overwrites the user's
    real config — silent data loss. Unknown keys are logged and dropped so the
    rest of the config still loads.

    Args:
        cls: The config dataclass to construct.
        data: Raw dict from the on-disk config (may be empty or None).
        label: Human-readable section name, used only for the warning log.

    Returns:
        An instance of ``cls`` — defaults when ``data`` is empty.
    """
    if not data:
        return cls()
    valid = {f.name for f in fields(cls)}
    unknown = set(data) - valid
    if unknown:
        logger.warning("Ignoring unknown %s config keys: %s", label, sorted(unknown))
        data = {k: v for k, v in data.items() if k in valid}
    return cls(**data)


CONFIG_DIR = Path.home() / '.servonaut'
CONFIG_PATH = CONFIG_DIR / 'config.json'
BACKUP_DIR = CONFIG_DIR / 'backups'
BACKUP_PREFIX = 'config-'
BACKUP_SUFFIX = '.json'
MAX_BACKUPS = 5
# The copy taken before a schema upgrade, named by the schema it came from
# (``pre-upgrade-v4-<stamp>.json``). The prefix keeps it out of the save
# rotation, so the saves that follow an upgrade never prune the only copy of
# the pre-upgrade config.
UPGRADE_BACKUP_PREFIX = 'pre-upgrade-'
BACKUP_KIND_SAVE = 'save'
BACKUP_KIND_UPGRADE = 'pre-upgrade'
_BACKUP_STAMP_FORMAT = '%Y%m%dT%H%M%S'
_UPGRADE_BACKUP_VERSION_RE = re.compile(r'^pre-upgrade-v(\d+)-')
# Older releases wrote the pre-upgrade copy beside config.json, always named
# ``<config stem>.v1.bak.<stamp>`` whatever the schema was.
_LEGACY_UPGRADE_BACKUP_INFIX = '.v1.bak.'

# Legacy paths (pre-consolidation, v1)
_LEGACY_CONFIG = Path.home() / '.ec2_ssh_config.json'
_LEGACY_CACHE = Path.home() / '.ec2_ssh_cache.json'
_LEGACY_KEYWORDS = Path.home() / '.ec2_ssh_keywords.json'
_LEGACY_LOG_DIR = Path.home() / '.ec2_ssh_logs'

# Legacy paths (ec2-ssh era, v2.0–2.1)
_LEGACY_EC2SSH_DIR = Path.home() / '.ec2-ssh'


def _write_json_secure(target: Path, data: Any) -> None:
    """Write *data* as JSON to *target* atomically with mode ``0o600``.

    Args:
        target: Destination path.
        data: JSON-serialisable object.
    """
    _write_bytes_secure(target, json.dumps(data, indent=2).encode("utf-8"))


def _write_bytes_secure(target: Path, payload: bytes) -> None:
    """Write *payload* to *target* atomically with mode ``0o600``.

    Creates a sibling temp file, writes into it, fsyncs, then renames it
    over *target* so callers never see a partially-written file. The file
    is restricted to owner read/write (``0o600``) from the moment it is
    created.

    Args:
        target: Destination path.
        payload: Bytes to write.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.parent / f".{target.name}.tmp_{os.getpid()}"
    # Unlink any pre-existing file at tmp_path first so O_EXCL (via
    # O_NOFOLLOW) cannot race with a pre-planted symlink left from a
    # previous crashed run.
    try:
        tmp_path.unlink(missing_ok=True)
    except OSError:
        pass
    # O_NOFOLLOW: refuse to open if tmp_path is a symlink — prevents a
    # pre-planted symlink from redirecting the write to an arbitrary file.
    # getattr fallback covers platforms that lack O_NOFOLLOW (Windows).
    _O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(
        str(tmp_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    os.replace(str(tmp_path), str(target))
    # Re-apply perms: pre-existing file preserves its old mode on some
    # platforms after an os.replace over it.
    os.chmod(str(target), 0o600)


def _version_from_backup_name(path: Path) -> Optional[int]:
    """Schema version encoded in a ``pre-upgrade-v<N>-…`` backup name."""
    match = _UPGRADE_BACKUP_VERSION_RE.match(path.name)
    return int(match.group(1)) if match else None


def _version_from_backup_content(path: Path) -> Optional[int]:
    """Schema version stored in a backup file (1 when it has no ``version`` key)."""
    try:
        data = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        return int(data.get('version', 1))
    except (TypeError, ValueError):
        return None


def _restrict_to_owner(path: Path) -> None:
    """Best-effort ``chmod 0600`` for a file group or others can read."""
    try:
        if path.stat().st_mode & 0o077:
            os.chmod(str(path), 0o600)
    except OSError as exc:
        logger.warning("Could not restrict permissions on %s: %s", path, exc)


def describe_backup(entry: Dict[str, Any]) -> str:
    """Short label for a ``list_backups()`` entry, e.g. ``pre-upgrade v4``."""
    if entry.get("kind") != BACKUP_KIND_UPGRADE:
        return "on save"
    version = entry.get("from_version")
    return BACKUP_KIND_UPGRADE if version is None else f"{BACKUP_KIND_UPGRADE} v{version}"


def _ensure_config_dir() -> None:
    """Create ~/.servonaut/ directory if it doesn't exist."""
    CONFIG_DIR.mkdir(exist_ok=True)


def _migrate_legacy_paths() -> None:
    """Migrate files from old locations to ~/.servonaut/.

    Handles two migration paths:
    1. Scattered v1 files (~/.ec2_ssh_*) → ~/.servonaut/
    2. ec2-ssh era directory (~/.ec2-ssh/) → ~/.servonaut/
    """
    if CONFIG_PATH.exists():
        return

    import shutil

    # Migration path 1: ec2-ssh consolidated dir → servonaut
    if _LEGACY_EC2SSH_DIR.exists() and _LEGACY_EC2SSH_DIR.is_dir():
        _ensure_config_dir()
        logger.info("Migrating ~/.ec2-ssh/ to %s", CONFIG_DIR)
        for item in _LEGACY_EC2SSH_DIR.iterdir():
            dest = CONFIG_DIR / item.name
            if item.is_dir():
                if dest.exists():
                    # Merge directory contents
                    for sub in item.iterdir():
                        shutil.move(str(sub), str(dest / sub.name))
                    item.rmdir()
                else:
                    shutil.move(str(item), str(dest))
            else:
                shutil.move(str(item), str(dest))
            logger.info("Moved %s → %s", item, dest)
        # Remove old dir if empty
        try:
            _LEGACY_EC2SSH_DIR.rmdir()
        except OSError:
            pass
        return

    # Migration path 2: scattered v1 files → servonaut
    if not _LEGACY_CONFIG.exists():
        return

    _ensure_config_dir()
    logger.info("Migrating legacy config files to %s", CONFIG_DIR)

    # Move config
    shutil.move(str(_LEGACY_CONFIG), str(CONFIG_PATH))
    logger.info("Moved %s → %s", _LEGACY_CONFIG, CONFIG_PATH)

    # Move cache
    if _LEGACY_CACHE.exists():
        dest = CONFIG_DIR / 'cache.json'
        shutil.move(str(_LEGACY_CACHE), str(dest))
        logger.info("Moved %s → %s", _LEGACY_CACHE, dest)

    # Move keywords
    if _LEGACY_KEYWORDS.exists():
        dest = CONFIG_DIR / 'keywords.json'
        shutil.move(str(_LEGACY_KEYWORDS), str(dest))
        logger.info("Moved %s → %s", _LEGACY_KEYWORDS, dest)

    # Move logs directory contents
    if _LEGACY_LOG_DIR.exists() and _LEGACY_LOG_DIR.is_dir():
        new_log_dir = CONFIG_DIR / 'logs'
        new_log_dir.mkdir(exist_ok=True)
        for item in _LEGACY_LOG_DIR.iterdir():
            dest = new_log_dir / item.name
            shutil.move(str(item), str(dest))
        _LEGACY_LOG_DIR.rmdir()
        logger.info("Moved %s → %s", _LEGACY_LOG_DIR, new_log_dir)


class ConfigManager:
    """Manages application configuration with automatic migration and validation.

    Handles loading, saving, validation, and migration of configuration files.
    Provides singleton-like behavior with cached configuration.

    Example:
        config_manager = ConfigManager()
        config = config_manager.get()
        config_manager.update(cache_ttl_seconds=600)
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """Initialize the configuration manager.

        Args:
            config_path: Alternative config file to read and write instead of
                ``~/.servonaut/config.json`` (the TUI's ``--config`` flag).
                Every other runtime file keeps its usual location.
        """
        self._config: Optional[AppConfig] = None
        self._load_error: Optional[str] = None
        _migrate_legacy_paths()
        _ensure_config_dir()
        load_secrets_env()
        self._config_path = Path(config_path).expanduser() if config_path else CONFIG_PATH

    def load(self) -> AppConfig:
        """Load configuration from disk.

        Automatically migrates v1 config to v2 if needed.
        Returns default config if file doesn't exist.

        Returns:
            AppConfig instance
        """
        if not self._config_path.exists():
            logger.info("No config file found at %s, using defaults", self._config_path)
            self._config = AppConfig()
            return self._config

        try:
            with open(self._config_path, 'r') as f:
                raw_data = json.load(f)

            # Check if migration needed (any version below CONFIG_VERSION,
            # or no version key at all = v1).
            if self._needs_migration(raw_data):
                from_version = raw_data.get('version', 1)
                logger.info(
                    "Migrating config from v%s to v%d...",
                    from_version, CONFIG_VERSION,
                )
                self._create_upgrade_backup(from_version)
                raw_data = migrate_to_latest(raw_data)
                # Save migrated config immediately with 0o600 permissions.
                _write_json_secure(self._config_path, raw_data)
                logger.info("Migration complete")

            # Deserialize to AppConfig
            self._config = self._deserialize(raw_data)

            # Fix legacy keyword_store_path if still pointing to old location
            if self._config.keyword_store_path in (
                '~/.ec2_ssh_keywords.json',
                '~/.ec2-ssh/keywords.json',
            ):
                self._config.keyword_store_path = '~/.servonaut/keywords.json'
                self.save(self._config)

            # Upgrade ai_chunk_size from old default (4000) to new default (100000)
            if self._config.ai_chunk_size == 4000:
                self._config.ai_chunk_size = 100000
                self.save(self._config)

            # Validate and warn
            warnings = self._validate(self._config)
            for warning in warnings:
                logger.warning(warning)

            return self._config

        except json.JSONDecodeError as e:
            self._load_error = (
                f"Config file has invalid JSON (line {e.lineno}, col {e.colno}): {e.msg}. "
                f"Using default settings — your saved configuration was NOT loaded. "
                f"Fix {self._config_path} or delete it to start fresh."
            )
            logger.error("Config JSON parse error: %s", self._load_error)
            self._config = AppConfig()
            return self._config
        except Exception as e:
            self._load_error = (
                f"Failed to load config: {e}. "
                f"Using default settings — your saved configuration was NOT loaded."
            )
            logger.error("Config load error: %s", self._load_error)
            self._config = AppConfig()
            return self._config

    def save(self, config: AppConfig) -> None:
        """Save configuration to disk.

        Rotates a local backup of the previous config before writing so the
        user can recover from accidental overwrites (e.g. a sync pull that
        wipes data). Keeps MAX_BACKUPS most recent backups.

        The file is written atomically (temp → rename) with mode ``0o600``
        so credentials stored in config.json are never world-readable, even
        briefly during the write.

        Args:
            config: AppConfig instance to save
        """
        try:
            # Snapshot the current file BEFORE overwriting.
            self._create_backup()

            # Serialize to dict
            data = self._serialize(config)

            # Atomic write with restricted permissions.
            _write_json_secure(self._config_path, data)

            self._config = config

        except Exception as e:
            logger.error("Error saving config: %s", e)
            raise

    # ------------------------------------------------------------------
    # Local backup rotation
    # ------------------------------------------------------------------

    @staticmethod
    def _backup_dir() -> Path:
        """Directory that holds the save and pre-upgrade config backups."""
        return BACKUP_DIR

    def _create_backup(self) -> Optional[Path]:
        """Copy the current config.json into the backups dir with a timestamp.

        No-op if config.json does not exist yet (first save). Failures are
        logged but not raised — a backup failure must not block normal saves.
        """
        backup_path = self._snapshot_config(BACKUP_PREFIX)
        if backup_path is not None:
            self._prune_backups()
        return backup_path

    def _create_upgrade_backup(self, from_version: Any) -> Optional[Path]:
        """Keep a copy of config.json before a schema upgrade rewrites it.

        Args:
            from_version: The on-disk schema version (``version`` key; 1 when absent).
        """
        try:
            label = f"v{int(from_version)}"
        except (TypeError, ValueError):
            label = "unknown"
        return self._snapshot_config(f"{UPGRADE_BACKUP_PREFIX}{label}-")

    def _snapshot_config(self, prefix: str) -> Optional[Path]:
        """Copy config.json to ``<backup dir>/<prefix><stamp>.json``, owner-only.

        Returns:
            The backup path, or None when there is nothing to copy or the
            copy failed (logged, never raised).
        """
        if not self._config_path.exists():
            return None
        try:
            payload = self._config_path.read_bytes()
            backup_dir = self._backup_dir()
            backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            timestamp = datetime.now().strftime(_BACKUP_STAMP_FORMAT)
            backup_path = backup_dir / f"{prefix}{timestamp}{BACKUP_SUFFIX}"
            # Avoid collisions within the same second
            counter = 1
            while backup_path.exists():
                backup_path = backup_dir / f"{prefix}{timestamp}-{counter}{BACKUP_SUFFIX}"
                counter += 1
            _write_bytes_secure(backup_path, payload)
            logger.info("Created config backup: %s", backup_path)
            return backup_path
        except OSError as exc:
            logger.warning("Failed to create config backup: %s", exc)
            return None

    def _prune_backups(self) -> None:
        """Delete old save backups, keeping the MAX_BACKUPS most recent.

        Pre-upgrade backups use a different prefix and are never pruned.
        """
        try:
            backups = sorted(
                self._backup_dir().glob(f"{BACKUP_PREFIX}*{BACKUP_SUFFIX}"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in backups[MAX_BACKUPS:]:
                try:
                    old.unlink()
                except OSError as exc:
                    logger.warning("Could not remove old backup %s: %s", old, exc)
        except OSError as exc:
            logger.warning("Backup pruning failed: %s", exc)

    def list_backups(self) -> List[Dict[str, Any]]:
        """Return metadata for every restorable config backup, newest first.

        Covers the save rotation, pre-upgrade copies, and the pre-upgrade
        copies older releases left beside config.json.

        Each entry: {path, timestamp (datetime), size_bytes, kind,
        from_version}. ``kind`` is ``BACKUP_KIND_SAVE`` or
        ``BACKUP_KIND_UPGRADE``; ``from_version`` is the schema version a
        pre-upgrade copy came from (None for save backups or when unknown).
        """
        backup_dir = self._backup_dir()
        candidates = []
        if backup_dir.is_dir():
            candidates += [
                (path, BACKUP_KIND_SAVE, None)
                for path in backup_dir.glob(f"{BACKUP_PREFIX}*{BACKUP_SUFFIX}")
            ]
            candidates += [
                (path, BACKUP_KIND_UPGRADE, _version_from_backup_name(path))
                for path in backup_dir.glob(f"{UPGRADE_BACKUP_PREFIX}*{BACKUP_SUFFIX}")
            ]
        candidates += [
            (path, BACKUP_KIND_UPGRADE, _version_from_backup_content(path))
            for path in self._legacy_upgrade_backups()
        ]

        out: List[Dict[str, Any]] = []
        for path, kind, from_version in candidates:
            try:
                stat = path.stat()
            except OSError:
                continue
            out.append({
                "path": path,
                "timestamp": datetime.fromtimestamp(stat.st_mtime),
                "size_bytes": stat.st_size,
                "kind": kind,
                "from_version": from_version,
            })
        out.sort(key=lambda entry: entry["timestamp"], reverse=True)
        return out

    def _legacy_upgrade_backups(self) -> List[Path]:
        """Pre-upgrade copies older releases wrote beside config.json.

        Those were copied with the config's own mode, so an old readable
        config left a readable copy; each one found is narrowed to owner-only.
        """
        folder = self._config_path.parent
        pattern = glob.escape(self._config_path.stem) + _LEGACY_UPGRADE_BACKUP_INFIX + "*"
        found = [path for path in folder.glob(pattern) if path.is_file()]
        for path in found:
            _restrict_to_owner(path)
        return found

    def restore_backup(self, backup_path: Path) -> AppConfig:
        """Restore config.json from a listed backup file.

        The current config is itself backed up first so the restore is
        reversible (you'll see the pre-restore state in the backup list).

        Args:
            backup_path: Path of an entry returned by ``list_backups()``.

        Returns:
            Freshly loaded AppConfig.

        Raises:
            FileNotFoundError: If backup_path doesn't exist.
            ValueError: If backup_path is not a listed backup, or its
                content is not a config file.
        """
        backup_path = Path(backup_path).expanduser().resolve()
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")
        listed = {entry["path"].resolve() for entry in self.list_backups()}
        if backup_path not in listed:
            raise ValueError(
                f"Refusing to restore from a path outside the config backups: {backup_path}"
            )

        payload = backup_path.read_bytes()
        try:
            is_config = isinstance(json.loads(payload), dict)
        except (UnicodeDecodeError, ValueError):
            is_config = False
        if not is_config:
            raise ValueError(f"Backup is not a valid config file: {backup_path}")

        # Snapshot the current state before overwriting so the user can undo.
        self._create_backup()

        _write_bytes_secure(self._config_path, payload)
        logger.info("Restored config from %s", backup_path)

        # Force a reload on next get()
        self._config = None
        return self.get()

    def get(self) -> AppConfig:
        """Get current configuration (cached).

        Returns:
            AppConfig instance
        """
        if self._config is None:
            self._config = self.load()
        return self._config

    @property
    def load_error(self) -> Optional[str]:
        """Return the error message from the last load attempt, or None if OK."""
        return self._load_error

    def update(self, **kwargs: Any) -> AppConfig:
        """Update configuration fields and save.

        Args:
            **kwargs: Field names and values to update

        Returns:
            Updated AppConfig instance

        Example:
            config_manager.update(cache_ttl_seconds=600, theme='light')
        """
        config = self.get()

        # Get valid field names from AppConfig
        valid_fields = {f.name for f in fields(AppConfig)}

        # Update only valid fields
        for key, value in kwargs.items():
            if key not in valid_fields:
                logger.warning("Unknown config field '%s', ignoring", key)
                continue
            setattr(config, key, value)

        self.save(config)
        return config

    def _validate(self, config: AppConfig) -> List[str]:
        """Validate configuration and return list of warnings.

        Args:
            config: AppConfig instance to validate

        Returns:
            List of warning messages (empty if valid)
        """
        warnings = []

        # Check version
        if config.version != CONFIG_VERSION:
            warnings.append(
                f"Config version mismatch: found {config.version}, "
                f"expected {CONFIG_VERSION}"
            )

        # Validate cache TTL
        if config.cache_ttl_seconds < 0:
            warnings.append("cache_ttl_seconds is negative, should be >= 0")

        # Validate SSH port in connection profiles
        for profile in config.connection_profiles:
            if not (1 <= profile.ssh_port <= 65535):
                warnings.append(
                    f"Invalid SSH port {profile.ssh_port} in profile "
                    f"'{profile.name}', should be 1-65535"
                )

        # Validate connection rules reference existing profiles
        profile_names = {p.name for p in config.connection_profiles}
        for rule in config.connection_rules:
            if rule.profile_name not in profile_names:
                warnings.append(
                    f"Connection rule '{rule.name}' references unknown "
                    f"profile '{rule.profile_name}'"
                )

        # Validate default_key exists if set
        if config.default_key:
            key_path = Path(config.default_key).expanduser()
            if not key_path.exists():
                warnings.append(
                    f"default_key path does not exist: {config.default_key}"
                )

        return warnings

    def _needs_migration(self, raw_data: Dict[str, Any]) -> bool:
        """Check whether the on-disk config is older than ``CONFIG_VERSION``.

        Args:
            raw_data: Raw configuration dictionary

        Returns:
            True if migration is needed (no ``version`` key, or a version
            lower than current), False otherwise.
        """
        try:
            on_disk = int(raw_data.get('version', 0) or 0)
        except (TypeError, ValueError):
            on_disk = 0
        return on_disk < CONFIG_VERSION

    def _serialize(self, config: AppConfig) -> Dict[str, Any]:
        """Convert AppConfig to JSON-serializable dictionary.

        User-entered SSH key paths are collapsed to ``~/…`` literals when they
        live under the current user's home directory, so the resulting config
        is portable across machines, usernames, and OSes (the read path already
        expands ``~`` per-OS). Paths outside home are left untouched.

        Args:
            config: AppConfig instance

        Returns:
            Dictionary ready for JSON serialization
        """
        data = asdict(config)
        normalize_config_paths(data)
        return data

    def _deserialize(self, raw_data: Dict[str, Any]) -> AppConfig:
        """Convert dictionary to AppConfig instance.

        Args:
            raw_data: Raw configuration dictionary

        Returns:
            AppConfig instance
        """
        # Convert nested dicts to dataclass instances. ``_coerce`` drops keys
        # that are no longer in the schema so a field removed in a newer
        # release doesn't crash the load — a crash here falls back to defaults
        # and the next save silently overwrites the user's real config.
        scan_rules = [
            _coerce(ScanRule, r, 'scan_rules')
            for r in raw_data.get('scan_rules', [])
        ]
        connection_profiles = [
            _coerce(ConnectionProfile, p, 'connection_profiles')
            for p in raw_data.get('connection_profiles', [])
        ]
        connection_rules = [
            _coerce(ConnectionRule, r, 'connection_rules')
            for r in raw_data.get('connection_rules', [])
        ]
        custom_servers = [
            _coerce(CustomServer, s, 'custom_servers')
            for s in raw_data.get('custom_servers', [])
        ]
        ip_ban_configs = [
            _coerce(IPBanConfig, c, 'ip_ban_configs')
            for c in raw_data.get('ip_ban_configs', [])
        ]
        db_profiles = [
            _coerce(DBProfile, p, 'db_profiles')
            for p in raw_data.get('db_profiles', [])
        ]
        ai_provider = _coerce(AIProviderConfig, raw_data.get('ai_provider', {}), 'ai_provider')
        mcp = _coerce(MCPConfig, raw_data.get('mcp', {}), 'mcp')
        relay = _coerce(RelayConfig, raw_data.get('relay', {}), 'relay')

        # Coerce nested object_storage blocks BEFORE coercing the parent so
        # _coerce(OVHConfig/HetznerConfig) receives a dict with the sub-field
        # already converted to a dataclass instance.
        raw_ovh = dict(raw_data.get('ovh', {}))
        if 'object_storage' in raw_ovh:
            raw_ovh['object_storage'] = _coerce(
                ObjectStorageConfig, raw_ovh['object_storage'], 'ovh.object_storage'
            )
        ovh = _coerce(OVHConfig, raw_ovh, 'ovh')

        raw_hetzner = dict(raw_data.get('hetzner', {}))
        if 'object_storage' in raw_hetzner:
            raw_hetzner['object_storage'] = _coerce(
                ObjectStorageConfig, raw_hetzner['object_storage'], 'hetzner.object_storage'
            )
        hetzner = _coerce(HetznerConfig, raw_hetzner, 'hetzner')

        raw_aws = dict(raw_data.get('aws', {}))
        if 'object_storage' in raw_aws:
            raw_aws['object_storage'] = _coerce(
                ObjectStorageConfig, raw_aws['object_storage'], 'aws.object_storage'
            )
        aws = _coerce(AWSConfig, raw_aws, 'aws')

        gcp = _coerce(GCPConfig, raw_data.get('gcp', {}), 'gcp')
        azure = _coerce(AzureConfig, raw_data.get('azure', {}), 'azure')
        memory = _coerce(MemoryConfig, raw_data.get('memory', {}), 'memory')
        ssh_config = _coerce(SSHConfig, raw_data.get('ssh', {}), 'ssh')
        voice = _coerce(VoiceConfig, raw_data.get('voice', {}), 'voice')

        # Build AppConfig with converted objects, filtering out unknown keys
        valid_fields = {f.name for f in fields(AppConfig)}
        config_dict = {k: v for k, v in raw_data.items() if k in valid_fields}
        config_dict['scan_rules'] = scan_rules
        config_dict['connection_profiles'] = connection_profiles
        config_dict['connection_rules'] = connection_rules
        config_dict['custom_servers'] = custom_servers
        config_dict['ip_ban_configs'] = ip_ban_configs
        config_dict['db_profiles'] = db_profiles
        config_dict['ai_provider'] = ai_provider
        config_dict['mcp'] = mcp
        config_dict['relay'] = relay
        config_dict['ovh'] = ovh
        config_dict['hetzner'] = hetzner
        config_dict['aws'] = aws
        config_dict['gcp'] = gcp
        config_dict['azure'] = azure
        config_dict['memory'] = memory
        config_dict['ssh'] = ssh_config
        config_dict['voice'] = voice

        # Warn about dropped keys for debugging
        unknown_keys = set(raw_data.keys()) - valid_fields
        if unknown_keys:
            logger.warning("Ignoring unknown config keys: %s", unknown_keys)

        return AppConfig(**config_dict)

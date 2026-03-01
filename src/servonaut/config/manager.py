"""Configuration manager for loading, saving, and validating app configuration."""

from __future__ import annotations

from dataclasses import asdict, fields
from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import logging

from .schema import (
    AppConfig,
    ScanRule,
    ConnectionProfile,
    ConnectionRule,
    CONFIG_VERSION,
)
from .migration import migrate_v1_to_v2, create_backup

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / '.servonaut'
CONFIG_PATH = CONFIG_DIR / 'config.json'

# Legacy paths (pre-consolidation, v1)
_LEGACY_CONFIG = Path.home() / '.ec2_ssh_config.json'
_LEGACY_CACHE = Path.home() / '.ec2_ssh_cache.json'
_LEGACY_KEYWORDS = Path.home() / '.ec2_ssh_keywords.json'
_LEGACY_LOG_DIR = Path.home() / '.ec2_ssh_logs'

# Legacy paths (ec2-ssh era, v2.0–2.1)
_LEGACY_EC2SSH_DIR = Path.home() / '.ec2-ssh'


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

    def __init__(self) -> None:
        """Initialize the configuration manager."""
        self._config: Optional[AppConfig] = None
        _migrate_legacy_paths()
        _ensure_config_dir()
        self._config_path = CONFIG_PATH

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

            # Check if migration needed
            if self._needs_migration(raw_data):
                logger.info("Detected v1 config, migrating to v2...")
                create_backup(self._config_path)
                raw_data = migrate_v1_to_v2(raw_data)
                # Save migrated config immediately
                with open(self._config_path, 'w') as f:
                    json.dump(raw_data, f, indent=2)
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

            # Validate and warn
            warnings = self._validate(self._config)
            for warning in warnings:
                logger.warning(warning)

            return self._config

        except json.JSONDecodeError as e:
            logger.error("Error: Config file is corrupted (invalid JSON): %s", e)
            logger.info("Using default configuration. Fix or delete %s", self._config_path)
            self._config = AppConfig()
            return self._config
        except Exception as e:
            logger.error("Error loading config: %s", e)
            logger.info("Using default configuration")
            self._config = AppConfig()
            return self._config

    def save(self, config: AppConfig) -> None:
        """Save configuration to disk.

        Args:
            config: AppConfig instance to save
        """
        try:
            # Serialize to dict
            data = self._serialize(config)

            # Write to file
            with open(self._config_path, 'w') as f:
                json.dump(data, f, indent=2)

            self._config = config

        except Exception as e:
            logger.error("Error saving config: %s", e)
            raise

    def get(self) -> AppConfig:
        """Get current configuration (cached).

        Returns:
            AppConfig instance
        """
        if self._config is None:
            self._config = self.load()
        return self._config

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
        """Check if configuration needs migration from v1 to v2.

        Args:
            raw_data: Raw configuration dictionary

        Returns:
            True if migration needed, False otherwise
        """
        return 'version' not in raw_data

    def _serialize(self, config: AppConfig) -> Dict[str, Any]:
        """Convert AppConfig to JSON-serializable dictionary.

        Args:
            config: AppConfig instance

        Returns:
            Dictionary ready for JSON serialization
        """
        data = asdict(config)
        return data

    def _deserialize(self, raw_data: Dict[str, Any]) -> AppConfig:
        """Convert dictionary to AppConfig instance.

        Args:
            raw_data: Raw configuration dictionary

        Returns:
            AppConfig instance
        """
        # Extract nested object lists
        scan_rules_data = raw_data.get('scan_rules', [])
        connection_profiles_data = raw_data.get('connection_profiles', [])
        connection_rules_data = raw_data.get('connection_rules', [])

        # Convert to dataclass instances
        scan_rules = [ScanRule(**rule) for rule in scan_rules_data]
        connection_profiles = [
            ConnectionProfile(**profile) for profile in connection_profiles_data
        ]
        connection_rules = [
            ConnectionRule(**rule) for rule in connection_rules_data
        ]

        # Build AppConfig with converted objects
        config_dict = dict(raw_data)
        config_dict['scan_rules'] = scan_rules
        config_dict['connection_profiles'] = connection_profiles
        config_dict['connection_rules'] = connection_rules

        return AppConfig(**config_dict)

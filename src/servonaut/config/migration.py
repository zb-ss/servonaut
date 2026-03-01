"""Configuration migration utilities for upgrading from v1 to v2."""

from __future__ import annotations

import logging
from typing import Dict, Any
from pathlib import Path
import json
import shutil
from datetime import datetime

from .schema import CONFIG_VERSION

logger = logging.getLogger(__name__)


def migrate_v1_to_v2(v1_data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate v1 configuration to v2 format.

    Args:
        v1_data: V1 configuration dictionary

    Returns:
        V2 configuration dictionary with all new fields

    V1 Format:
        {
            "instance_keys": {"i-xxx": "/path/to/key"},
            "default_key": "/path/to/default"
        }

    V2 Format:
        {
            "version": 2,
            "instance_keys": {...},
            "default_key": "...",
            "default_username": "ec2-user",
            "cache_ttl_seconds": 300,
            "default_scan_paths": ["~/shared/"],
            "scan_rules": [],
            "connection_profiles": [],
            "connection_rules": [],
            "terminal_emulator": "auto",
            "keyword_store_path": "~/.servonaut/keywords.json",
            "theme": "dark"
        }
    """
    # Preserve v1 fields
    v2_data = {
        'version': CONFIG_VERSION,
        'instance_keys': v1_data.get('instance_keys', {}),
        'default_key': v1_data.get('default_key', ''),
    }

    # Add v2-only fields with defaults
    v2_data.update({
        'default_username': 'ec2-user',
        'cache_ttl_seconds': 300,
        'default_scan_paths': ['~/shared/'],
        'scan_rules': [],
        'connection_profiles': [],
        'connection_rules': [],
        'terminal_emulator': 'auto',
        'keyword_store_path': '~/.servonaut/keywords.json',
        'theme': 'dark',
    })

    return v2_data


def create_backup(config_path: Path) -> bool:
    """Create backup of v1 config file before migration.

    Args:
        config_path: Path to the config file

    Returns:
        True if backup created successfully, False otherwise
    """
    if not config_path.exists():
        return False

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = config_path.with_suffix(f'.v1.bak.{timestamp}')

    try:
        shutil.copy2(config_path, backup_path)
        logger.info("Created backup: %s", backup_path)
        return True
    except Exception as e:
        logger.warning("Failed to create backup: %s", e)
        return False

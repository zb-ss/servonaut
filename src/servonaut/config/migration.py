"""Configuration migration utilities for upgrading old config files."""

from __future__ import annotations

import logging
from typing import Dict, Any
from pathlib import Path
import json
import shutil
from datetime import datetime

from .schema import CONFIG_VERSION

logger = logging.getLogger(__name__)


def _migrate_v2_to_v3(data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate a v2 configuration dictionary to v3.

    The v3 bump only adds new optional keys to ``AIProviderConfig``
    (``provider_preference``, ``local_fallback_provider``, ``dismissed_banners``)
    so deserialisation already works without explicit fill — the
    :class:`AIProviderConfig` dataclass defaults cover any missing keys at
    ``__init__`` time. The migration is therefore mostly a no-op; we still
    fill in defaults defensively so a round-tripped JSON dump never has the
    keys absent.

    Args:
        data: V2 configuration dictionary (loaded JSON).

    Returns:
        V3 configuration dictionary with ``version=3`` and the new
        ``ai_provider`` keys present (with safe defaults).
    """
    out = dict(data)
    out['version'] = CONFIG_VERSION

    ai_provider = out.get('ai_provider')
    if isinstance(ai_provider, dict):
        ai_provider = dict(ai_provider)
        ai_provider.setdefault('provider_preference', None)
        ai_provider.setdefault('local_fallback_provider', None)
        ai_provider.setdefault('dismissed_banners', [])
        out['ai_provider'] = ai_provider

    return out


def migrate_v1_to_v2(v1_data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate v1 configuration to the current schema version.

    Note: despite the name, this function stamps ``CONFIG_VERSION`` (the
    *current* latest version), not ``2`` literal. The v2→v3 bump is purely
    additive (new optional ``ai_provider`` keys with safe dataclass
    defaults), so chaining the two steps would be a no-op — any v1 file
    that goes through this function comes out usable on v3 directly.

    Args:
        v1_data: V1 configuration dictionary

    Returns:
        Latest-version configuration dictionary with all required fields

    V1 Format:
        {
            "instance_keys": {"i-xxx": "/path/to/key"},
            "default_key": "/path/to/default"
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


def migrate_to_latest(data: Dict[str, Any]) -> Dict[str, Any]:
    """Run every migration step needed to bring ``data`` up to ``CONFIG_VERSION``.

    Callers that don't want to manage individual migration steps should use
    this helper. The function is idempotent for already-current configs.

    Branches:
      - No ``version`` key → treat as v1, run :func:`migrate_v1_to_v2` (which
        already lands at ``CONFIG_VERSION`` via its own short-circuit).
      - ``version == 2`` → run :func:`_migrate_v2_to_v3`.
      - ``version >= CONFIG_VERSION`` → return as-is.
    """
    out = data
    current = out.get('version')
    if current is None:
        out = migrate_v1_to_v2(out)
        current = out.get('version')
    if current == 2:
        out = _migrate_v2_to_v3(out)
        current = out.get('version')
    return out


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

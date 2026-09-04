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


def _migrate_v4_to_v5(data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate a v4 configuration dictionary to v5.

    v5 introduces explicit consent for chat memory injection.  The v4
    schema shipped ``chat_inject_server_memory: bool = True`` (default
    on) which silently enabled sending probed local memory to the
    hosted AI backend.  v5:

    - Renames the meaning of ``chat_inject_server_memory`` to "user
      explicitly consented" (default False).
    - Adds ``chat_inject_server_memory_decision`` tri-state
      (``unset``/``allowed``/``denied``).
    - Resets every existing user to ``unset`` so they see the consent
      modal once on next chat.  This is intentional even for users
      who had it set to True under v4 — the trust model genuinely
      changed and a one-time prompt is the honest way to surface it.
    """
    out = dict(data)
    out['version'] = 5
    out['chat_inject_server_memory'] = False
    out['chat_inject_server_memory_decision'] = 'unset'
    return out


def _migrate_v3_to_v4(data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate a v3 configuration dictionary to v4.

    v4 splits the shared ``ai_provider.api_key`` into per-provider fields
    (``openai_api_key``, ``anthropic_api_key``, ``gemini_api_key``). The
    legacy ``api_key`` field is preserved on disk for one release so a
    user who reverts the CLI doesn't lose their key. The migration copies
    the legacy value into the per-provider field that matches
    ``ai_provider.provider`` at the time of upgrade.

    Ollama and Servonaut don't use ``api_key`` so the copy is a no-op for
    those providers.
    """
    out = dict(data)
    out['version'] = 4

    ai_provider = out.get('ai_provider')
    if isinstance(ai_provider, dict):
        ai_provider = dict(ai_provider)
        ai_provider.setdefault('openai_api_key', '')
        ai_provider.setdefault('anthropic_api_key', '')
        ai_provider.setdefault('gemini_api_key', '')

        legacy_key = (ai_provider.get('api_key') or '').strip()
        provider = (ai_provider.get('provider') or '').strip().lower()
        target_field = {
            'openai': 'openai_api_key',
            'anthropic': 'anthropic_api_key',
            'gemini': 'gemini_api_key',
        }.get(provider)
        if legacy_key and target_field and not ai_provider.get(target_field):
            ai_provider[target_field] = legacy_key

        out['ai_provider'] = ai_provider

    return out


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
    out['version'] = 3

    ai_provider = out.get('ai_provider')
    if isinstance(ai_provider, dict):
        ai_provider = dict(ai_provider)
        ai_provider.setdefault('provider_preference', None)
        ai_provider.setdefault('local_fallback_provider', None)
        ai_provider.setdefault('dismissed_banners', [])
        out['ai_provider'] = ai_provider

    return out


def migrate_v1_to_v2(v1_data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate v1 configuration to v2.

    Stamps ``version = 2`` and lets :func:`migrate_to_latest` chain
    through v2→v3 and v3→v4 as needed. (Pre-v4 this function used to
    stamp ``CONFIG_VERSION`` directly because the chain was a series of
    no-op additive bumps; v4 is no longer purely additive — it
    materialises per-provider key defaults — so we go through the chain
    properly now.)

    Args:
        v1_data: V1 configuration dictionary

    Returns:
        V2 configuration dictionary

    V1 Format:
        {
            "instance_keys": {"i-xxx": "/path/to/key"},
            "default_key": "/path/to/default"
        }
    """
    # Preserve v1 fields
    v2_data = {
        'version': 2,
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


# The v5 default for ``cloudtrail_max_events``. Only this exact value is
# raised by the v6 migration, so a deliberate choice is never overwritten.
_V5_CLOUDTRAIL_MAX_EVENTS = 100
_V6_CLOUDTRAIL_MAX_EVENTS = 500


def _migrate_v5_to_v6(data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate a v5 configuration dictionary to v6.

    v5 shipped ``cloudtrail_max_events: 100``, and the CloudTrail browser
    shows 100 events per page — so the cap allowed exactly one page and the
    pager could never turn. v6 raises that to 500 (five pages, and about two
    seconds against a day of events).

    Every saved config carries the key, so raising the dataclass default
    alone would reach nobody who had ever saved settings. Only the old
    default value is raised; any other number is a deliberate choice and is
    left alone.
    """
    out = dict(data)
    out['version'] = 6
    if out.get('cloudtrail_max_events') == _V5_CLOUDTRAIL_MAX_EVENTS:
        out['cloudtrail_max_events'] = _V6_CLOUDTRAIL_MAX_EVENTS
    return out


def migrate_to_latest(data: Dict[str, Any]) -> Dict[str, Any]:
    """Run every migration step needed to bring ``data`` up to ``CONFIG_VERSION``.

    Callers that don't want to manage individual migration steps should use
    this helper. The function is idempotent for already-current configs.

    Branches:
      - No ``version`` key → treat as v1, run :func:`migrate_v1_to_v2`
        (which lands at ``CONFIG_VERSION`` via its own short-circuit).
      - ``version == 2`` → run :func:`_migrate_v2_to_v3` then chain.
      - ``version == 3`` → run :func:`_migrate_v3_to_v4` then chain.
      - ``version == 4`` → run :func:`_migrate_v4_to_v5` then chain.
      - ``version == 5`` → run :func:`_migrate_v5_to_v6`.
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
    if current == 3:
        out = _migrate_v3_to_v4(out)
        current = out.get('version')
    if current == 4:
        out = _migrate_v4_to_v5(out)
        current = out.get('version')
    if current == 5:
        out = _migrate_v5_to_v6(out)
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

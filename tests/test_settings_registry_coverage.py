"""Registry + full-config-coverage guard for the settings package.

Three guarantees:

1. ``registry.PANELS`` has at least the catalogued count and every lazy factory
   resolves to a real :class:`SettingsPanel` subclass with a matching PANEL_ID.
2. Every top-level :class:`AppConfig` field is claimed by some panel — the
   "full coverage" acceptance criterion. The claim map below is the contract;
   if a new config field is added without assigning it to a panel, this test
   fails, forcing the author to surface it in the UI (or explicitly mark it
   non-UI).
3. :class:`SettingsScreen` imports and constructs (import smoke), and the
   back-compat ``from servonaut.screens.settings import SettingsScreen`` path
   still resolves.
"""

from __future__ import annotations

from dataclasses import fields

import pytest

from servonaut.config.schema import AppConfig
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.registry import PANELS, PanelSpec


# Minimum catalogued panel count (the spec's Panel Catalog enumerates 24).
_MIN_PANELS = 24


# Every top-level AppConfig field → the panel id(s) that surface it (or a
# launcher panel that owns the deeper editor). A field mapped to "_no_ui" is
# intentionally not user-editable in Settings (internal counters / bookkeeping).
#
# Nested dataclass fields (aws.*, ovh.*, hetzner.*, etc.) are covered by the
# owning provider panel; only the TOP-LEVEL AppConfig attribute is asserted
# here since that is the unit ConfigManager.update() operates on.
_FIELD_TO_PANEL = {
    "version": "_no_ui",  # schema version, bumped by migrations only
    "default_key": "general",
    "instance_keys": "ssh_keys",
    "default_username": "general",
    "cache_ttl_seconds": "general",
    "default_scan_paths": "scan",
    "scan_rules": "scan",
    "connection_profiles": "connections",
    "connection_rules": "connections",
    "custom_servers": "custom_servers",
    "terminal_emulator": "general",
    "keyword_store_path": "history_paths",
    "command_history_path": "history_paths",
    "max_command_history": "history_paths",
    "theme": "general",
    "log_viewer_default_paths": "log_viewer",
    "log_viewer_custom_paths": "log_viewer",
    "log_viewer_scan_directories": "log_viewer",
    "log_viewer_scan_max_depth": "log_viewer",
    "log_viewer_max_lines": "log_viewer",
    "log_viewer_tail_lines": "log_viewer",
    "cloudtrail_default_region": "cloudtrail",
    "cloudtrail_max_events": "cloudtrail",
    "cloudtrail_default_lookback_hours": "cloudtrail",
    "cloudtrail_default_lookback_minutes": "cloudtrail",
    "cloudwatch_default_region": "cloudwatch",
    "cloudwatch_max_events": "cloudwatch",
    "cloudwatch_log_group_prefix": "cloudwatch",
    "abuseipdb_api_key": "ip_lookup",
    "ip_ban_configs": "ip_ban",
    "ip_ban_audit_path": "ip_ban",
    "db_profiles": "_no_ui",  # managed via the db_setup_* tools, not Settings
    "db_scan_roots": "_no_ui",  # per-instance scan roots, edited via the DB scan-roots screen, not Settings
    "ai_provider": "ai_provider",
    "ai_chunk_size": "ai_chat",
    "ai_system_prompt": "ai_chat",
    "mcp": "mcp",
    "ssh": "_no_ui",  # advanced SSH transport tuning (keepalive/connect timeout); editable via config.json, not surfaced in the Settings TUI
    "voice": "voice",
    "bw_vault_folder": "bw_ssh",  # local vault-folder scope for the Bitwarden SSH picker; surfaced by BwSshPanel
    "relay": "relay",
    "ovh": "ovh",
    "hetzner": "hetzner",
    "aws": "aws",
    "gcp": "gcp",
    "azure": "azure",
    "chat_history_path": "history_paths",
    "chat_max_history_messages": "ai_chat",
    "chat_system_prompt": "ai_chat",
    "chat_max_tool_iterations": "ai_chat",
    "chat_max_tool_rounds": "ai_chat",
    "chat_tool_guard_level": "ai_chat",
    "chat_keep_tool_results": "ai_chat",
    "chat_inject_server_memory": "ai_chat",
    "chat_inject_server_memory_decision": "ai_chat",
    "sync_encryption_enabled": "memory",
    "memory": "memory",
    "memory_first_connect_dismissed_count": "_no_ui",  # dismissal counter
}


def test_panel_count_meets_catalogue():
    """At least the catalogued number of panels are registered."""
    assert len(PANELS) >= _MIN_PANELS, (
        f"expected >= {_MIN_PANELS} panels, found {len(PANELS)}"
    )


def test_every_factory_resolves_to_matching_panel():
    """Each lazy factory imports a SettingsPanel subclass whose PANEL_ID matches."""
    for spec in PANELS:
        assert isinstance(spec, PanelSpec)
        cls = spec.factory()
        assert isinstance(cls, type)
        assert issubclass(cls, SettingsPanel), f"{spec.id} factory is not a SettingsPanel"
        assert cls.PANEL_ID == spec.id, (
            f"PANEL_ID {cls.PANEL_ID!r} != registry id {spec.id!r}"
        )


def test_panel_ids_are_unique():
    """No two registry entries share an id (nav-button id collisions)."""
    ids = [spec.id for spec in PANELS]
    assert len(ids) == len(set(ids)), f"duplicate panel ids: {ids}"


def test_every_appconfig_field_is_claimed_by_a_panel():
    """Every top-level AppConfig field is reachable by some panel (coverage guard).

    If this fails after adding a config field, add the field to
    ``_FIELD_TO_PANEL`` pointing at the panel that surfaces it (or ``"_no_ui"``
    with a justification comment if it is intentionally internal).
    """
    config_field_names = {f.name for f in fields(AppConfig)}
    mapped = set(_FIELD_TO_PANEL)

    unmapped = config_field_names - mapped
    assert not unmapped, (
        f"AppConfig fields with no panel claim (add to _FIELD_TO_PANEL): {sorted(unmapped)}"
    )

    stale = mapped - config_field_names
    assert not stale, (
        f"_FIELD_TO_PANEL references fields not on AppConfig (remove): {sorted(stale)}"
    )


def test_every_claimed_panel_exists_in_registry():
    """Each non-``_no_ui`` panel referenced by the claim map is a real panel id."""
    registry_ids = {spec.id for spec in PANELS}
    claimed = {pid for pid in _FIELD_TO_PANEL.values() if pid != "_no_ui"}
    missing = claimed - registry_ids
    assert not missing, f"claim map points at unregistered panel ids: {sorted(missing)}"


def test_settings_screen_import_smoke():
    """The back-compat export path resolves and SettingsScreen constructs."""
    from servonaut.screens.settings import SettingsScreen

    screen = SettingsScreen()
    assert screen is not None


def test_app_module_imports():
    """The app module imports cleanly with the refactored settings package."""
    import servonaut.app  # noqa: F401

"""Round-trip tests for representative settings panels.

Each test mounts a real :class:`SettingsPanel` inside a minimal Textual host
backed by a real :class:`ConfigManager` pointed at a temp file, then exercises
the full ``load → edit → collect → persist`` contract and asserts:

- scalar / nested values round-trip through the on-disk config, and
- nested fields the panel does NOT expose are PRESERVED across a save
  (the spec's central correctness requirement — a panel saving via
  ``dataclasses.replace`` must never clobber a sibling field a wizard owns).

A panel is driven directly (``panel.load()`` / ``panel.persist()``) after it
has mounted so the editor sub-widgets (``StringListEditor`` / ``KeyValueEditor``)
have attached their rows. Persisting writes through the real ConfigManager, so
re-reading from disk proves the field actually survived serialisation.
"""

from __future__ import annotations

from typing import Optional, Type
from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.widgets import Input, Select, Switch

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import (
    AIProviderConfig,
    AppConfig,
    AWSConfig,
    HetznerConfig,
    IPBanConfig,
    ObjectStorageConfig,
    OVHConfig,
)
from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.panels.ai_chat import AiChatPanel
from servonaut.screens.settings.panels.ai_provider import AiProviderPanel
from servonaut.screens.settings.panels.aws import AwsPanel
from servonaut.screens.settings.panels.connections import ConnectionsPanel
from servonaut.screens.settings.panels.general import GeneralPanel
from servonaut.screens.settings.panels.hetzner import HetznerPanel
from servonaut.screens.settings.panels.ip_ban import IpBanPanel
from servonaut.screens.settings.panels.mcp import McpPanel
from servonaut.screens.settings.panels.ovh import OvhPanel


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _temp_config_manager(tmp_path, config: AppConfig) -> ConfigManager:
    """Return a real ConfigManager whose on-disk path is inside *tmp_path*.

    The config is pre-seeded (in memory) and written to disk so the first
    ``persist`` rotates a backup of a real file, matching production behaviour.
    """
    manager = ConfigManager()
    manager._config_path = tmp_path / "config.json"  # type: ignore[attr-defined]
    manager._config = config  # type: ignore[attr-defined]
    manager.save(config)
    return manager


class _PanelHost(App):
    """Minimal Textual app that mounts exactly one settings panel."""

    CSS_PATH = str(
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "src" / "servonaut" / "app.css"
    )

    def __init__(self, panel_cls: Type[SettingsPanel], manager: ConfigManager) -> None:
        super().__init__()
        self._panel_cls = panel_cls
        self.config_manager = manager
        # Panels reach for these via getattr(..., None); MagicMock keeps the
        # not-configured branches alive without real services.
        self.auth_service = MagicMock()
        self.auth_service.is_authenticated = False
        self.auth_service.has_feature = MagicMock(return_value=False)
        self.aws_object_storage_service = None
        self.hetzner_object_storage_service = None
        self.ovh_object_storage_service = None
        self.panel: Optional[SettingsPanel] = None

    def on_mount(self) -> None:
        self.panel = self._panel_cls()
        self.mount(self.panel)


# ---------------------------------------------------------------------------
# general
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_general_roundtrip(tmp_path):
    """General panel writes scalar fields through to the on-disk config."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(GeneralPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        assert isinstance(panel, GeneralPanel)
        panel.query_one("#general_username", Input).value = "deploy"
        panel.query_one("#general_default_key", Input).value = "~/.ssh/deploy.pem"
        panel.query_one("#general_cache_ttl", Input).value = "900"
        panel.query_one("#general_theme", Select).value = "light"
        panel.persist()
        await pilot.pause()

    reread = ConfigManager()
    reread._config_path = tmp_path / "config.json"  # type: ignore[attr-defined]
    fresh = reread.load()
    assert fresh.default_username == "deploy"
    assert fresh.default_key == "~/.ssh/deploy.pem"
    assert fresh.cache_ttl_seconds == 900
    assert fresh.theme == "light"


@pytest.mark.asyncio
async def test_general_rejects_non_integer_ttl(tmp_path):
    """collect() raises ValidationError on a non-integer cache TTL."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(GeneralPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#general_cache_ttl", Input).value = "not-a-number"
        with pytest.raises(ValidationError) as exc:
            panel.collect()
        assert exc.value.field_id == "general_cache_ttl"


@pytest.mark.asyncio
async def test_general_rejects_empty_username(tmp_path):
    """collect() raises ValidationError when the username is blank."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(GeneralPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#general_username", Input).value = "   "
        with pytest.raises(ValidationError) as exc:
            panel.collect()
        assert exc.value.field_id == "general_username"


# ---------------------------------------------------------------------------
# ai_provider — preserves provider_preference / dismissed_banners / legacy key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ai_provider_preserves_unexposed_fields(tmp_path):
    """Saving the AI provider panel keeps fields it does not expose intact."""
    seeded = AppConfig(
        ai_provider=AIProviderConfig(
            provider="openai",
            openai_api_key="sk-old",
            provider_preference="anthropic",
            local_fallback_provider="ollama",
            dismissed_banners=["ai.banner.paying_twice"],
            api_key="legacy-key",
        )
    )
    manager = _temp_config_manager(tmp_path, seeded)
    app = _PanelHost(AiProviderPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#ai_provider_openai_key").value = "sk-new"
        panel.query_one("#ai_provider_max_tokens", Input).value = "2048"
        panel.persist()
        await pilot.pause()

    fresh = _reload(tmp_path)
    ai = fresh.ai_provider
    # Exposed edits applied.
    assert ai.openai_api_key == "sk-new"
    assert ai.max_tokens == 2048
    # Un-exposed fields preserved — the central correctness invariant.
    assert ai.provider_preference == "anthropic"
    assert ai.local_fallback_provider == "ollama"
    assert ai.dismissed_banners == ["ai.banner.paying_twice"]
    assert ai.api_key == "legacy-key"


@pytest.mark.asyncio
async def test_ai_provider_chat_preference_is_selectable(tmp_path):
    """The editable Chat provider select writes provider_preference, and the
    'no preference' option clears it back to None."""
    from textual.widgets import Select

    seeded = AppConfig(ai_provider=AIProviderConfig(provider="openai"))
    manager = _temp_config_manager(tmp_path, seeded)
    app = _PanelHost(AiProviderPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        # Pick a chat provider and save.
        panel.query_one("#ai_provider_pref_select", Select).value = "servonaut"
        panel.persist()
        await pilot.pause()
        assert _reload(tmp_path).ai_provider.provider_preference == "servonaut"

        # Back to "Ask on first chat" → None.
        panel.query_one("#ai_provider_pref_select", Select).value = ""
        panel.persist()
        await pilot.pause()
        assert _reload(tmp_path).ai_provider.provider_preference is None


@pytest.mark.asyncio
async def test_ai_provider_rejects_bad_temperature(tmp_path):
    """collect() raises ValidationError for an out-of-range temperature."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(AiProviderPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#ai_provider_temperature", Input).value = "9.5"
        with pytest.raises(ValidationError) as exc:
            panel.collect()
        assert exc.value.field_id == "ai_provider_temperature"


# ---------------------------------------------------------------------------
# aws — preserves control-plane role fields not on the panel + secret round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aws_preserves_control_plane_and_roundtrips_secret(tmp_path):
    """AWS save preserves control-plane fields and round-trips an $ENV secret raw."""
    seeded = AppConfig(
        aws=AWSConfig(
            control_plane_role_arn="arn:aws:iam::111:role/Read",
            control_plane_role_arns={"111": "arn:aws:iam::111:role/Read"},
            control_plane_external_id="$CTRL_EXT_ID",
            control_plane_mutate_role_arn="arn:aws:iam::111:role/Write",
            control_plane_mutate_role_arns={"111": "arn:aws:iam::111:role/Write"},
            object_storage=ObjectStorageConfig(),
        )
    )
    manager = _temp_config_manager(tmp_path, seeded)
    app = _PanelHost(AwsPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        # Edit only the S3 secret; leave the control-plane editors untouched.
        panel.query_one("#aws_s3_secret_key").value = "$AWS_SECRET_ACCESS_KEY"
        panel.query_one("#aws_default_region", Input).value = "eu-west-1"
        panel.persist()
        await pilot.pause()

    aws = _reload(tmp_path).aws
    # Edited fields.
    assert aws.default_region == "eu-west-1"
    # Secret stored RAW — never resolved at save time.
    assert aws.object_storage.secret_key == "$AWS_SECRET_ACCESS_KEY"
    # Control-plane fields (not edited via the panel) preserved.
    assert aws.control_plane_role_arn == "arn:aws:iam::111:role/Read"
    assert aws.control_plane_role_arns == {"111": "arn:aws:iam::111:role/Read"}
    assert aws.control_plane_external_id == "$CTRL_EXT_ID"
    assert aws.control_plane_mutate_role_arn == "arn:aws:iam::111:role/Write"
    assert aws.control_plane_mutate_role_arns == {"111": "arn:aws:iam::111:role/Write"}


@pytest.mark.asyncio
async def test_aws_rejects_negative_cache_ttl(tmp_path):
    """collect() raises ValidationError for a negative cache TTL."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(AwsPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#aws_cache_ttl", Input).value = "-1"
        with pytest.raises(ValidationError) as exc:
            panel.collect()
        assert exc.value.field_id == "aws_cache_ttl"


# ---------------------------------------------------------------------------
# ovh — preserves wizard-owned credential secrets
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ovh_preserves_wizard_secrets(tmp_path):
    """OVH save preserves application_secret / consumer_key / client_secret."""
    seeded = AppConfig(
        ovh=OVHConfig(
            enabled=True,
            application_key="app-key",
            application_secret="app-secret",
            consumer_key="$OVH_CONSUMER_KEY",
            client_secret="$OVH_CLIENT_SECRET",
            object_storage=ObjectStorageConfig(),
        )
    )
    manager = _temp_config_manager(tmp_path, seeded)
    app = _PanelHost(OvhPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#ovh_default_username", Input).value = "debian"
        panel.persist()
        await pilot.pause()

    ovh = _reload(tmp_path).ovh
    assert ovh.default_username == "debian"
    # Wizard-owned secrets preserved verbatim (including $ENV raw form).
    assert ovh.application_key == "app-key"
    assert ovh.application_secret == "app-secret"
    assert ovh.consumer_key == "$OVH_CONSUMER_KEY"
    assert ovh.client_secret == "$OVH_CLIENT_SECRET"


# ---------------------------------------------------------------------------
# hetzner — preserves api_token owned by the setup wizard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hetzner_preserves_api_token(tmp_path):
    """Hetzner save preserves the wizard-owned api_token via replace."""
    seeded = AppConfig(
        hetzner=HetznerConfig(
            enabled=True,
            api_token="$HCLOUD_TOKEN",
            object_storage=ObjectStorageConfig(),
        )
    )
    manager = _temp_config_manager(tmp_path, seeded)
    app = _PanelHost(HetznerPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#hetzner_default_username", Input).value = "core"
        panel.persist()
        await pilot.pause()

    hetzner = _reload(tmp_path).hetzner
    assert hetzner.default_username == "core"
    # Wizard-owned token preserved (RAW $ENV form, never resolved).
    assert hetzner.api_token == "$HCLOUD_TOKEN"


# ---------------------------------------------------------------------------
# mcp — list editors round-trip + integer validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_roundtrip_lists_and_guard(tmp_path):
    """MCP panel round-trips guard level, blocklist, allowlist through disk."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(McpPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#mcp_guard_level", Select).value = "dangerous"
        panel.query_one("#mcp_max_output_lines", Input).value = "250"
        panel.persist()
        await pilot.pause()

    mcp = _reload(tmp_path).mcp
    assert mcp.guard_level == "dangerous"
    assert mcp.max_output_lines == 250
    # The default blocklist/allowlist survived the round-trip (non-empty).
    assert mcp.command_blocklist
    assert mcp.command_allowlist


@pytest.mark.asyncio
async def test_mcp_rejects_bad_max_output_lines(tmp_path):
    """collect() raises ValidationError for a non-integer max output lines."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(McpPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#mcp_max_output_lines", Input).value = "abc"
        with pytest.raises(ValidationError) as exc:
            panel.collect()
        assert exc.value.field_id == "mcp_max_output_lines"


# ---------------------------------------------------------------------------
# ai_chat — memory-inject toggle promotes the tri-state consent decision
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ai_chat_inject_toggle_promotes_decision_allowed(tmp_path):
    """Enabling memory inject promotes the decision to 'allowed' on save."""
    seeded = AppConfig(
        chat_inject_server_memory=False,
        chat_inject_server_memory_decision="unset",
    )
    manager = _temp_config_manager(tmp_path, seeded)
    app = _PanelHost(AiChatPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#ai_chat_inject_server_memory", Switch).value = True
        panel.persist()
        await pilot.pause()

    fresh = _reload(tmp_path)
    assert fresh.chat_inject_server_memory is True
    assert fresh.chat_inject_server_memory_decision == "allowed"


@pytest.mark.asyncio
async def test_ai_chat_inject_toggle_promotes_decision_denied(tmp_path):
    """Disabling memory inject promotes the decision to 'denied' on save."""
    seeded = AppConfig(
        chat_inject_server_memory=True,
        chat_inject_server_memory_decision="allowed",
    )
    manager = _temp_config_manager(tmp_path, seeded)
    app = _PanelHost(AiChatPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#ai_chat_inject_server_memory", Switch).value = False
        panel.persist()
        await pilot.pause()

    fresh = _reload(tmp_path)
    assert fresh.chat_inject_server_memory is False
    assert fresh.chat_inject_server_memory_decision == "denied"


@pytest.mark.asyncio
async def test_ai_chat_rejects_bad_chunk_size(tmp_path):
    """collect() raises ValidationError for a non-integer chunk size."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(AiChatPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#ai_chat_chunk_size", Input).value = "lots"
        with pytest.raises(ValidationError) as exc:
            panel.collect()
        assert exc.value.field_id == "ai_chat_chunk_size"


# ---------------------------------------------------------------------------
# connections — profile-reference validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connections_rejects_dangling_profile_reference(tmp_path, config_with_profiles):
    """A connection rule referencing a missing profile fails collect()."""
    manager = _temp_config_manager(tmp_path, config_with_profiles)
    app = _PanelHost(ConnectionsPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        # Drop all profiles in-memory while keeping the rule that references one.
        panel._profiles = []  # type: ignore[attr-defined]
        with pytest.raises(ValidationError) as exc:
            panel.collect()
        assert exc.value.field_id == "rl_profile_name"


@pytest.mark.asyncio
async def test_connections_roundtrip_preserves_profiles_and_rules(tmp_path, config_with_profiles):
    """Persisting the connections panel writes the profile/rule lists to disk."""
    manager = _temp_config_manager(tmp_path, config_with_profiles)
    app = _PanelHost(ConnectionsPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.persist()
        await pilot.pause()

    fresh = _reload(tmp_path)
    assert [p.name for p in fresh.connection_profiles] == ["bastion-prod", "proxy-staging"]
    assert [r.profile_name for r in fresh.connection_rules] == ["bastion-prod", "proxy-staging"]


# ---------------------------------------------------------------------------
# ip_ban — inline-CRUD upsert round-trips through disk
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ip_ban_inline_save_roundtrips(tmp_path):
    """The ip_ban inline form upserts a WAF config that survives to disk."""
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(IpBanPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        # Drive the inline form like the user would, then save.
        panel.query_one("#ipban_input_name", Input).value = "waf-block"
        panel.query_one("#ipban_select_method", Select).value = "waf"
        panel.query_one("#ipban_input_ip_set_id", Input).value = "set-123"
        panel.query_one("#ipban_input_ip_set_name", Input).value = "blocklist"
        panel._handle_ipban_save()  # type: ignore[attr-defined]
        await pilot.pause()

    configs = _reload(tmp_path).ip_ban_configs
    assert any(c.name == "waf-block" and c.method == "waf" for c in configs)
    saved = next(c for c in configs if c.name == "waf-block")
    assert saved.ip_set_id == "set-123"
    assert saved.ip_set_name == "blocklist"


@pytest.mark.asyncio
async def test_ip_ban_remove_roundtrips(tmp_path):
    """Removing a selected ip_ban entry deletes it from the on-disk config."""
    seeded = AppConfig(
        ip_ban_configs=[
            IPBanConfig(name="keep", method="waf", ip_set_id="a", ip_set_name="a"),
            IPBanConfig(name="drop", method="waf", ip_set_id="b", ip_set_name="b"),
        ]
    )
    manager = _temp_config_manager(tmp_path, seeded)
    app = _PanelHost(IpBanPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        # Force the "drop" row to be the selected one.
        panel._get_selected_name = lambda: "drop"  # type: ignore[assignment]
        panel._handle_ipban_remove()  # type: ignore[attr-defined]
        await pilot.pause()

    names = [c.name for c in _reload(tmp_path).ip_ban_configs]
    assert names == ["keep"]


# ---------------------------------------------------------------------------
# Shared reload helper
# ---------------------------------------------------------------------------


def _reload(tmp_path) -> AppConfig:
    """Read the on-disk config back through a fresh ConfigManager."""
    manager = ConfigManager()
    manager._config_path = tmp_path / "config.json"  # type: ignore[attr-defined]
    return manager.load()

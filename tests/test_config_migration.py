"""Tests for configuration migration."""

from servonaut.config.migration import migrate_v1_to_v2, migrate_to_latest, create_backup
from servonaut.config.schema import (
    AppConfig,
    SSHConfig,
    CONFIG_VERSION,
    DEFAULT_AUTO_SCAN_INTERVAL_SECONDS,
)


class TestMigrateV1ToV2:

    def test_preserves_v1_fields(self):
        v1 = {
            'instance_keys': {'i-123': '/key.pem'},
            'default_key': '/default.pem',
        }
        v2 = migrate_v1_to_v2(v1)
        assert v2['instance_keys'] == {'i-123': '/key.pem'}
        assert v2['default_key'] == '/default.pem'

    def test_adds_v2_fields(self):
        v2 = migrate_v1_to_v2({})
        # migrate_v1_to_v2 stamps version=2; migrate_to_latest chains
        # subsequent steps (v2→v3→v4). This split lets each migration step
        # be tested in isolation.
        assert v2['version'] == 2
        assert v2['default_username'] == 'ec2-user'
        assert v2['cache_ttl_seconds'] == 300
        assert v2['scan_rules'] == []
        assert v2['connection_profiles'] == []
        assert v2['connection_rules'] == []
        assert v2['terminal_emulator'] == 'auto'
        assert v2['theme'] == 'dark'

    def test_empty_v1_defaults(self):
        v2 = migrate_v1_to_v2({})
        assert v2['instance_keys'] == {}
        assert v2['default_key'] == ''


class TestMigrateToLatest:

    def test_v1_chains_to_current_version(self):
        v1 = {'instance_keys': {}, 'default_key': ''}
        out = migrate_to_latest(v1)
        assert out['version'] == CONFIG_VERSION

    def test_v3_to_v4_copies_legacy_api_key_into_per_provider_field(self):
        v3 = {
            'version': 3,
            'ai_provider': {'provider': 'anthropic', 'api_key': 'sk-ant-123'},
        }
        out = migrate_to_latest(v3)
        assert out['version'] == CONFIG_VERSION
        assert out['ai_provider']['anthropic_api_key'] == 'sk-ant-123'
        assert out['ai_provider']['openai_api_key'] == ''
        assert out['ai_provider']['gemini_api_key'] == ''
        # Legacy field kept on disk for one release so a CLI rollback
        # doesn't lose the value.
        assert out['ai_provider']['api_key'] == 'sk-ant-123'

    def test_v3_to_v4_does_not_clobber_existing_per_provider_key(self):
        v3 = {
            'version': 3,
            'ai_provider': {
                'provider': 'openai',
                'api_key': 'sk-old',
                'openai_api_key': 'sk-new',
            },
        }
        out = migrate_to_latest(v3)
        assert out['ai_provider']['openai_api_key'] == 'sk-new'

    def test_v3_to_v4_no_op_for_ollama_or_servonaut(self):
        for provider in ('ollama', 'servonaut'):
            v3 = {
                'version': 3,
                'ai_provider': {'provider': provider, 'api_key': ''},
            }
            out = migrate_to_latest(v3)
            assert out['ai_provider']['openai_api_key'] == ''
            assert out['ai_provider']['anthropic_api_key'] == ''
            assert out['ai_provider']['gemini_api_key'] == ''

    def test_already_at_current_version_is_noop(self):
        cfg = {'version': CONFIG_VERSION, 'ai_provider': {}}
        out = migrate_to_latest(cfg)
        assert out['version'] == CONFIG_VERSION

    def test_old_config_without_ssh_key_loads_clean(self):
        """A config that pre-dates the ssh field loads with SSHConfig defaults.

        This verifies the additive convention — CONFIG_VERSION did NOT change
        and no migration step was added; AppConfig(**config_dict) must supply
        the SSHConfig default_factory when the key is absent.
        """
        old_config = {
            'version': CONFIG_VERSION,
            'default_key': '/home/user/.ssh/id_rsa',
            'default_username': 'ec2-user',
            # intentionally NO 'ssh' key
        }
        # Simulate what manager._deserialize does: filter to valid fields and
        # call AppConfig(**config_dict).  The 'ssh' key is absent, so the
        # default_factory must supply an SSHConfig() instance.
        from dataclasses import fields
        valid = {f.name for f in fields(AppConfig)}
        config_dict = {k: v for k, v in old_config.items() if k in valid}
        config = AppConfig(**config_dict)
        assert isinstance(config.ssh, SSHConfig)
        assert config.ssh.server_alive_interval == 30
        assert config.mcp.command_timeout_seconds == 60
        assert config.mcp.transfer_timeout_seconds == 300

    # ------------------------------------------------------------------
    # Back-compat: v2, v3, v4, and no-version configs all land at v5
    # with the new auto-scan fields available at their defaults.
    # ------------------------------------------------------------------

    def _assert_new_fields_at_defaults(self, out: dict) -> None:
        """The new MemoryConfig auto-scan fields are additive.

        The migration does NOT write them into the JSON dict — the
        MemoryConfig dataclass provides defaults when they are absent from
        disk (the _coerce / AppConfig(**dict) path handles this). What we
        assert here is that migrate_to_latest does NOT overwrite them with
        wrong values and that the result is accepted by AppConfig with the
        expected defaults.

        Note: auto_sync_enabled has been relocated to the server-side
        MemorySettings and is no longer a MemoryConfig field.
        """
        from servonaut.config.manager import ConfigManager
        import json
        import tempfile
        import pathlib

        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "cfg.json"
            p.write_text(json.dumps(out))
            mgr = ConfigManager()
            mgr._config_path = p
            mem = mgr.load().memory

        assert mem.auto_scan_enabled is False, (
            "auto_scan_enabled should default False after migration"
        )
        assert mem.auto_scan_interval_seconds == DEFAULT_AUTO_SCAN_INTERVAL_SECONDS, (
            f"auto_scan_interval_seconds should be {DEFAULT_AUTO_SCAN_INTERVAL_SECONDS}"
        )
        assert mem.auto_scan_stale_only is True, (
            "auto_scan_stale_only should default True after migration"
        )

    def test_no_version_config_lands_at_v5_with_new_fields(self):
        """No-version dict (treated as v1) migrates cleanly to v5."""
        no_version = {'instance_keys': {}, 'default_key': ''}
        out = migrate_to_latest(no_version)
        assert out['version'] == 5
        self._assert_new_fields_at_defaults(out)

    def test_v2_config_lands_at_v5_with_new_fields(self):
        """v2 on-disk config migrates to v5 preserving new field defaults."""
        v2 = {
            'version': 2,
            'default_username': 'ec2-user',
            'cache_ttl_seconds': 300,
        }
        out = migrate_to_latest(v2)
        assert out['version'] == 5
        self._assert_new_fields_at_defaults(out)

    def test_v3_config_lands_at_v5_with_new_fields(self):
        """v3 on-disk config migrates to v5 preserving new field defaults."""
        v3 = {
            'version': 3,
            'ai_provider': {'provider': 'openai', 'api_key': ''},
        }
        out = migrate_to_latest(v3)
        assert out['version'] == 5
        self._assert_new_fields_at_defaults(out)

    def test_v4_config_lands_at_v5_with_new_fields(self):
        """v4 on-disk config migrates to v5 preserving new field defaults."""
        v4 = {
            'version': 4,
            'ai_provider': {
                'provider': 'openai',
                'api_key': '',
                'openai_api_key': 'sk-test',
                'anthropic_api_key': '',
                'gemini_api_key': '',
            },
        }
        out = migrate_to_latest(v4)
        assert out['version'] == 5
        self._assert_new_fields_at_defaults(out)

    def test_v4_config_with_existing_memory_block_preserves_fields(self):
        """v4 config with a 'memory' block migrates and preserves memory fields."""
        v4 = {
            'version': 4,
            'ai_provider': {'provider': 'openai'},
            'memory': {
                'enabled': False,
                'redaction_enabled': True,
                'disabled_modules': ['containers'],
            },
        }
        out = migrate_to_latest(v4)
        assert out['version'] == 5
        # Memory fields we put in are still there after migration.
        assert out.get('memory', {}).get('enabled') is False
        assert out.get('memory', {}).get('disabled_modules') == ['containers']
        # New fields absent from disk — defaults picked up via ConfigManager.
        self._assert_new_fields_at_defaults(out)


class TestCreateBackup:

    def test_creates_backup_file(self, tmp_path):
        config_file = tmp_path / 'config.json'
        config_file.write_text('{"test": true}')
        result = create_backup(config_file)
        assert result is True
        backups = list(tmp_path.glob('*.v1.bak.*'))
        assert len(backups) == 1
        assert backups[0].read_text() == '{"test": true}'

    def test_nonexistent_file(self, tmp_path):
        result = create_backup(tmp_path / 'nope.json')
        assert result is False

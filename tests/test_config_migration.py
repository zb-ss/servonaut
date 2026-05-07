"""Tests for configuration migration."""

from servonaut.config.migration import migrate_v1_to_v2, migrate_to_latest, create_backup
from servonaut.config.schema import CONFIG_VERSION


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

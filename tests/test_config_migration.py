"""Tests for configuration migration."""

from servonaut.config.migration import migrate_v1_to_v2, create_backup
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
        assert v2['version'] == CONFIG_VERSION
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

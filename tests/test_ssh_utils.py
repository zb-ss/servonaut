"""Tests for SSH utility functions."""

import os

from servonaut.utils.ssh_utils import (
    expand_key_path,
    validate_key_path,
    get_key_permissions,
    parse_ssh_output,
)


class TestExpandKeyPath:

    def test_expand_tilde(self):
        result = expand_key_path('~/my-key.pem')
        assert result == os.path.expanduser('~/my-key.pem')
        assert '~' not in result

    def test_absolute_path(self):
        assert expand_key_path('/absolute/path.pem') == '/absolute/path.pem'

    def test_env_var(self, monkeypatch):
        monkeypatch.setenv('MY_KEY_DIR', '/custom/keys')
        assert expand_key_path('$MY_KEY_DIR/key.pem') == '/custom/keys/key.pem'


class TestValidateKeyPath:

    def test_existing_file(self, tmp_path):
        key_file = tmp_path / 'test.pem'
        key_file.touch()
        assert validate_key_path(str(key_file)) is True

    def test_nonexistent_file(self):
        assert validate_key_path('/nonexistent/path.pem') is False

    def test_directory_not_file(self, tmp_path):
        assert validate_key_path(str(tmp_path)) is False


class TestGetKeyPermissions:

    def test_permissions_600(self, tmp_path):
        key_file = tmp_path / 'test.pem'
        key_file.touch()
        os.chmod(str(key_file), 0o600)
        assert get_key_permissions(str(key_file)) == '600'

    def test_permissions_400(self, tmp_path):
        key_file = tmp_path / 'test.pem'
        key_file.touch()
        os.chmod(str(key_file), 0o400)
        assert get_key_permissions(str(key_file)) == '400'


class TestParseSshOutput:

    def test_basic(self):
        assert parse_ssh_output('line1\nline2\nline3\n') == ['line1', 'line2', 'line3']

    def test_strips_whitespace(self):
        assert parse_ssh_output('  line1  \n  line2  \n') == ['line1', 'line2']

    def test_skips_empty_lines(self):
        assert parse_ssh_output('line1\n\n\nline2\n') == ['line1', 'line2']

    def test_empty_input(self):
        assert parse_ssh_output('') == []

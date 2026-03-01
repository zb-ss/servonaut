"""Tests for platform utilities."""

from servonaut.utils.platform_utils import (
    get_os,
    command_exists,
    get_home_dir,
    get_ssh_dir,
)


class TestGetOs:

    def test_returns_known_value(self):
        result = get_os()
        assert result in ['linux', 'darwin', 'windows'] or isinstance(result, str)


class TestCommandExists:

    def test_python_exists(self):
        assert command_exists('python3') is True

    def test_nonexistent_command(self):
        assert command_exists('nonexistent_command_xyz_12345') is False


class TestGetHomeDir:

    def test_returns_existing_path(self):
        home = get_home_dir()
        assert home.exists()
        assert home.is_dir()


class TestGetSshDir:

    def test_returns_ssh_path(self):
        ssh_dir = get_ssh_dir()
        assert ssh_dir.name == '.ssh'
        assert ssh_dir.parent == get_home_dir()

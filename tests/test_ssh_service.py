"""Tests for SSH service."""

import os

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from servonaut.services.ssh_service import SSHService
from servonaut.config.schema import AppConfig


class TestSSHService:

    @pytest.fixture
    def mock_config_manager(self):
        manager = MagicMock()
        manager.get.return_value = AppConfig(
            default_key='',
            instance_keys={},
        )
        return manager

    @pytest.fixture
    def ssh_service(self, mock_config_manager, tmp_path):
        service = SSHService(mock_config_manager)
        service._ssh_dir = tmp_path / '.ssh'
        service._ssh_dir.mkdir()
        return service


class TestBuildSshCommand(TestSSHService):

    def test_basic_command(self, ssh_service):
        cmd = ssh_service.build_ssh_command(host='1.2.3.4', username='ec2-user')
        assert cmd[0] == 'ssh'
        assert '-o' in cmd
        assert 'StrictHostKeyChecking=no' in cmd
        assert 'ec2-user@1.2.3.4' in cmd

    def test_with_key_path(self, ssh_service):
        cmd = ssh_service.build_ssh_command(
            host='1.2.3.4',
            username='ec2-user',
            key_path='/path/to/key.pem',
        )
        assert '-i' in cmd
        assert '/path/to/key.pem' in cmd
        assert 'IdentitiesOnly=yes' in cmd

    def test_with_proxy_jump(self, ssh_service):
        cmd = ssh_service.build_ssh_command(
            host='10.0.1.100',
            username='ec2-user',
            proxy_jump='bastion@jump.example.com',
        )
        assert '-J' in cmd
        assert 'bastion@jump.example.com' in cmd

    def test_proxy_args_takes_precedence(self, ssh_service):
        cmd = ssh_service.build_ssh_command(
            host='10.0.1.100',
            username='ec2-user',
            proxy_jump='ignored@host',
            proxy_args=['-o', 'ProxyCommand=ssh -W %h:%p bastion'],
        )
        assert '-J' not in cmd
        assert 'ProxyCommand=ssh -W %h:%p bastion' in cmd

    def test_with_remote_command(self, ssh_service):
        cmd = ssh_service.build_ssh_command(
            host='1.2.3.4',
            username='ec2-user',
            remote_command='ls -la',
        )
        assert cmd[-1] == 'ls -la'

    def test_key_path_tilde_expansion(self, ssh_service):
        cmd = ssh_service.build_ssh_command(
            host='1.2.3.4',
            username='ec2-user',
            key_path='~/my-key.pem',
        )
        key_idx = cmd.index('-i') + 1
        assert '~' not in cmd[key_idx]

    def test_no_key_means_no_identities_only(self, ssh_service):
        cmd = ssh_service.build_ssh_command(host='1.2.3.4', username='ec2-user')
        assert 'IdentitiesOnly=yes' not in cmd


class TestGetKeyPath(TestSSHService):

    def test_returns_instance_key(self, ssh_service, mock_config_manager):
        mock_config_manager.get.return_value = AppConfig(
            instance_keys={'i-abc123': '/path/to/key.pem'},
        )
        assert ssh_service.get_key_path('i-abc123') == '/path/to/key.pem'

    def test_falls_back_to_default_key(self, ssh_service, mock_config_manager):
        mock_config_manager.get.return_value = AppConfig(
            default_key='/default/key.pem',
            instance_keys={},
        )
        assert ssh_service.get_key_path('i-unknown') == '/default/key.pem'

    def test_returns_none_when_no_key(self, ssh_service, mock_config_manager):
        mock_config_manager.get.return_value = AppConfig(
            default_key='',
            instance_keys={},
        )
        assert ssh_service.get_key_path('i-unknown') is None


class TestDiscoverKey(TestSSHService):

    def test_exact_match(self, ssh_service):
        (ssh_service._ssh_dir / 'mykey').touch()
        result = ssh_service.discover_key('mykey')
        assert result is not None
        assert result.endswith('mykey')

    def test_pem_extension(self, ssh_service):
        (ssh_service._ssh_dir / 'mykey.pem').touch()
        result = ssh_service.discover_key('mykey')
        assert result is not None
        assert result.endswith('mykey.pem')

    def test_id_rsa_prefix(self, ssh_service):
        (ssh_service._ssh_dir / 'id_rsa_mykey').touch()
        result = ssh_service.discover_key('mykey')
        assert result is not None
        assert 'id_rsa_mykey' in result

    def test_no_match(self, ssh_service):
        assert ssh_service.discover_key('nonexistent') is None

    def test_empty_key_name(self, ssh_service):
        assert ssh_service.discover_key('') is None

    def test_no_ssh_dir(self, ssh_service):
        ssh_service._ssh_dir = Path('/nonexistent/.ssh')
        assert ssh_service.discover_key('mykey') is None

    def test_fuzzy_match(self, ssh_service):
        (ssh_service._ssh_dir / 'my-custom-mykey-file.pem').touch()
        result = ssh_service.discover_key('mykey')
        assert result is not None


class TestListAvailableKeys(TestSSHService):

    def test_finds_pem_files(self, ssh_service):
        (ssh_service._ssh_dir / 'key1.pem').touch()
        (ssh_service._ssh_dir / 'key2.pem').touch()
        keys = ssh_service.list_available_keys()
        assert len(keys) == 2

    def test_finds_id_rsa(self, ssh_service):
        (ssh_service._ssh_dir / 'id_rsa').touch()
        keys = ssh_service.list_available_keys()
        assert len(keys) == 1

    def test_empty_dir(self, ssh_service):
        assert ssh_service.list_available_keys() == []

    def test_no_ssh_dir(self, ssh_service):
        ssh_service._ssh_dir = Path('/nonexistent/.ssh')
        assert ssh_service.list_available_keys() == []


class TestCheckKeyPermissions(TestSSHService):

    def test_correct_600(self, ssh_service):
        key = ssh_service._ssh_dir / 'key.pem'
        key.touch()
        os.chmod(str(key), 0o600)
        assert ssh_service.check_key_permissions(str(key)) is True

    def test_correct_400(self, ssh_service):
        key = ssh_service._ssh_dir / 'key.pem'
        key.touch()
        os.chmod(str(key), 0o400)
        assert ssh_service.check_key_permissions(str(key)) is True

    def test_wrong_permissions(self, ssh_service):
        key = ssh_service._ssh_dir / 'key.pem'
        key.touch()
        os.chmod(str(key), 0o644)
        assert ssh_service.check_key_permissions(str(key)) is False

    def test_nonexistent_file(self, ssh_service):
        assert ssh_service.check_key_permissions('/nonexistent.pem') is False


class TestCheckSshAgent(TestSSHService):

    def test_agent_running(self, ssh_service, monkeypatch):
        monkeypatch.setenv('SSH_AGENT_PID', '12345')
        assert ssh_service.check_ssh_agent() is True

    def test_agent_not_running(self, ssh_service, monkeypatch):
        monkeypatch.delenv('SSH_AGENT_PID', raising=False)
        assert ssh_service.check_ssh_agent() is False

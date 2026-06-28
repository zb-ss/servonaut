"""Tests for SCP service."""

from servonaut.services.scp_service import SCPService
from servonaut.config.schema import SSHConfig


class TestSCPService:

    def setup_method(self):
        self.scp_service = SCPService()


class TestBuildUploadCommand(TestSCPService):

    def test_basic(self):
        cmd = self.scp_service.build_upload_command(
            local_path='/tmp/file.txt',
            remote_path='/home/ec2-user/',
            host='9.9.9.9',
            username='ec2-user',
        )
        assert cmd[0] == 'scp'
        assert 'StrictHostKeyChecking=no' in cmd
        assert '/tmp/file.txt' in cmd
        assert 'ec2-user@9.9.9.9:/home/ec2-user/' in cmd  # leak-guard:allow (AWS default account, not a personal path)

    def test_includes_keepalive_options(self):
        """SCP base args carry the same keepalive options as SSH."""
        cmd = self.scp_service.build_upload_command(
            local_path='/tmp/file.txt',
            remote_path='/home/ec2-user/',  # leak-guard:allow (AWS default account, not a personal path)
            host='9.9.9.9',
            username='ec2-user',
        )
        assert 'ServerAliveInterval=30' in cmd
        assert 'ServerAliveCountMax=5' in cmd
        assert 'TCPKeepAlive=yes' in cmd
        assert 'ConnectTimeout=15' in cmd

    def test_custom_ssh_config_values_flow_through(self):
        """Custom SSHConfig values are reflected in SCP base args."""
        custom_ssh = SSHConfig(
            server_alive_interval=120,
            server_alive_count_max=2,
            tcp_keepalive=False,
            connect_timeout=10,
        )
        svc = SCPService(ssh_config=custom_ssh)
        cmd = svc.build_upload_command(
            local_path='/tmp/f', remote_path='/remote',
            host='9.9.9.9', username='user',
        )
        assert 'ServerAliveInterval=120' in cmd
        assert 'ServerAliveCountMax=2' in cmd
        assert 'TCPKeepAlive=no' in cmd
        assert 'ConnectTimeout=10' in cmd

    def test_with_key(self):
        cmd = self.scp_service.build_upload_command(
            local_path='/tmp/file.txt',
            remote_path='/home/ec2-user/',
            host='9.9.9.9',
            username='ec2-user',
            key_path='/path/to/key.pem',
        )
        assert '-i' in cmd
        assert '/path/to/key.pem' in cmd
        assert 'IdentitiesOnly=yes' in cmd

    def test_with_proxy_jump(self):
        cmd = self.scp_service.build_upload_command(
            local_path='/tmp/file.txt',
            remote_path='/home/ec2-user/',
            host='10.0.1.1',
            username='ec2-user',
            proxy_jump='bastion@jump.example.com',
        )
        assert '-J' in cmd
        assert 'bastion@jump.example.com' in cmd

    def test_proxy_args_takes_precedence(self):
        cmd = self.scp_service.build_upload_command(
            local_path='/tmp/file.txt',
            remote_path='/home/ec2-user/',
            host='10.0.1.1',
            username='ec2-user',
            proxy_jump='ignored@host',
            proxy_args=['-o', 'ProxyCommand=ssh -W %h:%p bastion'],
        )
        assert '-J' not in cmd
        assert 'ProxyCommand=ssh -W %h:%p bastion' in cmd


class TestBuildDownloadCommand(TestSCPService):

    def test_basic(self):
        cmd = self.scp_service.build_download_command(
            remote_path='/var/log/app.log',
            local_path='/tmp/',
            host='9.9.9.9',
            username='ec2-user',
        )
        assert cmd[0] == 'scp'
        assert 'ec2-user@9.9.9.9:/var/log/app.log' in cmd
        assert '/tmp/' in cmd

    def test_argument_order(self):
        upload = self.scp_service.build_upload_command(
            local_path='/local',
            remote_path='/remote',
            host='9.9.9.9',
            username='user',
        )
        download = self.scp_service.build_download_command(
            remote_path='/remote',
            local_path='/local',
            host='9.9.9.9',
            username='user',
        )
        # Upload: ... local user@host:remote
        assert upload[-2] == '/local'
        assert upload[-1] == 'user@9.9.9.9:/remote'
        # Download: ... user@host:remote local
        assert download[-2] == 'user@9.9.9.9:/remote'
        assert download[-1] == '/local'


class TestSCPServiceDefaults:

    def test_default_constructor_uses_ssh_config_defaults(self):
        """SCPService() with no args uses SSHConfig() defaults."""
        svc = SCPService()
        assert svc._ssh_config.server_alive_interval == 30
        assert svc._ssh_config.server_alive_count_max == 5
        assert svc._ssh_config.tcp_keepalive is True
        assert svc._ssh_config.connect_timeout == 15
        assert svc._transfer_timeout_seconds == 300

    def test_custom_transfer_timeout_stored(self):
        svc = SCPService(transfer_timeout_seconds=600)
        assert svc._transfer_timeout_seconds == 600

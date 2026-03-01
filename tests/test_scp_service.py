"""Tests for SCP service."""

from servonaut.services.scp_service import SCPService


class TestSCPService:

    def setup_method(self):
        self.scp_service = SCPService()


class TestBuildUploadCommand(TestSCPService):

    def test_basic(self):
        cmd = self.scp_service.build_upload_command(
            local_path='/tmp/file.txt',
            remote_path='/home/ec2-user/',
            host='1.2.3.4',
            username='ec2-user',
        )
        assert cmd[0] == 'scp'
        assert 'StrictHostKeyChecking=no' in cmd
        assert '/tmp/file.txt' in cmd
        assert 'ec2-user@1.2.3.4:/home/ec2-user/' in cmd

    def test_with_key(self):
        cmd = self.scp_service.build_upload_command(
            local_path='/tmp/file.txt',
            remote_path='/home/ec2-user/',
            host='1.2.3.4',
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
            host='1.2.3.4',
            username='ec2-user',
        )
        assert cmd[0] == 'scp'
        assert 'ec2-user@1.2.3.4:/var/log/app.log' in cmd
        assert '/tmp/' in cmd

    def test_argument_order(self):
        upload = self.scp_service.build_upload_command(
            local_path='/local',
            remote_path='/remote',
            host='1.2.3.4',
            username='user',
        )
        download = self.scp_service.build_download_command(
            remote_path='/remote',
            local_path='/local',
            host='1.2.3.4',
            username='user',
        )
        # Upload: ... local user@host:remote
        assert upload[-2] == '/local'
        assert upload[-1] == 'user@1.2.3.4:/remote'
        # Download: ... user@host:remote local
        assert download[-2] == 'user@1.2.3.4:/remote'
        assert download[-1] == '/local'

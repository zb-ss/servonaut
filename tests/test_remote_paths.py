"""Read-only remote checks preserve quoting, configuration and Vault identity."""

from types import SimpleNamespace
from unittest.mock import Mock
import shlex
import subprocess

import pytest

from servonaut.config.schema import AppConfig
from servonaut.services.remote_paths import remote_path_kind, remote_home_basename, remote_parent_directory
from servonaut.utils.remote_shell import shell_path


def test_scan_roots_keep_the_configured_first_path():
    from servonaut.screens.file_browser import get_scan_paths_for_instance
    config = AppConfig(default_scan_paths=['/srv/second/', '/srv/first', '/srv/second'])
    assert get_scan_paths_for_instance(config, {}) == ['/srv/second/', '/srv/first/']


@pytest.mark.asyncio
@pytest.mark.parametrize('path', ["/srv/it's a folder", '-leading', '~/path [a]', '/srv/$(touch marker)', '/srv/line\nname'])
@pytest.mark.parametrize('kind', ['directory', 'file', 'other', 'missing'])
async def test_remote_probe_keeps_literal_paths_and_resolved_identity(monkeypatch, path, kind):
    config = AppConfig()
    config.ssh.connect_timeout = 7  # fixture verifies the configured deadline
    app = SimpleNamespace(config_manager=Mock(), ssh_service=Mock())
    app.config_manager.get.return_value = config
    app.ssh_service.build_ssh_command.return_value = ['ssh', 'web-1', 'read-only-check']
    options = dict(
        host='web-1', username='deploy', key_path=None, proxy_args=['-J', 'hop'],
        port=2222, extra_options=['BatchMode=yes'], identity_agent='/tmp/agent.sock',
        identity_file='/tmp/key.pub', certificate_file='/tmp/key-cert.pub',
        known_hosts_file='/tmp/pins',
    )
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=kind, stderr=''))
    monkeypatch.setattr('servonaut.services.remote_paths.run_ssh', run)
    assert await remote_path_kind(app, options, path) == kind
    kwargs = app.ssh_service.build_ssh_command.call_args.kwargs
    assert {key: kwargs[key] for key in options} == options
    command = shlex.split(kwargs['remote_command'])
    assert command[:2] == ['/bin/sh', '-c']
    assert shell_path(path) in command[2]
    assert run.call_args.kwargs['timeout'] == 7


@pytest.mark.asyncio
@pytest.mark.parametrize(('returncode', 'stdout', 'stderr'), [(255, '', 'Authentication failed'), (0, 'unexpected', '')])
async def test_failed_or_unrecognized_probe_is_not_treated_as_missing(monkeypatch, returncode, stdout, stderr):
    app = SimpleNamespace(config_manager=Mock(), ssh_service=Mock())
    app.config_manager.get.return_value = AppConfig()
    app.ssh_service.build_ssh_command.return_value = ['ssh', 'web-1']
    monkeypatch.setattr('servonaut.services.remote_paths.run_ssh', Mock(return_value=SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)))
    with pytest.raises(RuntimeError):
        await remote_path_kind(app, dict(host='web-1', username='deploy'), '/srv/folder')


@pytest.mark.asyncio
@pytest.mark.parametrize(('output', 'expected'), [('/srv/login-home\0', 'login-home'), ('/srv/home with spaces/\0', 'home with spaces'), ('/\0', '.')])
async def test_remote_home_basename_is_read_from_the_resolved_login(monkeypatch, output, expected):
    app = SimpleNamespace(config_manager=Mock(), ssh_service=Mock())
    app.config_manager.get.return_value = AppConfig()
    app.ssh_service.build_ssh_command.return_value = ['ssh', 'web-1']
    monkeypatch.setattr('servonaut.services.remote_paths.run_ssh', Mock(return_value=SimpleNamespace(returncode=0, stdout=output, stderr='')))
    options = dict(host='web-1', username='shared-login', port=2222)
    assert await remote_home_basename(app, options) == expected
    kwargs = app.ssh_service.build_ssh_command.call_args.kwargs
    assert kwargs['username'] == 'shared-login' and kwargs['port'] == 2222
    assert '$HOME' in shlex.split(kwargs['remote_command'])[2]


@pytest.mark.asyncio
@pytest.mark.parametrize('path', ['~', '$HOME', '${HOME}', '.', '..', '/srv/directory/..'])
async def test_up_resolves_home_and_dot_paths_using_the_same_connection(monkeypatch, path):
    app = SimpleNamespace(config_manager=Mock(), ssh_service=Mock())
    app.config_manager.get.return_value = AppConfig()
    app.ssh_service.build_ssh_command.return_value = ['ssh', 'web-1']
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=b'/srv/parent folder\0', stderr=b''))
    monkeypatch.setattr('servonaut.services.remote_paths.run_ssh', run)
    options = dict(host='web-1', username='shared-login', port=2222)
    assert await remote_parent_directory(app, options, path) == '/srv/parent folder'
    kwargs = app.ssh_service.build_ssh_command.call_args.kwargs
    assert {key: kwargs[key] for key in options} == options
    assert f'cd {shell_path(path)} && cd ..' in shlex.split(kwargs['remote_command'])[2]
    assert run.call_args.kwargs['text'] is False


@pytest.mark.asyncio
@pytest.mark.parametrize('output', [b'', b'relative\0', b'/srv/parent', b'/srv/one\0/srv/two\0'])
async def test_up_rejects_an_incomplete_or_ambiguous_parent(monkeypatch, output):
    app = SimpleNamespace(config_manager=Mock(), ssh_service=Mock())
    app.config_manager.get.return_value = AppConfig()
    monkeypatch.setattr('servonaut.services.remote_paths.run_ssh', Mock(return_value=SimpleNamespace(returncode=0, stdout=output, stderr=b'')))
    with pytest.raises(RuntimeError, match='parent folder'):
        await remote_parent_directory(app, {}, '~')


@pytest.mark.asyncio
async def test_remote_parent_timeout_can_be_reported_and_retried(monkeypatch):
    app = SimpleNamespace(config_manager=Mock(), ssh_service=Mock())
    app.config_manager.get.return_value = AppConfig()
    monkeypatch.setattr('servonaut.services.remote_paths.run_ssh', Mock(side_effect=subprocess.TimeoutExpired('ssh', 7)))
    with pytest.raises(RuntimeError, match='Connection timed out'):
        await remote_parent_directory(app, {}, '~')

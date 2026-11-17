"""Copy paths, portable listings and errors remain literal and predictable."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual.widgets import Button, Static
from textual.content import Content

from servonaut.config.schema import SSHConfig
from servonaut.screens.file_browser import build_remote_tree
from servonaut.screens.path_picker import RemotePathPickerModal
from servonaut.screens.scp_folder_confirm import SCPFolderConfirmModal
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.services.remote_paths import remote_path_kind
from servonaut.services.scp_service import SCPService
from servonaut.widgets.remote_tree import RemoteTree
from tests._async_bounds import wait_until
from tests.test_remote_tree_sudo_fallback import _make_tree
from tests.test_remote_tree_workers import TreeApp
from tests.test_scp_browser import OPTIONS
from tests.test_workspace_server_screens import _ServerWorkspaceApp


def _failed_worker(stderr: str):
    return SimpleNamespace(
        name='scp_transfer', is_finished=True, is_cancelled=False,
        error=None, result=(1, '', stderr),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('stderr', ['scp: [/b', 'scp: [link=x'])
async def test_failed_copy_status_accepts_unterminated_markup(stderr, monkeypatch):
    app = _ServerWorkspaceApp(False)
    async with app.run_test() as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        original = Content.from_markup

        def reject_server_markup(text, *args, **kwargs):
            # Server bytes must reach the literal-content sink, even where a
            # particular renderer happens to tolerate this unfinished tag.
            assert stderr not in text, 'server stderr was passed to the markup parser'
            return original(text, *args, **kwargs)

        monkeypatch.setattr(Content, 'from_markup', reject_server_markup)
        worker = _failed_worker(stderr)
        screen._transfer_worker = worker
        screen.on_worker_state_changed(SimpleNamespace(worker=worker))
        assert stderr in screen.query_one('#status_output', Static).render().plain
        assert app._exception is None


def _local_shell_listing(monkeypatch, tree, *, path_prefix: Path | None = None, home: Path | None = None):
    environment = dict(os.environ)
    if path_prefix is not None:
        environment['PATH'] = str(path_prefix) + os.pathsep + os.environ['PATH']
    if home is not None:
        environment['HOME'] = str(home)

    def run(command):
        result = subprocess.run(['/bin/sh', '-c', command], env=environment, capture_output=True, check=False)
        return result.stdout.decode('utf-8', 'surrogateescape'), result.stderr.decode('utf-8', 'replace') if result.returncode else None

    monkeypatch.setattr(tree, '_run_ls', run)


@pytest.mark.parametrize('home_alias', [False, True])
def test_literal_listing_follows_a_symlinked_root(tmp_path, monkeypatch, home_alias):
    target = tmp_path / 'release'
    target.mkdir()
    (target / 'payload.txt').write_bytes(b'fixture')
    link = tmp_path / 'current'
    link.symlink_to(target, target_is_directory=True)
    tree = _make_tree()
    tree._literal_paths = True
    _local_shell_listing(monkeypatch, tree, home=link)
    path = '~' if home_alias else str(link)
    entries = tree._fetch_directory_contents(path)
    assert [(entry['name'], entry['type']) for entry in entries] == [('payload.txt', 'file')]
    assert entries[0]['path'] == path.rstrip('/') + '/payload.txt'


@pytest.mark.skipif(shutil.which('busybox') is None, reason='requires BusyBox ls')
def test_busybox_listing_preserves_literal_names_and_child_link_types(tmp_path, monkeypatch):
    root = tmp_path / 'listing'
    root.mkdir()
    names = ['space name', "it's [1]", 'line\nname', 'back\\slash', 'trailing ']
    for name in names:
        (root / name).write_bytes(b'fixture')
    (root / 'folder').mkdir()
    (root / 'file link').symlink_to(root / names[0])
    (root / 'folder link').symlink_to(root / 'folder', target_is_directory=True)
    (root / 'broken').symlink_to(root / 'missing')
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    wrapper = bin_dir / 'ls'
    wrapper.write_text('#!/bin/sh\nexec ' + shutil.which('busybox') + ' ls "$@"\n')
    wrapper.chmod(0o755)
    tree = _make_tree()
    tree._literal_paths = True
    _local_shell_listing(monkeypatch, tree, path_prefix=bin_dir)
    entries = {entry['name']: entry for entry in tree._fetch_directory_contents(str(root))}
    assert set(entries) == set(names + ['folder', 'file link', 'folder link', 'broken'])
    assert entries['file link']['type'] == 'file'
    assert entries['folder link']['type'] == 'directory'
    assert entries['broken']['type'] == 'other'


def test_portable_listing_fallback_does_not_hide_a_permission_error(monkeypatch):
    tree = _make_tree()
    tree._literal_paths = True
    run = Mock(side_effect=[('', "ls: invalid option -- 'b'"), ('', 'Permission denied'), ('', 'Permission denied')])
    monkeypatch.setattr(tree, '_run_ls', run)
    with pytest.raises(RuntimeError, match='Permission denied'):
        tree._fetch_directory_contents('/srv/folder')


@pytest.mark.asyncio
async def test_shellless_download_keeps_the_previous_single_file_copy(tmp_path, monkeypatch):
    app = _ServerWorkspaceApp(False)
    app.scp_service = Mock(execute_transfer=AsyncMock(return_value=(0, '', '')))
    monkeypatch.setattr('servonaut.services.remote_paths.remote_path_kind', AsyncMock(side_effect=RuntimeError('This service allows sftp connections only')))
    async with app.run_test() as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        screen._transfer_direction = 'download'
        screen._resolved_transfer_options = AsyncMock(return_value=OPTIONS)
        screen._command_for = Mock(return_value=['scp', '--', 'source', 'destination'])
        assert await screen._transfer(app.instances[0], str(tmp_path / 'out'), '/srv/file') == (0, '', '')
        screen._command_for.assert_called_once_with(OPTIONS, str(tmp_path / 'out'), '/srv/file', recursive=False)
        assert 'folder detection' in screen.query_one('#status_output', Static).render().plain.lower()


@pytest.mark.asyncio
async def test_unavailable_upload_collision_check_requires_explicit_consent(tmp_path, monkeypatch):
    folder = tmp_path / 'source'
    folder.mkdir()
    app = _ServerWorkspaceApp(False)
    app.scp_service = Mock(execute_transfer=AsyncMock(return_value=(0, '', '')))
    monkeypatch.setattr('servonaut.services.remote_paths.remote_path_kind', AsyncMock(side_effect=RuntimeError('No POSIX shell')))
    async with app.run_test() as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        screen._resolved_transfer_options = AsyncMock(return_value=OPTIONS)
        screen._command_for = Mock()
        worker = screen.run_worker(screen._transfer(app.instances[0], str(folder), '/srv/destination'), exit_on_error=False)
        await wait_until(lambda: worker.is_finished or isinstance(app.screen, SCPFolderConfirmModal))
        assert isinstance(app.screen, SCPFolderConfirmModal)
        app.screen.action_cancel()
        await wait_until(lambda: worker.is_finished)
        app.scp_service.execute_transfer.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('ending', ['.', '..'])
async def test_typed_dot_folder_collision_checks_the_actual_merge_target(tmp_path, monkeypatch, ending):
    folder = tmp_path / 'site'
    folder.mkdir()
    probe = AsyncMock(return_value='directory')
    monkeypatch.setattr('servonaut.services.remote_paths.remote_path_kind', probe)
    app = _ServerWorkspaceApp(False)
    async with app.run_test() as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        assert await screen._folder_collision(OPTIONS, str(folder) + '/' + ending, '/srv/destination/')
        assert probe.await_args.args[-1].rstrip('/') == '/srv/destination/' + ending


@pytest.mark.parametrize('direction', ['upload', 'download'])
@pytest.mark.parametrize('path', ['$HOME/path [1]', '${HOME}/path [1]'])
def test_copy_normalizes_the_same_home_alias_as_the_remote_probe(monkeypatch, direction, path):
    monkeypatch.setattr('servonaut.utils.scp_client._answers', {'scp': True})
    service = SCPService()
    build = service.build_upload_command if direction == 'upload' else service.build_download_command
    command = build(local_path='/tmp/file', remote_path=path, host='web-1', username='deploy')
    assert next(arg for arg in command if arg.startswith('deploy@web-1:')).startswith('deploy@web-1:~/')


@pytest.mark.parametrize('path', ['~other/path', '~other'])
def test_copy_rejects_named_user_home_expansion(path):
    with pytest.raises(ValueError, match='home'):
        SCPService().build_upload_command('/tmp/file', path, 'web-1', 'deploy')


@pytest.mark.asyncio
async def test_probe_rejects_named_user_home_expansion_before_connecting(monkeypatch):
    app = SimpleNamespace(config_manager=Mock(), ssh_service=Mock())
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout='directory', stderr=''))
    monkeypatch.setattr('servonaut.services.remote_paths.run_ssh', run)
    with pytest.raises(ValueError, match='home'):
        await remote_path_kind(app, OPTIONS, '~other/path')
    run.assert_not_called()


@pytest.mark.asyncio
async def test_remote_picker_shows_a_plain_error_and_logs_the_detail(monkeypatch, caplog):
    raw = "ls: cannot access '/srv/missing': No such file or directory"
    app = _ServerWorkspaceApp(False)
    monkeypatch.setattr(RemoteTree, '_fetch_directory_async', AsyncMock(return_value=[]))
    async with app.run_test() as pilot:
        picker = RemotePathPickerModal(app.instances[0], source=False, root='/srv', options=OPTIONS)
        await app.push_screen(picker)
        await wait_until(lambda: not picker.is_loading())
        picker.on_remote_tree_load_state(RemoteTree.LoadState('/srv/missing', False, raw))
        shown = picker.query_one('#path_picker_error', Static).render().plain
        assert 'ls:' not in shown and '/srv/missing' not in shown
        assert 'folder' in shown.lower()
        assert raw in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['directory', 'file'])
async def test_collision_dialog_names_target_kind_and_explains_link_behavior(kind):
    app = _ServerWorkspaceApp(False)
    target = '/srv/uploads/site'
    async with app.run_test(size=(100, 30)) as pilot:
        modal = SCPFolderConfirmModal(target=target, kind=kind)
        await app.push_screen(modal)
        await pilot.pause()
        shown = '\n'.join(widget.render().plain for widget in modal.query(Static))
        assert target in shown
        assert ('folder' if kind == 'directory' else 'file') in shown.lower()
        if kind == 'directory':
            assert 'links' in shown.lower() and 'followed' in shown.lower()
        else:
            assert 'fail' in shown.lower()
            assert not modal.query('#scp_folder_confirm') or modal.query_one('#scp_folder_confirm', Button).disabled


@pytest.mark.asyncio
async def test_confirmation_target_redraws_in_demo_mode_without_changing_the_path():
    app = _ServerWorkspaceApp(False)
    target = '/srv/1.1.1.1/site'
    async with app.run_test(size=(100, 30)) as pilot:
        modal = SCPFolderConfirmModal(target=target, kind='directory')
        await app.push_screen(modal)
        await pilot.pause()
        label = modal.query_one('#scp_folder_target', Static)
        for key, demo in [('ctrl+shift+d', True), ('ctrl+e', False)]:
            await pilot.press(key)
            await pilot.pause()
            assert app.demo_mode is demo
            assert ('1.1.1.1' in label.render().plain) is not demo
            assert modal._target == target
            assert modal.query_one('#scp_folder_cancel', Button).has_focus


@pytest.mark.parametrize('value', [-1, float('nan'), float('inf'), True, 'invalid'])
def test_listing_allowance_rejects_unbounded_or_invalid_values(value):
    assert SSHConfig(listing_allowance_seconds=value).listing_allowance_seconds == SSHConfig().listing_allowance_seconds


@pytest.mark.parametrize('name', ['x/..', r'x\057..', r'x\000y'])
def test_literal_directory_parser_drops_invalid_basename_records(name):
    tree = _make_tree()
    tree._literal_paths = True
    assert tree._parse_ls_output(f'total 1\n-rw-r--r-- 1 root root 1 Jan 1 00:00 {name}\n', '/srv') == []


@pytest.mark.asyncio
async def test_error_rows_retain_data_and_redraw_on_demo_change(monkeypatch):
    raw = 'Unexpected response for 1.1.1.1'
    tree = _make_tree()
    monkeypatch.setattr(tree, '_fetch_directory_async', AsyncMock(side_effect=RuntimeError(raw)))
    app = TreeApp(tree)
    async with app.run_test() as pilot:
        tree.navigate('/srv')
        await wait_until(lambda: not tree.is_listing)
        error = tree.root.children[0].children[0]
        tree._scrub = lambda text: text.replace('1.1.1.1', '<address>')
        tree.refresh_labels()
        assert '1.1.1.1' not in error.label.plain
        assert error.data and error.data.get('error') == raw


@pytest.mark.asyncio
async def test_transfer_status_is_redrawn_from_raw_text_on_demo_toggle():
    raw = 'scp: 1.1.1.1 failed'
    app = _ServerWorkspaceApp(False)
    async with app.run_test() as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        worker = _failed_worker(raw)
        screen._transfer_worker = worker
        screen.on_worker_state_changed(SimpleNamespace(worker=worker))
        app.demo_mode = True
        app.redaction_service = SimpleNamespace(scrub_stream=lambda text: text.replace('1.1.1.1', '<address>'))
        screen.refresh_after_demo_toggle()
        assert '1.1.1.1' not in screen.query_one('#status_output', Static).render().plain
        app.demo_mode = False
        screen.refresh_after_demo_toggle()
        assert raw in screen.query_one('#status_output', Static).render().plain
        assert worker.result[-1] == raw


def test_listing_deadline_adds_a_configured_allowance(monkeypatch):
    app = _ServerWorkspaceApp(False)
    app.config_manager.get().ssh.connect_timeout = 7
    app.config_manager.get().ssh.listing_allowance_seconds = 19
    assert asdict(app.config_manager.get().ssh)['listing_allowance_seconds'] == 19
    tree = build_remote_tree(app, app.instances[0])
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout='total 0\n', stderr=''))
    monkeypatch.setattr('servonaut.widgets.remote_tree.run_ssh', run)
    tree._run_ls('ls -la /srv')
    assert run.call_args.kwargs['timeout'] == 26


def test_listing_allowance_survives_a_configuration_round_trip(tmp_path):
    from servonaut.config.manager import ConfigManager

    manager = ConfigManager(config_path=tmp_path / 'config.json')
    config = manager.get()
    config.ssh.listing_allowance_seconds = 19
    manager.save(config)
    assert ConfigManager(config_path=tmp_path / 'config.json').load().ssh.listing_allowance_seconds == 19


@pytest.mark.parametrize('direction', ['upload', 'download'])
def test_relative_local_colon_paths_remain_local_operands(direction):
    service = SCPService()
    build = service.build_upload_command if direction == 'upload' else service.build_download_command
    command = build(local_path='backup:1/', remote_path='/srv/file', host='web-1', username='deploy')
    assert command[-2 if direction == 'upload' else -1] == './backup:1/'

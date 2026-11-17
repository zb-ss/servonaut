"""Browse fills one endpoint; recursive copies require explicit collision consent."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from textual.widgets import Button, Input

from servonaut.screens.path_picker import LocalPathPickerModal, RemotePathPickerModal
from servonaut.screens.scp_folder_confirm import SCPFolderConfirmModal
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.widgets.remote_tree import RemoteTree
from tests._async_bounds import wait_until
from tests.test_workspace_server_screens import _ServerWorkspaceApp


OPTIONS = dict(host='web-1', username='deploy', key_path=None, port=2222, proxy_args=[], extra_options=[])


@pytest.mark.asyncio
@pytest.mark.parametrize('upload', [True, False])
@pytest.mark.parametrize('side', ['local', 'remote'])
async def test_browse_changes_only_its_field_returns_focus_and_never_copies(tmp_path, monkeypatch, upload, side):
    app = _ServerWorkspaceApp(False)
    app.scp_service = Mock(execute_transfer=AsyncMock())
    monkeypatch.setattr(RemoteTree, '_fetch_directory_async', AsyncMock(return_value=[]))
    monkeypatch.setattr('servonaut.services.remote_paths.remote_path_kind', AsyncMock(return_value='directory'))
    async with app.run_test(size=(100, 30)) as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        screen._resolved_transfer_options = AsyncMock(return_value=OPTIONS)
        if not upload:
            screen.query_one('#radio_download').value = True
        local = screen.query_one('#local_path_input', Input)
        remote = screen.query_one('#remote_path_input', Input)
        local.value, remote.value = str(tmp_path), '/srv/unchanged'
        before = (local.value, remote.value)
        await pilot.pause()
        await pilot.click(f'#{side}_path_browse')
        picker_class = LocalPathPickerModal if side == 'local' else RemotePathPickerModal
        await wait_until(lambda: isinstance(app.screen, picker_class))
        picker = app.screen
        assert picker.source is ((side == 'local') == upload)
        chosen = str(tmp_path / 'chosen') if side == 'local' else '/srv/chosen/'
        picker.dismiss(chosen)
        field = local if side == 'local' else remote
        await wait_until(lambda: app.screen is screen and not field.disabled and field.has_focus)
        assert field.value == chosen
        assert (remote.value if side == 'local' else local.value) == before[1 if side == 'local' else 0]
        app.scp_service.execute_transfer.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('size', [(160, 50), (100, 30)])
@pytest.mark.parametrize('navigation', [True, False])
async def test_copy_geometry_has_stacked_roles_and_aligned_fixed_browse_buttons(size, navigation):
    app = _ServerWorkspaceApp(navigation)
    async with app.run_test(size=size) as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        for upload in (True, False, True):
            screen.query_one('#radio_upload' if upload else '#radio_download').value = True
            await pilot.pause()
            source, destination = ('local', 'remote') if upload else ('remote', 'local')
            assert screen.query_one(f'#{source}_path_group').region.y < screen.query_one(f'#{destination}_path_group').region.y
            for side in ('local', 'remote'):
                field = screen.query_one(f'#{side}_path_input', Input)
                field.value = '/srv/' + 'long-path/' * 50 + 'report.txt'
                browse = screen.query_one(f'#{side}_path_browse', Button)
                assert field.region.y == browse.region.y
                assert field.region.right < browse.region.x and browse.region.width == 14
                assert screen.region.contains_region(browse.region)
            assert screen.region.contains_region(screen.query_one('#transfer_button', Button).region)


@pytest.mark.asyncio
async def test_active_transfer_freezes_fields_direction_and_browse(tmp_path, monkeypatch):
    app = _ServerWorkspaceApp(False)
    source = tmp_path / 'payload.txt'
    source.write_text('payload')
    gate = asyncio.Event()

    async def transfer(*args):
        await gate.wait()
        return 0, '', ''

    async with app.run_test(size=(100, 30)) as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        monkeypatch.setattr(screen, '_transfer', transfer)
        screen.query_one('#local_path_input', Input).value = str(source)
        screen.query_one('#remote_path_input', Input).value = '/srv/payload.txt'
        screen._start_transfer()
        selectors = ('#local_path_input', '#remote_path_input', '#direction_selector', '#local_path_browse', '#remote_path_browse', '#transfer_button')
        assert all(screen.query_one(selector).disabled for selector in selectors)
        gate.set()
        await wait_until(lambda: screen._transfer_worker.is_finished and not screen.query_one('#transfer_button').disabled)
        assert not any(screen.query_one(selector).disabled for selector in selectors)


@pytest.mark.asyncio
@pytest.mark.parametrize('upload', [True, False])
@pytest.mark.parametrize('confirm', [True, False])
async def test_folder_collision_confirm_or_cancel_never_copies_early(tmp_path, monkeypatch, upload, confirm):
    app = _ServerWorkspaceApp(False)
    app.scp_service = Mock(execute_transfer=AsyncMock(return_value=(0, '', '')))
    folder = tmp_path / 'folder with spaces'
    folder.mkdir()
    destination = tmp_path / 'destination'
    destination.mkdir()
    (destination / folder.name).mkdir()
    probe = AsyncMock(return_value='directory')
    monkeypatch.setattr('servonaut.services.remote_paths.remote_path_kind', probe)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        screen._resolved_transfer_options = AsyncMock(return_value=OPTIONS)
        screen._command_for = Mock(return_value=['scp', '-r', '--', 'source', 'destination'])
        if not upload:
            screen.query_one('#radio_download').value = True
            await pilot.pause()
        local_path = str(folder if upload else destination)
        remote_path = '/srv/destination/' if upload else '/srv/' + folder.name
        screen.query_one('#local_path_input', Input).value = local_path
        screen.query_one('#remote_path_input', Input).value = remote_path
        screen._start_transfer()
        await wait_until(lambda: isinstance(app.screen, SCPFolderConfirmModal))
        await wait_until(lambda: bool(app.screen.query('#scp_folder_confirm')) and app.screen.query_one('#scp_folder_confirm').region.width > 0)
        app.scp_service.execute_transfer.assert_not_awaited()
        assert screen.query_one('#local_path_input', Input).disabled
        await pilot.click('#scp_folder_confirm' if confirm else '#scp_folder_cancel')
        await wait_until(lambda: app.screen is screen and not screen.query_one('#transfer_button').disabled)
        assert screen.query_one('#local_path_input', Input).value == local_path
        assert screen.query_one('#remote_path_input', Input).value == remote_path
        if confirm:
            screen._command_for.assert_called_once_with(OPTIONS, local_path, remote_path, recursive=True)
            app.scp_service.execute_transfer.assert_awaited_once()
        else:
            screen._command_for.assert_not_called()
            app.scp_service.execute_transfer.assert_not_awaited()


@pytest.mark.asyncio
async def test_remote_home_folder_collision_uses_its_actual_basename(tmp_path, monkeypatch):
    (tmp_path / 'login-home').mkdir()
    resolve_home = AsyncMock(return_value='login-home')
    monkeypatch.setattr('servonaut.services.remote_paths.remote_home_basename', resolve_home)
    app = _ServerWorkspaceApp(False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        screen._transfer_direction = 'download'
        assert await screen._folder_collision(OPTIONS, str(tmp_path), '~/')
        resolve_home.assert_awaited_once_with(app, OPTIONS)


@pytest.mark.asyncio
async def test_remote_up_resolves_home_reports_failure_and_retries(monkeypatch):
    app = _ServerWorkspaceApp(False)
    monkeypatch.setattr(RemoteTree, '_fetch_directory_async', AsyncMock(return_value=[]))
    resolve = AsyncMock(side_effect=[RuntimeError('Permission denied'), '/srv'])
    monkeypatch.setattr('servonaut.services.remote_paths.remote_parent_directory', resolve)
    async with app.run_test(size=(100, 30)) as pilot:
        picker = RemotePathPickerModal(app.instances[0], source=False, root='~', options=OPTIONS)
        await app.push_screen(picker)
        await wait_until(lambda: not picker.is_loading())
        picker.action_up()
        await wait_until(lambda: picker._error == 'Permission denied')
        assert picker.query_one('#path_picker_choose', Button).disabled
        picker.action_retry()
        await wait_until(lambda: picker.query_one(RemoteTree).current_path == '/srv' and not picker.is_loading())
        assert picker.query_one('#path_picker_location', Input).value == '/srv'
        assert not picker._error and not app._exception
        assert resolve.await_count == 2
        resolve.assert_awaited_with(app, OPTIONS, '~')


@pytest.mark.asyncio
async def test_remote_go_cancels_a_pending_home_parent_resolution(monkeypatch):
    app = _ServerWorkspaceApp(False)
    monkeypatch.setattr(RemoteTree, '_fetch_directory_async', AsyncMock(return_value=[]))
    started, release = asyncio.Event(), asyncio.Event()

    async def resolve(*args):
        started.set()
        await release.wait()
        return '/srv/stale'

    monkeypatch.setattr('servonaut.services.remote_paths.remote_parent_directory', resolve)
    async with app.run_test(size=(100, 30)) as pilot:
        picker = RemotePathPickerModal(app.instances[0], source=True, root='~', options=OPTIONS)
        await app.push_screen(picker)
        await wait_until(lambda: not picker.is_loading())
        picker.action_up()
        await started.wait()
        assert picker.query_one('#path_picker_choose', Button).disabled
        picker.query_one('#path_picker_location', Input).value = '/srv/chosen'
        picker.action_go()
        release.set()
        await wait_until(lambda: not picker.is_loading())
        await pilot.pause()
        assert picker.query_one(RemoteTree).current_path == '/srv/chosen'
        assert not app._exception


@pytest.mark.asyncio
@pytest.mark.parametrize('remote', [True, False])
async def test_picker_demo_shortcut_preserves_operational_path_and_cursor(tmp_path, monkeypatch, remote):
    app = _ServerWorkspaceApp(False)
    monkeypatch.setattr(RemoteTree, '_fetch_directory_async', AsyncMock(return_value=[]))
    async with app.run_test(size=(100, 30)) as pilot:
        picker = RemotePathPickerModal(app.instances[0], source=True, root='/srv', options=OPTIONS) if remote else LocalPathPickerModal(str(tmp_path), source=True)
        await app.push_screen(picker)
        await wait_until(lambda: not picker.is_loading())
        field = picker.query_one('#path_picker_location', Input)
        tree = picker.query_one('#path_picker_tree')
        tree.focus()
        await pilot.pause()
        raw, cursor = field.value, tree.cursor_node
        for key, demo in [('ctrl+shift+d', True), ('ctrl+e', False)]:
            await pilot.press(key)
            await wait_until(lambda: field.password is demo)
            assert app.demo_mode is demo
            assert field.value == raw and tree.cursor_node is cursor
            assert not app._exception


@pytest.mark.asyncio
@pytest.mark.parametrize('size', [(160, 50), (100, 30)])
@pytest.mark.parametrize('remote', [False, True])
async def test_picker_long_paths_keep_location_selection_and_actions_visible(tmp_path, monkeypatch, size, remote):
    app = _ServerWorkspaceApp(False)
    root = tmp_path.joinpath(*(['nested-folder'] * 20))
    root.mkdir(parents=True)
    (root / 'report.txt').write_bytes(b'fixture')
    monkeypatch.setattr(RemoteTree, '_fetch_directory_async', AsyncMock(return_value=[]))
    async with app.run_test(size=size) as pilot:
        if remote:
            path = '/srv/' + 'nested-folder/' * 30
            picker = RemotePathPickerModal(app.instances[0], source=False, root=path, options=OPTIONS)
        else:
            path = str(root)
            picker = LocalPathPickerModal(path, source=False)
        await app.push_screen(picker)
        await wait_until(lambda: not picker.is_loading())
        await pilot.pause()
        field = picker.query_one('#path_picker_location', Input)
        assert field.value == path
        for selector in ('#path_picker_location', '#path_picker_selected', '#path_picker_cancel', '#path_picker_choose'):
            widget = picker.query_one(selector)
            assert widget.region.width > 0 and picker.region.contains_region(widget.region)
        assert not picker.query_one('#path_picker_choose', Button).disabled

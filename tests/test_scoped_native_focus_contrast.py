"""Native scoped focus stays readable while actions and copy retain their targets."""

from __future__ import annotations

import asyncio
import json
import subprocess
import webbrowser
from unittest.mock import Mock, create_autospec

import keyring
import pytest
from rich.cells import cell_len
from textual import constants
from textual.widgets import Button, Input, RadioButton, RadioSet, Tree

from servonaut.screens.file_browser import FileBrowserScreen
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services.scp_service import SCPService
from servonaut.widgets.remote_tree import RemoteTree
from tests._async_bounds import wait_until
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours
from tests.test_selection_copy import _SelectionScreen, _drag, clipboard  # noqa: F401
from tests.test_server_tool_identity_contrast import _no_external_operations  # noqa: F401
from tests.test_settings_presentation import _tab_to
from tests.test_workspace_server_screens import _ServerWorkspaceApp

pytestmark = pytest.mark.usefixtures("navigation_open")


THEMES = ('ansi-dark', 'ansi-light', 'servonaut', 'servonaut-light')


@pytest.fixture(autouse=True)
def _native_truecolor_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    """Advertise RGB support before each App constructs its native Console."""
    for name in ('NO_COLOR', 'FORCE_COLOR', 'TEXTUAL_THEME'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('TERM', 'xterm-256color')
    monkeypatch.setenv('COLORTERM', 'truecolor')
    assert not constants.FILTERS, 'Clear TEXTUAL_FILTERS before process import'
    assert constants.COLOR_SYSTEM in {'auto', 'truecolor'}, (
        'Clear TEXTUAL_COLOR_SYSTEM before process import'
    )


@pytest.fixture(autouse=True)
def _no_secret_process_or_browser(monkeypatch):
    refused = []

    def refuse(*args, **kwargs):
        refused.append('external boundary')
        raise AssertionError('Use a local fake for the external boundary')

    async def refuse_async(*args, **kwargs):
        refuse()

    for name in ('get_password', 'get_credential', 'set_password', 'delete_password'):
        monkeypatch.setattr(keyring, name, refuse)
    monkeypatch.setattr(subprocess, 'Popen', refuse)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', refuse_async)
    for name in ('open', 'open_new', 'open_new_tab'):
        monkeypatch.setattr(webbrowser, name, refuse)
    yield
    assert not refused


def _palette(app):
    assert not app.no_color and not app.console.no_color
    assert app.console.color_system == 'truecolor' and not constants.FILTERS
    assert constants.COLOR_SYSTEM in {'auto', 'truecolor'}
    palette = app.ansi_theme
    if app.current_theme.ansi:
        assert palette is app._textual_ansi_themes[0 if app.current_theme.dark else 1]
    return palette


def _literal(app, widget, literal, palette):
    """Read complete compositor glyphs, accounting for wide tree icons."""
    bounds = widget.region.intersection(app.screen.region)
    strips = app.screen._compositor.render_strips()
    for y in range(bounds.y, bounds.bottom):
        crop = strips[y].crop(bounds.x, bounds.right)
        index = crop.text.find(literal)
        if index < 0:
            continue
        x = bounds.x + cell_len(crop.text[:index])
        width = cell_len(literal)
        assert strips[y].crop(x, x + width).text == literal
        glyphs = []
        for column in range(x, x + width):
            assert app.get_widget_at(column, y)[0] is widget
            style = app.screen._compositor.get_style_at(column, y)
            fg, bg = _paint_colours(style, palette)
            glyphs.append({'style': str(style), 'bold': bool(style.bold),
                           'underline': bool(style.underline),
                           'foreground': list(fg), 'background': list(bg),
                           'contrast': _contrast(fg, bg)})
        return glyphs, (x, y)
    pytest.fail(f'Complete native label {literal!r} is not painted')


def _paint(app, widget, literal, palette, name, rows, failures):
    assert app.screen.region.contains_region(widget.region)
    glyphs, point = _literal(app, widget, literal, palette)
    rows.append({'stage': name, 'label': literal, 'glyphs': glyphs,
                 'widget': widget.id, 'focused': widget.has_focus,
                 'region': list(widget.region), 'content_region': list(widget.content_region),
                 'theme': app.current_theme.name,
                 'focus_owner': app.focused.id if app.focused else None,
                 'palette_foreground': list(palette.foreground_color),
                 'palette_background': list(palette.background_color)})
    if app.current_theme.ansi:
        if min(g['contrast'] for g in glyphs) < 4.5:
            failures.append([name, 'paired-glyph-contrast', glyphs])
        # Indexed low colors must not be promoted by boldColors terminals.
        if any(g['bold'] for g in glyphs):
            failures.append([name, 'paired-indexed-glyph-bold', glyphs])
    return point


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
async def test_vault_focus_dispatch_keeps_native_action(theme, clipboard, record_property):
    app = _ServerWorkspaceApp(False)
    app.theme = theme
    app.vault_command_service = None
    notify = Mock(wraps=app.notify)
    app.notify = notify
    rows, failures, messages = [], [], {}
    try:
        async with app.run_test(size=(160, 50), message_hook=lambda m: messages.setdefault(id(m), m)) as pilot:
            palette = _palette(app)
            screen = ServerActionsScreen(app.instances[0])
            await app.push_screen(screen)
            await _tab_to(pilot, screen.query_one('#btn_use_vault_key', Button))
            await pilot.hover(offset=(0, 0))
            await pilot.pause()
            button = screen.query_one('#btn_use_vault_key', Button)
            assert button.has_focus and not button.disabled
            geometry = button.region, button.content_region
            _paint(app, button, 'Use vault key', palette, 'vault-focused', rows, failures)
            other = screen.query_one('#btn_ban_ip', Button)
            assert screen.region.contains_region(other.region)
            await pilot.hover(other)
            await pilot.pause()
            assert app.focused is button and other.mouse_hover
            _paint(app, button, 'Use vault key', palette, 'vault-focused-other-hover', rows, failures)
            await pilot.press('enter')
            await wait_until(lambda: sum(c.args == ('Vault services are unavailable.',)
                                        for c in notify.call_args_list) == 1)
            await wait_until(lambda: not button.has_class('-active'))
            assert not any(isinstance(m, Button.Pressed) and m.button is other
                           for m in messages.values())
            await _tab_to(pilot, other)
            await pilot.hover(button)
            await pilot.pause()
            assert app.focused is other and button.mouse_hover and not button.has_focus
            _paint(app, button, 'Use vault key', palette, 'vault-hover-only', rows, failures)
            if app.current_theme.ansi and not all(g['underline'] for g in rows[-1]['glyphs']):
                failures.append(['vault-hover-only', 'missing-native-hover-cue'])
            await _tab_to(pilot, button)
            await pilot.pause()
            assert app.focused is button and button.mouse_hover
            _paint(app, button, 'Use vault key', palette, 'vault-focused-hover', rows, failures)
            if app.current_theme.ansi:
                signatures = [[(g['foreground'], g['background'], g['bold']) for g in rows[i]['glyphs']]
                              for i in (0, 1, 3)]
                assert signatures[0] == signatures[1] == signatures[2]
            assert await pilot.click(button)
            await wait_until(lambda: sum(c.args == ('Vault services are unavailable.',)
                                        for c in notify.call_args_list) == 2)
            presses = [m for m in messages.values() if isinstance(m, Button.Pressed)
                       and m.button is button]
            assert len(presses) == 2 and app.screen is screen
            assert (button.region, button.content_region) == geometry
            assert clipboard.calls == [] and app._exception is None
    finally:
        record_property('scoped_native_vault_focus', json.dumps({'rows': rows, 'failures': failures}))
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
async def test_remote_tree_cursor_navigation_and_copy_remain_native(theme, clipboard, record_property):
    app = _ServerWorkspaceApp(False)
    app.theme = theme
    app.config_manager.get().default_scan_paths = ['/example']
    rows, failures, messages = [], [], {}
    try:
        async with app.run_test(size=(160, 50), message_hook=lambda m: messages.setdefault(id(m), m)) as pilot:
            palette = _palette(app)
            screen = FileBrowserScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            tree = screen.query_one(RemoteTree)
            assert app.focused is tree
            branch = tree.root.children[0]
            tree._cache[branch.data['path']] = [
                {'name': 'readme Ω.txt', 'path': '/example/readme Ω.txt', 'type': 'file', 'size': '128'},
            ]
            await pilot.press('down', 'space')
            await wait_until(lambda: branch.is_expanded and len(branch.children) == 1)
            await pilot.press('down')
            await pilot.pause()
            selected = branch.children[0]
            assert tree.cursor_node is selected
            geometry = tree.region, tree.content_region
            point = _paint(app, tree, 'readme Ω.txt', palette, 'tree-cursor', rows, failures)
            await pilot.press('enter')
            await pilot.pause()
            assert await pilot.click(tree, offset=(point[0] - tree.region.x, point[1] - tree.region.y))
            events = [m for m in messages.values() if isinstance(m, Tree.NodeSelected)
                      and m.control is tree and m.node is selected]
            assert len(events) == 2 and tree.cursor_node is selected
            assert (tree.region, tree.content_region) == geometry
            assert clipboard.calls == []  # Tree deliberately has ALLOW_SELECT=False.
            # A neighboring real editor still copies the fresh native gesture.
            clipboard.succeeds = False
            await app.push_screen(_SelectionScreen())
            await pilot.pause()
            editor = app.screen.query_one('#first')
            await _drag(pilot, editor, (6, 0), (5, 1))
            assert editor.selected_text == 'café\nfirst'
            assert clipboard.calls == ['café\nfirst'] and app.clipboard == 'café\nfirst'
            app.pop_screen()
            await pilot.pause()
            assert app.screen is screen and tree.cursor_node is selected
            assert app._exception is None
    finally:
        record_property('scoped_native_tree_focus', json.dumps({'rows': rows, 'failures': failures}))
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
async def test_scp_native_radioset_focus_direction_and_enter_do_not_transfer(
    theme, clipboard, record_property, tmp_path,
):
    app = _ServerWorkspaceApp(False)
    app.theme = theme
    app.scp_service = create_autospec(SCPService, instance=True, spec_set=True)
    rows, failures, messages = [], [], {}
    try:
        async with app.run_test(size=(160, 50), message_hook=lambda m: messages.setdefault(id(m), m)) as pilot:
            palette = _palette(app)
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            start_transfer = Mock(wraps=screen._start_transfer)
            screen._start_transfer = start_transfer
            radio = screen.query_one('#direction_selector', RadioSet)
            upload = screen.query_one('#radio_upload', RadioButton)
            download = screen.query_one('#radio_download', RadioButton)
            local = screen.query_one('#local_path_input', Input)
            remote = screen.query_one('#remote_path_input', Input)
            source = tmp_path / 'example.txt'
            source.write_text('Local fixture payload')
            local.value, remote.value = str(source), '/example/example.txt'
            await _tab_to(pilot, radio)
            await pilot.pause()
            assert radio.has_focus and not upload.can_focus and not download.can_focus
            geometry = radio.region, upload.region, download.region
            _paint(app, upload, 'Upload (Local → Remote)', palette, 'radio-upload-selected', rows, failures)
            await pilot.press('right')
            await pilot.pause()
            assert screen._transfer_direction == 'upload' and download.has_class('-selected')
            _paint(app, download, 'Download (Remote → Local)', palette, 'radio-download-selected', rows, failures)
            await pilot.press('space')
            await wait_until(lambda: screen._transfer_direction == 'download')
            await pilot.press('up', 'enter')
            await wait_until(lambda: screen._transfer_direction == 'upload')
            assert await pilot.click(download)
            await wait_until(lambda: screen._transfer_direction == 'download')
            changed = [m for m in messages.values() if isinstance(m, RadioSet.Changed)
                       and m.radio_set is radio]
            assert [m.pressed.id for m in changed] == ['radio_download', 'radio_upload', 'radio_download']
            assert radio.has_focus and not upload.has_focus and not download.has_focus
            assert not upload.value and download.value
            assert (radio.region, upload.region, download.region) == geometry
            assert (local.value, remote.value) == (str(source), '/example/example.txt')
            start_transfer.assert_not_called()
            for name in ('build_upload_command', 'build_download_command', 'execute_transfer'):
                getattr(app.scp_service, name).assert_not_called()
            assert clipboard.calls == [] and app._exception is None
    finally:
        record_property('scoped_native_scp_focus', json.dumps({'rows': rows, 'failures': failures}))
    assert not failures, json.dumps(failures)

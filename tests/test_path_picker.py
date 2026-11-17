"""Path selection remains separate from copying, with bounded dialog geometry."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath
from threading import Event
from types import SimpleNamespace

import pytest
from textual.app import App
from textual.widgets import Button, Input

from servonaut.screens.path_picker import LocalPathPickerModal, local_start, remote_parent
from servonaut.styles import CSS_FILES
from servonaut.utils.markup import single_line_text
from servonaut.widgets.local_path_tree import LocalEntry, LocalPathTree, local_display_text
from tests._async_bounds import wait_until
from tests.test_remote_tree_workers import TreeApp


class PickerApp(App):
    CSS_PATH = CSS_FILES

    def __init__(self, picker) -> None:
        super().__init__()
        self.picker = picker
        self.demo_mode = False
        self.redaction_service = SimpleNamespace(scrub_stream=lambda value: value.replace('1.1.1.1', '<address>'))
        self.results = []

    def on_mount(self) -> None:
        self.push_screen(self.picker, self.results.append)


@pytest.mark.parametrize(('path', 'expected'), [
    ('/srv/a/b/', '/srv/a'), ('/srv/', '/'), ('/', '/'),
    ('~/folder/', '~'), ('~', '~'), ('relative/file', 'relative'),
    ('file', '.'), ('', '~'),
])
def test_remote_parent_uses_posix_paths(path, expected):
    assert remote_parent(path) == expected


def test_local_start_handles_files_missing_parents_and_relative_paths(tmp_path, monkeypatch):
    hidden = tmp_path / '.hidden'
    hidden.mkdir()
    source = hidden / 'report.txt'
    source.write_text('payload')
    monkeypatch.chdir(tmp_path)
    assert local_start(str(source), True) == hidden
    assert local_start('.hidden/report.txt', True) == hidden
    assert local_start(str(hidden / 'gone' / 'file'), False) == hidden
    assert local_start('~', False) == Path.home()


def test_embedded_local_home_in_an_error_is_display_only():
    raw = f"Permission denied: '{Path.home() / '.ssh'}'"
    shown = local_display_text(raw)
    assert str(Path.home()) not in shown and '~' in shown
    assert str(Path.home()) in raw
    sibling = str(Path.home()) + '-backup'
    assert local_display_text(sibling) == sibling


def test_path_display_cannot_insert_rows_or_unencodable_bytes():
    raw = 'name\r\n\t\x1b\udcff'
    assert single_line_text(raw) == r'name\r\n\t\x1b\udcff'


def test_local_listing_preserves_hidden_names_and_file_folder_types(tmp_path):
    (tmp_path / '.hidden').mkdir()
    file = tmp_path / "it's [a]\nfile"
    file.write_bytes(b'fixture')
    entries = LocalPathTree._read_directory(tmp_path, False)
    assert {(entry.path.name, entry.is_directory) for entry in entries} == {('.hidden', True), (file.name, False)}
    assert [entry.path for entry in LocalPathTree._read_directory(tmp_path, True)] == [tmp_path / '.hidden']


@pytest.mark.asyncio
async def test_dismissed_local_tree_never_waits_for_thread_to_update_ui(tmp_path, monkeypatch):
    from tests._async_bounds import STEP_TIMEOUT_SECONDS

    started, release, finished = Event(), Event(), Event()

    def read(path, directories_only):
        started.set()
        release.wait(STEP_TIMEOUT_SECONDS)
        finished.set()
        return [LocalEntry(path / 'file.txt', False)]

    monkeypatch.setattr(LocalPathTree, '_read_directory', staticmethod(read))
    tree = LocalPathTree(tmp_path)
    app = TreeApp(tree)
    try:
        async with app.run_test() as pilot:
            await wait_until(started.is_set)
            await tree.remove()
            release.set()
            await wait_until(finished.is_set)
            await pilot.pause()
            assert not tree.is_attached and app._exception is None
    finally:
        release.set()


@pytest.mark.parametrize(('value', 'expected'), [
    ('D:/data/report.txt', 'D:/data'), ('D:/missing/child', 'D:/'),
    ('D:/', 'D:/'), ('C:/work/report.txt', 'C:/work'),
])
def test_local_start_keeps_windows_drive_roots(monkeypatch, value, expected):
    class WindowsPathFixture(PureWindowsPath):
        def expanduser(self):
            return self

        def absolute(self):
            return self

        def is_dir(self):
            return self in {PureWindowsPath('D:/'), PureWindowsPath('D:/data'), PureWindowsPath('C:/work')}

        def is_file(self):
            return self.name == 'report.txt'

        @classmethod
        def home(cls):
            return cls('C:/work')

    monkeypatch.setattr('servonaut.screens.path_picker.Path', WindowsPathFixture)
    assert local_start(value, True) == PureWindowsPath(expected)


@pytest.mark.asyncio
@pytest.mark.parametrize('size', [(160, 50), (100, 30)])
@pytest.mark.parametrize('source', [True, False])
async def test_local_picker_keeps_actions_visible_and_distinguishes_file_and_folder(tmp_path, size, source):
    folder = tmp_path / '.hidden'
    folder.mkdir()
    file = tmp_path / '[b] report with spaces.txt'
    file.write_text('bytes')
    picker = LocalPathPickerModal(str(tmp_path), source=source)
    app = PickerApp(picker)
    async with app.run_test(size=size) as pilot:
        tree = picker.query_one(LocalPathTree)
        await wait_until(lambda: Path(tree.path) == tmp_path and not picker.is_loading() and len(tree.root.children) == 2)
        await pilot.pause()
        choose = picker.query_one('#path_picker_choose', Button)
        for selector in ('#path_picker_location', '#path_picker_go', '#path_picker_up', '#path_picker_cancel', '#path_picker_choose'):
            widget = picker.query_one(selector)
            assert widget.region.width > 0 and picker.region.contains_region(widget.region)
            assert app.get_widget_at(*widget.region.center)[0] is widget
        child = next(node for node in tree.root.children if node.data.path == file)
        tree.move_cursor(child)
        await pilot.pause()
        assert choose.disabled is not source
        assert str(choose.label) == ('Choose file' if source else 'Choose folder')
        folder_node = next(node for node in tree.root.children if node.data.path == folder)
        tree.move_cursor(folder_node)
        await pilot.pause()
        assert not choose.disabled and str(choose.label) == 'Choose folder'
        tree.focus()
        await pilot.press('enter')
        await pilot.pause()
        assert app.screen is picker and folder_node.is_expanded
        await wait_until(lambda: not picker.is_loading())
        await pilot.click(choose)
        await wait_until(lambda: bool(app.results))
        expected = str(folder) if source else str(folder) + picker.separator
        assert app.results == [expected]


@pytest.mark.asyncio
async def test_escape_and_demo_toggle_preserve_raw_path_and_cursor(tmp_path):
    path = tmp_path / '1.1.1.1'
    path.mkdir()
    picker = LocalPathPickerModal(str(path), source=False)
    app = PickerApp(picker)
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: not picker.is_loading())
        field = picker.query_one('#path_picker_location', Input)
        tree = picker.query_one(LocalPathTree)
        cursor = tree.cursor_node
        original = field.value
        field.focus()
        field.cursor_position = 2
        for demo in (True, False):
            app.demo_mode = demo
            picker.refresh_after_demo_toggle()
            assert field.password is demo
            assert field.value == original and field.cursor_position == 2
            assert tree.cursor_node is cursor and Path(tree.path) == path
        await pilot.press('escape')
        await wait_until(lambda: bool(app.results))
        assert app.results == [None]


@pytest.mark.asyncio
async def test_missing_local_location_stays_in_dialog_and_can_recover(tmp_path):
    picker = LocalPathPickerModal(str(tmp_path), source=False)
    app = PickerApp(picker)
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: not picker.is_loading())
        field = picker.query_one('#path_picker_location', Input)
        field.value = str(tmp_path / 'gone')
        await pilot.click('#path_picker_go')
        await wait_until(lambda: bool(picker._error))
        assert app.screen is picker and not app.results
        assert picker.query_one('#path_picker_choose', Button).disabled
        picker.action_choose()
        assert not app.results
        field.value = str(tmp_path)
        await wait_until(lambda: not picker.query_one('#path_picker_go', Button).has_class('-active'))
        await pilot.click('#path_picker_go')
        await wait_until(lambda: not picker._error and not picker.is_loading())
        assert not picker.query_one('#path_picker_choose', Button).disabled


@pytest.mark.asyncio
async def test_local_permission_failure_is_inline_and_retry_restores_selection(tmp_path, monkeypatch):
    original = LocalPathTree._read_directory
    failed = False

    def read(path, directories_only):
        nonlocal failed
        if path == tmp_path and not failed:
            failed = True
            raise PermissionError(13, 'Permission denied', str(path))
        return original(path, directories_only)

    monkeypatch.setattr(LocalPathTree, '_read_directory', staticmethod(read))
    picker = LocalPathPickerModal(str(tmp_path), source=False)
    app = PickerApp(picker)
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: 'Permission denied' in picker._error and not picker.is_loading())
        assert picker.query_one('#path_picker_retry', Button).display
        assert picker.query_one('#path_picker_choose', Button).disabled
        assert not app.results
        picker.action_retry()
        await wait_until(lambda: not picker._error and not picker.is_loading() and not picker.query_one('#path_picker_choose', Button).disabled)
        picker.action_choose()
        await wait_until(lambda: bool(app.results))
        assert app.results == [str(tmp_path) + picker.separator]


@pytest.mark.asyncio
async def test_confirm_does_not_accept_a_previous_cursor_selection(tmp_path):
    paths = [tmp_path / name for name in ('one.txt', 'two.txt')]
    for path in paths:
        path.write_text('fixture')
    picker = LocalPathPickerModal(str(tmp_path), source=True)
    app = PickerApp(picker)
    async with app.run_test() as pilot:
        tree = picker.query_one(LocalPathTree)
        await wait_until(lambda: not picker.is_loading() and len(tree.root.children) == 2)
        tree.move_cursor(tree.root.children[0])
        await pilot.pause()
        tree.move_cursor(tree.root.children[1])
        picker.action_choose()  # highlight delivery has not caught up with the cursor
        assert not app.results
        await pilot.pause()
        picker.action_choose()
        await wait_until(lambda: bool(app.results))
        assert app.results == [str(paths[1])]

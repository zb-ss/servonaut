"""Directory workers cannot duplicate or overwrite another branch's listing."""

from __future__ import annotations

import asyncio
import shlex
from unittest.mock import AsyncMock

import pytest
from textual.app import App, ComposeResult

from tests._async_bounds import wait_until
from tests.test_remote_tree_sudo_fallback import _make_tree


class TreeApp(App):
    def __init__(self, tree):
        super().__init__()
        self._path_tree_widget = tree

    def compose(self) -> ComposeResult:
        yield self._path_tree_widget


def entry(path):
    return {'name': path.rsplit('/', 1)[-1], 'path': path, 'type': 'file', 'size': '4'}


@pytest.mark.asyncio
async def test_multiple_directory_completions_and_cached_reexpansion(monkeypatch):
    tree = _make_tree()
    gates = {'/one': asyncio.Event(), '/two': asyncio.Event()}
    started = []

    async def fetch(path):
        started.append(path)
        await gates[path].wait()
        return [entry(path + '/report.txt')]

    monkeypatch.setattr(tree, '_fetch_directory_async', fetch)
    app = TreeApp(tree)
    async with app.run_test() as pilot:
        nodes = [tree.root.add(path, data={'path': path, 'type': 'directory'}) for path in gates]
        for node in nodes:
            node.expand()
        await wait_until(lambda: len(started) == 2)
        gates['/two'].set()
        await wait_until(lambda: nodes[1].children and nodes[1].children[0].data is not None)
        assert nodes[1].children[0].data['path'] == '/two/report.txt'
        assert nodes[0].children[0].data is None
        gates['/one'].set()
        await wait_until(lambda: not tree.is_listing)
        assert nodes[0].children[0].data['path'] == '/one/report.txt'
        nodes[1].collapse()
        nodes[1].expand()
        await pilot.pause()
        assert len(nodes[1].children) == 1 and started == ['/one', '/two']


@pytest.mark.asyncio
async def test_navigation_ignores_late_cancelled_listing(monkeypatch):
    tree = _make_tree()
    gate = asyncio.Event()
    started = asyncio.Event()

    async def fetch(path):
        if path == '/old':
            started.set()
            try:
                await gate.wait()
            except asyncio.CancelledError:
                await gate.wait()
        return [entry(path + '/file')]

    monkeypatch.setattr(tree, '_fetch_directory_async', fetch)
    app = TreeApp(tree)
    async with app.run_test() as pilot:
        tree.navigate('/old')
        await started.wait()
        old = tree.root.children[0]
        tree.navigate('/new')
        await wait_until(lambda: not tree.is_listing)
        gate.set()
        await pilot.pause()
        assert tree.root.children[0].data['path'] == '/new'
        assert tree.root.children[0].children[0].data['path'] == '/new/file'
        assert old not in tree.root.children


@pytest.mark.asyncio
async def test_failure_retry_and_empty_folder_are_settled_states(monkeypatch):
    tree = _make_tree()
    calls = []

    async def fetch(path):
        calls.append(path)
        if len(calls) == 1:
            raise RuntimeError('Permission denied')
        return []

    monkeypatch.setattr(tree, '_fetch_directory_async', fetch)
    app = TreeApp(tree)
    async with app.run_test() as pilot:
        tree.navigate('/folder')
        await wait_until(lambda: calls and not tree.is_listing)
        assert not tree.selection_ready()
        tree.retry('/folder')
        await wait_until(lambda: len(calls) == 2 and not tree.is_listing and tree.cursor_node is tree.root.children[0])
        assert tree.selection_ready()
        assert tree.root.children[0].children[0].label.plain == '📭 Empty directory'


@pytest.mark.asyncio
async def test_configured_root_must_load_before_it_can_be_confirmed(monkeypatch):
    tree = _make_tree()
    monkeypatch.setattr(tree, '_fetch_directory_async', AsyncMock(return_value=[]))
    app = TreeApp(tree)
    async with app.run_test() as pilot:
        node = tree.root.children[0]
        tree.move_cursor(node)
        await pilot.pause()
        assert not tree.selection_ready()
        node.expand()
        await wait_until(lambda: not tree.is_listing and bool(node.children))
        assert tree.selection_ready()


@pytest.mark.parametrize(('escaped', 'raw'), [
    (r'a\ b', 'a b'), (r'back\\slash', 'back\\slash'),
    (r'line\nname', 'line\nname'), (r'name\033[31m', 'name\x1b[31m'),
    ('café', 'café'),
    (r'caf\303\251', 'café'), (r'trailing\ ', 'trailing '),
    (r'carriage\rname', 'carriage\rname'), (r'opaque\377', 'opaque\udcff'),
])
def test_literal_listing_decodes_escapes_without_changing_operational_paths(escaped, raw):
    tree = _make_tree()
    tree._literal_paths = True
    output = f'total 1\n-rw-r--r-- 1 root root 4 Jan 1 00:00 {escaped}\n'
    rows = tree._parse_ls_output(output, '/srv')
    assert rows[0]['path'] == '/srv/' + raw
    assert '\x1b' not in tree._label(rows[0]['name']).plain
    assert '\n' not in tree._label(rows[0]['name']).plain
    assert '\t' not in tree._label(rows[0]['name']).plain


def test_literal_symlink_types_use_nul_delimited_names(monkeypatch):
    tree = _make_tree()
    tree._literal_paths = True
    rows = [
        {'name': 'file\nlink', 'type': 'directory', 'symlink': True},
        {'name': 'folder link', 'type': 'directory', 'symlink': True},
        {'name': 'broken', 'type': 'directory', 'symlink': True},
    ]
    commands = []

    def run(command):
        commands.append(command)
        return 'file\0file\nlink\0directory\0folder link\0other\0broken\0', None

    monkeypatch.setattr(tree, '_run_ls', run)
    typed = tree._resolve_symlinks(rows, '/srv')
    assert {row['name']: row['type'] for row in typed} == {'file\nlink': 'file', 'folder link': 'directory', 'broken': 'other'}
    assert '\\0' in shlex.split(commands[0])[2]


def test_a_typed_file_location_is_not_an_empty_selectable_folder(monkeypatch):
    tree = _make_tree()
    tree._literal_paths = True
    monkeypatch.setattr(tree, '_run_ls', lambda command: ('-rw-r--r-- 1 root root 4 Jan 1 00:00 /srv/file\n', None))
    with pytest.raises(RuntimeError, match='Not a directory'):
        tree._fetch_directory_contents('/srv/file')

"""Enter in the log viewer's remote file browser adds a file, opens a directory.

The screen says "Enter: add file", but the focused tree bound Enter itself,
so the screen's binding never fired and only ``f`` could add a file.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from textual.app import App

from servonaut.config.schema import AppConfig, CustomServer
from servonaut.screens.log_picker import BrowseRemoteScreen
from servonaut.services.connection_service import ConnectionService
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.ssh_service import SSHService
from servonaut.widgets.remote_tree import RemoteTree

_LISTING = (
    "total 8\n"
    "drwxr-xr-x 2 root root 4096 Jan  1 00:00 nginx\n"
    "-rw-r----- 1 root adm  2048 Jan  1 00:00 syslog\n"
    "lrwxrwxrwx 1 root root   10 Jan  1 00:00 current.log -> app-01.log\n"
    "lrwxrwxrwx 1 root root   12 Jan  1 00:00 archive -> /srv/archive\n"
)


def _fake_ssh(cmd, **kwargs):
    """ls lists _LISTING; the symlink lookup reports current.log as a file link."""
    remote = cmd[-1]
    if remote.startswith("cd "):
        return SimpleNamespace(returncode=0, stdout="current.log\n", stderr="")
    return SimpleNamespace(returncode=0, stdout=_LISTING, stderr="")

_UNSET = "<unset>"


class _BrowseHost(App):
    def __init__(self) -> None:
        super().__init__()
        manager = MagicMock()
        manager.get.return_value = AppConfig(default_username="ec2-user")
        self.config_manager = manager
        self.ssh_service = SSHService(manager)
        self.connection_service = ConnectionService(manager)
        self.demo_mode = False
        self.redaction_service = None
        server = CustomServer(name="web-1", host="10.0.0.5", username="deploy")
        self._instance = CustomServerService(manager).to_instance_dict(server)
        self.result: Optional[str] = _UNSET

    def on_mount(self) -> None:
        def _done(value: Optional[str]) -> None:
            self.result = value

        self.push_screen(BrowseRemoteScreen(self._instance), _done)


def _node(tree: RemoteTree, path: str):
    """The tree node whose data path is *path*."""
    pending = [tree.root]
    while pending:
        node = pending.pop()
        if node.data and node.data.get("path") == path:
            return node
        pending.extend(node.children)
    raise AssertionError(f"no node for {path}")


async def _expand_var_log(app: _BrowseHost, pilot) -> RemoteTree:
    await pilot.pause()
    tree = app.screen.query_one("#browse_tree", RemoteTree)
    tree.focus()
    tree.move_cursor(_node(tree, "/var/log"))
    await pilot.press("enter")
    await app.screen.workers.wait_for_complete()
    await tree.workers.wait_for_complete()
    await pilot.pause()
    return tree


@pytest.mark.asyncio
async def test_enter_on_a_directory_expands_it_and_on_a_file_adds_it():
    app = _BrowseHost()

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_fake_ssh):
        async with app.run_test(headless=True) as pilot:
            tree = await _expand_var_log(app, pilot)

            var_log = _node(tree, "/var/log")
            assert var_log.is_expanded
            assert app.result == _UNSET, "Enter on a directory must not dismiss"

            tree.move_cursor(_node(tree, "/var/log/syslog"))
            await pilot.press("enter")
            await pilot.pause()

    assert app.result == "browse:/var/log/syslog"


@pytest.mark.asyncio
async def test_enter_on_an_expanded_directory_collapses_it():
    app = _BrowseHost()

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_fake_ssh):
        async with app.run_test(headless=True) as pilot:
            tree = await _expand_var_log(app, pilot)
            await pilot.press("enter")
            await pilot.pause()
            assert not _node(tree, "/var/log").is_expanded

    assert app.result == _UNSET


@pytest.mark.asyncio
async def test_d_still_adds_a_directory():
    app = _BrowseHost()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        tree = app.screen.query_one("#browse_tree", RemoteTree)
        tree.focus()
        tree.move_cursor(_node(tree, "/home"))
        await pilot.press("d")
        await pilot.pause()

    assert app.result == "adddir:/home"


@pytest.mark.asyncio
async def test_enter_on_a_symlink_to_a_file_adds_it():
    app = _BrowseHost()

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_fake_ssh):
        async with app.run_test(headless=True) as pilot:
            tree = await _expand_var_log(app, pilot)
            tree.move_cursor(_node(tree, "/var/log/current.log"))
            await pilot.press("enter")
            await pilot.pause()

    assert app.result == "browse:/var/log/current.log"


@pytest.mark.asyncio
async def test_enter_on_a_symlink_to_a_directory_expands_it():
    app = _BrowseHost()

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_fake_ssh):
        async with app.run_test(headless=True) as pilot:
            tree = await _expand_var_log(app, pilot)
            tree.move_cursor(_node(tree, "/var/log/archive"))
            await pilot.press("enter")
            await tree.workers.wait_for_complete()
            await pilot.pause()
            assert _node(tree, "/var/log/archive").is_expanded

    assert app.result == _UNSET


@pytest.mark.asyncio
async def test_enter_does_nothing_here_when_the_tree_is_not_focused():
    app = _BrowseHost()

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_fake_ssh):
        async with app.run_test(headless=True) as pilot:
            tree = await _expand_var_log(app, pilot)
            tree.move_cursor(_node(tree, "/var/log/syslog"))
            app.screen.set_focus(None)
            await pilot.press("enter")
            await pilot.pause()

    assert app.result == _UNSET

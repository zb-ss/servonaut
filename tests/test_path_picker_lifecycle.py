"""A picker can finish starting after it has already been dismissed."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from servonaut.screens.path_picker import LocalPathPickerModal, RemotePathPickerModal
from servonaut.widgets.remote_tree import RemoteTree
from tests._async_bounds import wait_until
from tests.test_workspace_server_screens import _ServerWorkspaceApp


def _picker(kind, app, tmp_path, picker_class=None):
    if kind == "local":
        return (picker_class or LocalPathPickerModal)(str(tmp_path), source=True)
    return (picker_class or RemotePathPickerModal)(
        app.instances[0], source=True, root="/srv",
        options=dict(host="web-1", username="deploy", key_path=None,
                     port=2222, proxy_args=[], extra_options=[]),
    )


@pytest.fixture
def host(monkeypatch):
    monkeypatch.setattr(RemoteTree, "_fetch_directory_async", AsyncMock(return_value=[]))
    return _ServerWorkspaceApp(False)


def _closed_picker(picker_class, close_action):
    class ClosedDuringStartup(picker_class):
        async def on_mount(self):
            if close_action == "escape":
                self.action_cancel()
            else:
                self.dismiss(None)
            # Follow the existing screen-startup regression: dismantle the
            # real children before Textual dispatches inherited mount work.
            await self.remove_children()

    return ClosedDuringStartup


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["local", "remote"])
@pytest.mark.parametrize("close_action", ["dismiss", "escape"])
async def test_picker_closed_during_startup_does_not_crash(host, tmp_path, kind, close_action):
    picker_class = LocalPathPickerModal if kind == "local" else RemotePathPickerModal
    picker = _picker(kind, host, tmp_path, _closed_picker(picker_class, close_action))
    async with host.run_test(size=(100, 30)) as pilot:
        host.push_screen(picker)
        await pilot.pause()
        assert picker not in host.screen_stack
        assert host._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["local", "remote"])
async def test_picker_demo_refresh_after_dismissal_is_harmless(host, tmp_path, kind):
    picker = _picker(kind, host, tmp_path)
    async with host.run_test(size=(100, 30)):
        await host.push_screen(picker)
        await wait_until(lambda: not picker.is_loading())
        await picker.dismiss(None)
        picker.refresh_after_demo_toggle()
        assert picker not in host.screen_stack
        assert host._exception is None

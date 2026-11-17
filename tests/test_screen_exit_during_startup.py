"""Closing the window while the fleet screen starts up must end cleanly.

The desktop window can close right after its first frame, so the app begins to
exit before the fleet screen's mount handlers have run. Textual then dismantles
the screen underneath them, which used to end the process with a traceback.
"""

from __future__ import annotations

import asyncio

import pytest
from textual.app import App
from textual.screen import Screen

from scripts.desktop_probe import child
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.widgets.workspace.screen import WorkspaceScreen
from tests._async_bounds import wait_until


class _ExitsBeforeStartup(InstanceListScreen):
    """Asks the app to exit first, as a closing window does, then lets the
    screen's own start-up handlers run against the dismantled screen."""

    async def on_mount(self) -> None:
        self.app.exit()
        await self.remove_children()


class _ErrorLog(child.ProbeApp):
    def __init__(self) -> None:
        super().__init__()
        self.errors: list[BaseException] = []

    def _handle_exception(self, error: Exception) -> None:
        self.errors.append(error)
        super()._handle_exception(error)


@pytest.mark.asyncio
async def test_fleet_screen_exits_cleanly_when_closed_during_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(child, "InstanceListScreen", _ExitsBeforeStartup)
    app = _ErrorLog()
    async with app.run_test(size=(120, 40)):
        pass
    assert app.errors == []
    assert (app.return_code or 0) == 0


class _ExitsBeforeWorkspaceSetup(WorkspaceScreen):
    async def on_mount(self) -> None:
        self.app.exit()
        await self.remove_children()


@pytest.mark.asyncio
async def test_workspace_screen_skips_setup_once_the_app_is_exiting() -> None:
    errors: list[BaseException] = []

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(_ExitsBeforeWorkspaceSetup())

        def _handle_exception(self, error: Exception) -> None:
            errors.append(error)
            super()._handle_exception(error)

    async with Host().run_test():
        pass
    assert errors == []


class _SlowToCompose(InstanceListScreen):
    """Takes a while to mount its widgets, as the real screen does on a busy machine."""

    async def mount_composed_widgets(self, widgets: list) -> None:
        await asyncio.sleep(0.5)
        await super().mount_composed_widgets(widgets)


@pytest.mark.asyncio
async def test_fleet_screen_skips_startup_when_replaced_before_it_has_composed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(child, "InstanceListScreen", _SlowToCompose)
    app = _ErrorLog()
    async with app.run_test(size=(120, 40)) as pilot:
        # The fleet screen is current as soon as it is pushed, but its widgets
        # are still being composed; navigating away at once dismantles it.
        app.push_screen(_SlowToCompose())
        await wait_until(lambda: type(app.screen) is _SlowToCompose)
        await app.switch_screen(Screen())
        await pilot.pause()
        await pilot.pause()
    assert app.errors == []


@pytest.mark.asyncio
async def test_fleet_screen_skips_startup_when_the_app_shuts_down_before_it_has_composed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(child, "InstanceListScreen", _SlowToCompose)
    app = _ErrorLog()
    async with app.run_test(size=(120, 40)):
        app.push_screen(_SlowToCompose())
        await wait_until(lambda: type(app.screen) is _SlowToCompose)
    assert app.errors == []

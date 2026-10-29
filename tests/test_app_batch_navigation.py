"""Global navigation must not cancel a screen-owned mutation worker."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from textual.screen import ModalScreen, Screen

from servonaut.app import ServonautApp
from servonaut.widgets.sidebar import Sidebar
from tests._async_bounds import wait_until


class _HeldScreen(Screen):
    holding = True

    def navigation_hold_reason(self):
        return "Wait for the selected keys to finish." if self.holding else None


class _App(ServonautApp):
    def on_mount(self, event):
        event.prevent_default()
        self.push_screen(getattr(self, "initial_hold", None) or _HeldScreen())

    async def on_unmount(self, event):
        event.prevent_default()


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation", ["quit", "palette", "sidebar", "settings"])
@pytest.mark.parametrize("confirmation_open", [False, True])
async def test_navigation_keeps_batch_worker_alive(navigation, confirmation_open):
    app = _App()
    release, completed = asyncio.Event(), asyncio.Event()
    async with app.run_test() as pilot:
        screen = app.screen

        async def batch():
            await release.wait()
            completed.set()

        screen.run_worker(batch())
        if confirmation_open:
            await app.push_screen(ModalScreen())
        current = app.screen
        try:
            if navigation == "quit":
                await pilot.press("q")
            elif navigation == "palette":
                await pilot.press("ctrl+p")
            elif navigation == "sidebar":
                app.on_sidebar_navigation_requested(Sidebar.NavigationRequested("nav_list"))
            else:
                app.open_settings_screen()
            await pilot.pause()
            assert not app._exit
            assert app.screen is current
        finally:
            release.set()
        await wait_until(completed.is_set)
        screen.holding = False
        if confirmation_open:
            app.pop_screen()
        await pilot.press("ctrl+p")
        await wait_until(lambda: app.screen.__class__.__name__ == "CommandPalette")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["teams", "vault-review", "vault-delete"])
async def test_real_management_screen_holds_application_navigation(monkeypatch, kind):
    from servonaut.screens.team_management import TeamManagementScreen
    from servonaut.screens.vault import VaultScreen

    screen = TeamManagementScreen() if kind == "teams" else VaultScreen()
    monkeypatch.setattr(type(screen), "compose", lambda self: iter(()))
    monkeypatch.setattr(type(screen), "on_mount", lambda self, event: event.prevent_default())
    if kind == "teams":
        screen._server_busy = True
    elif kind == "vault-review":
        screen._deletion_review_active = True
    else:
        screen._busy_work.append(SimpleNamespace(holds_screen=True))
    app = _App()
    app.initial_hold = screen
    release, completed = asyncio.Event(), asyncio.Event()
    async with app.run_test() as pilot:
        async def batch():
            await release.wait()
            completed.set()

        screen.run_worker(batch())
        try:
            app.on_sidebar_navigation_requested(Sidebar.NavigationRequested("nav_list"))
            await pilot.pause()
            assert app.screen is screen
        finally:
            release.set()
        await wait_until(completed.is_set)

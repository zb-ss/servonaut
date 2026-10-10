"""Vault navigation follows discovery on sidebars that are already mounted.

Discovery answers after the first screen is on display. The sidebars already
mounted, on top of the stack or below it, must show the Vault entries then,
without the user having to switch screens first.
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button

from servonaut.widgets.sidebar import Sidebar

VAULT_NAV_IDS = ("nav_vault", "nav_ca")


class _SidebarScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Sidebar()


class _Host(App):
    vault_available = reactive(False)

    def on_mount(self) -> None:
        self.push_screen(_SidebarScreen())


def _vault_nav_shown(screen: Screen) -> list[bool]:
    return [screen.query_one(f"#{nav_id}", Button).display for nav_id in VAULT_NAV_IDS]


@pytest.mark.asyncio
async def test_open_sidebar_shows_vault_once_discovery_finishes() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert _vault_nav_shown(screen) == [False, False]

        app.vault_available = True
        await pilot.pause()
        assert _vault_nav_shown(screen) == [True, True]

        app.vault_available = False
        await pilot.pause()
        assert _vault_nav_shown(screen) == [False, False]


@pytest.mark.asyncio
async def test_sidebar_below_the_top_screen_follows_discovery_too() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        below = app.screen
        await app.push_screen(_SidebarScreen())
        await pilot.pause()

        app.vault_available = True
        await pilot.pause()
        assert _vault_nav_shown(app.screen) == [True, True]
        app.pop_screen()
        await pilot.pause()
        assert app.screen is below
        assert _vault_nav_shown(below) == [True, True]


@pytest.mark.asyncio
async def test_sidebar_composed_after_discovery_starts_with_vault_shown() -> None:
    app = _Host()
    app.vault_available = True
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert _vault_nav_shown(app.screen) == [True, True]

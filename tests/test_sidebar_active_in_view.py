"""The sidebar scrolls its active entry into view when a screen opens.

On a short terminal the expanded section can reach below the fold; the entry
for the screen being shown must still be visible.
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Button

from servonaut.widgets.sidebar import Sidebar


class IPBanScreen(Screen):
    """Named like the real screen, which is how the sidebar finds its entry."""

    def compose(self) -> ComposeResult:
        yield Sidebar()


class InstanceListScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Sidebar()


class _Host(App):
    def __init__(self, screen: type) -> None:
        super().__init__()
        self._first = screen

    def on_mount(self) -> None:
        self.push_screen(self._first())


async def _visible_in_sidebar(pilot, button_id: str) -> bool:
    for _ in range(5):
        await pilot.pause()
    screen = pilot.app.screen
    button = screen.query_one(f"#{button_id}", Button)
    viewport = screen.query_one("#sidebar-scroll").region
    return viewport.contains_region(button.region)


@pytest.mark.asyncio
async def test_an_entry_below_the_fold_is_scrolled_into_view() -> None:
    app = _Host(IPBanScreen)
    async with app.run_test(size=(100, 24)) as pilot:
        assert await _visible_in_sidebar(pilot, "nav_ip_ban")


@pytest.mark.asyncio
async def test_an_entry_already_in_view_leaves_the_sidebar_at_the_top() -> None:
    app = _Host(InstanceListScreen)
    async with app.run_test(size=(100, 24)) as pilot:
        assert await _visible_in_sidebar(pilot, "nav_list")
        assert pilot.app.screen.query_one("#sidebar-scroll").scroll_y == 0

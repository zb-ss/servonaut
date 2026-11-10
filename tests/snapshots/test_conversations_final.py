"""Previous chats at 100x30 with the navigation shown: the actions stay on screen."""

from __future__ import annotations

import asyncio

import pytest

from servonaut.screens.ai_conversations_screen import AIConversationsScreen

from . import _harness

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.mark.parametrize("tab, prefix", [("tab_cloud", "convs"), ("tab_local", "local")])
@pytest.mark.parametrize("size", [(100, 30), (100, 24), (90, 30)])
def test_the_actions_stay_inside_the_visible_content(tab: str, prefix: str, size: tuple) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp()
        async with app.run_test(size=size) as pilot:
            await _harness.wait_for_fleet(pilot)
            await app.push_screen(AIConversationsScreen())
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen.query_one("#convs_tabs").active = tab
            await pilot.pause()
            await pilot.pause()
            assert screen.query_one("Sidebar").display
            container = screen.query_one("#convs_container")
            actions = screen.query_one(f"#{prefix}_actions")
            for button in actions.query("ActionButton"):
                region = button.region
                assert region.width > 0 and region.height > 0, button.id
                assert container.region.contains_region(region), (button.id, region, container.region)
            table = screen.query_one(f"#{prefix}_scroll")
            assert table.region.height >= 3

    asyncio.run(main())

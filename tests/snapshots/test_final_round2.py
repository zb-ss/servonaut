"""Second pass over the sentence-case sweep: SCP roles, Appearance header, fleet columns."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from textual.widgets import RadioSet, Static

from servonaut.screens.scp_transfer import SCPTransferScreen, path_roles

from . import _harness


def _on(factory: Callable[[], Any], check: Callable[[Any, Any], Awaitable[None]], size=(160, 50)) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp()
        async with app.run_test(size=size) as pilot:
            await _harness.wait_for_fleet(pilot)
            await app.push_screen(factory())
            await pilot.pause()
            await pilot.pause()
            await check(pilot, app.screen)

    asyncio.run(main())


def test_the_transfer_roles_read_the_same_after_toggling_both_ways() -> None:
    async def check(pilot: Any, screen: Any) -> None:
        local = screen.query_one("#local_path_role", Static)
        remote = screen.query_one("#remote_path_role", Static)
        opened = (local.visual.plain, remote.visual.plain)
        assert opened == path_roles(True)
        buttons = screen.query_one("#direction_selector", RadioSet)
        buttons.query_one("#radio_download").value = True
        await pilot.pause()
        assert (local.visual.plain, remote.visual.plain) == path_roles(False)
        buttons.query_one("#radio_upload").value = True
        await pilot.pause()
        assert (local.visual.plain, remote.visual.plain) == opened

    _on(lambda: SCPTransferScreen({"id": "web-1", "name": "web-1"}), check)


def test_the_appearance_title_and_description_use_the_shared_header_styles() -> None:
    from servonaut.screens.settings.shell import SettingsScreen

    async def check(pilot: Any, screen: Any) -> None:
        heading = screen.query_one("#appearance_heading")
        title = heading.query(".panel-title").first(Static)
        description = screen.query_one("#appearance_description", Static)
        assert title.styles.text_style.bold
        assert not description.styles.text_style.bold
        assert description.styles.color != title.styles.color
        # No row of its own above the title: it shares the row with the buttons.
        assert tuple(title.styles.margin) == (0, 0, 0, 0)
        assert title.region.y <= description.region.y

    _on(lambda: SettingsScreen("appearance"), check)


def _appearance(size: tuple[int, int], *, navigation: str) -> tuple[bool, int, int]:
    """(preview beside the cards, card columns, panel width) for a terminal size."""
    from servonaut.screens.settings.shell import SettingsScreen

    result: list = []

    async def main() -> None:
        app = _harness.SnapshotApp()
        async with app.run_test(size=size) as pilot:
            await _harness.wait_for_fleet(pilot)
            if navigation == "hidden":
                await pilot.click("#workspace_navigation")
                await pilot.pause()
            await app.push_screen(SettingsScreen("appearance"))
            await _harness.wait_until(pilot, lambda: app.screen.query("#appearance_cards"), "the cards")
            await pilot.pause()
            await pilot.pause()
            panel = app.screen.query_one("AppearancePanel")
            side = app.screen.query_one("#appearance_layout").has_class("-side")
            result.append((side, panel.card_columns, panel.size.width))

    asyncio.run(main())
    return result[0]


def test_appearance_at_160x50_with_the_navigation_open_has_two_columns_and_the_preview_beside() -> None:
    side, columns, width = _appearance((160, 50), navigation="open")
    assert (side, columns) == (True, 2), width


def test_appearance_at_160x50_with_the_navigation_hidden_has_two_columns_and_the_preview_beside() -> None:
    side, columns, width = _appearance((160, 50), navigation="hidden")
    assert (side, columns) == (True, 2), width


def test_appearance_at_100x30_stacks_the_preview_and_keeps_two_columns() -> None:
    side, columns, width = _appearance((100, 30), navigation="open")
    assert not side and columns >= 2, width

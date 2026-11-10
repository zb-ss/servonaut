"""Settings, Help and Previous chats use the shared screen header classes."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from textual.widgets import Static

from servonaut.screens.ai_conversations_screen import AIConversationsScreen
from servonaut.screens.help import HelpScreen
from servonaut.screens.settings.shell import SettingsScreen

from . import _harness


def _on(screen_factory: Callable[[], Any], check: Callable[[Any], Awaitable[None]]) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp()
        async with app.run_test(size=(160, 50)) as pilot:
            await _harness.wait_for_fleet(pilot)
            await app.push_screen(screen_factory())
            await _harness.wait_until(pilot, lambda: app.screen.query(".screen-title, .screen-description"), "the header")
            await pilot.pause()
            await check(app.screen)

    asyncio.run(main())


def test_the_settings_panel_title_and_description_are_shared_header_classes() -> None:
    async def check(screen: Any) -> None:
        title = screen.query(".panel-title").first(Static)
        assert title.has_class("screen-title")
        assert title.styles.text_style.bold
        for description in screen.query(".panel-description"):
            assert description.has_class("screen-description")

    _on(lambda: SettingsScreen("general"), check)


def test_the_help_hint_is_a_shared_description() -> None:
    async def check(screen: Any) -> None:
        assert screen.query_one("#help_navigation_hint").has_class("screen-description")

    _on(HelpScreen, check)


def test_previous_chats_title_and_subtitle_are_shared_header_classes() -> None:
    async def check(screen: Any) -> None:
        assert screen.query_one("#convs_title").has_class("screen-title")
        assert screen.query_one("#convs_subtitle").has_class("screen-description")
        assert screen.query_one("#convs_title", Static).styles.border_bottom[0] in ("", "none")

    _on(AIConversationsScreen, check)

"""The SSH CA screen keeps every action reachable on a short terminal."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult

from servonaut.screens.ca import CaScreen
from servonaut.styles import CSS_FILES


@pytest.mark.asyncio
async def test_ca_actions_scroll_into_reach_at_100x30() -> None:
    class _Harness(App):
        CSS_PATH = CSS_FILES

        def __init__(self) -> None:
            super().__init__()
            self.vault_command_service = None
            self.config_manager = SimpleNamespace(get=lambda: SimpleNamespace())

        def on_mount(self) -> None:
            self.push_screen(CaScreen())

    app = _Harness()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        content = app.screen.query_one("#ca_content")
        scan = app.screen.query_one("#ca_break_glass_scan")

        assert content.styles.overflow_y == "auto"
        assert content.max_scroll_y > 0  # the column is taller than the terminal
        content.scroll_to_widget(scan, animate=False)
        await pilot.pause()
        assert content.scroll_y > 0
        assert scan.region.bottom <= content.region.bottom

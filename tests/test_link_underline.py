"""The workspace's text controls underline their words and nothing else."""

from __future__ import annotations

import pytest
from rich.cells import cell_len
from textual.app import App, ComposeResult
from textual.geometry import Region
from textual.widgets import Button

from servonaut.styles import CSS_FILES
from servonaut.widgets.workspace import WorkspaceControls


class _ControlsApp(App):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        yield WorkspaceControls("Fleet")


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", ["#workspace_navigation", "#workspace_chat", "#workspace_chat_end"])
async def test_workspace_controls_underline_only_their_words(selector: str) -> None:
    app = _ControlsApp()
    async with app.run_test(size=(100, 20)) as pilot:
        await pilot.pause()
        control = app.query_one(selector, Button)
        label = control.label.plain
        underlined = ""
        for strip in control.render_lines(Region(0, 0, control.size.width, control.size.height)):
            for segment in strip:
                if segment.style is not None and segment.style.underline:
                    underlined += segment.text
        assert underlined == label
        assert cell_len(underlined) == cell_len(label)

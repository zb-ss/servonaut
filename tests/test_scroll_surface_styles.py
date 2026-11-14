"""Scrolling content widgets keep the surface while page scrollers blend in.

Every Textual widget that scrolls its own content is also a
``ScrollableContainer`` to the stylesheet, so a type rule for page scrollers
reaches trees, logs, text areas and the open Select list too.
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.color import Color
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Log, OptionList, RichLog, Select, TextArea, Tree
from textual.widgets._select import SelectOverlay

from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_DARK, SERVONAUT_LIGHT


class _StyledHost(App):
    CSS_PATH = CSS_FILES

    def __init__(self, theme_name: str) -> None:
        super().__init__()
        self._theme_name = theme_name

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="page"):
            yield Tree("root")
            yield RichLog()
            yield Log()
            yield TextArea()
            yield OptionList("one")
            yield DataTable()
            yield Select([("one", 1), ("two", 2)], id="pick")

    def on_mount(self) -> None:
        for theme in (SERVONAUT_DARK, SERVONAUT_LIGHT):
            self.register_theme(theme)
        self.theme = self._theme_name


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", [SERVONAUT_DARK.name, SERVONAUT_LIGHT.name])
async def test_content_scrollers_keep_the_surface(theme: str) -> None:
    app = _StyledHost(theme)
    async with app.run_test(size=(80, 40)) as pilot:
        app.query_one("#pick", Select).expanded = True
        await pilot.pause()
        surface = Color.parse(app.get_css_variables()["surface"])

        for widget_type in (Tree, RichLog, Log, TextArea, OptionList, SelectOverlay):
            for widget in app.query(widget_type):
                assert widget.styles.background == surface, widget_type.__name__

        # The redesign's page scrollers and tables stay transparent.
        assert app.query_one("#page", VerticalScroll).styles.background.a == 0
        assert app.query_one(DataTable).styles.background.a == 0

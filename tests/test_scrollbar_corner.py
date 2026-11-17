"""The square where two scrollbars meet is not painted black."""
from __future__ import annotations

import pytest
from textual.app import App
from textual.widgets import DataTable

from servonaut.styles import CSS_FILES


class _Host(App):
    CSS_PATH = CSS_FILES

    def compose(self):
        table = DataTable(id="table")
        table.add_columns(*[f"column {i}" for i in range(12)])
        for row in range(30):
            table.add_row(*[f"{row}-{col} value" for col in range(12)])
        yield table


@pytest.mark.asyncio
async def test_the_scrollbar_corner_is_not_black() -> None:
    app = _Host()
    async with app.run_test(size=(60, 14)) as pilot:
        await pilot.pause(0.5)
        table = app.query_one("#table", DataTable)
        assert table.show_vertical_scrollbar and table.show_horizontal_scrollbar
        x, y = table.region.right - 1, table.region.bottom - 1
        strip = app.screen._compositor.render_strips()[y]
        cell = strip.crop(x, x + 1)
        colour = next(iter(cell)).style.bgcolor.get_truecolor()
        assert (colour.red, colour.green, colour.blue) != (0, 0, 0)

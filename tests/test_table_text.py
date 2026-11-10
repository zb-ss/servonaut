"""Theme-coloured table cells: colour, modifiers and the live theme switch."""

from __future__ import annotations

import pytest
from textual.app import App
from textual.widgets import DataTable

from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.utils.table_text import rebuild_keeping_cursor, themed_cell


class _Host(App):
    def on_mount(self) -> None:
        for theme in SERVONAUT_THEMES:
            self.register_theme(theme)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"],
)
async def test_cell_keeps_colour_and_bold_in_every_theme(name: str) -> None:
    app = _Host()
    async with app.run_test() as pilot:
        app.theme = name
        await pilot.pause()
        cell = themed_cell(app, "critical", "bold $text-error")
        style = cell.style
        assert cell.plain == "critical"
        assert "bold" in str(style)
        colour = str(style).replace("bold", "").strip()
        assert colour, f"no colour kept in {name}"
        # Rich only accepts its own spelling of a colour: this must not raise.
        from rich.style import Style

        assert Style.parse(str(style)).color is not None
        assert "ansi_" not in str(style)


@pytest.mark.asyncio
async def test_unknown_token_keeps_the_modifiers_only() -> None:
    app = _Host()
    async with app.run_test():
        cell = themed_cell(app, "x", "bold $no-such-token")
        assert str(cell.style) == "bold"


def test_outside_text_is_shown_verbatim() -> None:
    app = _Host()
    assert themed_cell(app, "a [link=").plain == "a [link="


class _TableHost(_Host):
    def compose(self):
        yield DataTable()


@pytest.mark.asyncio
async def test_rebuild_after_a_theme_switch_restyles_cells_and_keeps_the_cursor() -> None:
    app = _TableHost()
    async with app.run_test() as pilot:
        table = app.query_one(DataTable)
        table.add_column("c", width=10)

        def fill() -> None:
            table.clear()
            for _ in range(3):
                table.add_row(themed_cell(app, "high", "$text-error"))

        fill()
        table.move_cursor(row=2)
        before = str(table.get_row_at(0)[0].style)
        app.theme = "servonaut-light"
        await pilot.pause()
        rebuild_keeping_cursor(table, fill)
        assert str(table.get_row_at(0)[0].style) != before
        assert table.cursor_row == 2

"""Shared foundations: button roles, table cursor and header, screen header, navigation."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.color import Color
from textual.widgets import Button, DataTable

from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES


class _ThemedApp(App):
    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        for theme in SERVONAUT_THEMES:
            self.register_theme(theme)


class _RolesApp(_ThemedApp):
    def compose(self) -> ComposeResult:
        yield Button("Holder", id="holder")
        yield Button("Neutral", id="neutral")
        yield Button("Primary", id="primary", variant="primary")
        yield Button("Warning", id="warning", variant="warning")
        yield Button("Error", id="error", variant="error")


def _edge(widget: Button) -> Color:
    return widget.styles.border.top[1]


def _theme_colour(app: App, name: str) -> Color:
    return Color.parse(app.theme_variables[name])


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
async def test_button_roles_have_distinct_idle_outlines(theme: str) -> None:
    app = _RolesApp()
    app.theme = theme
    async with app.run_test(size=(60, 30)) as pilot:
        app.query_one("#holder").focus()
        await pilot.hover(offset=(59, 29))
        await pilot.pause()
        neutral, primary = _edge(app.query_one("#neutral")), _edge(app.query_one("#primary"))
        assert neutral == _theme_colour(app, "border-blurred")
        assert primary == _theme_colour(app, "primary")
        assert _edge(app.query_one("#warning")) == _theme_colour(app, "warning")
        assert _edge(app.query_one("#error")) == _theme_colour(app, "error")
        assert neutral != primary


@pytest.mark.asyncio
@pytest.mark.parametrize("button_id", ["neutral", "primary", "warning", "error"])
async def test_every_button_role_shows_focus_and_hover(button_id: str) -> None:
    app = _RolesApp()
    async with app.run_test(size=(60, 30)) as pilot:
        button = app.query_one(f"#{button_id}", Button)
        app.query_one("#holder").focus()
        await pilot.hover(offset=(59, 29))
        await pilot.pause()
        idle = (_edge(button), button.styles.text_style)
        button.focus()
        await pilot.pause()
        assert (_edge(button), button.styles.text_style) != idle
        app.query_one("#holder").focus()
        await pilot.hover(button)
        await pilot.pause()
        assert (_edge(button), button.styles.text_style) != idle


class _TableApp(_ThemedApp):
    def compose(self) -> ComposeResult:
        table = DataTable(id="table", cursor_type="row")
        table.add_columns("Name", "State")
        for row in range(4):
            table.add_row(f"web-{row}", "running")
        yield table


def _luminance(colour) -> float:
    def linear(value: int) -> float:
        channel = value / 255
        return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4

    return 0.2126 * linear(colour.red) + 0.7152 * linear(colour.green) + 0.0722 * linear(colour.blue)


def _contrast(style) -> float:
    lighter, darker = sorted((_luminance(style.color.get_truecolor()), _luminance(style.bgcolor.get_truecolor())), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
@pytest.mark.parametrize("focused", [True, False])
async def test_cursor_row_is_a_muted_fill_with_readable_normal_text(theme: str, focused: bool) -> None:
    app = _TableApp()
    app.theme = theme
    async with app.run_test(size=(60, 20)) as pilot:
        table = app.query_one(DataTable)
        table.focus() if focused else app.set_focus(None)
        await pilot.pause()
        style = table.get_component_rich_style("datatable--cursor")
        assert not style.reverse
        assert _contrast(style) >= 4.5
        surface = app.theme_variables["surface"]
        assert style.bgcolor.get_truecolor().hex != Color.parse(surface).hex


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["ansi-dark", "ansi-light"])
async def test_terminal_themes_draw_the_cursor_row_with_the_native_cursor_pair(theme: str) -> None:
    app = _TableApp()
    app.theme = theme
    async with app.run_test(size=(60, 20)) as pilot:
        table = app.query_one(DataTable)
        table.focus()
        await pilot.pause()
        cursor = table.get_component_rich_style("datatable--cursor")
        normal = table.get_component_rich_style("datatable--even-row")
        # The block-cursor colours already are the inverted pair: reversing
        # them again would put the row back to normal colours.
        assert not cursor.reverse
        assert (cursor.color, cursor.bgcolor) != (normal.color, normal.bgcolor)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
async def test_table_header_text_is_readable_on_its_fill(theme: str) -> None:
    app = _TableApp()
    app.theme = theme
    async with app.run_test(size=(60, 20)) as pilot:
        await pilot.pause()
        style = app.query_one(DataTable).get_component_rich_style("datatable--header")
        assert _contrast(style) >= 4.5, (theme, style)
        assert style.color.get_truecolor().hex.lower() == Color.parse(app.theme_variables["background"]).hex.lower()

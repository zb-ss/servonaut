"""Shared foundations: button roles, table cursor and header, screen header, navigation."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.color import Color
from textual.widgets import Button

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

"""Expanded native Select labels contrast with their themed highlight fill."""

from __future__ import annotations

import json

import pytest
from rich.text import Text
from textual import constants
from textual.app import ComposeResult
from textual.theme import BUILTIN_THEMES
from textual.widgets import Select
from textual.widgets._select import SelectOverlay

from servonaut.styles.themes import SERVONAUT_THEMES
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost
from tests.test_navigation_dialog_contrast import (
    _contrast,
    _paint_colours,
    _painted_text_styles,
)


THEMES = tuple(sorted(set(BUILTIN_THEMES) | {theme.name for theme in SERVONAUT_THEMES}))
SELECTED_LABEL = "Selected café [literal] Ω"


class _SelectHost(BasicDialogHost):
    def compose(self) -> ComposeResult:
        yield Select(
            [("Before", "before"), (Text(SELECTED_LABEL), "selected"), ("After", "after")],
            value="selected", allow_blank=False, id="native_select",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_native_select_highlight_contrast_preserves_selection_and_focus(
    theme: str, size: tuple[int, int], record_property, monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    monkeypatch.setenv("TERM", "xterm-256color")
    assert not constants.FILTERS
    assert constants.COLOR_SYSTEM in {"auto", "truecolor"}
    app = _SelectHost()
    assert set(THEMES) == set(app.available_themes)
    app.theme = theme
    async with app.run_test(size=size) as pilot:
        select = app.query_one("#native_select", Select)
        select.focus()
        await pilot.press("enter")
        overlay = select.query_one(SelectOverlay)
        await wait_until(lambda: select.expanded and overlay.has_focus)
        await pilot.pause()
        assert not app.no_color and app.console.color_system == "truecolor"
        assert app.screen.region.contains_region(overlay.region)
        palette = app.ansi_theme_dark if app.current_theme.dark else app.ansi_theme_light
        selected = _painted_text_styles(overlay, SELECTED_LABEL)
        adjacent = _painted_text_styles(overlay, "Before")
        ratios = [_contrast(*_paint_colours(style, palette)) for style in selected]
        record_property("select_highlight", json.dumps({
            "theme": theme, "size": size, "minimum_contrast": min(ratios),
            "styles": [str(style) for style in selected],
        }))
        # Native fills remain theme-owned; their automatic foreground gives
        # some built-in blue highlights between 3:1 and 4.5:1 contrast.
        assert min(ratios) >= 3.0, (theme, size, ratios, [str(style) for style in selected])
        if theme == "gruvbox":
            # The reported 2.36:1 regression must clear the normal-text bar.
            assert min(ratios) >= 4.5
        selected_fills = {_paint_colours(style, palette)[1] for style in selected}
        adjacent_fills = {_paint_colours(style, palette)[1] for style in adjacent}
        assert selected_fills.isdisjoint(adjacent_fills)
        await pilot.press("escape")
        await wait_until(lambda: not select.expanded)
        assert app.focused is select and select.value == "selected"
        await pilot.press("enter", "down", "enter")
        await wait_until(lambda: select.value == "after" and not select.expanded)
        assert app.focused is select

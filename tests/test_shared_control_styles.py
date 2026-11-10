"""Shared control styling, checked on widgets laid out with the real stylesheet."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Checkbox, Input, MaskedInput, RadioButton, RadioSet, Select, TextArea

from servonaut.styles import CSS_FILES

FRAMED = ("#select_box", "#input_box", "#masked_box", "#area_box", "#check_box", "#radio_box")


class _ControlsApp(App):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        yield Select([("One", 1), ("Two", 2)], id="select_box")
        yield Input(id="input_box")
        yield MaskedInput("999", id="masked_box")
        yield TextArea(id="area_box")
        yield Checkbox("Check", id="check_box")
        yield RadioSet(RadioButton("Radio"), id="radio_box")


def _edges(widget) -> list[str]:
    return [edge[0] for edge in widget.styles.border]


def _frame(app: App, selector: str):
    widget = app.query_one(selector)
    return widget.query_one("SelectCurrent") if isinstance(widget, Select) else widget


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", FRAMED)
async def test_framed_controls_use_round_borders_idle_and_focused(selector: str) -> None:
    app = _ControlsApp()
    async with app.run_test(size=(80, 60)) as pilot:
        await pilot.pause()
        assert _edges(_frame(app, selector)) == ["round"] * 4
        app.query_one(selector).focus()
        await pilot.pause()
        assert _edges(_frame(app, selector)) == ["round"] * 4


@pytest.mark.asyncio
async def test_select_keeps_its_height_and_rounds_the_open_list() -> None:
    app = _ControlsApp()
    async with app.run_test(size=(80, 60)) as pilot:
        select = app.query_one(Select)
        select.focus()
        await pilot.pause()
        assert select.region.height == 3
        await pilot.press("enter")
        await pilot.pause()
        overlay = select.query_one("SelectOverlay")
        assert select.expanded
        assert _edges(overlay) == ["round"] * 4
        assert _edges(select.query_one("SelectCurrent")) == ["round"] * 4
        assert select.region.height == 3

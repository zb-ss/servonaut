"""Shared control styling, checked on widgets laid out with the real stylesheet."""

from __future__ import annotations

import pytest
from rich.cells import cell_len
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.geometry import Region
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    MaskedInput,
    RadioButton,
    RadioSet,
    Select,
    TextArea,
)

from servonaut.screens.instance_list import FleetChip
from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.widgets.action_button import ActionButton
from servonaut.widgets.link_button import LinkButton
from servonaut.widgets.workspace import WorkspaceControls

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


def _underlined_cells(widget) -> tuple[str, int]:
    """The widget's rendered text and how many of its cells carry an underline."""
    text, underlined = "", 0
    for strip in widget.render_lines(Region(0, 0, widget.size.width, widget.size.height)):
        for segment in strip:
            text += segment.text
            if segment.style is not None and segment.style.underline:
                underlined += cell_len(segment.text)
    return text, underlined


def _words_underlined(widget, label: str) -> bool:
    """True when exactly the label's cells are underlined and nothing else."""
    text, underlined = _underlined_cells(widget)
    return text.strip() == label and underlined == cell_len(label)


class _LinkApp(App):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        yield Button("Plain", id="spacer_button")
        yield LinkButton("Refresh (r)", id="link_idle")
        yield LinkButton("Copy row (y)", id="link_disabled", disabled=True)
        yield LinkButton("Update to v1.2.3", id="link_with_classes", classes="extra")
        yield WorkspaceControls("Fleet")


LINK_IDS = ("#link_idle", "#link_disabled", "#link_with_classes", "#workspace_navigation", "#workspace_chat")


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", LINK_IDS)
async def test_link_controls_underline_only_their_words(selector: str) -> None:
    app = _LinkApp()
    async with app.run_test(size=(100, 20)) as pilot:
        await pilot.pause()
        link = app.query_one(selector, Button)
        label = link.label.plain
        text, underlined = _underlined_cells(link)
        assert link.size.height == 1
        assert text.strip() == label
        assert underlined == cell_len(label)


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", ("#link_idle", "#workspace_chat"))
async def test_link_controls_keep_words_only_underline_when_hovered_or_focused(selector: str) -> None:
    app = _LinkApp()
    async with app.run_test(size=(100, 20)) as pilot:
        link = app.query_one(selector, Button)
        label = link.label.plain
        await pilot.hover(selector)
        await pilot.pause()
        assert link.mouse_hover
        assert _words_underlined(link, label)
        link.can_focus = True
        link.focus()
        await pilot.hover("#spacer_button")
        await pilot.pause()
        assert link.has_focus
        assert _words_underlined(link, label)
        assert link.region.height == 1


BORDER_GLYPHS = set("╭╮╰╯─│━┃┏┓┗┛▔▁▏▕▀▄█")


class _HoverApp(App):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        yield Button("Away", id="away_button")
        yield FleetChip("state", "running", "Running")
        yield FleetChip("provider", "aws", "AWS")
        yield Button("Compact", id="compact_button", compact=True)
        yield ActionButton("Action", id="compact_action", compact=True)
        yield LinkButton("Refresh (r)", id="link_button")


BORDERLESS = ("#chip_state_running", "#chip_provider_aws", "#compact_button", "#compact_action", "#link_button")


def _top_row_text(widget) -> str:
    strip = widget.render_lines(Region(0, 0, widget.size.width, 1))[0]
    return "".join(segment.text for segment in strip)


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", BORDERLESS)
async def test_borderless_buttons_gain_no_border_on_hover_or_focus(selector: str) -> None:
    app = _HoverApp()
    async with app.run_test(size=(100, 20)) as pilot:
        await pilot.pause()
        widget = app.query_one(selector, Button)
        app.query_one("#away_button").focus()
        await pilot.hover("#away_button")
        await pilot.pause()
        idle = widget.region
        assert not (set(_top_row_text(widget)) & BORDER_GLYPHS)

        await pilot.hover(selector)
        await pilot.pause()
        assert widget.mouse_hover
        assert widget.region == idle
        assert not (set(_top_row_text(widget)) & BORDER_GLYPHS)

        widget.focus()
        await pilot.hover("#away_button")
        await pilot.pause()
        assert widget.has_focus
        assert widget.region == idle
        assert not (set(_top_row_text(widget)) & BORDER_GLYPHS)


class _BackApp(App):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        yield ActionButton("Focus holder", id="holder")
        yield ActionButton("Back", "esc", id="btn_back")
        yield ActionButton("Refresh", "r", id="other_action")


def _word_colour(widget, word: str):
    """The foreground the label's words are painted with."""
    for strip in widget.render_lines(Region(0, 0, widget.outer_size.width, widget.outer_size.height)):
        for segment in strip:
            if word in segment.text and segment.style is not None:
                return segment.style.color
    raise AssertionError(f"{word!r} is not painted")


@pytest.mark.asyncio
async def test_back_action_words_are_not_muted() -> None:
    app = _BackApp()
    async with app.run_test(size=(60, 12)) as pilot:
        app.query_one("#holder").focus()
        await pilot.pause()
        back = app.query_one("#btn_back", ActionButton)
        other = app.query_one("#other_action", ActionButton)
        assert _word_colour(back, "Back") == _word_colour(other, "Refresh")


class _PanelApp(App):
    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        for theme in SERVONAUT_THEMES:
            self.register_theme(theme)

    def compose(self) -> ComposeResult:
        with Vertical(id="bar"):
            yield Input(id="bar_input")
            yield Select([("One", 1)], id="bar_select")
            yield Checkbox("Check", id="bar_check")
            yield TextArea(id="bar_area")


def _luminance(colour) -> float:
    def linear(value: int) -> float:
        channel = value / 255
        return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4

    return 0.2126 * linear(colour.r) + 0.7152 * linear(colour.g) + 0.0722 * linear(colour.b)


def _frame_contrast(frame, backdrop) -> float:
    lighter, darker = sorted((_luminance(frame), _luminance(backdrop)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
async def test_idle_frames_stay_visible_on_a_panel_backdrop(theme: str) -> None:
    app = _PanelApp()
    app.theme = theme
    async with app.run_test(size=(80, 40)) as pilot:
        app.query_one("#bar").styles.background = app.theme_variables["panel"]
        app.set_focus(None)
        await pilot.pause()
        backdrop = app.query_one("#bar").styles.background
        input_frame = app.query_one("#bar_input").styles.border.top[1]
        for selector in ("#bar_select > SelectCurrent", "#bar_check", "#bar_area"):
            frame = app.query_one(selector).styles.border.top[1]
            assert frame != backdrop, selector
            assert frame == input_frame, selector
            if frame.ansi is None and backdrop.ansi is None:
                assert _frame_contrast(frame, backdrop) >= 1.3, selector


@pytest.mark.asyncio
async def test_command_palette_list_stays_unframed() -> None:
    app = _ControlsApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("ctrl+p")
        await pilot.pause()
        await pilot.pause()
        palette_list = app.screen.query_one("CommandList")
        assert palette_list.styles.border.left[0] in ("", "none")
        assert palette_list.styles.border.right[0] in ("", "none")

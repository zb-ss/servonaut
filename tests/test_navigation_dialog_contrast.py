"""Native navigation and overflow hints remain readable across terminal palettes."""

from __future__ import annotations

import pytest
from rich.color import Color
from rich.color_triplet import ColorTriplet
from rich.style import Style
from rich.terminal_theme import DEFAULT_TERMINAL_THEME, SVG_EXPORT_THEME, TerminalTheme
from textual._ansi_theme import ALABASTER, MONOKAI
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.screen import ModalScreen, Screen
from textual.widget import Widget
from textual.widgets import Button, Input, Static

from servonaut.styles import CSS_FILES
from servonaut.styles.themes import (
    SERVONAUT_ANSI_DARK,
    SERVONAUT_ANSI_LIGHT,
    SERVONAUT_THEMES,
)
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame
from servonaut.widgets.sidebar import Sidebar
from tests._async_bounds import wait_until
from tests.test_workspace_pilot import _Host

pytestmark = pytest.mark.usefixtures("navigation_open")


# Explicit terminal palettes keep ANSI assertions independent of the test
# runner's terminal and include both dark and light terminal configurations.
PALETTES = {
    "rich-default": DEFAULT_TERMINAL_THEME,
    "rich-svg-export": SVG_EXPORT_THEME,
    "textual-alabaster": ALABASTER,
    "textual-monokai": MONOKAI,
    "servonaut-dark": SERVONAUT_ANSI_DARK,
    "servonaut-light": SERVONAUT_ANSI_LIGHT,
}


@pytest.fixture(autouse=True)
def _terminal_colours(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)


def _painted_text_styles(widget: Widget, text: str) -> list[Style]:
    """Find the complete visible label, excluding adjacent border/background cells."""
    for strip in widget.render_lines(widget.region.size.region):
        start = strip.text.find(text)
        if start < 0:
            continue
        end = start + len(text)
        offset = 0
        styles: list[Style] = []
        for segment in strip:
            next_offset = offset + len(segment.text)
            if offset < end and next_offset > start:
                styles.append(segment.style or Style())
            offset = next_offset
        assert styles, f"{text!r} has no painted segments"
        return styles
    pytest.fail(f"Complete label {text!r} is missing from the painted {widget!r}")


def _paint_colours(
    style: Style, palette: TerminalTheme,
) -> tuple[ColorTriplet, ColorTriplet]:
    """Resolve native default/reverse/dim semantics as Rich's SVG renderer does."""
    foreground = (style.color or Color.default()).get_truecolor(palette)
    background = (style.bgcolor or Color.default()).get_truecolor(
        palette, foreground=False,
    )
    if style.reverse:
        foreground, background = background, foreground
    if style.dim:
        foreground = ColorTriplet(*(
            int(fg + (bg - fg) * 0.4) for fg, bg in zip(foreground, background)
        ))
    return foreground, background


def _contrast(foreground: ColorTriplet, background: ColorTriplet) -> float:
    def luminance(colour: ColorTriplet) -> float:
        def linear(value: int) -> float:
            channel = value / 255
            if channel <= 0.04045:
                return channel / 12.92
            return ((channel + 0.055) / 1.055) ** 2.4

        red, green, blue = (linear(value) for value in colour)
        return 0.2126 * red + 0.7152 * green + 0.0722 * blue

    lighter, darker = sorted(
        (luminance(foreground), luminance(background)), reverse=True,
    )
    return (lighter + 0.05) / (darker + 0.05)


def _assert_readable(styles: list[Style], *, context: str) -> None:
    failures = []
    for name, palette in PALETTES.items():
        for style in styles:
            ratio = _contrast(*_paint_colours(style, palette))
            if ratio < 4.5:
                failures.append(f"{name}: {ratio:.2f}:1 ({style})")
    assert not failures, f"{context}: " + "; ".join(failures)


class _OrdinarySidebarScreen(Screen):
    """Exercise the native rail outside WorkspaceScreen's more-specific rules."""

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Sidebar()
            yield Input(id="ordinary-content")


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["ansi-dark", "ansi-light"])
@pytest.mark.parametrize("context", ["ordinary", "workspace"])
@pytest.mark.parametrize("state", ["unfocused", "focused-active", "focused-alternate"])
async def test_ansi_navigation_painted_labels_keep_contrast_in_each_focus_state(
    theme: str, context: str, state: str,
) -> None:
    app = _Host()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        if context == "ordinary":
            app.push_screen(_OrdinarySidebarScreen())
            await pilot.pause()
            # This minimal screen has no destination; supply the same route
            # class as a real fleet screen without changing navigation itself.
            app.screen.query_one("#nav_list", Button).add_class("--active")
        sidebar = app.screen.query_one(Sidebar)
        active = sidebar.query_one("#nav_list", Button)
        alternate = sidebar.query_one("#nav_custom_servers", Button)
        await pilot.pause()
        regions = active.region, alternate.region
        assert not sidebar.navigation_mode
        assert app.focused is not active
        if state != "unfocused":
            sidebar.enter_navigation_mode()
            await wait_until(lambda: app.focused is active)
            if state == "focused-alternate":
                await pilot.press("tab")
                await pilot.pause()
                assert app.focused is alternate
        await pilot.pause()
        active_styles = _painted_text_styles(active, "Instances")
        _assert_readable(
            active_styles, context=f"{theme}/{context}/{state}/active route",
        )
        assert all(style.bold and style.reverse for style in active_styles)
        if state == "focused-active":
            assert all(style.underline for style in active_styles)
        elif state == "focused-alternate":
            alternate_styles = _painted_text_styles(alternate, "Custom Servers")
            _assert_readable(alternate_styles, context=f"{theme}/{context}/{state}")
            assert all(style.underline for style in alternate_styles)
        assert active.has_class("--active")
        if context == "workspace" and state != "unfocused":
            assert active.styles.border_left[0] == "thick"
        assert (active.region, alternate.region) == regions
        if state != "unfocused":
            await pilot.press("escape")
            await pilot.pause()
            assert not sidebar.navigation_mode and app.focused is not alternate


class _DialogHost(App):
    CSS_PATH = CSS_FILES

    def __init__(self, theme: str) -> None:
        super().__init__()
        for registered in SERVONAUT_THEMES:
            self.register_theme(registered)
        self.theme = theme
        self.animation_level = "none"

    def compose(self) -> ComposeResult:
        yield Input(id="origin")


class _NeutralOverflowDialog(ModalScreen[None]):
    def __init__(self) -> None:
        super().__init__(classes="dialog-screen")

    def compose(self) -> ComposeResult:
        body = DialogBody(Static("\n".join(f"Detail {index}" for index in range(60))))
        yield DialogFrame(
            heading=Static("Review details"), body=body, size="large",
            actions=DialogActions(Button("Close", id="close-details")),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"],
)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_neutral_overflow_hint_paints_readable_text_above_pinned_actions(
    theme: str, size: tuple[int, int],
) -> None:
    app = _DialogHost(theme)
    screen = _NeutralOverflowDialog()
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        body = screen.query_one(DialogBody)
        await wait_until(lambda: frame.border_subtitle == "Scroll for all details")
        await pilot.pause()
        assert body.max_scroll_y > 0
        styles = _painted_text_styles(frame, "Scroll for all details")
        _assert_readable(styles, context=f"{theme}/{size}/neutral overflow subtitle")
        action = screen.query_one("#close-details", Button)
        action_region = action.region
        assert frame.content_region.contains_region(action_region)
        assert screen.region.contains_region(action_region)
        assert frame.region.height <= int(size[1] * 0.9)
        body.scroll_end(animate=False)
        await pilot.pause()
        assert action.region == action_region
        assert body.scroll_y > 0
        detail = body.query_one(Static)
        endpoint = detail.content_region.x, detail.content_region.bottom - 1
        assert body.content_region.contains(*endpoint)
        assert app.get_widget_at(*endpoint)[0] is detail
        assert _painted_text_styles(detail, "Detail 59")

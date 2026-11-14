"""Native footer shortcuts remain readable against the application's panel."""

from __future__ import annotations

import asyncio
import json

import pytest
from textual.app import App, ComposeResult
from textual.constants import FILTERS
from textual.widgets import Footer, Input, Select
from textual.widgets._footer import FooterKey

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES
from tests._async_bounds import STEP_TIMEOUT_SECONDS, wait_until
from tests.test_ansi_chat_dialog_contrast import _painted_glyphs
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours


THEMES = (
    "solarized-light", "solarized-dark", "servonaut-light", "servonaut",
    "ansi-light", "ansi-dark",
)


class _FooterHost(App):
    """Use real styles and native bindings without constructing any services."""

    CSS_PATH = CSS_FILES
    BINDINGS = [("f6", "inspect_record", "Inspect"), ("f7", "review_record", "Review")]

    def __init__(self, theme: str) -> None:
        super().__init__()
        for registered in SERVONAUT_THEMES:
            self.register_theme(registered)
        self.theme = theme
        self.animation_level = "none"
        self.inspections = 0

    def compose(self) -> ComposeResult:
        yield Input(id="origin")
        yield Select([("First", "first"), ("Second", "second")], value="first", allow_blank=False)
        yield Footer()

    def action_inspect_record(self) -> None:
        self.inspections += 1

    def action_review_record(self) -> None:
        self.push_screen(ConfirmActionScreen(
            title="Review example server", description="Review web-1.",
            consequences=["Fixture only; no server operation is attached."],
            confirm_text="web-1", action_label="Delete",
        ))


def _assert_readable(app: App, key: FooterKey, *, state: str) -> dict:
    assert app.screen.region.contains_region(key.region)
    evidence = {}
    for label in (key.key_display, key.description):
        glyphs = _painted_glyphs(key, label)
        colours = [_paint_colours(style, app.ansi_theme) for _, style in glyphs]
        ratios = [_contrast(fg, bg) for fg, bg in colours]
        # AA-sized text is an explicit readability contract for this fixture.
        assert all(ratio >= 4.5 for ratio in ratios), (
            app.theme, state, label, ratios,
        )
        evidence[label] = {
            "minimum_contrast": min(ratios),
            "foreground": colours[0][0].hex,
            "background": colours[0][1].hex,
        }
    return evidence


def _footer_key(app: App, description: str) -> FooterKey:
    return next(key for key in app.screen.query_one(Footer).query(FooterKey)
                if key.description == description)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_native_footer_painted_shortcuts_keep_contrast_and_actions(
    monkeypatch: pytest.MonkeyPatch, theme: str, size: tuple[int, int],
    record_property,
) -> None:
    assert not FILTERS, "Footer contrast requires native unfiltered colours"
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    app = _FooterHost(theme)
    async with app.run_test(size=size) as pilot:
        footer = app.screen.query_one(Footer)
        origin = app.screen.query_one("#origin", Input)
        await wait_until(lambda: app.focused is origin)
        await wait_until(lambda: bool(footer.query(FooterKey)))
        await pilot.pause()
        await wait_until(lambda: any(
            key.description == "Inspect" and key.is_mounted and key.is_attached
            for key in footer.query(FooterKey)
        ))
        inspect = _footer_key(app, "Inspect")
        assert inspect.is_mounted and inspect.is_attached
        evidence = {"idle": _assert_readable(app, inspect, state="idle")}

        async def hover_and_click_current_inspect() -> dict:
            while True:
                current_footer = app.screen.query_one(Footer)
                inspect = next((key for key in current_footer.query(FooterKey)
                                if key.description == "Inspect"
                                and key.is_mounted and key.is_attached), None)
                if inspect is None:
                    await pilot.pause()
                    continue
                hovered = await pilot.hover(inspect)
                await pilot.pause()
                current_footer = app.screen.query_one(Footer)
                if not inspect.is_attached or not any(
                    key is inspect for key in current_footer.query(FooterKey)
                ):
                    continue  # Native bindings replaced the hovered child.
                assert inspect.is_mounted and inspect.screen is app.screen
                assert inspect.key == "f6" and inspect.action == "inspect_record"
                assert hovered
                assert app.mouse_over is inspect and app.hover_over is inspect
                assert inspect.mouse_hover
                assert app.get_widget_at(*app.mouse_position)[0] is inspect
                hover_colours = _assert_readable(app, inspect, state="hover")
                assert app.get_widget_at(*inspect.region.center)[0] is inspect
                assert await pilot.click(inspect)
                return hover_colours

        evidence["hover"] = await asyncio.wait_for(
            hover_and_click_current_inspect(), STEP_TIMEOUT_SECONDS,
        )
        await wait_until(lambda: app.inspections == 1)
        await pilot.press("f6")
        await wait_until(lambda: app.inspections == 2)
        selector = app.screen.query_one(Select)
        selector.focus()
        await pilot.press("enter")
        await wait_until(lambda: selector.expanded)
        await pilot.pause()
        evidence["selector"] = _assert_readable(
            app, _footer_key(app, "Dismiss menu"), state="selector",
        )
        await pilot.press("escape")
        await wait_until(lambda: not selector.expanded)
        await pilot.press("f7")
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        await pilot.pause()
        cancel = _footer_key(app, "Cancel")
        evidence["confirmation"] = _assert_readable(app, cancel, state="confirmation")
        await pilot.press("escape")
        await wait_until(lambda: not isinstance(app.screen, ConfirmActionScreen))
        assert app.inspections == 2
        record_property("native-footer-colours", json.dumps({
            "theme": theme, "size": size, "states": evidence,
            "palette_basis": "App.ansi_theme",
        }))

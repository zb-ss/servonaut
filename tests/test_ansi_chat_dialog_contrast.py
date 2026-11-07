"""Native dialog actions and retained chat selections remain readable."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from rich.color import Color, ColorSystem, ColorType
from rich.style import Style
from rich.terminal_theme import TerminalTheme
from textual._ansi_theme import ALABASTER, MONOKAI
from textual.constants import FILTERS
from textual.app import ComposeResult
from textual.binding import Binding
from textual.pilot import Pilot
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import Button, Input, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.settings.shell import DiscardChangesModal
from servonaut.styles.themes import SERVONAUT_ANSI_DARK, SERVONAUT_ANSI_LIGHT
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame
from tests._async_bounds import wait_until
from tests.test_dialog_frame import DialogHost
from tests.test_fleet_workspace_layout import _LayoutHost, _open_chat
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours


THEMES = ("servonaut", "servonaut-light", "ansi-dark", "ansi-light")


@pytest.fixture(autouse=True)
def _offline_colours(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not FILTERS, "Native colour probes require TEXTUAL_FILTERS unset"
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)


def _matching_palette(theme: str, *, dark: bool | None = None) -> TerminalTheme:
    if dark is None:
        dark = not theme.endswith("light")
    return SERVONAUT_ANSI_DARK if dark else SERVONAUT_ANSI_LIGHT


def _painted_glyphs(widget: Widget, label: str) -> list[tuple[str, Style]]:
    """Read complete visible glyphs from the compositor, excluding the border."""
    region = widget.content_region
    rows = widget.screen._compositor.render_strips()
    for y in range(region.y, region.bottom):
        strip = rows[y].crop(region.x, region.right)
        start = strip.text.find(label)
        if start < 0:
            continue
        end = start + len(label)
        offset = 0
        glyphs: list[tuple[str, Style]] = []
        for segment in strip:
            next_offset = offset + len(segment.text)
            if offset < end and next_offset > start:
                visible = segment.text[max(0, start - offset):end - offset]
                glyphs.extend((char, segment.style or Style()) for char in visible)
            offset = next_offset
        assert "".join(char for char, _ in glyphs) == label
        return glyphs
    pytest.fail(f"Complete {label!r} missing from visible {widget!r}")


def _symbolic_colour(colour: Color | None) -> dict[str, object]:
    value = colour or Color.default()
    return {
        "type": value.type.name, "index": value.number,
        "default": value.is_default,
        "truecolor": value.triplet.hex if value.triplet else None,
    }


def _glyph_evidence(
    glyph: str, style: Style, theme: str, *, dark: bool | None = None,
) -> dict[str, Any]:
    if dark is None:
        dark = not theme.endswith("light")
    foreground = style.color or Color.default()
    background = style.bgcolor or Color.default()
    same_index = (
        foreground.type == background.type == ColorType.STANDARD
        and foreground.number == background.number
    )
    alternate = MONOKAI if dark else ALABASTER
    palettes = {"matching": _matching_palette(theme, dark=dark),
                "matched-alternate": alternate}
    colours = {}
    for name, palette in palettes.items():
        fg, bg = _paint_colours(style, palette)
        colours[name] = {
            "foreground": fg.hex, "background": bg.hex,
            "contrast": _contrast(fg, bg),
        }
    return {
        "glyph": glyph, "foreground": _symbolic_colour(style.color),
        "background": _symbolic_colour(style.bgcolor),
        "reverse": style.reverse, "dim": style.dim, "bold": style.bold,
        "sgr": style.render(glyph, color_system=ColorSystem.TRUECOLOR),
        "same_ansi_index": same_index,
        "palette_independent_equal_colours_without_bold_bright": same_index,
        "bold_as_bright_terminal_dependent": bool(
            style.bold and foreground.type == ColorType.STANDARD
            and foreground.number is not None and foreground.number < 8
        ),
        "matched_alternate_name": "MONOKAI" if dark else "ALABASTER",
        "palettes": colours,
    }


def _assert_readable(
    widget: Widget, label: str, theme: str,
    record_property: Callable[[str, object], None],
) -> None:
    """Resolve symbolic defaults/reverse/dim against the named terminal palette."""
    evidence = [_glyph_evidence(glyph, style, theme)
                for glyph, style in _painted_glyphs(widget, label)]
    record_property("native-glyph-evidence", json.dumps({
        "theme": theme, "label": label,
        "gate": "matching palette only; matched alternate is diagnostic",
        "bold_policy": "normal ANSI index; bold-as-bright terminal dependent",
        "glyphs": evidence,
    }, sort_keys=True))
    failures = []
    for glyph in evidence:
        colours = glyph["palettes"]["matching"]
        ratio = colours["contrast"]
        if ratio < 4.5:
            failures.append(glyph)
    assert not failures, f"{theme}/{label}: " + json.dumps(failures, sort_keys=True)


async def _tab_to(pilot: Pilot, widget: Widget) -> None:
    for _ in range(len(widget.screen.focus_chain) + 1):
        if widget.app.focused is widget:
            return
        await pilot.press("tab")
    pytest.fail(f"Native Tab did not reach {widget!r}")


def _dialog(variant: str) -> tuple[ModalScreen[bool], str]:
    if variant == "warning":
        return DiscardChangesModal("General"), "discard-confirm"
    return ConfirmActionScreen(
        title="Delete server", description="Review the selected server.",
        consequences=["Services on web-1 will stop."], confirm_text="web-1",
        action_label="Delete", severity="danger",
    ), "btn_confirm"


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("variant", ("warning", "error"))
@pytest.mark.parametrize("state", ("rest", "hover", "focus", "focus-hover"))
async def test_enabled_severity_action_paints_readable_complete_native_label(
    theme: str, variant: str, state: str,
    record_property: Callable[[str, object], None],
) -> None:
    app = DialogHost()
    app.theme = theme
    screen, button_id = _dialog(variant)
    results: list[bool] = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        await app.push_screen(screen, results.append)
        await pilot.pause()
        safe = screen.focused
        expected_safe = "discard-cancel" if variant == "warning" else "confirm_input"
        assert safe is screen.query_one(f"#{expected_safe}")
        button = screen.query_one(f"#{button_id}", Button)
        if variant == "error":
            assert button.disabled
            await pilot.press(*"web-1")
            await wait_until(lambda: not button.disabled)
        assert not button.disabled and results == []
        outer = button.region
        await pilot.hover(f"#{expected_safe}")
        if "focus" in state:
            await _tab_to(pilot, button)
        if "hover" in state:
            await pilot.hover(f"#{button_id}")
        await pilot.pause()
        assert (app.focused is button) is ("focus" in state)
        assert button.mouse_hover is ("hover" in state)
        assert screen.region.contains_region(button.region)
        assert app.get_widget_at(*button.region.center)[0] is button
        label = button.label.plain.strip()
        _assert_readable(button, label, theme, record_property)
        if "focus" in state:
            assert all(style.underline for _, style in _painted_glyphs(button, label))
        assert button.region == outer and results == []
        assert await pilot.click(f"#{button_id}")
        await wait_until(lambda: results == [True])
        await wait_until(lambda: app.focused is origin)
        assert app.screen is not screen and app.focused is origin
        assert app._exception is None


def _registry_state(button: Button, state: str) -> dict[str, Any]:
    theme = button.app.current_theme
    dark = bool(theme.dark)
    palette = _matching_palette(theme.name, dark=dark)
    glyphs = [_glyph_evidence(glyph, style, theme.name, dark=dark)
              for glyph, style in _painted_glyphs(button, "Continue")]
    native_rows = button.screen._compositor.render_strips()
    borders = []
    for y in (button.region.y, button.region.bottom - 1):
        cells = []
        for segment in native_rows[y].crop(button.region.x, button.region.right):
            fg, bg = _paint_colours(segment.style or Style(), palette)
            cells.extend([char, fg.hex, bg.hex] for char in segment.text)
        borders.append(cells)
    return {
        "theme": theme.name, "theme_dark": theme.dark,
        "palette_basis": "actual current_theme.dark",
        "variant": button.variant, "state": state, "disabled": button.disabled,
        "focus": button.app.focused.id, "hover": button.mouse_hover,
        "native_active": button.has_class("-active"),
        "glyphs": glyphs, "border_pose": borders,
        "raw_borders": {
            edge: [getattr(button.styles, "border_" + edge)[0],
                   getattr(button.styles, "border_" + edge)[1].css]
            for edge in ("top", "right", "bottom", "left")
        },
    }


def _glyph_pairs(row: dict[str, Any]) -> list[tuple[str, str]]:
    return [(g["palettes"]["matching"]["foreground"],
             g["palettes"]["matching"]["background"]) for g in row["glyphs"]]


@pytest.mark.asyncio
@pytest.mark.timeout(180)
async def test_registered_themes_keep_severity_text_and_pressed_cues_readable(
    record_property: Callable[[str, object], None],
) -> None:
    # One host covers the registry without booting an app for every state.
    app = DialogHost()
    names = tuple(sorted(app.available_themes))
    screen = _NativeStateDialog("warning")
    rows: list[dict[str, Any]] = []
    failures = []
    try:
        async with app.run_test(size=(100, 30)) as pilot:
            await app.push_screen(screen)
            await pilot.pause()
            button = screen.query_one("#state-action", Button)
            origin = screen.query_one("#state-input", Input)
            # Extend only the observation window for native transient paint.
            button.active_effect_duration = 1.0
            for name in names:
                await wait_until(lambda: not button.has_class("-active"))
                app.theme = name
                await pilot.pause()
                assert app.current_theme.name == name
                for variant in ("warning", "error"):
                    await wait_until(lambda: not button.has_class("-active"))
                    button.variant = variant
                    button.disabled = True
                    origin.focus()
                    for state in ("disabled-rest", "disabled-hover"):
                        target = "#state-action" if state.endswith("hover") else "#state-input"
                        await pilot.hover(target)
                        await pilot.pause()
                        row = _registry_state(button, state)
                        rows.append(row)
                        # Inactive controls are AA-exempt, but stay identifiable.
                        if any(fg == bg for fg, bg in _glyph_pairs(row)):
                            failures.append([name, variant, state, "invisible"])
                    before = len(screen.pressed)
                    assert await pilot.click("#state-action")
                    await pilot.pause()
                    assert len(screen.pressed) == before and app.focused is origin
                    button.disabled = False
                    outer = button.region
                    for state in ("rest", "hover", "focus", "focus-hover", "native-active"):
                        if state in ("rest", "hover"):
                            origin.focus()
                        else:
                            await _tab_to(pilot, button)
                        target = ("#state-action" if state in
                                  ("hover", "focus-hover", "native-active") else "#state-input")
                        await pilot.hover(target)
                        if state == "native-active":
                            assert await pilot.click("#state-action")
                            assert button.has_class("-active")
                            assert len(screen.pressed) == before + 1
                        await pilot.pause()
                        row = _registry_state(button, state)
                        if state == "native-active":
                            assert row["native_active"]
                            previous = rows[-1]
                            assert previous["state"] == "focus-hover"
                            if (_glyph_pairs(row) == _glyph_pairs(previous)
                                    and row["border_pose"] == previous["border_pose"]):
                                failures.append([name, variant, state, "no pressed cue"])
                        rows.append(row)
                        ratio = min(g["palettes"]["matching"]["contrast"] for g in row["glyphs"])
                        if ratio < 4.5:
                            failures.append([name, variant, state, ratio])
                        assert button.region == outer
                        assert app.get_widget_at(*button.region.center)[0] is button
            assert app._exception is None
    finally:
        record_property("registered-native-glyphs", json.dumps({
            "registered_themes": names, "rows": rows,
            "disabled_policy": "AA exempt; non-invisible only",
            "failures": failures,
        }, sort_keys=True))
    assert len(rows) == len(names) * 2 * 7
    assert not failures, json.dumps(failures, sort_keys=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("focused", (True, False))
async def test_chat_selection_keeps_native_painted_contrast_when_focus_moves(
    theme: str, focused: bool,
    record_property: Callable[[str, object], None],
) -> None:
    app = _LayoutHost(navigation_visible=False)
    app.theme = theme
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        draft = "Keep this draft Ω [b] café"
        editor.load_text(draft)
        await pilot.pause()
        assert editor.selection == Selection.cursor((0, 0))
        await pilot.press(*["right"] * 5, *["shift+right"] * 10)
        await pilot.pause()
        expected = Selection((0, 5), (0, 15))
        assert editor.selection == expected and editor.selected_text == "this draft"
        document, scroll, outer = editor.document, editor.scroll_offset, editor.region
        if not focused:
            await pilot.press("tab")
            await pilot.pause()
            assert app.focused is panel.query_one("#btn-chat-mic", Button)
        assert editor.has_focus is focused
        assert editor.document is document and editor.selection == expected
        assert editor.text == draft and editor.scroll_offset == scroll
        _assert_readable(editor, "this draft", theme, record_property)
        if theme.startswith("ansi-"):
            selected = _painted_glyphs(editor, "this draft")
            adjacent = _painted_glyphs(editor, "Keep ")
            record_property("native-adjacent-glyph-evidence", json.dumps([
                _glyph_evidence(glyph, style, theme) for glyph, style in adjacent
            ], sort_keys=True))
            assert all(style.reverse for _, style in selected)
            palette = _matching_palette(theme)
            selected_colours = {_paint_colours(style, palette) for _, style in selected}
            adjacent_colours = {_paint_colours(style, palette) for _, style in adjacent}
            assert selected_colours.isdisjoint(adjacent_colours)
        await _tab_to(pilot, editor)
        app.copy_to_clipboard("Previous clipboard value")
        await pilot.press("ctrl+c")
        await wait_until(lambda: app.clipboard == "this draft")
        assert editor.document is document and editor.selection == expected
        assert editor.text == draft and editor.region == outer
        assert app._exception is None


class _NativeStateDialog(ModalScreen[bool]):
    """Keep the native pressed cue mounted until its paint can be inspected."""

    AUTO_FOCUS = "#state-input"
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, variant: str) -> None:
        super().__init__(classes="dialog-screen")
        self.variant = variant
        self.pressed: list[str | None] = []

    def compose(self) -> ComposeResult:
        yield DialogFrame(
            heading=Static("Review operation"),
            body=DialogBody(Input(id="state-input")),
            actions=DialogActions(
                Button("Cancel", id="state-cancel"),
                Button("Continue", variant=self.variant, id="state-action", disabled=True),
            ),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.pressed.append(event.button.id)
        if event.button.id == "state-cancel":
            self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


def _button_state_evidence(button: Button, state: str, theme: str) -> dict[str, Any]:
    glyphs = _painted_glyphs(button, "Continue")
    return {
        "state": state, "disabled": button.disabled,
        "hover": button.mouse_hover, "focus": button.app.focused.id,
        "opacity": button.styles.opacity,
        "underline": any(style.underline for _, style in glyphs),
        "glyphs": [_glyph_evidence(glyph, style, theme) for glyph, style in glyphs],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("variant", ("warning", "error"))
async def test_native_pressed_and_disabled_severity_states_remain_readable_and_safe(
    theme: str, variant: str, record_property: Callable[[str, object], None],
) -> None:
    app = DialogHost()
    app.theme = theme
    screen = _NativeStateDialog(variant)
    results: list[bool] = []
    states = []
    async with app.run_test(size=(100, 30)) as pilot:
        content = app.query_one("#origin", Input)
        content.focus()
        await app.push_screen(screen, results.append)
        await pilot.pause()
        button = screen.query_one("#state-action", Button)
        origin = screen.query_one("#state-input", Input)
        outer = button.region
        for state in ("disabled-rest", "disabled-hover"):
            target = "#state-action" if state.endswith("hover") else "#state-input"
            await pilot.hover(target)
            await pilot.pause()
            states.append(_button_state_evidence(button, state, theme))
            record_property("native-button-states", json.dumps(states, sort_keys=True))
            assert button.disabled and app.focused is origin and screen.pressed == []
            assert button.styles.opacity == 0.5
            assert await pilot.click("#state-action")
            await pilot.pause()
            assert screen.pressed == [] and app.focused is origin
        await pilot.press("tab")
        assert app.focused is screen.query_one("#state-cancel", Button)
        button.disabled = False
        # Hold the native transient cue long enough to inspect it without a race.
        button.active_effect_duration = 10
        await _tab_to(pilot, button)
        assert await pilot.click("#state-action")
        await pilot.pause()
        assert button.has_class("-active") and screen.pressed == ["state-action"]
        states.append(_button_state_evidence(button, "native-active", theme))
        record_property("native-button-states", json.dumps(states, sort_keys=True))
        _assert_readable(button, "Continue", theme, record_property)
        assert button.region == outer and results == []
        assert app.get_widget_at(*button.region.center)[0] is button
        await pilot.press("escape")
        await wait_until(lambda: results == [False])
        await wait_until(lambda: app.focused is content)
        if theme.startswith("ansi-"):
            assert all(not state["underline"] for state in states[:2])
        # Disabled text is exempt from AA, but must not disappear into its fill.
        assert all(
            glyph["palettes"]["matching"]["foreground"]
            != glyph["palettes"]["matching"]["background"]
            for state in states[:2] for glyph in state["glyphs"]
        )
        assert app._exception is None

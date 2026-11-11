"""A key hint is drawn as a small key cap: the key between two half-block edges."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.geometry import Region

from servonaut.widgets.action_button import ActionButton, ActionRow, action_label, keycap_parts
from servonaut.widgets.link_button import LinkButton
from tests.test_action_button import CSS_FILES, cap

EDGE_LEFT, EDGE_RIGHT = "▐", "▌"


def test_a_key_cap_is_the_key_between_two_edges_and_adds_two_cells() -> None:
    parts = keycap_parts("ctrl+r")
    assert [text for text, _ in parts] == [EDGE_LEFT, "ctrl+r", EDGE_RIGHT]
    assert action_label("Reload", "ctrl+r").cell_length == len("Reload") + 1 + len("ctrl+r") + 2


def test_the_key_is_literal_text() -> None:
    assert [text for text, _ in keycap_parts("[b]")][1] == "[b]"


def test_disabled_and_terminal_caps_keep_the_same_width() -> None:
    widths = {len("".join(t for t, _ in keycap_parts("x", ansi=a, disabled=d)))
              for a in (False, True) for d in (False, True)}
    assert widths == {3}


def test_a_disabled_cap_has_no_fill() -> None:
    assert all("on" not in str(style).split() for _, style in keycap_parts("x", disabled=True))


class _Host(App):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        with ActionRow(id="row"):
            yield ActionButton("Browse", "b", id="action")
            yield ActionButton("Locked", "l", disabled=True, id="locked")
        yield LinkButton("Copy row", key="y", id="link")


def _painted(widget) -> str:
    text = ""
    for strip in widget.render_lines(Region(0, 0, widget.outer_size.width, widget.outer_size.height)):
        text += "".join(segment.text for segment in strip)
    return text


@pytest.mark.asyncio
async def test_action_buttons_and_links_draw_the_cap() -> None:
    async with _Host().run_test(size=(60, 12)) as pilot:
        await pilot.pause()
        assert cap("b") in _painted(pilot.app.query_one("#action"))
        assert cap("y") in _painted(pilot.app.query_one("#link"))


@pytest.mark.asyncio
async def test_a_disabled_button_draws_its_key_quietly() -> None:
    async with _Host().run_test(size=(60, 12)) as pilot:
        await pilot.pause()
        painted = _painted(pilot.app.query_one("#locked"))
        assert EDGE_LEFT not in painted and " l " in painted


@pytest.mark.asyncio
async def test_the_vault_tabs_and_refresh_draw_the_cap() -> None:
    from servonaut.screens.vault import VaultScreen
    from tests._async_bounds import wait_until
    from tests.test_vault_screen import _StyledVaultHost
    from tests.test_vault_workspace_views import _Service

    app = _StyledVaultHost(_Service(local=True))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: isinstance(screen, VaultScreen) and screen._identity_state != "loading")
        await pilot.pause()
        for button_id, key in (("vault_items", "i"), ("vault_refresh", "r")):
            assert cap(key) in _painted(screen.query_one(f"#{button_id}")), button_id


def _lum(colour) -> float:
    def channel(value: int) -> float:
        value /= 255
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    return 0.2126 * channel(colour.red) + 0.7152 * channel(colour.green) + 0.0722 * channel(colour.blue)


def _ratio(first, second) -> float:
    light, dark = sorted((_lum(first), _lum(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def _segment(widget, text: str):
    for strip in widget.render_lines(Region(0, 0, widget.outer_size.width, widget.outer_size.height)):
        for segment in strip:
            if segment.text.strip() == text and segment.style is not None:
                return segment.style
    raise AssertionError(f"{text!r} is not painted")


class _CapHost(App):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        yield ActionButton("Browse", "k", id="framed")
        yield ActionButton("Browse", "k", compact=True, id="compact")
        yield ActionButton("Other", "o", id="other")


@pytest.mark.asyncio
async def test_the_cap_shows_against_the_button_in_every_theme_and_state() -> None:
    """In every registered theme, idle, hovered and focused, framed and compact."""
    app = _CapHost()
    problems = []
    async with app.run_test(size=(60, 14)) as pilot:
        for theme in sorted(app.available_themes):
            app.theme = theme
            await pilot.pause()
            if app.current_theme.ansi:
                continue
            for button_id in ("framed", "compact"):
                button = app.query_one(f"#{button_id}", ActionButton)
                for state in ("idle", "hover", "focus"):
                    if state == "idle":
                        app.set_focus(None)
                        await pilot.hover(app.query_one("#other"), offset=(0, 0))
                    elif state == "hover":
                        app.set_focus(None)
                        await pilot.hover(button)
                    else:
                        await pilot.hover(app.query_one("#other"), offset=(0, 0))
                        button.focus()
                    await pilot.pause()
                    word = _segment(button, "Browse")
                    cap = _segment(button, "k")
                    name = f"{theme}/{button_id}/{state}"
                    if cap.bgcolor.get_truecolor() == word.bgcolor.get_truecolor():
                        problems.append(f"{name}: the cap vanishes into the button")
                    elif _ratio(cap.bgcolor.get_truecolor(), word.bgcolor.get_truecolor()) < 1.08:
                        problems.append(f"{name}: the cap is barely visible")
                    if _ratio(cap.color.get_truecolor(), cap.bgcolor.get_truecolor()) < 4.5:
                        problems.append(f"{name}: the key is hard to read")
    assert not problems, "\n".join(problems[:20])

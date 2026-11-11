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

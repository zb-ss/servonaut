"""Complete host-key review and native consent remain usable with navigation."""
from __future__ import annotations

from dataclasses import replace

import pytest
from rich.cells import cell_len
from textual.content import Content
from textual.geometry import Region
from textual.widget import Widget
from textual.widgets import Button, Checkbox, DataTable

from servonaut.services.vault import crypto
from servonaut.widgets.sidebar import Sidebar
from tests._async_bounds import wait_until
from tests._native_actions import click_action
from tests._workspace_reflow_conformance import (
    _match_button_label_rows, assert_button_label_painted, tab_to,
)
from tests.test_workspace_vault_reflow import (
    HOST_KEY, _VaultHost, inert_services as _inert_services, stable_open,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


THEMES = ("servonaut", "servonaut-light", "ansi-dark", "ansi-light")
TRUST_CAPTION = "I checked these host-key fingerprints: pin them"


def _assert_full_wrapped_glyphs(
    app: _VaultHost, target: Widget, source: Content, width: int, viewport: Region,
) -> tuple[int, int]:
    """Compare unrestricted expected rows and hit-test every painted glyph."""
    assert width > 0 and viewport.height > 0
    assert app.screen.region.contains_region(viewport)
    expected = tuple(line.plain for line in source.without_spans.wrap(width, overflow="fold"))
    assert len(expected) <= viewport.height, (expected, viewport)
    strips = app.screen._compositor.render_strips()
    painted = tuple(strips[y].crop(viewport.x, viewport.right).text
                    for y in range(viewport.y, viewport.bottom))
    start, columns = _match_button_label_rows(expected, painted)
    clip = app.screen._compositor.find_widget(target).clip
    last = None
    for line, (fragment, column) in enumerate(zip(expected, columns), start=start):
        left = viewport.x + cell_len(painted[line][:column])
        y = viewport.y + line
        for x in range(left, left + cell_len(fragment)):
            assert viewport.contains(x, y) and clip.contains(x, y)
            hit = app.get_widget_at(x, y)[0]
            assert hit is target or target in hit.ancestors, (x, y, hit)
        if fragment.rstrip():
            last = (left + cell_len(fragment.rstrip()) - 1, y)
    assert last is not None
    return last


def _review_app(theme: str) -> _VaultHost:
    """Start from a saved fixture theme without performing a settings change."""
    app = _VaultHost(navigation_visible=True)
    app.config_manager._config = replace(app.config_manager.get(), theme=theme)
    app.theme = theme
    assert app.theme == theme and app.config_manager.get().theme == theme
    return app


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_full_fingerprint_wraps_inside_native_80_column_review(theme: str) -> None:
    app = _review_app(theme)
    async with app.run_test(size=(80, 24), notifications=True) as pilot:
        screen = await stable_open(app, "auto")
        await pilot.pause()
        assert screen.query_one(Sidebar).display
        assert not screen.has_class("-chat-open")
        table = screen.query_one("#auto_bind_table", DataTable)
        before = (tuple(screen._rows), set(screen._selected), table.cursor_row)
        scroller = screen.query_one("#auto_bind_detail_scroll")
        detail = screen.query_one("#auto_bind_detail")
        await tab_to(pilot, scroller)
        await pilot.press("end")
        await pilot.wait_for_scheduled_animations()
        fingerprint = crypto.ssh_public_fingerprint(HOST_KEY)
        # A complete public SHA256 fingerprint exercises the former long-token crop.
        assert len(fingerprint) == 50
        viewport = scroller.scrollable_content_region
        assert detail.content_region.width <= viewport.width
        _assert_full_wrapped_glyphs(
            app, detail, Content("  " + fingerprint), detail.content_region.width, viewport,
        )
        assert (tuple(screen._rows), set(screen._selected), table.cursor_row) == before
        await click_action(pilot, "#auto_bind_apply")
        await wait_until(lambda: "tick the box" in screen._status_raw)
        assert not screen.query_one("#auto_bind_trust", Checkbox).value
        assert not app.vault_command_service.operations
        assert (tuple(screen._rows), set(screen._selected), table.cursor_row) == before
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_full_trust_caption_has_native_glyph_hits_at_80_columns(theme: str) -> None:
    app = _review_app(theme)
    async with app.run_test(size=(80, 24), notifications=True) as pilot:
        screen = await stable_open(app, "auto")
        await pilot.pause()
        assert screen.query_one(Sidebar).display
        assert not screen.has_class("-chat-open")
        table = screen.query_one("#auto_bind_table", DataTable)
        before = (tuple(screen._rows), set(screen._selected), table.cursor_row)
        trust = screen.query_one("#auto_bind_trust", Checkbox)
        assert trust.label.plain == TRUST_CAPTION and trust.value is False
        await tab_to(pilot, trust)
        x, y = _assert_full_wrapped_glyphs(
            app, trust, trust.render(), trust.content_region.width, trust.content_region,
        )
        # The final caption glyph belongs to the same native consent Checkbox.
        assert await pilot.click(trust, offset=(x - trust.region.x, y - trust.region.y))
        await pilot.pause()
        assert app.focused is trust and trust.value is True
        assert trust.label.plain == TRUST_CAPTION
        assert not app.vault_command_service.operations
        await pilot.press("space")
        await pilot.pause()
        assert trust.value is False
        assert (tuple(screen._rows), set(screen._selected), table.cursor_row) == before
        assert not app.vault_command_service.operations
        await tab_to(pilot, screen.query_one("#auto_bind_back", Button))
        for button in screen.query_one("#auto_bind_actions").query(Button):
            assert_button_label_painted(app, button)
            assert app.get_widget_at(*button.content_region.center)[0] is button
        assert app.screen is screen and app._exception is None

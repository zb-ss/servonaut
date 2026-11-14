"""Unsaved settings remain readable through native edits, errors and themes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from rich.cells import cell_len
from textual.widgets import Input, Static

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from tests._async_bounds import wait_until
from tests._native_actions import click_action
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours
from tests.test_server_tool_identity_contrast import (
    _no_external_operations as _no_external_operations,
)
from tests.test_settings_presentation import _Host, _ready, _tab_to

pytestmark = pytest.mark.usefixtures("navigation_open")


def _assert_status_contrast(app: _Host, marker: Static) -> None:
    """Measure the complete visible word against its actual composed background."""
    bounds = marker.region.intersection(app.screen.region)
    compositor = app.screen._compositor
    strips = compositor.render_strips()
    for y in range(bounds.y, bounds.bottom):
        text = strips[y].crop(bounds.x, bounds.right).text
        offset = text.find("unsaved")
        if offset < 0:
            continue
        start = bounds.x + cell_len(text[:offset])
        for x in range(start, start + cell_len("unsaved")):
            assert app.get_widget_at(x, y)[0] is marker
            style = compositor.get_style_at(x, y)
            ratio = _contrast(*_paint_colours(style, app.ansi_theme))
            assert ratio >= 4.5, (app.theme, ratio, style)
        return
    pytest.fail("The complete unsaved status is not painted in its pinned dock")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_dirty_status_has_readable_native_paint_and_preserves_validation(
    tmp_path: Path, size: tuple[int, int],
) -> None:
    path = tmp_path / "config.json"
    manager = ConfigManager(config_path=path)
    manager.save(AppConfig(theme="atom-one-light"))
    manager.load()
    saved = path.read_bytes()
    app = _Host(manager, navigation_visible=True)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        marker = panel.query_one("#dirty_general", Static)
        username = panel.query_one("#general_username", Input)
        original = username.value
        assert not panel.is_dirty() and marker.render().plain == ""
        await _tab_to(pilot, username)
        await pilot.press("ctrl+a", "ctrl+k")
        assert username.value == ""
        await wait_until(panel.is_dirty)
        # Inspect mounted theme changes; the field draft remains untouched.
        for theme in ("atom-one-light", "atom-one-dark", "catppuccin-frappe", "atom-one-light"):
            app.theme = theme
            await pilot.pause()
            assert username.value == "" and panel.is_dirty()
            assert marker.render().plain == "● unsaved"
            _assert_status_contrast(app, marker)
        with patch.object(manager, "update", wraps=manager.update) as update:
            await click_action(pilot, "#save_general")
            status = panel.query_one("#status_general", Static)
            await wait_until(lambda: status.render().plain == "Username cannot be empty")
            assert app.focused is username and username.has_class("field-error")
            assert panel.is_dirty() and marker.render().plain == "● unsaved"
            _assert_status_contrast(app, marker)
            update.assert_not_called()
        assert path.read_bytes() == saved
        await pilot.press(*original)
        await wait_until(lambda: not panel.is_dirty())
        assert marker.render().plain == "" and path.read_bytes() == saved
        assert app._exception is None

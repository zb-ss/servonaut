"""Visible workspace reflow and controls retain their meaning and state."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from textual.document._document import Selection
from textual.geometry import Region
from textual.widgets import Button, TextArea

from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.fleet_values import ValueRow
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.sidebar_section import SidebarSection
from tests._async_bounds import wait_until
from tests.test_workspace_pilot import _Host, _assert_controls_clickable, _click, _row


def _line_values(app: _Host) -> dict[str, ValueRow]:
    """The one-line form's rows by field, with the painted value reachable."""
    rows = {row.field: row for row in app.screen.query_one("#fleet_value_line").query(ValueRow)}
    assert app.screen.query_one("#fleet_value_bar").display
    return rows


@pytest.mark.asyncio
@pytest.mark.parametrize("resize", ["navigation", "terminal"])
async def test_values_stay_complete_and_reachable_after_reflow(resize: str) -> None:
    app = _Host()
    app.instances = [_row("web-1"), _row("api-1"), _row("db-1")]
    async with app.run_test(size=(120 if resize == "terminal" else 100, 30)) as pilot:
        app.screen.query_one(InstanceTable).move_cursor(row=2)
        await pilot.pause()
        rows = _line_values(app)
        selected = app.screen.query_one(InstanceTable).get_selected_instance()
        expected = {field: selected[field] for field in ("public_ip", "private_ip", "region")}
        assert selected["name"] == "db-1" and rows["name"].value == "db-1"
        assert {field: rows[field].value for field in expected} == expected
        if resize == "navigation":
            await _click(pilot, "#workspace_navigation")
            await pilot.press("shift+f6")
        else:
            await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert _line_values(app) == rows
        for field, value in expected.items():
            row = rows[field]
            assert row.value == value and row.region.width > 0
            assert app.get_widget_at(*row.region.center)[0] is row


@pytest.mark.asyncio
async def test_reflow_keeps_the_values_and_the_chat_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _Host()
    async with app.run_test(size=(120, 30)) as pilot:
        app.screen.query_one(InstanceTable).focus()
        await pilot.pause()
        rows = _line_values(app)
        values = {field: row.value for field, row in rows.items()}
        await pilot.press("f2")
        await pilot.pause()
        composer = app.screen.query_one("#chat-input", TextArea)
        composer.load_text("Keep this unsent draft")
        composer.selection = Selection((0, 5), (0, 9))
        await pilot.pause()
        composer_selection = composer.selection
        with patch.object(ValueRow, "set_value", autospec=True) as repaint:
            for operation in ("hide", "show", "narrow", "wide"):
                if operation in {"hide", "show"}:
                    await _click(pilot, "#workspace_navigation")
                else:
                    await pilot.resize_terminal(100 if operation == "narrow" else 120, 30)
                await pilot.pause()
                assert _line_values(app) == rows
                assert {field: row.value for field, row in rows.items()} == values
                assert composer.text == "Keep this unsent draft"
                assert composer.selection == composer_selection
            repaint.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("monochrome", [False, True])
async def test_action_labels_and_link_affordance_stay_visible_without_width_jumps(
    monkeypatch: pytest.MonkeyPatch, theme: str, monochrome: bool,
) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    if monochrome:
        monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _Host()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        navigation = app.screen.query_one("#workspace_navigation", Button)
        chat = app.screen.query_one("#workspace_chat", Button)
        end = app.screen.query_one("#workspace_chat_end", Button)
        regions = navigation.region, chat.region
        end_region = None
        states = (
            (True, False), (False, False), (False, True), (True, True),
            (True, False), (False, True),
        )
        for nav_visible, chat_open in states:
            sidebar = app.screen.query_one(Sidebar)
            if sidebar.display != nav_visible:
                await _click(pilot, "#workspace_navigation")
            panel = next(iter(app.screen.query(ChatPanel)), None)
            if bool(panel and not panel._collapsed) != chat_open:
                await pilot.press("f2")
            await pilot.pause()
            panel = next(iter(app.screen.query(ChatPanel)), None)
            expected = (
                "Hide navigation" if nav_visible else "Show navigation",
                "Collapse chat" if chat_open else ("Restore chat" if panel else "Open chat"),
            )
            buttons = list(zip((navigation, chat), expected))
            if panel is not None:
                buttons.append((end, "End chat"))
                if end_region is None:
                    end_region = end.region
                assert end.region == end_region and end.region.width == 10
            for button, label in buttons:
                assert button.label.plain == label
                segments = [
                    segment
                    for strip in button.render_lines(Region(0, 0, *button.region.size))
                    for segment in strip
                ]
                assert label in "".join(segment.text for segment in segments)
                assert any(
                    segment.text.strip() and segment.style and segment.style.underline
                    for segment in segments
                )
            assert (navigation.region, chat.region) == regions
            _assert_controls_clickable(app)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
async def test_navigation_focus_is_flat_and_keeps_the_active_route_marker(
    theme: str,
) -> None:
    app = _Host()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("shift+f6")
        await pilot.pause()
        sidebar = app.screen.query_one(Sidebar)
        active = sidebar.query_one("#nav_list", Button)
        section = sidebar.query_one("#section_core", SidebarSection)
        header = section.query_one(".section-header", Button)
        alternate = sidebar.query_one("#nav_custom_servers", Button)
        regions = {button: button.region for button in (active, header, alternate)}
        for button in (header, alternate, active):
            button.focus()
            await pilot.pause()
            assert app.focused is button
            assert not button.styles.border_top[0]
            assert not button.styles.border_right[0]
            assert not button.styles.border_bottom[0]
            assert button.region == regions[button]
            segments = [
                segment for y in range(button.size.height)
                for segment in button.render_line(y)
            ]
            assert any(
                segment.text.strip() and segment.style and segment.style.underline
                for segment in segments
            )
            assert active.has_class("--active")
            assert active.styles.border_left[0] == "thick"

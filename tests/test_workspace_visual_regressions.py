"""Visible workspace reflow and controls retain their meaning and state."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from textual.document._document import Selection
from textual.geometry import Region
from textual.widgets import Button, TextArea

from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.sidebar_section import SidebarSection
from tests._async_bounds import wait_until
from tests.test_workspace_pilot import _Host, _assert_controls_clickable, _click, _row


def _visible_detail_text(detail: TextArea) -> str:
    """Use the real painted strips, including the widget's outer style cache."""
    return "".join(
        strip.text for strip in detail.render_lines(Region(0, 0, *detail.size))
    ).replace(" ", "")


@pytest.mark.asyncio
@pytest.mark.parametrize("resize", ["navigation", "terminal"])
async def test_details_render_full_values_after_reflow(resize: str) -> None:
    app = _Host()
    app.instances = [_row("web-1"), _row("api-1"), _row("db-1")]
    app.instances[2].update(public_ip="192.0.2.12", private_ip="10.0.0.12")
    async with app.run_test(size=(120 if resize == "terminal" else 100, 30)) as pilot:
        app.screen.query_one(InstanceTable).move_cursor(row=2)
        await pilot.pause()
        detail = app.screen.query_one("#instance_detail", TextArea)
        document = detail.document
        original = detail.text
        assert "PublicIP:192.0.2.12" in _visible_detail_text(detail)
        if resize == "navigation":
            await _click(pilot, "#workspace_navigation")
            await pilot.press("shift+f6")
        else:
            await pilot.resize_terminal(100, 30)
        await wait_until(lambda: detail.wrapped_document._width == detail.wrap_width)
        await pilot.pause()
        assert detail.document is document and detail.text == original
        rendered = _visible_detail_text(detail)
        assert "PublicIP:192.0.2.12" in rendered
        assert "PrivateIP:10.0.0.12" in rendered
        assert "Region:local" in rendered


@pytest.mark.asyncio
async def test_reflow_preserves_detail_selection_scroll_and_chat_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _Host()
    async with app.run_test(size=(120, 30)) as pilot:
        detail = app.screen.query_one("#instance_detail", TextArea)
        detail.load_text("\n".join(
            f"Line {index}: neutral fixture value" for index in range(12)
        ))
        selection = Selection((6, 8), (6, 15))
        detail.selection = selection
        await pilot.pause()
        detail.scroll_to(y=4, animate=False, force=True)
        app.screen.query_one(InstanceTable).focus()
        await pilot.pause()
        original_scroll = detail.scroll_offset
        assert original_scroll.y > 0
        document = detail.document
        await pilot.press("f2")
        await pilot.pause()
        composer = app.screen.query_one("#chat-input", TextArea)
        composer.load_text("Keep this unsent draft")
        composer.selection = Selection((0, 5), (0, 9))
        await pilot.pause()
        composer_selection = composer.selection
        with patch.object(detail, "load_text", wraps=detail.load_text) as reload_text:
            for operation in ("hide", "show", "narrow", "wide"):
                if operation in {"hide", "show"}:
                    await _click(pilot, "#workspace_navigation")
                else:
                    await pilot.resize_terminal(100 if operation == "narrow" else 120, 30)
                await pilot.pause()
                assert detail.document is document
                assert detail.selection == selection
                assert detail.scroll_offset == original_scroll
                assert composer.text == "Keep this unsent draft"
                assert composer.selection == composer_selection
            reload_text.assert_not_called()


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

"""CloudTrail's native filters keep the inspector tied to visible records."""

from __future__ import annotations

import pytest
from textual.containers import VerticalScroll
from textual.pilot import Pilot
from textual.widgets import DataTable, Select, Static

from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
from servonaut.services.cloudtrail_service import LookupPage
from tests._async_bounds import wait_until
from tests.test_selection_copy import _Clipboard, clipboard as clipboard
from tests.test_workspace_pilot import _click
from tests.test_workspace_security_reflow import (
    _SecurityHost,
    _fake_boundaries as _fake_boundaries,
)


async def _choose(pilot: Pilot, select: Select, *, first: bool) -> None:
    select.scroll_visible(animate=False, immediate=True)
    await pilot.pause()
    select.focus()
    await pilot.press("enter")
    await wait_until(lambda: select.expanded)
    await pilot.press("home")
    if first:
        await pilot.press("down")
    await pilot.press("enter")
    await wait_until(lambda: not select.expanded)
    await pilot.pause()


def _visible_detail(app: _SecurityHost, detail: Static, reader: VerticalScroll) -> str:
    region = detail.region.intersection(reader.scrollable_content_region).intersection(app.screen.region)
    strips = app.screen._compositor.render_strips()
    return "\n".join(strips[y].crop(region.x, region.right).text for y in range(region.y, region.bottom))


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)], ids=["100x30", "160x50"])
async def test_native_filter_exclusion_clears_inspector_and_selection(
    size: tuple[int, int], clipboard: _Clipboard,
) -> None:
    # Distinct taxonomy names make Home/Down choose the same first real option.
    names = ["AuthorizeSecurityGroupIngress", "DescribeInstances", "StartInstances", "StopInstances"]
    events = [
        {
            "event_time": f"2026-01-01 00:00:0{4 - index}",
            "event_name": name,
            "username": "other" if name == "StartInstances" else "operator",
            "source_ip": "198.51.100.1",
            "resource_type": "AWS::EC2::Instance",
            "resource_name": "web-1",
            "region": "eu-west-2",
            "error_code": "",
            "raw_event": f"{name} [literal]\nlast café Ω",
        }
        for index, name in enumerate(names)
    ]
    app = _SecurityHost(True)
    app.cloudtrail_service.lookup_page.return_value = LookupPage(events=events, next_token=None)
    async with app.run_test(size=size) as pilot:
        screen = CloudTrailBrowserScreen()
        await app.push_screen(screen)
        await pilot.pause()
        fetch = screen.query_one("#ct_btn_fetch")
        fetch.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        await _click(pilot, "#ct_btn_fetch")
        table = screen.query_one("#cloudtrail_table", DataTable)
        await wait_until(lambda: table.row_count == 4)
        app.clear_notifications()
        table.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        table.focus()
        await pilot.press("home", "down", "down", "enter")
        await wait_until(lambda: screen._selected_event is events[2])
        detail = screen.query_one("#event_detail_text", Static)
        assert "StartInstances" in detail.render().plain

        event_picker = screen.query_one("#ct_select_event_name", Select)
        await _choose(pilot, event_picker, first=True)
        assert event_picker.value == "AuthorizeSecurityGroupIngress"
        assert table.row_count == 1 and len(screen._visible) == 1
        assert screen._visible[0] is events[0]
        assert screen._selected_event is None
        assert detail.render().plain == "Select an event to view details."
        reader = screen.query_one("#event_detail", VerticalScroll)
        detail.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert "Select an event to view details." in " ".join(_visible_detail(app, detail, reader).split())

        # Native Enter selects the remaining record; full literal detail stays copyable.
        table.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        table.focus()
        await pilot.press("home", "enter")
        await wait_until(lambda: screen._selected_event is events[0])
        assert events[0]["raw_event"] in detail.render().plain
        reader.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        reader.focus()
        await pilot.press("end")
        await pilot.wait_for_scheduled_animations()
        await pilot.pause()
        assert "last café Ω" in _visible_detail(app, detail, reader)
        await pilot.press("y")
        await wait_until(lambda: bool(clipboard.calls))
        assert events[0]["raw_event"] in clipboard.calls[-1]
        assert "StartInstances" not in clipboard.calls[-1]

        # Widening the list keeps the still-visible identity and exact inspector.
        selected_text = detail.render().plain
        await _choose(pilot, event_picker, first=False)
        assert event_picker.value is Select.NULL and table.row_count == 4
        assert screen._selected_event is events[0]
        assert detail.render().plain == selected_text
        await _choose(pilot, event_picker, first=True)
        assert screen._selected_event is events[0]

        # Combining a username filter can exclude every record and must clear too.
        user_picker = screen.query_one("#ct_select_username", Select)
        user_picker.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        user_picker.focus()
        await pilot.press("enter", "home", "down", "down", "enter")
        await pilot.pause()
        assert user_picker.value == "other"
        assert table.row_count == 0 and screen._visible == []
        assert screen._selected_event is None
        assert detail.render().plain == "Select an event to view details."
        app.cloudtrail_service.lookup_page.assert_awaited_once()

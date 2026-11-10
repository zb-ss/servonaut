"""CloudWatch pagination remains readable beside the source-IP table."""

from __future__ import annotations

import json

import pytest
from textual.widgets import Button, DataTable, Static

from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
from tests._workspace_reflow_conformance import assert_button_label_painted
from tests.test_workspace_reflow import _painted
from tests.test_workspace_security_reflow import (
    _SecurityHost,
    _fake_boundaries as _fake_boundaries,
    _opener,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.mark.asyncio
@pytest.mark.parametrize("event_count", [12, 112])
async def test_cloudwatch_narrow_pager_paints_complete_count_and_page_summary(
    event_count: int,
) -> None:
    app = _SecurityHost(True)
    app.cloudwatch_service.get_log_events.return_value = [
        {
            "timestamp": "2026-01-01 00:00:01",
            "log_stream": "stream-one",
            "message": f"Fixture event {index}",
        }
        for index in range(event_count)
    ]
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _opener("watch")(app, pilot)
        summary = screen.query_one("#cw_page_info", Static)
        pager = screen.query_one("#cloudwatch_pager")
        pager.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        # The navigation rail and source-IP panel leave a genuinely narrow pane.
        assert summary.region.width < 40
        assert screen.region.contains_region(summary.region)
        expected = (
            "12 events total" if event_count == 12 else
            "Page 1 of 2 (112 events total)"
        )
        assert expected in " ".join(_painted(app, summary).split())
        assert "…" not in _painted(app, summary)
        previous = screen.query_one("#cw_btn_prev", Button)
        following = screen.query_one("#cw_btn_next", Button)
        assert previous.disabled
        assert following.disabled is (event_count == 12)
        if event_count == 112:
            assert await pilot.click("#cw_btn_next")
            await pilot.pause()
            assert screen._current_page == 1
            assert screen.query_one("#cloudwatch_events_table", DataTable).row_count == 12
            assert "Page 2 of 2 (112 events total)" in " ".join(_painted(app, summary).split())
            assert not previous.disabled and following.disabled


@pytest.mark.asyncio
@pytest.mark.parametrize("event_count", [0, 112], ids=["empty", "paged"])
async def test_cloudwatch_short_initial_view_keeps_controls_and_inspector_visible(
    event_count: int,
) -> None:
    app = _SecurityHost(True, multi=True)
    app.cloudwatch_service.get_log_events.return_value = [
        {
            "timestamp": f"2026-01-01 00:{index // 60:02d}:{index % 60:02d}",
            "log_stream": "stream-one",
            # RFC5737 documentation address exercises the real IP-table scrollbar.
            "message": json.dumps({
                "clientIp": "198.51.100.123", "action": "BLOCK",
                "message": f"Fixture event {index}",
            }),
        }
        for index in range(event_count)
    ]
    async with app.run_test(size=(100, 30)) as pilot:
        if event_count:
            screen = await _opener("watch")(app, pilot)
        else:
            screen = CloudWatchBrowserScreen()
            await app.push_screen(screen)
            await pilot.pause()
        app.clear_notifications()
        await pilot.pause()
        outer = screen.query_one("#cloudwatch_outer")
        assert outer.scroll_y == 0
        assert screen.has_class("-short") and screen.has_class("-content-narrow")
        assert screen.query_one("#cw_filter_account").display
        viewport = outer.scrollable_content_region.intersection(screen.region)
        table = screen.query_one("#cloudwatch_events_table", DataTable)
        assert viewport.contains_region(table.region)
        assert table.scrollable_content_region.height >= 4
        if event_count:
            assert table.row_count == 100
            table_paint = _painted(app, table)
            assert "2026-01-01 00:00:00" in table_paint
            assert "2026-01-01 00:00:01" in table_paint
            ips = screen.query_one("#cloudwatch_ips_table", DataTable)
            assert ips.row_count == 1 and viewport.contains_region(ips.region)
            assert "198.51.100.123" in _painted(app, ips)

        # No reveal/focus/scroll occurs before checking the original view.
        previous = screen.query_one("#cw_btn_prev", Button)
        following = screen.query_one("#cw_btn_next", Button)
        ban = screen.query_one("#cw_btn_ban_ip", Button)
        for button in (previous, following, ban):
            assert viewport.contains_region(button.region), button.region
            assert app.get_widget_at(*button.region.center)[0] is button
            assert_button_label_painted(app, button)
        detail = screen.query_one("#cloudwatch_detail")
        guidance = screen.query_one("#cloudwatch_detail_text", Static)
        assert viewport.contains_region(detail.region)
        assert detail.scrollable_content_region.contains_region(guidance.region)
        assert "Select a log event to view the full message." in " ".join(
            _painted(app, guidance).split()
        )
        assert previous.disabled
        assert following.disabled is (event_count == 0)

        if event_count:
            summary = screen.query_one("#cw_page_info", Static)
            assert viewport.contains_region(summary.region)
            assert "Page 1 of 2 (112 events total)" in " ".join(
                _painted(app, summary).split()
            )
            assert await pilot.click("#cw_btn_next")
            await pilot.pause()
            assert screen._current_page == 1 and table.row_count == 12
            assert "Page 2 of 2 (112 events total)" in " ".join(
                _painted(app, summary).split()
            )
            assert not previous.disabled and following.disabled
            assert await pilot.click("#cw_btn_prev")
            await pilot.pause()
            assert screen._current_page == 0 and table.row_count == 100
            app.cloudwatch_service.get_log_events.assert_awaited_once()
        else:
            app.cloudwatch_service.get_log_events.assert_not_awaited()

"""The CloudWatch source-IP filter is a real button, and its key cycles it too."""

from __future__ import annotations

import pytest

from tests._async_bounds import wait_until

from servonaut.widgets.action_button import ActionButton
from tests.test_workspace_security_reflow import (
    _SecurityHost,
    _fake_boundaries as _fake_boundaries,
    _opener,
)


@pytest.mark.asyncio
async def test_ip_filter_button_and_key_cycle_the_same_filter() -> None:
    app = _SecurityHost(True)
    app.cloudwatch_service.get_log_events.return_value = [
        {"timestamp": "2026-01-01 00:00:01", "log_stream": "stream-one", "message": "event"}
    ]
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("watch")(app, pilot)
        toggle = screen.query_one("#cw_btn_ip_filter", ActionButton)
        assert toggle.words == "Filter: all"
        assert toggle.label.plain.split() == ["Filter:", "all", "\u2590f\u258c"]
        # The button is painted on its own row, inside the panel header.
        header = screen.query_one("#cw_top_ips_header")
        assert toggle.region.height == 1 and header.region.contains_region(toggle.region)

        assert await pilot.click("#cw_btn_ip_filter")
        await pilot.pause()
        assert toggle.words == "Filter: allowed"
        await pilot.press("f")
        await pilot.pause()
        assert toggle.words == "Filter: blocked"
        assert toggle.variant == "error"


@pytest.mark.asyncio
async def test_the_filter_button_names_the_current_filter_and_fits_at_100x30() -> None:
    app = _SecurityHost(True)
    app.cloudwatch_service.get_log_events.return_value = [
        {"timestamp": "2026-01-01 00:00:01", "log_stream": "stream-one", "message": "event"}
    ]
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _opener("watch")(app, pilot)
        toggle = screen.query_one("#cw_btn_ip_filter", ActionButton)
        header = screen.query_one("#cw_top_ips_header")
        for words in ("Filter: all", "Filter: allowed", "Filter: blocked"):
            await wait_until(lambda: toggle.words == words)
            await pilot.pause()
            # It names the filter in force, not an action, and is not cut.
            assert toggle.content_size.width >= toggle.label.cell_length, words
            assert header.region.contains_region(toggle.region), words
            await pilot.press("f")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 24), (100, 30), (130, 40), (160, 50)])
async def test_the_top_ips_header_stays_one_row_and_nothing_moves(size) -> None:
    app = _SecurityHost(True)
    app.cloudwatch_service.get_log_events.return_value = [
        {"timestamp": "2026-01-01 00:00:01", "log_stream": "stream-one", "message": "event"}
    ]
    async with app.run_test(size=size) as pilot:
        screen = await _opener("watch")(app, pilot)
        toggle = screen.query_one("#cw_btn_ip_filter", ActionButton)
        heading = screen.query_one("#cw_top_ips_label")
        header = screen.query_one("#cw_top_ips_header")
        table = screen.query_one("#cloudwatch_ips_table")
        ban = screen.query_one("#cw_btn_ban_ip")
        await wait_until(lambda: header.size.width > 0)
        await pilot.pause()
        await pilot.pause()
        anchor = (table.region, ban.region, header.region)
        # Longest label the button can show, measured from the button itself.
        widest_button = max(
            toggle.natural_width(short=False, hint=True) + len(f"Filter: {name.lower()}") - len(toggle.words)
            for name in screen._IP_FILTERS
        )
        shown_expected = len("Top IPs") + widest_button <= header.size.width
        # Measured: the pane is 29 cells wide up to 130x40 (heading 7 + button 24
        # does not fit) and 41 at 160x50 (it does).
        assert shown_expected == (size[0] >= 160), (size, header.size.width, widest_button)
        for presses in range(5):
            words = toggle.words
            assert header.region.height == 1, (size, words)
            assert toggle.region.height == 1 and header.region.contains_region(toggle.region)
            assert toggle.content_size.width >= toggle.label.cell_length, (size, words)
            # Shown exactly when heading + the longest button fit the header.
            assert heading.display == shown_expected, (size, words, header.size.width, widest_button)
            if heading.display:
                assert heading.region.width >= len("Top IPs"), (size, words)
                assert heading.content_size.width >= len("Top IPs"), (size, words)
                assert not heading.region.intersection(toggle.region).area, (size, words)
                assert heading.region.right <= toggle.region.x, (size, words)
            assert (table.region, ban.region, header.region) == anchor, (size, presses)
            # The table starts right under the one-row header, so no row is lost.
            assert table.region.y == header.region.bottom, (size, words)
            if size == (100, 30):
                assert table.content_size.height - 1 >= 1, (size, words)
            await pilot.press("f")
            await pilot.pause()
            await pilot.pause()

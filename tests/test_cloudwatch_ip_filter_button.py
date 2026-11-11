"""The CloudWatch source-IP filter is a real button, and its key cycles it too."""

from __future__ import annotations

import pytest

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
        assert toggle.words == "Show all"
        assert toggle.label.plain.split() == ["Show", "all", "\u2590f\u258c"]
        # The button is painted on its own row, inside the panel header.
        header = screen.query_one("#cw_top_ips_header")
        assert toggle.region.height == 1 and header.region.contains_region(toggle.region)

        assert await pilot.click("#cw_btn_ip_filter")
        await pilot.pause()
        assert toggle.words == "Show allowed"
        await pilot.press("f")
        await pilot.pause()
        assert toggle.words == "Show blocked"
        assert toggle.variant == "error"

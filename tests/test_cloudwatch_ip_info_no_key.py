"""Native source-IP selection tolerates an unconfigured optional abuse lookup."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Static

from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
from tests._workspace_reflow_conformance import tab_to
from tests.test_cloud_browser_error_lifecycle import (
    _fetch, _finished, _host, _open, _painted,
)
from tests.test_workspace_security_reflow import _fake_boundaries as _fake_boundaries

pytestmark = pytest.mark.usefixtures("navigation_open")


# Capture before the shared fixture substitutes an error-result fake. The
# regression must exercise the actual no-key return, not a mocked None.
_NATIVE_ABUSE_INFO = CloudWatchBrowserScreen._fetch_abuse_info


@pytest.mark.asyncio
@pytest.mark.parametrize("demo", [False, True])
async def test_native_ip_enter_without_abuse_key_keeps_browser_and_geo_result(
    demo: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _host(demo)
    app.config_manager.update(abuseipdb_api_key="")
    geo = AsyncMock(return_value=None)
    monkeypatch.setattr(CloudWatchBrowserScreen, "_fetch_ip_geo", geo)
    monkeypatch.setattr(CloudWatchBrowserScreen, "_fetch_abuse_info", _NATIVE_ABUSE_INFO)
    async with app.run_test(size=(160, 50), notifications=True) as pilot:
        screen = await _open(app, pilot, "watch")
        assert app.config_manager.get().abuseipdb_api_key == ""
        assert screen._fetch_abuse_info.__func__ is _NATIVE_ABUSE_INFO
        await _fetch(pilot, screen, "watch")
        await _finished(pilot, screen, "watch", 1)
        ips = screen.query_one("#cloudwatch_ips_table", DataTable)
        assert ips.row_count == 1
        await tab_to(pilot, ips)
        await pilot.press("home", "enter")
        await screen.workers.wait_for_complete()
        await pilot.pause()
        assert app.is_running and app.screen is screen
        assert app.focused is ips and screen._selected_ip_row == 0
        geo.assert_awaited_once_with("1.1.1.1")

        detail = screen.query_one("#cloudwatch_detail_text", Static)
        plain = detail.render().plain
        shown_ip = "198.51.100.149" if demo else "1.1.1.1"
        assert f"IP Info: {shown_ip}" in plain
        assert "AbuseIPDB" not in plain
        expected_geo = "[redacted in demo mode]" if demo else "lookup failed"
        assert f"Geolocation: {expected_geo}" in plain
        reader = screen.query_one("#cloudwatch_detail", VerticalScroll)
        await tab_to(pilot, reader)
        await pilot.press("end")
        await pilot.wait_for_scheduled_animations()
        await pilot.pause()
        assert "".join(expected_geo.split()) in "".join(_painted(app, detail, reader).split())
        assert app.is_running and app._exception is None

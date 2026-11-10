"""Real filter layout must survive a controlled narrow width request."""
from __future__ import annotations

import asyncio

import pytest
from textual.containers import Container
from textual.widgets import Button, Select

from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import assert_button_label_painted, tab_to
from tests.test_workspace_security_reflow import (
    _SecurityHost, _fake_boundaries as _fake_boundaries,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.mark.asyncio
@pytest.mark.parametrize("narrow,multi", [
    (False, False), (False, True), (True, False), (True, True),
], ids=["wide-single", "wide-multiple", "narrow-single", "narrow-multiple"])
async def test_requested_filter_width_keeps_native_actions_and_selections(
    narrow: bool, multi: bool,
) -> None:
    # This deliberate width request tests sizing, not the unseen full-run leaf.
    app = _SecurityHost(True, multi=multi)
    async with app.run_test(size=(100, 30) if narrow else (180, 50)) as pilot:
        origin = app.screen
        screen = CloudTrailBrowserScreen()
        await app.push_screen(screen)
        filters = screen.query_one("#cloudtrail_filters", Container)
        fetch = screen.query_one("#ct_btn_fetch", Button)
        back = screen.query_one("#ct_btn_back", Button)
        time_range = screen.query_one("#ct_select_time_range", Select)

        def mounted_layout() -> bool:
            if app._exception is not None:
                raise app._exception
            return (
                screen.is_mounted and filters.is_mounted
                and fetch.is_mounted and back.is_mounted and time_range.is_mounted
                and not screen._layout_required
                and screen.has_class("-content-narrow") is narrow
                and filters.has_class("-with-account") is multi
            )

        await wait_until(mounted_layout)
        assert screen.has_class("-content-narrow") is narrow
        assert filters.has_class("-with-account") is multi
        previous = time_range.value
        await tab_to(pilot, time_range)
        await pilot.press("enter")
        await wait_until(lambda: time_range.expanded)
        await pilot.press("up", "enter")
        await wait_until(lambda: not time_range.expanded)
        assert time_range.value != previous
        await pilot.press("f5")
        await wait_until(lambda: (
            bool(screen._events) and not fetch.disabled
            and app.cloudtrail_service.lookup_page.await_count == 1
        ))
        pickers = tuple(filters.query(Select))
        selections = {picker.id: picker.value for picker in pickers}
        account = screen._account

        # Preserve production sizing and min-width: only request a native width.
        filters.styles.width = 33
        refreshed = asyncio.Event()
        screen.call_after_refresh(refreshed.set)

        def resized_layout() -> bool:
            if app._exception is not None:
                raise app._exception
            return refreshed.is_set() and not screen._layout_required

        await wait_until(resized_layout)
        assert screen.has_class("-content-narrow") is narrow
        assert filters.has_class("-with-account") is multi
        for button, caption in ((fetch, "Fetch"), (back, "Back")):
            await tab_to(pilot, button)
            await pilot.wait_for_scheduled_animations()
            assert app.focused is button
            assert button.words == caption
            assert_button_label_painted(app, button)
            hit = app.get_widget_at(*button.region.center)[0]
            assert hit is button or button in hit.ancestors
            assert {picker.id: picker.value for picker in pickers} == selections
            assert screen._account == account and app._exception is None
            assert app.cloudtrail_service.lookup_page.await_count == 1

        # A real pointer Fetch and native Back retain the complete action route.
        assert await pilot.click(
            fetch, offset=(fetch.region.width // 2, fetch.region.height // 2),
        )
        await wait_until(lambda: (
            app.cloudtrail_service.lookup_page.await_count == 2 and not fetch.disabled
        ))
        assert {picker.id: picker.value for picker in pickers} == selections
        assert screen._account == account and app._exception is None
        await tab_to(pilot, back)
        await pilot.wait_for_scheduled_animations()
        assert_button_label_painted(app, back)
        assert app.get_widget_at(*back.region.center)[0] is back
        await pilot.press("enter")
        await wait_until(lambda: app.screen is origin)
        assert app.cloudtrail_service.lookup_page.await_count == 2
        assert app._exception is None

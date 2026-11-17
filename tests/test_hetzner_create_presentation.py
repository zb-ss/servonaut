"""Hetzner catalogs remain reachable beside the fixed confirmation controls."""

from __future__ import annotations

import pytest
from textual.widget import Widget
from textual.widgets import Button, DataTable

from servonaut.screens.hetzner_create import HetznerCreateScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import assert_button_label_painted
from tests.test_workspace_cloud_managers import _CloudApp, _ready, _tab_to

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)], ids=["narrow", "wide"])
@pytest.mark.parametrize("visible", [False, True], ids=["rail-hidden", "rail-visible"])
async def test_native_catalog_focus_excludes_pinned_confirmation(
    size: tuple[int, int], visible: bool,
) -> None:
    app = _CloudApp(HetznerCreateScreen, visible)
    async with app.run_test(size=size) as pilot:
        screen = await _ready(app, "hetzner_types_table")
        tables = [screen.query_one(selector, DataTable) for selector in (
            "#hetzner_types_table", "#hetzner_images_table",
            "#hetzner_locations_table", "#hetzner_keys_table",
        )]
        await wait_until(lambda: all(table.row_count for table in tables))
        await pilot.pause()
        selection = tuple((table, table.cursor_coordinate) for table in tables)
        submit = screen.query_one("#btn_hetzner_create_submit", Button)
        back = screen.query_one("#btn_hetzner_create_back", Button)
        footer = submit.parent.parent
        footer_region = footer.region

        def whole_target_owned(widget: Widget) -> None:
            assert widget.region.width > 0 and widget.region.height > 0
            assert screen.region.contains_region(widget.region)
            assert screen.find_widget(widget).clip.contains_region(widget.region)
            for y in range(widget.region.y, widget.region.bottom):
                for x in range(widget.region.x, widget.region.right):
                    hit = app.get_widget_at(x, y)[0]
                    assert hit is widget or widget in hit.ancestors

        for table in tables:
            await _tab_to(app, pilot, f"#{table.id}")
            await pilot.wait_for_scheduled_animations()
            await pilot.pause()
            assert app.focused is table
            assert not table.region.overlaps(footer.region)
            whole_target_owned(table)
            assert tuple((item, item.cursor_coordinate) for item in tables) == selection
            assert footer.region == footer_region

        for button in (submit, back):
            await _tab_to(app, pilot, f"#{button.id}")
            await pilot.wait_for_scheduled_animations()
            await pilot.pause()
            whole_target_owned(button)
            assert_button_label_painted(app, button)
            assert footer.region == footer_region
        await _tab_to(app, pilot, "#btn_hetzner_create_submit")
        await pilot.wait_for_scheduled_animations()
        assert not submit.disabled
        assert await pilot.click(submit)
        await wait_until(lambda: any(
            notification.message == "Please enter a server name."
            for notification in app._notifications
        ))
        assert app.screen is screen
        app.hetzner_service.create_server.assert_not_awaited()
        assert tuple((item, item.cursor_coordinate) for item in tables) == selection
        await _tab_to(app, pilot, "#btn_hetzner_create_back")
        await pilot.wait_for_scheduled_animations()
        whole_target_owned(back)
        assert_button_label_painted(app, back)
        assert await pilot.click(back)
        await wait_until(lambda: app.screen is not screen)
        assert app._exception is None

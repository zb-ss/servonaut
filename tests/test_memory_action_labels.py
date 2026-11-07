"""Native memory actions retain their full labels in both workspace layouts."""

from __future__ import annotations

import pytest
from textual.widgets import Button, DataTable

from servonaut.screens.memory import MemoryScreen
from tests._async_bounds import wait_until
from tests.test_workspace_memory_core import (
    _MemoryWorkspaceApp,
    _local_services_only as _local_services_only,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_memory_action_labels_remain_painted_through_native_focus_scroll(size) -> None:
    app = _MemoryWorkspaceApp("memory-populated", navigation_visible=True)
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        assert isinstance(screen, MemoryScreen)
        table = screen.query_one("#memory-table", DataTable)
        await wait_until(lambda: table.row_count == 2)
        table.move_cursor(row=1)
        await pilot.pause()
        row = table.cursor_row
        body = screen.query_one("#memory-container")
        targets = (
            "btn_refresh_all", "btn_refresh_module", "btn_pin_key",
            "btn_clear_module", "btn_annotate", "btn_view_summary", "btn_export",
        )
        for button_id in targets:
            button = screen.query_one(f"#{button_id}", Button)
            assert not button.disabled
            for _ in range(len(screen.focus_chain) + 1):
                if app.focused is button:
                    break
                await pilot.press("tab")
            assert app.focused is button
            await pilot.wait_for_scheduled_animations()
            assert screen.region.contains_region(button.region)
            hit = app.get_widget_at(*button.content_region.center)[0]
            assert hit is button or button in hit.ancestors
            region = button.region
            strips = screen._compositor.render_strips()
            painted = "\n".join(
                strips[y].crop(region.x, region.right).text
                for y in range(region.y, region.bottom)
            )
            assert str(button.label) in painted, (button_id, painted)
        assert table.cursor_row == row
        if size == (100, 30):
            assert body.scroll_y > 0
        app.memory_service.refresh_all.assert_not_awaited()
        app.memory_service.refresh.assert_not_awaited()
        app.memory_service.pin.assert_not_awaited()
        app.memory_service.clear.assert_not_called()
        assert app._exception is None

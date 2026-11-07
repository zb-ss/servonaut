"""An empty recovery inventory exposes its guidance and actions on arrival."""

from unittest.mock import AsyncMock

import pytest
from textual.widgets import Button, DataTable, Static

from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import assert_button_label_painted
from tests.test_workspace_ovh_resources import _ResourceApp
from tests.test_workspace_reflow import _painted


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_type", ["vps", "cloud"])
async def test_empty_snapshots_expose_guidance_and_actions_before_scrolling(
    monkeypatch, provider_type: str,
) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _ResourceApp(True)
    service = app.bundles["ovh"].snapshot
    service.list_vps_snapshots.return_value = []
    service.list_cloud_snapshots = AsyncMock(return_value=[])
    mutations = []
    for method in (
        "create_vps_snapshot", "create_cloud_snapshot", "restore_vps_snapshot",
        "delete_vps_snapshot", "delete_cloud_snapshot", "configure_vps_backup",
    ):
        guard = AsyncMock(side_effect=AssertionError("Unexpected snapshot write"))
        setattr(service, method, guard)
        mutations.append(guard)

    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        previous = app.screen
        screen = OVHSnapshotsScreen({
            "id": "vps-example" if provider_type == "vps" else "project-example/instance-example",
            "name": "web-1", "provider_type": provider_type, "account": "ovh",
        })
        await app.push_screen(screen)
        container = screen.query_one("#snapshots_container")
        loader = service.list_vps_snapshots if provider_type == "vps" else service.list_cloud_snapshots
        await wait_until(lambda: loader.await_count == 1 and not screen._read_loading.is_busy)
        await pilot.pause()
        loader.assert_awaited_once()

        # No focus/reveal/scroll step may conceal an unusable initial layout.
        assert container.scroll_y == 0
        table = screen.query_one("#snapshots_table", DataTable)
        assert table.is_mounted and table.row_count == 0 and not table.display
        empty = screen.query_one("#snapshot_empty_state", Static)
        assert "No snapshots found." in _painted(app, empty)
        for selector in ("#btn_create", "#btn_restore", "#btn_delete", "#btn_back"):
            button = screen.query_one(selector, Button)
            assert_button_label_painted(app, button)
            assert app.get_widget_at(*button.region.center)[0] is button

        assert await pilot.click(screen.query_one("#btn_back", Button))
        await pilot.pause()
        assert app.screen is previous

    for guard in mutations:
        guard.assert_not_called()

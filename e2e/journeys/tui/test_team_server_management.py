"""Share edited connection details once, then remove exact shared records."""
from __future__ import annotations

import pytest

from e2e.journeys.tui.test_team_management import _open_team, _press, _screen_idle, _seed

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_edit_share_all_remove_single_and_multiple_and_show_config_author(tui, seed, fake_cloud, size):
    slug = _seed(seed, fake_cloud)
    path = f"/api/v1/teams/{slug}/servers"
    async with tui(size=size) as t:
        await _open_team(t)
        await _screen_idle(t)
        await _press(t, "#btn_share_all")
        await t.wait_for_screen("ShareServersConfirmModal")
        await _press(t, "#share_confirm_none")
        listing = t.on_screen("#share_confirm_list")
        listing.focus()
        await t.press("home", "space")
        await t.fill("#share_confirm_name", "application")
        await t.fill("#share_confirm_username", "deploy")
        await t.fill("#share_confirm_port", "2201")
        listing.focus()
        await t.press("down", "space")
        await t.fill("#share_confirm_name", "database")
        await t.fill("#share_confirm_username", "admin")
        await t.fill("#share_confirm_port", "70000")
        await _press(t, "#share_confirm_share")
        await t.wait_for_toast(r"Port must be a number between 1 and 65535", severity="error")
        assert t.screen_name() == "ShareServersConfirmModal"
        assert fake_cloud.requests(path, "POST") == []
        await t.fill("#share_confirm_port", "2202")
        await _press(t, "#share_confirm_share")
        await t.wait_for_screen("TeamManagementScreen")
        await t.wait_for_toast(r"Share All: Shared 2")
        await _screen_idle(t)
        posts = fake_cloud.requests(path, "POST")
        assert [(r["body"]["name"], r["body"]["username"], r["body"]["port"]) for r in posts] == [
            ("application", "deploy", 2201), ("database", "admin", 2202),
        ]
        # Reopening Share All excludes the original instances and all shared rows.
        await _press(t, "#btn_share_all")
        await t.wait_for_screen("ShareServersConfirmModal")
        offered = t.on_screen("#share_confirm_list")
        await t.wait_until(lambda: offered.option_count > 0, desc="remaining servers")
        labels = [str(offered.get_option_at_index(i).prompt) for i in range(offered.option_count)]
        assert not any("app-1" in label or "db-1" in label or "application" in label or "database" in label for label in labels)
        await t.press("escape")
        await t.wait_for_screen("TeamManagementScreen")
        assert len(fake_cloud.requests(path, "POST")) == 2

        # The single removal refers to its id, so a display name cannot redirect it.
        table = t.on_screen("#servers_table")
        table.focus()
        await t.wait_until(lambda: table.has_focus, desc="server table focused")
        await t.press("down")
        await t.wait_until(lambda: table.cursor_row == 1, desc="second shared server selected")
        selected = t.app.screen._shared_servers[table.cursor_row]["id"]
        assert table.cursor_row > 0
        await _press(t, "#btn_remove_server")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.press("escape")
        await t.wait_for_screen("TeamManagementScreen")
        assert fake_cloud.requests(method="DELETE") == []
        await _press(t, "#btn_remove_server")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.fill("#confirm_input", "REMOVE")
        await _press(t, "#btn_confirm")
        await t.wait_for_toast(r"Removed 1 shared server")
        await _screen_idle(t)
        assert len(fake_cloud.requests(method="DELETE")) == 1
        assert fake_cloud.requests(method="DELETE")[0]["status"] == 204
        assert fake_cloud.requests(method="DELETE")[0]["path"] == f"{path}/{selected}"
        assert all(row["id"] != selected for row in fake_cloud.account.shared_servers(slug))

        await _press(t, "#btn_remove_servers")
        await t.wait_for_screen("BulkActionModal")
        await _press(t, "#bulk_action_all")
        await t.fill("#bulk_action_confirm_input", "REMOVE")
        await _press(t, "#bulk_action_submit")
        await t.wait_for_screen("TeamManagementScreen")
        await _screen_idle(t)
        assert fake_cloud.account.shared_servers(slug) == []
        assert t.table_rows("#servers_table") == []
        assert not any(row.get("is_shared") and row.get("team_slug") == slug for row in t.app.instances)

        # A fresh config's author is resolved from the team's member records.
        await _press(t, "#btn_push_config")
        await _press(t, "#btn_confirm_push_config")
        await t.wait_for_toast(r"Pushed config version 1")
        await _screen_idle(t)
        assert t.table_rows("#configs_table")[0][3] == "Team owner"

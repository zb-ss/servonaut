"""A narrow key catalog keeps its selected account and project in view."""

from unittest.mock import AsyncMock

import pytest
from textual.widgets import Button, DataTable, Select, Static
from textual.containers import VerticalScroll

from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests.test_workspace_ovh_resources import _ResourceApp

pytestmark = pytest.mark.usefixtures("navigation_open")


def _painted(app, widget) -> str:
    strips = app.screen._compositor.render_strips()
    return "\n".join(
        strips[y].crop(widget.region.x, widget.region.right).text
        for y in range(widget.region.y, widget.region.bottom)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("key_count", [1, 30])
async def test_focused_narrow_ovh_keys_keep_account_project_and_actions(
    monkeypatch, key_count: int,
) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _ResourceApp(True, multi=True)
    cloud = app.bundles["backup"].cloud
    cloud.list_ssh_keys.return_value = [
        {"id": f"key-{index}", "name": f"backup-key-{index}", "public_key": "ssh-ed25519 fixture"}
        for index in range(key_count)
    ]
    cloud.add_ssh_key = AsyncMock(side_effect=AssertionError("Unexpected key write"))
    cloud.delete_ssh_key = AsyncMock(side_effect=AssertionError("Unexpected key deletion"))
    async with app.run_test(size=(100, 30)) as pilot:
        screen = OVHSSHKeysScreen()
        await app.push_screen(screen)
        table = screen.query_one("#ssh_keys_table", DataTable)
        await wait_until(lambda: table.row_count == 1)
        picker = screen.query_one("#ovh_ssh_keys_account", AccountPicker)
        picker.query_one(Select).value = "backup"
        await wait_until(lambda: table.row_count == key_count and screen._project_id == "project-backup")
        await wait_until(lambda: str(table.get_row_at(0)[0]) == "backup-key-0")
        table.focus()
        table.move_cursor(row=key_count - 1)
        await pilot.pause()
        actions = screen.query_one("#ovh_ssh_keys_actions")
        # The action row re-fits for the narrow width before the geometry is read.
        await wait_until(lambda: 4 <= table.region.height <= 6 and table.region.bottom <= actions.region.y
                         and all(screen.region.contains_region(b.region) for b in actions.query(Button)))

        assert screen.focused is table
        assert "backup" in _painted(app, picker)
        project = screen.query_one("#ovh_ssh_keys_project_label", Static)
        assert "project-backup" in _painted(app, project)
        assert f"backup-key-{key_count - 1}" in _painted(app, table)
        assert 4 <= table.region.height <= 6
        scope = screen.query_one("#ovh_ssh_keys_scope")
        actions = screen.query_one("#ovh_ssh_keys_actions")
        assert table.region.y >= scope.region.bottom
        assert table.region.bottom <= actions.region.y
        for button_id in ("btn_refresh", "btn_add_key", "btn_delete_key", "btn_back"):
            button = screen.query_one(f"#{button_id}", Button)
            assert screen.region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button

    cloud.add_ssh_key.assert_not_called()
    cloud.delete_ssh_key.assert_not_called()


@pytest.mark.asyncio
async def test_overlong_ovh_scope_retains_keyboard_scroll_and_full_value(monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _ResourceApp(True, multi=True)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = OVHSSHKeysScreen()
        await app.push_screen(screen)
        table = screen.query_one("#ssh_keys_table", DataTable)
        await wait_until(lambda: table.row_count == 1)
        project = screen.query_one("#ovh_ssh_keys_project_label", Static)
        full_value = "project-" + "complete-value-" * 40 + "last-part"
        project.update(full_value)
        scope = screen.query_one("#ovh_ssh_keys_scope", VerticalScroll)
        scope.focus()
        await pilot.pause()
        # The action row re-fits its buttons for the narrow width over a few frames.
        await wait_until(lambda: scope.region.height <= 6)
        assert scope.max_scroll_y > 0
        assert app.focused is scope
        await pilot.press("end")
        await pilot.wait_for_scheduled_animations()
        await pilot.pause()
        assert app.focused is scope
        assert scope.scroll_y > 0
        assert scope.scroll_y == scope.max_scroll_y
        assert "last-part" in _painted(app, scope)
        assert str(project.content) == full_value


@pytest.mark.asyncio
@pytest.mark.parametrize("multi", [False, True])
async def test_the_keys_panel_and_help_text_are_in_view_from_the_top_at_100x30(monkeypatch, multi: bool) -> None:
    from tests.snapshots._geometry import ovh_keys_panel_problems

    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _ResourceApp(True, multi=multi)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = OVHSSHKeysScreen()
        await app.push_screen(screen)
        table = screen.query_one("#ssh_keys_table", DataTable)
        await wait_until(lambda: table.row_count >= 1)
        table.focus()
        await pilot.pause()
        await pilot.pause()
        assert ovh_keys_panel_problems(screen) == []

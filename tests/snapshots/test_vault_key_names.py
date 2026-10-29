"""Vault key names and confirmation dialogs at both supported terminal sizes."""
from __future__ import annotations

import pytest

from textual.widgets import Button, Input

from tests._async_bounds import wait_until
from tests.test_vault_key_names_tui import _Host, _Service, _confirm_open, _loaded, _rename_open


@pytest.mark.parametrize("size", [(160, 50), (100, 30)], ids=["160x50", "100x30"])
@pytest.mark.parametrize("state", ["items", "rename", "delete", "bulk-select", "bulk-delete"])
def test_vault_key_management(screen_snapshot, size, state) -> None:
    service = _Service(names=[{"item_id": "k1", "name": "Deploy key for web-1"}])
    app = _Host(service)

    async def scene(pilot) -> None:
        screen = await _loaded(app, pilot)
        if state == "rename":
            screen.action_rename_key()
            await wait_until(lambda: _rename_open(app))
            app.screen.query_one("#vault_rename_key_input", Input).value = ""
            app.screen.query_one("#vault_rename_key_save", Button).press()
            await wait_until(lambda: "Name is required." in str(app.screen.query_one("#vault_rename_key_feedback").render()))
        elif state == "delete":
            screen.action_delete_key()
            await wait_until(lambda: _confirm_open(app))
        elif state in {"bulk-select", "bulk-delete"}:
            from servonaut.screens.bulk_action import BulkActionModal
            from textual.widgets import SelectionList

            screen.action_delete_keys()
            await wait_until(lambda: isinstance(app.screen, BulkActionModal)
                             and bool(app.screen.query("#bulk_action_list"))
                             and app.screen.query_one("#bulk_action_list", SelectionList).option_count == 1)
            if state == "bulk-delete":
                from tests.test_vault_bulk_delete import _review

                initial = app.screen
                initial.query_one("#bulk_action_list", SelectionList).select_all()
                await _review(app, pilot, initial)

    screen_snapshot(app, size, scene)

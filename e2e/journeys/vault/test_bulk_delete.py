"""Delete unused keys in either vault scope without connecting to hosts."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from textual.widgets import Button, DataTable, Input, SelectionList

from e2e.harness.waits import wait_for_async
from e2e.harness.fake_cloud.routes_vault import TEAM_ID
from e2e.journeys.vault.test_vault_key_names import _VaultHost, _ed25519_key_pair, _native_service
from servonaut.screens.bulk_action import BulkActionModal
from servonaut.styles import CSS_FILES

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


class _BulkHost(_VaultHost):
    CSS_PATH = CSS_FILES


@pytest.mark.parametrize("kind", ["personal", "team"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_bulk_delete_cancels_then_deletes_unused_keys_and_keeps_exposed_keys(
    fake_cloud, journey, account_home, monkeypatch, kind, size,
):
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[])
    home = account_home(f"bulk-delete-{kind}").home
    service = _native_service(fake_cloud, home, monkeypatch)
    # The vault fake signs team scopes against its fixture's canonical team id.
    team = fake_cloud.account.create_team(name="Example team", owner_user_id=service.auth.user_id, team_id=TEAM_ID) if kind == "team" else None
    vault = await service.create_vault(team=team["slug"] if team else None, name="Keys", grant_policy="auto")
    vault_id = vault["vault_id"]
    items = []
    for index in range(3):
        private_key, _ = _ed25519_key_pair()
        items.append(await service.import_keys(
            source="ssh", vault_id=vault_id, private_key=private_key.encode(), name=f"key-{index + 1}",
        ))
    fake_cloud.vault.open_exposure(vault_id, items[2]["item_id"], public_fingerprint=items[2]["public_fingerprint"])
    service._remote_executor = MagicMock(side_effect=AssertionError("vault deletion must not contact hosts"))
    app = _BulkHost(service, instances=[{"id": "i-0001", "name": "offline-1", "state": "stopped", "public_ip": "10.0.0.1"}])
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        await wait_for_async(lambda: screen.query_one("#vault_table", DataTable).row_count == 1, desc="vault listed")
        await wait_for_async(lambda: not screen.query_one("#vault_items", Button).disabled, desc="items enabled")
        screen.query_one("#vault_items", Button).press()
        await wait_for_async(lambda: screen._table_mode == "items" and len(screen._items) == 3, desc="three keys loaded")
        screen.query_one("#vault_delete_keys", Button).press()
        await wait_for_async(lambda: isinstance(app.screen, BulkActionModal)
                             and bool(app.screen.query("#bulk_action_list"))
                             and app.screen.query_one("#bulk_action_list", SelectionList).option_count == 3,
                             desc="bulk picker ready")
        app.screen.query_one("#bulk_action_list", SelectionList).select_all()
        await pilot.press("escape")
        await wait_for_async(lambda: app.screen is screen, desc="cancelled")
        assert fake_cloud.requests(method="DELETE") == []

        screen.query_one("#vault_delete_keys", Button).press()
        await wait_for_async(lambda: isinstance(app.screen, BulkActionModal)
                             and bool(app.screen.query("#bulk_action_list"))
                             and app.screen.query_one("#bulk_action_list", SelectionList).option_count == 3,
                             desc="picker reopened")
        modal = app.screen
        modal.query_one("#bulk_action_list", SelectionList).select_all()
        await wait_for_async(lambda: not modal.query_one("#bulk_action_submit", Button).disabled, desc="keys selected")
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_for_async(lambda: isinstance(app.screen, BulkActionModal) and app.screen is not modal
                             and bool(app.screen.query("#bulk_action_confirm_input")), desc="saved assignments reviewed")
        modal = app.screen
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await wait_for_async(lambda: not modal.query_one("#bulk_action_submit", Button).disabled, desc="confirmation accepted")
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_for_async(lambda: len(screen._items) == 1 and not screen._busy_work, desc="batch complete")
        assert screen._items[0]["item_id"] == items[2]["item_id"]
        assert any("Deleted 2" in note and "1 kept" in note for note in app.notifications)
        assert any("key-3" in note and "open exposures" in note for note in app.notifications)

    service._remote_executor.assert_not_called()
    assert len(fake_cloud.requests(method="DELETE")) == 2
    vaults = await service.list_vaults()
    assert next(row for row in vaults if row["vault_id"] == vault_id)["counts"]["items"] == 1
    assert len((await service.list_items(vault_id=vault_id, include_deleted=True))["data"]) == 3

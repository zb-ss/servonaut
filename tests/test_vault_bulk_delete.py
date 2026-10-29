"""Vault deletion batches keep assigned keys and report partial failures."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from textual.widgets import Button, Checkbox, DataTable, Input, SelectionList

from servonaut.screens.bulk_action import BulkActionModal
from servonaut.services.vault.errors import VaultKeyInUse
from tests._async_bounds import wait_until
from tests.test_vault_key_names_tui import VAULT, _Host, _Service, _loaded


def _keys() -> _Service:
    return _Service(
        items=[{"item_id": f"k{n}", "type": "ssh_key", "revision": 1} for n in range(1, 4)]
              + [{"item_id": "secret", "type": "secret", "revision": 1}],
        names=[{"item_id": f"k{n}", "name": f"server-{n}"} for n in range(1, 4)],
    )


async def _open(app, screen) -> BulkActionModal:
    screen.query_one("#vault_delete_keys", Button).press()
    await wait_until(lambda: isinstance(app.screen, BulkActionModal)
                     and bool(app.screen.query("#bulk_action_list"))
                     and app.screen.query_one("#bulk_action_list", SelectionList).option_count > 0)
    return app.screen


async def _review(app, pilot, initial) -> BulkActionModal:
    await pilot.pause()
    initial.query_one("#bulk_action_submit", Button).press()
    await wait_until(lambda: isinstance(app.screen, BulkActionModal) and app.screen is not initial
                     and bool(app.screen.query("#bulk_action_confirm_input")))
    return app.screen


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_bulk_delete_selects_only_ssh_keys_and_requires_typed_confirmation(size):
    service = _keys()
    app = _Host(service)
    async with app.run_test(size=size) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        assert not modal.query("#bulk_action_acknowledge")
        listing = modal.query_one("#bulk_action_list", SelectionList)
        assert listing.option_count == 3 and listing.selected == []
        listing.select("k1").select("k3")
        await pilot.pause()
        modal = await _review(app, pilot, modal)
        assert modal.query_one("#bulk_action_submit", Button).disabled
        assert service.delete_calls == []
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await pilot.pause()
        for selector in ("#bulk_action_cancel", "#bulk_action_submit"):
            assert modal.region.contains_region(modal.query_one(selector).region)
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_until(lambda: len(service.delete_calls) == 2)
        await wait_until(lambda: screen.query_one("#vault_table", DataTable).row_count == 2)
        assert [call["item_id"] for call in service.delete_calls] == ["k1", "k3"]
        assert all(call["vault_id"] == VAULT for call in service.delete_calls)
        assert any("Deleted 2" in message for message, _ in app.notes)


@pytest.mark.asyncio
async def test_cancel_bulk_delete_makes_no_usage_or_delete_request():
    service = _keys()
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        modal.query_one("#bulk_action_list", SelectionList).select_all()
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert service.usage_calls == service.delete_calls == []


@pytest.mark.asyncio
async def test_cancel_after_usage_review_keeps_all_keys_and_releases_navigation():
    service = _keys()
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        initial = await _open(app, screen)
        initial.query_one("#bulk_action_list", SelectionList).select_all()
        await _review(app, pilot, initial)
        assert screen.navigation_hold_reason()
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen and not screen._deletion_review_active)
        assert len(service.usage_calls) == 3 and service.delete_calls == []
        assert screen.query_one("#vault_table", DataTable).row_count == 4
        assert screen.navigation_hold_reason() is None


@pytest.mark.asyncio
async def test_bulk_delete_continues_after_in_use_and_service_failures():
    service = _keys()
    delete_one = service.delete_ssh_key

    async def delete(*, vault_id, item_id, servers):
        if item_id == "k1":
            raise VaultKeyInUse(team_servers=["web-1"], own_servers=[], unchecked=[])
        if item_id == "k2":
            raise RuntimeError("private diagnostic")
        return await delete_one(vault_id=vault_id, item_id=item_id, servers=servers)

    service.delete_ssh_key = AsyncMock(side_effect=delete)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        modal.query_one("#bulk_action_list", SelectionList).select_all()
        modal = await _review(app, pilot, modal)
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await pilot.pause()
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_until(lambda: service.delete_ssh_key.await_count == 3)
        await wait_until(lambda: screen.query_one("#vault_table", DataTable).row_count == 3)
        messages = "\n".join(message for message, _ in app.notes)
        assert "Deleted 1" in messages and "2 kept" in messages
        assert "server-1" in messages and "web-1" in messages and "server-2" in messages
        assert "private diagnostic" not in messages


@pytest.mark.asyncio
async def test_unchecked_assignments_need_the_extra_choice_and_stronger_phrase():
    service = _keys()
    service.ssh_key_usage = AsyncMock(return_value={"team_servers": [], "own_servers": [], "unchecked": ["offline-1"],
                                                  "unchecked_targets": [["aws", "", "i-1"]]})
    service.delete_ssh_key = AsyncMock(return_value={"deleted": True})
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        modal.query_one("#bulk_action_list", SelectionList).select("k1")
        modal = await _review(app, pilot, modal)
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        modal.query_one("#bulk_action_acknowledge", Checkbox).value = True
        await pilot.pause()
        assert modal.query_one("#bulk_action_submit", Button).disabled
        assert modal.query_one("#bulk_action_acknowledge_hint").display
        assert not service.delete_ssh_key.called
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE UNCHECKED"
        await pilot.pause()
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_until(lambda: service.delete_ssh_key.await_count == 1)
        service.delete_ssh_key.assert_awaited_once_with(
            vault_id=VAULT, item_id="k1", servers=[], allow_unchecked=True, unchecked_targets=[["aws", "", "i-1"]],
        )


@pytest.mark.asyncio
async def test_demo_mode_hides_key_and_server_names_in_partial_results():
    from servonaut.services.redaction_service import RedactionService

    service = _keys()
    service.names[0]["name"] = "private-key"
    service.delete_ssh_key = AsyncMock(side_effect=VaultKeyInUse(team_servers=["private-server"], own_servers=[], unchecked=[]))
    app = _Host(service)
    app.demo_mode = True
    app.redaction_service = RedactionService()
    app._instances_pristine = []
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        modal.query_one("#bulk_action_list", SelectionList).select("k1")
        modal = await _review(app, pilot, modal)
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await pilot.pause()
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_until(lambda: any("1 kept" in message for message, _ in app.notes))
        messages = "\n".join(message for message, _ in app.notes)
        assert "private-key" not in messages and "private-server" not in messages
        assert "private-key" not in screen._item_name_cell(service.items[0])

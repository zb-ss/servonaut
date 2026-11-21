"""Delete multiple selects the extra copies of a key and never one that is in use."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from textual.widgets import Button, DataTable, Input, SelectionList, Static

from e2e.harness.waits import wait_for_async
from e2e.journeys.vault.test_key_delete_service import (
    CAPABILITIES,
    SIZES,
    _binding_reads,
)
from e2e.journeys.vault.test_vault_key_names import _VaultHost, _ed25519_key_pair, _native_service
from servonaut.screens.bulk_action import BulkActionModal
from servonaut.services.vault.personal_targets import custom_binding_id
from servonaut.styles import CSS_FILES
from servonaut.widgets.filterable_selection import FilterableSelection

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

INSTANCES = [
    {"id": f"site-{n}", "name": f"site-{n}", "is_custom": True, "provider": "custom",
     "state": "running", "public_ip": f"10.0.0.{n}"}
    for n in (1, 2)
]


class _CopiesHost(_VaultHost):
    CSS_PATH = CSS_FILES


async def _vault_with_copies(fake_cloud, home, monkeypatch, bound_copies):
    """Three copies of one key; copy *i* (0-based) of *bound_copies* is bound to own server site-N in order."""
    fake_cloud.vault.set_capabilities(CAPABILITIES)
    service = _native_service(fake_cloud, home, monkeypatch)
    vault_id = (await service.create_vault(team=None, name="Keys", grant_policy="auto"))["vault_id"]
    private_key, _ = _ed25519_key_pair()
    # An empty known-keys map skips the client's own duplicate check, which is
    # how copies came to exist before the service refused them.
    items = [
        await service.import_keys(
            source="ssh", vault_id=vault_id, private_key=private_key.encode(),
            name=f"key-{index + 1}", known_keys={},
        )
        for index in range(3)
    ]
    for site, copy_index in enumerate(bound_copies, start=1):
        fake_cloud.vault._bindings[("custom", custom_binding_id(f"site-{site}"))] = {
            "vault_id": vault_id, "vault_item_id": items[copy_index]["item_id"],
        }
    fake_cloud.configure(binding_reads_retry_after=30)
    service._remote_executor = MagicMock(side_effect=AssertionError("vault deletion must not contact hosts"))
    return service, items


async def _open_picker(app):
    screen = app.screen
    await wait_for_async(lambda: screen.query_one("#vault_table", DataTable).row_count == 1, desc="vault listed")
    await wait_for_async(lambda: not screen.query_one("#vault_items", Button).disabled, desc="items enabled")
    screen.query_one("#vault_items", Button).press()
    await wait_for_async(lambda: screen._table_mode == "items" and len(screen._items) == 3, desc="three keys loaded")
    screen.query_one("#vault_delete_keys", Button).press()
    modal = await wait_for_async(
        lambda: app.screen if isinstance(app.screen, BulkActionModal)
        and bool(app.screen.query("#bulk_action_list"))
        and app.screen.query_one("#bulk_action_list", SelectionList).option_count == 3
        and bool(app.screen.query("#bulk_action_preset")) else None,
        desc="bulk picker ready",
    )
    return screen, modal


def _prompts(modal):
    listing = modal.query_one("#bulk_action_list", SelectionList)
    return {listing.get_option_at_index(i).value: str(listing.get_option_at_index(i).prompt)
            for i in range(listing.option_count)}


@pytest.mark.parametrize("size", SIZES)
async def test_duplicate_copies_preset_selects_the_unbound_copies_and_deletes_them(
    fake_cloud, journey, account_home, monkeypatch, size,
):
    home = account_home("dup-copies-one-bound").home
    service, items = await _vault_with_copies(fake_cloud, home, monkeypatch, bound_copies=[1])
    ids = [item["item_id"] for item in items]
    app = _CopiesHost(service, instances=INSTANCES)
    async with app.run_test(size=size):
        screen, modal = await _open_picker(app)
        picker = modal.query_one(FilterableSelection)
        await wait_for_async(lambda: "in use" in _prompts(modal)[ids[1]], desc="the bound copy marked in use")
        assert "in use" not in _prompts(modal)[ids[0]]
        assert "in use" not in _prompts(modal)[ids[2]]
        modal.query_one("#bulk_action_preset", Button).press()
        await wait_for_async(
            lambda: sorted(picker.selected) == sorted([ids[0], ids[2]]),
            desc="the two unbound copies selected",
        )

        modal.query_one("#bulk_action_submit", Button).press()
        await wait_for_async(lambda: isinstance(app.screen, BulkActionModal) and app.screen is not modal
                             and bool(app.screen.query("#bulk_action_confirm_input")), desc="usage reviewed")
        review = app.screen
        review.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await wait_for_async(lambda: not review.query_one("#bulk_action_submit", Button).disabled, desc="confirmation accepted")
        review.query_one("#bulk_action_submit", Button).press()
        await wait_for_async(lambda: len(screen._items) == 1 and not screen._busy_work, desc="batch complete")
        assert screen._items[0]["item_id"] == ids[1]

    service._remote_executor.assert_not_called()
    assert _binding_reads(fake_cloud) == []


@pytest.mark.parametrize("size", SIZES)
async def test_duplicate_copies_preset_keeps_every_copy_in_use_and_says_so(
    fake_cloud, journey, account_home, monkeypatch, size,
):
    home = account_home("dup-copies-two-bound").home
    service, items = await _vault_with_copies(fake_cloud, home, monkeypatch, bound_copies=[0, 1])
    ids = [item["item_id"] for item in items]
    app = _CopiesHost(service, instances=INSTANCES)
    async with app.run_test(size=size):
        _, modal = await _open_picker(app)
        picker = modal.query_one(FilterableSelection)
        modal.query_one("#bulk_action_preset", Button).press()
        note = modal.query_one("#bulk_action_note", Static)
        await wait_for_async(
            lambda: "in use, so all of them stay" in str(note.render()),
            desc="the note about copies in use",
        )
        assert picker.selected == [ids[2]]

    assert _binding_reads(fake_cloud) == []

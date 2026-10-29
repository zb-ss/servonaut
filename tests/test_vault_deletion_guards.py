"""Deletion uses real fleet records and discloses unavailable assignments."""
from __future__ import annotations

from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest
from rich.text import Text
from textual.widgets import Button, Input, SelectionList

from servonaut.screens._demo_resolve import replace_instances
from servonaut.services.redaction_service import RedactionService
from servonaut.services.vault.errors import VaultKeyInUse
from tests._async_bounds import wait_until
from tests.test_vault_bulk_delete import _keys, _open, _review
from tests.test_vault_key_names_tui import VAULT, _Host, _Service, _loaded

SERVER = {"id": "i-0123456789abcdef0", "name": "private-web", "public_ip": "8.8.8.8"}


@pytest.mark.asyncio
@pytest.mark.parametrize("bulk", [False, True])
async def test_demo_deletion_checks_the_real_bound_server(bulk):
    service = _Service()
    app = _Host(service)
    app.demo_mode = True
    app.redaction_service = RedactionService()
    replace_instances(app, None, [SERVER])

    async def usage(**kwargs):
        service.usage_calls.append(kwargs)
        return {"own_servers": [SERVER["name"]] if kwargs["servers"][0]["id"] == SERVER["id"] else [],
                "team_servers": [], "unchecked": [], "checked": 1}

    service.ssh_key_usage = usage
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        if bulk:
            modal = await _open(app, screen)
            modal.query_one("#bulk_action_list", SelectionList).select_all()
            # The initial picker selects; usage is reviewed before confirmation.
            if modal.query("#bulk_action_confirm_input"):
                modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
            await pilot.pause()
            modal.query_one("#bulk_action_submit", Button).press()
            await wait_until(lambda: bool(service.usage_calls) or bool(service.delete_calls))
        else:
            screen.action_delete_key()
            await wait_until(lambda: bool(service.usage_calls))
        assert service.usage_calls[0]["servers"] == [SERVER]
        assert service.delete_calls == []


@pytest.mark.asyncio
async def test_bulk_delete_does_not_offer_an_override_before_usage_is_checked():
    service = _keys()
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        assert not modal.query("#bulk_action_acknowledge")
        assert service.usage_calls == []


@pytest.mark.asyncio
async def test_unchecked_review_names_each_key_and_limits_the_override_to_it():
    service = _keys()

    async def usage(**kwargs):
        service.usage_calls.append(kwargs)
        return {"team_servers": [], "own_servers": [], "unchecked": ["web-1", "db-1"] if kwargs["item_id"] == "k1" else [],
                "unchecked_targets": [["aws", "", "i-1"], ["aws", "", "i-2"]] if kwargs["item_id"] == "k1" else []}

    service.ssh_key_usage = usage
    service.delete_ssh_key = AsyncMock(return_value={"deleted": True})
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        initial = await _open(app, screen)
        initial.query_one("#bulk_action_list", SelectionList).select_all()
        if initial.query("#bulk_action_confirm_input"):
            initial.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await pilot.pause()
        initial.query_one("#bulk_action_submit", Button).press()
        await wait_until(lambda: app.screen is not initial)
        await wait_until(lambda: bool(app.screen.query("#bulk_action_acknowledge")))
        review = app.screen
        description = str(review.query_one("#bulk_action_description").render())
        assert "server-1" in description and "web-1" in description and "db-1" in description
        assert not service.delete_ssh_key.called
        review.query_one("#bulk_action_acknowledge").value = True
        review.query_one("#bulk_action_confirm_input", Input).value = "DELETE UNCHECKED"
        await pilot.pause()
        review.query_one("#bulk_action_submit", Button).press()
        await wait_until(lambda: service.delete_ssh_key.await_count == 3)
        calls = {call.kwargs["item_id"]: call.kwargs for call in service.delete_ssh_key.await_args_list}
        assert calls["k1"]["allow_unchecked"] is True
        assert calls["k1"]["unchecked_targets"] == [["aws", "", "i-1"], ["aws", "", "i-2"]]
        assert not calls["k2"].get("allow_unchecked") and not calls["k3"].get("allow_unchecked")


@pytest.mark.asyncio
async def test_each_refused_key_has_one_notification():
    service = _keys()
    service.delete_ssh_key = AsyncMock(side_effect=VaultKeyInUse(team_servers=["web-1"], own_servers=[], unchecked=[]))
    app = _Host(service)
    async with app.run_test() as pilot:
        screen = await _loaded(app, pilot)
        app.notes.clear()
        await screen._delete_vault_keys(VAULT, ["k1"])
        refusals = [message for message, _ in app.notes if "web-1" in message or "still used" in message]
        assert len(refusals) == 1


@pytest.mark.asyncio
async def test_key_picker_uses_the_same_demo_name_as_the_items_table():
    service = _keys()
    app = _Host(service)
    app.demo_mode = True
    app.redaction_service = RedactionService()
    app._instances_pristine = []
    async with app.run_test() as pilot:
        screen = await _loaded(app, pilot)
        expected = screen._display_record_name("server-1")
        modal = await _open(app, screen)
        label = str(modal.query_one("#bulk_action_list", SelectionList).get_option_at_index(0).prompt)
        assert expected in label


@pytest.mark.asyncio
async def test_unknown_key_name_stays_literal_in_the_demo_picker():
    service = _keys()
    service.names = []
    app = _Host(service)
    app.demo_mode = True
    app.redaction_service = RedactionService()
    app._instances_pristine = []
    async with app.run_test() as pilot:
        screen = await _loaded(app, pilot)
        expected = Text.from_markup(screen._item_name_cell(service.items[0])).plain
        modal = await _open(app, screen)
        label = str(modal.query_one("#bulk_action_list", SelectionList).get_option_at_index(0).prompt)
        assert expected == "(name unknown)" and expected in label
        description = screen._bulk_deletion_description(service.items[:1], {"k1": {"unchecked": ["web-1"]}}, [])
        assert expected in description


@pytest.mark.asyncio
async def test_large_batch_refusals_have_bounded_notifications_and_the_full_count(caplog):
    app = _Host(_keys())
    async with app.run_test() as pilot:
        screen = await _loaded(app, pilot)
        app.notes.clear()
        screen._deletion_summary(0, [f"key-{n}: refused" for n in range(10)])
        assert len(app.notes) == 5
        assert "10 kept" in app.notes[0][0]
        assert "7 more" in app.notes[-1][0]
        assert "see the log" in app.notes[-1][0]
        assert all(any(f"key-{n}: refused" in record.message for record in caplog.records) for n in range(10))


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["review", "delete"])
async def test_bulk_screen_uses_one_service_batch_instead_of_per_key_reads(phase):
    service = _keys()
    usage = {"team_servers": [], "own_servers": [], "unchecked": [], "unchecked_targets": []}
    service.ssh_keys_usage = AsyncMock(return_value={"k1": usage, "k2": usage})
    service.delete_ssh_keys = AsyncMock(return_value=[SimpleNamespace(item_id=key, deleted=True, error=None) for key in ("k1", "k2")])
    service.ssh_key_usage = AsyncMock(side_effect=AssertionError("must use batch usage"))
    service.delete_ssh_key = AsyncMock(side_effect=AssertionError("must use batch deletion"))
    app = _Host(service)
    async with app.run_test() as pilot:
        screen = await _loaded(app, pilot)
        if phase == "review":
            await screen._check_deletion_usage(service, VAULT, ["k1", "k2"], [])
            service.ssh_keys_usage.assert_awaited_once_with(vault_id=VAULT, item_ids=["k1", "k2"], servers=[])
            service.ssh_key_usage.assert_not_awaited()
        else:
            await screen._delete_vault_keys(VAULT, ["k1", "k2"])
            service.delete_ssh_keys.assert_awaited_once()
            assert service.delete_ssh_keys.await_args.kwargs["item_ids"] == ["k1", "k2"]
            service.delete_ssh_key.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("partial", [False, True])
async def test_unexpected_batch_delete_error_reloads_items_and_keeps_the_app_alive(partial):
    service = _keys()

    async def interrupted(*, vault_id, servers, on_progress, **_kwargs):
        if partial:
            await service.delete_ssh_key(vault_id=vault_id, item_id="k1", servers=servers)
            on_progress(1, 3, SimpleNamespace(item_id="k1", deleted=True, error=None))
        raise RuntimeError("private diagnostic")

    service.delete_ssh_keys = AsyncMock(side_effect=interrupted)
    app = _Host(service)
    async with app.run_test() as pilot:
        screen = await _loaded(app, pilot)
        screen._load_items = AsyncMock(wraps=screen._load_items)
        initial = await _open(app, screen)
        listing = initial.query_one("#bulk_action_list", SelectionList)
        listing.select_all() if partial else listing.select("k1")
        modal = await _review(app, pilot, initial)
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await pilot.pause()
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_until(lambda: any("kept" in message for message, _ in app.notes))
        assert screen._load_items.await_count == 1
        assert app.screen is screen and not app._exit
        messages = "\n".join(message for message, _ in app.notes)
        assert "RuntimeError" in messages
        assert ("Deleted 1" in messages and "2 kept" in messages) if partial else ("Deleted 0" in messages and "1 kept" in messages)
        assert "private diagnostic" not in messages

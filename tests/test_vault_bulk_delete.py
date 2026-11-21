"""Vault deletion batches keep assigned keys and report partial failures."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from textual.widgets import Button, Checkbox, DataTable, Input, SelectionList

from servonaut.screens.bulk_action import BulkActionModal
from servonaut.services.vault.errors import VaultKeyInUse
from tests._async_bounds import wait_until
from tests.test_vault_key_names_tui import VAULT, _Host, _Service, _loaded

pytestmark = pytest.mark.usefixtures("navigation_open")


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
                     and bool(app.screen.query("#bulk_action_submit"))
                     and app.screen.query_one("#bulk_action_list", SelectionList).option_count > 0)
    return app.screen


async def _press_when_enabled(button: Button) -> None:
    """Press a submit button once the dialog has enabled it.

    The dialog enables submit from the selection and input change handlers, so
    a press right after changing them is ignored while the button is disabled.
    """
    await wait_until(lambda: not button.disabled)
    button.press()


async def _review(app, pilot, initial) -> BulkActionModal:
    await _press_when_enabled(initial.query_one("#bulk_action_submit", Button))
    await wait_until(lambda: isinstance(app.screen, BulkActionModal) and app.screen is not initial
                     and bool(app.screen.query("#bulk_action_confirm_input"))
                     and bool(app.screen.query("#bulk_action_submit")))
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
        await wait_until(lambda: modal._picker().selected == ["k1", "k3"])
        modal = await _review(app, pilot, modal)
        assert modal.query_one("#bulk_action_submit", Button).disabled
        assert service.delete_calls == []
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await wait_until(lambda: not modal.query_one("#bulk_action_submit", Button).disabled)
        for selector in ("#bulk_action_cancel", "#bulk_action_submit"):
            assert modal.region.contains_region(modal.query_one(selector).region)
        await _press_when_enabled(modal.query_one("#bulk_action_submit", Button))
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
        await _press_when_enabled(modal.query_one("#bulk_action_submit", Button))
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
        hint = modal.query_one("#bulk_action_acknowledge_hint")
        await wait_until(lambda: hint.display)
        assert modal.query_one("#bulk_action_submit", Button).disabled
        assert not service.delete_ssh_key.called
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE UNCHECKED"
        await _press_when_enabled(modal.query_one("#bulk_action_submit", Button))
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
        await _press_when_enabled(modal.query_one("#bulk_action_submit", Button))
        await wait_until(lambda: any("1 kept" in message for message, _ in app.notes))
        messages = "\n".join(message for message, _ in app.notes)
        assert "private-key" not in messages and "private-server" not in messages
        assert "private-key" not in screen._item_name_cell(service.items[0])


@pytest.mark.asyncio
async def test_bulk_review_keeps_a_key_used_only_by_other_members_with_counts():
    service = _keys()

    async def usage(**kwargs):
        service.usage_calls.append(kwargs)
        others = kwargs["item_id"] == "k1"
        return {"team_servers": [], "own_servers": [], "unchecked": [], "checked": 0,
                "other_members": {"members": 2 if others else 0, "servers": 3 if others else 0}}

    service.ssh_key_usage = usage
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        modal.query_one("#bulk_action_list", SelectionList).select_all()
        modal = await _review(app, pilot, modal)
        assert "Other members: 3 server(s) of 2 member(s)" in "\n".join(
            str(w.render()) for w in modal.query("Static"))
        assert "server-1" in "\n".join(str(w.render()) for w in modal.query("Static"))


# -- usage read on open, markers and "Select duplicate copies" ---------------

_FREE = {"team_servers": [], "own_servers": [], "unchecked": [], "checked": 1}
_BOUND = {"team_servers": ["site-1"], "own_servers": [], "unchecked": [], "checked": 1}


def _copies(count: int = 3, *, fingerprints: list[str] | None = None) -> _Service:
    prints = fingerprints or ["SHA256:same"] * count
    return _Service(
        items=[{"item_id": f"k{n}", "type": "ssh_key", "revision": 1, "public_fingerprint": prints[n - 1],
                "created_at": f"2026-01-0{n}T00:00:00Z"} for n in range(1, count + 1)],
        names=[{"item_id": f"k{n}", "name": f"key-{n}"} for n in range(1, count + 1)],
    )


def _with_overview(service: _Service, usages: dict | Exception) -> list[dict]:
    calls: list[dict] = []

    async def overview(**kwargs):
        calls.append(kwargs)
        if isinstance(usages, Exception):
            raise usages
        return {key: dict(value) for key, value in usages.items()}

    service.ssh_keys_usage_overview = overview
    return calls


def _labels(modal: BulkActionModal) -> list[str]:
    listing = modal.query_one("#bulk_action_list", SelectionList)
    return [str(listing.get_option_at_index(i).prompt) for i in range(listing.option_count)]


async def _preset(app, pilot, service):
    screen = await _loaded(app, pilot)
    modal = await _open(app, screen)
    modal.query_one("#bulk_action_preset", Button).press()
    await wait_until(lambda: bool(str(modal.query_one("#bulk_action_note").render())))
    return screen, modal


def _note(modal: BulkActionModal) -> str:
    return str(modal.query_one("#bulk_action_note").render())


@pytest.mark.asyncio
async def test_dialog_opens_after_one_usage_read_and_marks_the_bound_key():
    service = _copies(2, fingerprints=["SHA256:a", "SHA256:b"])
    calls = _with_overview(service, {"k1": _BOUND, "k2": _FREE})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        labels = _labels(modal)
        assert any(label.startswith("key-1") and label.endswith("in use") for label in labels)
        assert not any(label.startswith("key-2") and "in use" in label for label in labels)
        assert len(calls) == 1 and service.usage_calls == []
        modal.query_one("#bulk_action_list", SelectionList).select("k2")
        await _review(app, pilot, modal)
        assert [call["item_id"] for call in service.usage_calls] == ["k2"]
        assert len(calls) == 1


@pytest.mark.asyncio
async def test_duplicate_copies_never_select_the_copy_in_use():
    service = _copies(3)
    _with_overview(service, {"k1": _FREE, "k2": _BOUND, "k3": _FREE})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert sorted(modal._picker().selected) == ["k1", "k3"]
        assert "Selected 2 extra copies of 1 key" in _note(modal)


@pytest.mark.asyncio
async def test_duplicate_copies_note_counts_only_keys_that_gave_a_copy():
    service = _copies(4, fingerprints=["SHA256:a", "SHA256:a", "SHA256:b", "SHA256:b"])
    _with_overview(service, {"k1": _FREE, "k2": _FREE, "k3": _BOUND, "k4": _BOUND})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert modal._picker().selected == ["k2"]
        assert "Selected 1 extra copy of 1 key." in _note(modal)


@pytest.mark.asyncio
async def test_duplicate_copies_keep_the_oldest_when_none_is_in_use():
    service = _copies(3)
    _with_overview(service, {key: _FREE for key in ("k1", "k2", "k3")})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert sorted(modal._picker().selected) == ["k2", "k3"]


@pytest.mark.asyncio
async def test_duplicate_copies_keep_every_copy_when_several_are_in_use():
    service = _copies(2)
    _with_overview(service, {"k1": _BOUND, "k2": _BOUND})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert modal._picker().selected == []
        assert "in use, so all of them stay" in _note(modal)
        assert "No extra copy can be selected." in _note(modal)


@pytest.mark.asyncio
@pytest.mark.parametrize("unknown", [{"error": "boom"}, {**_FREE, "unchecked": [["aws", "", "i-1"]]}])
async def test_duplicate_copies_never_select_a_copy_with_unknown_usage(unknown):
    service = _copies(3)
    _with_overview(service, {"k1": _FREE, "k2": unknown, "k3": _FREE})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert "k2" not in modal._picker().selected
        assert "could not be checked and stay unselected" in _note(modal)
        assert any(label.startswith("key-2") and label.endswith("usage not checked") for label in _labels(modal))


@pytest.mark.asyncio
async def test_failed_usage_read_still_opens_the_dialog_without_selecting_copies():
    service = _copies(2)
    _with_overview(service, RuntimeError("private diagnostic"))
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert modal._picker().selected == []
        assert _note(modal).startswith("Could not check where keys are used")
        assert not any("in use" in label for label in _labels(modal))
        assert "In use first" not in {order.label for order in modal._picker()._orders}


@pytest.mark.asyncio
async def test_service_without_usage_overview_still_opens_the_dialog():
    service = _copies(2)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert modal._picker().selected == []
        assert _note(modal).startswith("Could not check where keys are used")


@pytest.mark.asyncio
async def test_unique_keys_report_that_nothing_is_stored_twice():
    service = _copies(2, fingerprints=["SHA256:a", "SHA256:b"])
    _with_overview(service, {"k1": _FREE, "k2": _FREE})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert modal._picker().selected == []
        assert _note(modal) == "No key is stored more than once in this vault."


@pytest.mark.asyncio
async def test_in_use_first_puts_the_bound_key_first():
    service = _copies(3, fingerprints=["SHA256:a", "SHA256:b", "SHA256:c"])
    _with_overview(service, {"k1": _FREE, "k2": _FREE, "k3": _BOUND})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        modal = await _open(app, screen)
        sort = modal.query_one("#bulk_action_sort", Button)
        for _ in range(5):
            if "In use first" in str(sort.label):
                break
            previous = str(sort.label)
            sort.press()
            await wait_until(lambda: str(sort.label) != previous)
        assert "In use first" in str(sort.label)
        await wait_until(lambda: _labels(modal)[0].startswith("key-3"))


@pytest.mark.asyncio
async def test_markup_in_a_key_name_is_literal_in_labels_and_note():
    service = _copies(2)
    service.names[0]["name"] = "[bold]key-1[/bold]"
    service.names[1]["name"] = "[red]key-2"
    _with_overview(service, {"k1": _BOUND, "k2": _BOUND})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert any("[bold]key-1[/bold]" in label for label in _labels(modal))
        assert "[bold]key-1[/bold], [red]key-2" in _note(modal)


@pytest.mark.asyncio
async def test_demo_mode_redacts_names_in_labels_and_note():
    from servonaut.services.redaction_service import RedactionService

    service = _copies(2)
    service.names[0]["name"] = "private-key"
    _with_overview(service, {"k1": _BOUND, "k2": _BOUND})
    app = _Host(service)
    app.demo_mode = True
    app.redaction_service = RedactionService()
    app._instances_pristine = []
    async with app.run_test(size=(160, 50)) as pilot:
        _, modal = await _preset(app, pilot, service)
        assert "private-key" not in _note(modal)
        assert not any("private-key" in label for label in _labels(modal))

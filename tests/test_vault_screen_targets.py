"""The Vault screen acts on the vault, item and device the user is looking at.

Vault-wide actions (Rotate, Import, Process grants, Members, Items, Exposures)
must reach the vault whose records are on screen, whichever table is open and
wherever its cursor is. Row actions (Reveal, Approve, Resolve, Rotate exposed
key) must read only the table they belong to.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import pytest
from textual.widgets import Button, DataTable, Input

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.vault import VaultMemberApprovalModal
from servonaut.screens.vault_import_modal import VaultImportModal
from tests._async_bounds import wait_until
from tests._vault_target_harness import (
    VAULT_A, VAULT_B, FakeVaultService, VaultHost, move_cursor, press, ready, settle, short,
    vault_screen,
)

pytestmark = pytest.mark.asyncio


async def _confirm_typed(app: Any, pilot: Any, word: str) -> None:
    await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen) and bool(app.screen.query("#confirm_input")))
    app.screen.query_one("#confirm_input", Input).value = word
    await pilot.pause()
    button = app.screen.query_one("#btn_confirm", Button)
    button.post_message(Button.Pressed(button))
    await settle(app, pilot)


async def _approve_grant(app: Any, pilot: Any) -> None:
    await wait_until(lambda: isinstance(app.screen, VaultMemberApprovalModal))
    button = app.screen.query_one("#vault_member_approve", Button)
    button.post_message(Button.Pressed(button))
    await settle(app, pilot)


async def _import_target(app: Any, pilot: Any) -> str:
    await wait_until(lambda: isinstance(app.screen, VaultImportModal))
    target = app.screen._vault_id
    app.screen.dismiss(None)
    await pilot.pause()
    return short(target)


async def _rotate(app: Any, pilot: Any) -> None:
    await press(app, pilot, "vault_rotate")
    await _confirm_typed(app, pilot, "ROTATE")


async def _grants(app: Any, pilot: Any) -> None:
    await press(app, pilot, "vault_grants")
    await _approve_grant(app, pilot)


async def _run(steps: Callable[[Any, Any, FakeVaultService], Awaitable[Any]]) -> Any:
    service = FakeVaultService()
    app = VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await ready(app, pilot)
        service.calls.clear()
        return await steps(app, pilot, service)


VAULT_TARGETS = "rotate", "process_grants", "get_vault", "list_items", "list_exposures"


@pytest.mark.parametrize("name,vault_row,expected,view_row", [
    ("items", 0, VAULT_A, 1),
    ("devices", 0, VAULT_A, 1),
    ("members", 1, VAULT_B, 0),
])
@pytest.mark.parametrize("action", ["rotate", "grants"])
async def test_vault_wide_actions_hit_the_vault_on_screen_not_a_table_cursor(
    name: str, vault_row: int, expected: str, view_row: int, action: str,
) -> None:
    """Open a view of one vault, put the cursor on another row, act on the vault."""

    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> list:
        await move_cursor(app, pilot, vault_row)
        await press(app, pilot, "vault_roster" if name == "members" else "vault_items")
        if name == "devices":
            await press(app, pilot, "vault_devices")
        await move_cursor(app, pilot, view_row)
        service.calls.clear()
        await (_rotate if action == "rotate" else _grants)(app, pilot)
        return service.targets(*VAULT_TARGETS)

    targets = await _run(steps)
    assert targets == [f"{'rotate' if action == 'rotate' else 'process_grants'}->{short(expected)}"]


async def test_import_from_the_items_view_targets_the_open_vault() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> str:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_items")
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_import")
        return await _import_target(app, pilot)

    assert await _run(steps) == short(VAULT_A)


async def test_import_from_an_empty_items_table_targets_the_open_vault() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> str:
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_items")
        screen = vault_screen(app)
        screen._items = []
        screen._render_items()
        await pilot.pause()
        await press(app, pilot, "vault_import")
        return await _import_target(app, pilot)

    assert await _run(steps) == short(VAULT_B)


async def test_a_devices_row_does_not_pick_a_vault_for_import_or_items() -> None:
    """The vault highlighted in the list stays the target; a device row never is."""

    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> tuple:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_devices")
        await move_cursor(app, pilot, 1)
        service.calls.clear()
        await press(app, pilot, "vault_import")
        target = await _import_target(app, pilot)
        await press(app, pilot, "vault_items")
        return target, service.targets(*VAULT_TARGETS)

    assert await _run(steps) == (short(VAULT_A), [f"list_items->{short(VAULT_A)}"])


async def test_members_tab_then_grants_and_rotate_hit_the_vault_whose_members_are_shown() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> list:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_items")
        await press(app, pilot, "vault_refresh")
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_roster")
        service.calls.clear()
        await _grants(app, pilot)
        await _rotate(app, pilot)
        await press(app, pilot, "vault_exposures")
        return service.targets(*VAULT_TARGETS)

    assert await _run(steps) == [
        f"process_grants->{short(VAULT_B)}", f"rotate->{short(VAULT_B)}", f"list_exposures->{short(VAULT_B)}",
    ]


async def test_the_roster_view_records_which_vault_it_shows() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> str:
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_roster")
        return short(vault_screen(app)._selected_vault_id)

    assert await _run(steps) == short(VAULT_B)


async def test_highlighting_a_vault_makes_it_the_selected_one_and_a_redraw_keeps_the_cursor_on_it() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> tuple:
        screen = vault_screen(app)
        await move_cursor(app, pilot, 1)
        selected = short(screen._selected_vault_id)
        screen._render_vaults()
        await pilot.pause()
        await pilot.pause()
        return selected, screen.query_one("#vault_table", DataTable).cursor_row, short(screen._selected_vault_id)

    assert await _run(steps) == (short(VAULT_B), 1, short(VAULT_B))


async def test_vault_actions_without_a_selected_vault_ask_for_one() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> tuple:
        await press(app, pilot, "vault_devices")
        vault_screen(app)._selected_vault_id = None
        service.calls.clear()
        for button in ("vault_rotate", "vault_grants", "vault_roster", "vault_import"):
            await press(app, pilot, button)
        return service.targets(*VAULT_TARGETS), type(app.screen).__name__, [n.message for n in app._notifications]

    targets, screen_name, notices = await _run(steps)
    assert targets == [] and screen_name == "VaultScreen"
    assert notices.count("Select a vault first.") == 4

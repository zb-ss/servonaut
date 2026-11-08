"""Moving the vault list's highlight while a view loads never mixes two vaults.

Items, Members and Exposures take a moment to load and the vault list stays
interactive meanwhile. Whatever the user highlights in that time, the records
that appear and the vault the next action targets must be the same vault.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any, AsyncIterator

import pytest
from textual.widgets import Button, DataTable

from servonaut.screens.vault_import_modal import VaultImportModal
from tests._async_bounds import wait_until
from tests._vault_target_harness import (
    VAULT_A, VAULT_B, VAULT_C, FakeVaultService, VaultHost, move_cursor, press, ready, settle, short,
    vault_screen,
)

pytestmark = pytest.mark.asyncio

ROWS_OF_A = {"items": "11-k", "exposures": "11-k", "roster": "Owner of 11"}


@contextlib.asynccontextmanager
async def _held(view_button: str, release_after: Any, *, awaiting_c: bool = False) -> AsyncIterator[tuple]:
    """Open *view_button* for vault A while its load is held, run *release_after*, release, settle."""
    service = FakeVaultService(awaiting_c=awaiting_c)
    service.gate = asyncio.Event()
    app = VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await ready(app, pilot)
        await move_cursor(app, pilot, 0)
        service.calls.clear()
        button = screen.query_one(f"#{view_button}", Button)
        button.post_message(Button.Pressed(button))
        await wait_until(lambda: any(n in ("list_items", "list_exposures", "get_vault") for n, _ in service.calls))
        await release_after(app, pilot, screen)
        service.gate.set()
        await settle(app, pilot)
        await pilot.pause(0.3)
        yield app, pilot, screen, service


def _consistent(screen: Any) -> bool:
    """Records of a vault are on screen only together with that vault selected."""
    if screen._table_mode == "vaults":
        return True
    shown = {"items": screen._items, "exposures": screen._exposures, "roster": screen._roster}.get(screen._table_mode)
    return bool(shown) and screen._selected_vault_id == VAULT_A


async def _arrow_down(app: Any, pilot: Any, screen: Any) -> None:
    screen.query_one("#vault_table", DataTable).focus()
    await pilot.press("down")
    await pilot.pause()


async def _click_second_row(app: Any, pilot: Any, screen: Any) -> None:
    # The first row sits under the header: y=2 is the second vault.
    screen.query_one("#vault_table", DataTable).focus()
    await pilot.pause()
    await pilot.click("#vault_table", offset=(4, 2))
    await pilot.pause(0.2)
    assert screen.query_one("#vault_table", DataTable).cursor_row == 1


@pytest.mark.parametrize("view_button", ["vault_items", "vault_exposures", "vault_roster"])
@pytest.mark.parametrize("move", [_arrow_down, _click_second_row], ids=["keyboard", "click"])
async def test_a_moved_highlight_never_leaves_one_vaults_records_with_another_selected(
    view_button: str, move: Any,
) -> None:
    async with _held(view_button, move) as (app, pilot, screen, service):
        assert _consistent(screen), (
            f"mode={screen._table_mode} selected={short(screen._selected_vault_id)}"
        )


async def test_exposure_actions_after_the_race_never_target_the_other_vault_keyboard() -> None:
    """Resolve and Rotate exposed key, answered like a user would, reach no other vault."""
    from tests.test_vault_row_actions import _confirm_typed

    async with _held("vault_exposures", _arrow_down) as (app, pilot, screen, service):
        service.calls.clear()
        await press(app, pilot, "vault_resolve_exposure")
        if type(app.screen).__name__ == "VaultExposureActionModal":
            app.screen.dismiss({"resolution": "accepted", "note": ""})
            await settle(app, pilot)
        await press(app, pilot, "vault_rotate_exposure")
        if type(app.screen).__name__ == "VaultExposureActionModal":
            app.screen.dismiss({"team": "ops", "servers": "web-1"})
            await _confirm_typed(app, pilot, "ROTATE")
        assert service.targets("resolve_exposure", "rotate_ssh_key") == []


async def test_exposure_actions_still_reach_the_vault_whose_exposures_are_shown() -> None:
    from tests.test_vault_row_actions import _confirm_typed

    async def nothing(app: Any, pilot: Any, screen: Any) -> None:
        return None

    async with _held("vault_exposures", nothing) as (app, pilot, screen, service):
        service.calls.clear()
        await press(app, pilot, "vault_resolve_exposure")
        app.screen.dismiss({"resolution": "accepted", "note": ""})
        await settle(app, pilot)
        await press(app, pilot, "vault_rotate_exposure")
        app.screen.dismiss({"team": "ops", "servers": "web-1"})
        await _confirm_typed(app, pilot, "ROTATE")
        assert service.targets("resolve_exposure", "rotate_ssh_key") == [
            f"resolve_exposure->{short(VAULT_A)}", f"rotate_ssh_key->{short(VAULT_A)}",
        ]


async def test_import_and_rotate_after_a_click_during_the_items_load_target_the_highlighted_vault() -> None:
    async with _held("vault_items", _click_second_row) as (app, pilot, screen, service):
        # The click moved the selection to B and the load was dropped: B is what actions use.
        assert screen._table_mode == "vaults"
        assert short(screen._selected_vault_id) == short(VAULT_B)
        await press(app, pilot, "vault_import")
        await wait_until(lambda: isinstance(app.screen, VaultImportModal))
        assert short(app.screen._vault_id) == short(VAULT_B)


async def test_a_load_that_nobody_moved_away_from_still_shows_its_records() -> None:
    async def nothing(app: Any, pilot: Any, screen: Any) -> None:
        return None

    for view_button, mode in (("vault_items", "items"), ("vault_exposures", "exposures"), ("vault_roster", "roster")):
        async with _held(view_button, nothing) as (app, pilot, screen, service):
            assert screen._table_mode == mode and screen._selected_vault_id == VAULT_A


async def test_a_dropped_load_says_so() -> None:
    async with _held("vault_items", _arrow_down) as (app, pilot, screen, service):
        assert "selection changed" in screen._status_raw.lower()


# ---------------------------------------------------------------------------
# Exposures goes through the same gate as the other vault actions
# ---------------------------------------------------------------------------


async def test_exposures_after_a_reload_to_an_empty_list_asks_for_a_vault() -> None:
    service = FakeVaultService()
    app = VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await ready(app, pilot)
        service.vaults_listed = False
        await press(app, pilot, "vault_refresh")
        await wait_until(lambda: not screen._vaults)
        service.calls.clear()
        await press(app, pilot, "vault_exposures")
        assert service.targets("list_exposures") == []
        assert "Select a vault first." in [n.message for n in app._notifications]


async def test_exposures_for_a_vault_awaiting_access_is_refused_like_items() -> None:
    service = FakeVaultService(awaiting_c=True)
    app = VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await ready(app, pilot)
        await move_cursor(app, pilot, 2)
        service.calls.clear()
        await press(app, pilot, "vault_exposures")
        assert service.targets("list_exposures") == []
        assert screen._table_mode == "vaults"
        assert "access" in screen._status_raw.lower()


async def test_exposures_from_the_vault_list_loads_the_highlighted_vault() -> None:
    service = FakeVaultService()
    app = VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await ready(app, pilot)
        await move_cursor(app, pilot, 1)
        service.calls.clear()
        await press(app, pilot, "vault_exposures")
        assert service.targets("list_exposures") == [f"list_exposures->{short(VAULT_B)}"]
        assert screen._table_mode == "exposures" and screen._selected_vault_id == VAULT_B

"""Row actions of the Vault screen read only the table they belong to.

Reveal, Approve device, Resolve exposure and Rotate exposed key index a list
that matches one view. Used from another view they must do nothing, not act
on whatever row the other table's cursor is on.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import pytest
from textual.widgets import Button, Input

from servonaut.screens.confirm_action import ConfirmActionScreen
from tests._async_bounds import wait_until
from tests._vault_target_harness import (
    VAULT_A, FakeVaultService, VaultHost, move_cursor, press, ready, settle, vault_screen,
)

pytestmark = pytest.mark.asyncio


async def _confirm_typed(app: Any, pilot: Any, word: str) -> None:
    await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen) and bool(app.screen.query("#confirm_input")))
    app.screen.query_one("#confirm_input", Input).value = word
    await pilot.pause()
    button = app.screen.query_one("#btn_confirm", Button)
    button.post_message(Button.Pressed(button))
    await settle(app, pilot)


async def _run(steps: Callable[[Any, Any, FakeVaultService], Awaitable[Any]]) -> Any:
    service = FakeVaultService()
    app = VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await ready(app, pilot)
        service.calls.clear()
        return await steps(app, pilot, service)


# ---------------------------------------------------------------------------
# Row actions read only their own table
# ---------------------------------------------------------------------------


async def test_reveal_after_switching_to_devices_reveals_nothing() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> tuple:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_items")
        await press(app, pilot, "vault_devices")
        await move_cursor(app, pilot, 2)
        service.calls.clear()
        vault_screen(app).action_reveal()
        await pilot.pause()
        screen_name = type(app.screen).__name__
        return service.calls_named("show_item"), screen_name, [n.message for n in app._notifications]

    reveals, screen_name, notices = await _run(steps)
    assert reveals == [] and screen_name == "VaultScreen"
    assert "Load a vault's items and select one first." in notices


async def test_approve_after_switching_to_items_approves_nothing() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> tuple:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_devices")
        await press(app, pilot, "vault_items")
        await move_cursor(app, pilot, 1)
        service.calls.clear()
        await press(app, pilot, "vault_approve")
        return service.calls_named("approve_device"), [n.message for n in app._notifications]

    approvals, notices = await _run(steps)
    assert approvals == []
    assert "Load devices and select a pending device first." in notices


async def test_the_pending_device_is_approved_from_the_devices_view() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> list:
        await press(app, pilot, "vault_devices")
        await move_cursor(app, pilot, 1)
        service.calls.clear()
        await press(app, pilot, "vault_approve")
        return service.calls_named("approve_device")

    assert await _run(steps) == [{"device_id": "d-2"}]


@pytest.mark.parametrize("button", ["vault_resolve_exposure", "vault_rotate_exposure"])
async def test_exposure_actions_from_another_view_do_nothing(button: str) -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> tuple:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_items")
        await press(app, pilot, "vault_exposures")
        assert vault_screen(app)._table_mode == "exposures"
        await press(app, pilot, "vault_devices")
        await move_cursor(app, pilot, 1)
        service.calls.clear()
        await press(app, pilot, button)
        return type(app.screen).__name__, service.calls, [n.message for n in app._notifications]

    screen_name, calls, notices = await _run(steps)
    assert screen_name == "VaultScreen" and calls == []
    assert any("select" in message.lower() for message in notices)


async def test_reveal_from_the_items_view_still_reveals_the_selected_item() -> None:
    async def steps(app: Any, pilot: Any, service: FakeVaultService) -> list:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_items")
        await move_cursor(app, pilot, 1)
        service.calls.clear()
        vault_screen(app).action_reveal()
        await _confirm_typed(app, pilot, "REVEAL")
        return service.calls_named("show_item")

    assert await _run(steps) == [{"vault_id": VAULT_A, "item_id": "11-k2"}]

"""The Rotate, Import and Process grants dialogs name the vault they act on."""

from __future__ import annotations

from typing import Any

import pytest
from textual.widgets import Static

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.vault import VaultMemberApprovalModal
from servonaut.screens.vault_import_modal import VaultImportModal
from tests._async_bounds import wait_until
from tests._vault_target_harness import FakeVaultService, VaultHost, move_cursor, press, ready

pytestmark = pytest.mark.asyncio

HOSTILE = "Platform [ @click=app.bell]team [/ [PROD]"


async def _open(names: dict, steps: Any) -> Any:
    service = FakeVaultService(names=names)
    app = VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await ready(app, pilot)
        return await steps(app, pilot)


def _plain(widget: Static) -> str:
    return widget.visual.plain


async def test_rotate_dialog_names_the_vault_and_keeps_its_other_lines() -> None:
    async def steps(app: Any, pilot: Any) -> tuple:
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_items")
        await press(app, pilot, "vault_rotate")
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        return _plain(app.screen.query_one("#modal_description", Static)), app.screen._title

    description, title = await _open({"B": HOSTILE}, steps)
    assert description.startswith(f"Vault: {HOSTILE}\n")
    assert description.endswith("A new vault key version will replace every current grant.")
    assert title == "Rotate vault key"


async def test_import_dialog_names_the_vault() -> None:
    async def steps(app: Any, pilot: Any) -> str:
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_items")
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_import")
        await wait_until(lambda: isinstance(app.screen, VaultImportModal))
        return _plain(app.screen.query_one("#vault_import_title", Static))

    title = await _open({"B": HOSTILE}, steps)
    assert title == f"Import SSH key into encrypted vault\nVault: {HOSTILE}"


async def test_grant_dialog_names_the_vault_and_keeps_its_other_lines() -> None:
    async def steps(app: Any, pilot: Any) -> list:
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_roster")
        await press(app, pilot, "vault_grants")
        await wait_until(lambda: isinstance(app.screen, VaultMemberApprovalModal))
        return [_plain(s) for s in app.screen.query(Static)]

    lines = await _open({"B": HOSTILE}, steps)
    assert f"Vault: {HOSTILE}" in lines
    assert any(line.endswith("is waiting for access to this vault.") for line in lines)
    assert "Approve vault access?" in lines


async def test_clicking_a_hostile_vault_name_in_a_dialog_does_nothing() -> None:
    async def steps(app: Any, pilot: Any) -> tuple:
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_items")
        await press(app, pilot, "vault_rotate")
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        description = app.screen.query_one("#modal_description", Static)
        await pilot.click(description, offset=(14, 0))
        await pilot.pause(0.2)
        return isinstance(app.screen, ConfirmActionScreen), len(app._notifications)

    assert await _open({"B": "[ @click=screen.dismiss(True)]B"}, steps) == (True, 0)

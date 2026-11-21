"""Key picker dialogs (vault import, delete duplicates) at both supported terminal sizes."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App
from textual.widgets import Button, Input, SelectionList

from servonaut.screens.bulk_action import BulkActionModal
from servonaut.screens.vault_import_modal import VaultImportModal
from servonaut.services.bw_key_import import ScannedKey
from servonaut.styles import CSS_FILES
from tests._async_bounds import wait_until
from tests.snapshots import _harness
from tests.test_vault_bulk_delete import _BOUND, _FREE, _copies, _with_overview
from tests.test_vault_key_names_tui import _Host as _VaultHost
from tests.test_vault_key_names_tui import _loaded

KEY_COUNT = 12
STORED_INDEX = 3
ENCRYPTED_INDEX = 5


class _ImportHost(App):
    CSS_PATH = CSS_FILES

    def on_mount(self) -> None:
        service = MagicMock()
        service.stored_keys = AsyncMock(
            return_value={f"SHA256:fingerprint-{STORED_INDEX}": {"name": "stored-key"}},
        )
        self.push_screen(VaultImportModal(service, "11111111-1111-4111-8111-111111111111", Path("/keys")))


def _local_keys(_directory) -> list[ScannedKey]:
    return [
        ScannedKey(
            path=Path(f"/keys/key-{n}"),
            filename=f"key-{n}",
            encrypted=n == ENCRYPTED_INDEX,
            key_type="ssh-ed25519",
            fingerprint=f"SHA256:fingerprint-{n}",
        )
        for n in range(1, KEY_COUNT + 1)
    ]


@pytest.mark.parametrize("size", [(160, 50), (100, 30)], ids=["160x50", "100x30"])
@pytest.mark.parametrize("state", ["listed", "filtered"])
def test_vault_import_picker(screen_snapshot, size, state) -> None:
    app = _ImportHost()

    async def scene(pilot) -> None:
        await wait_until(lambda: isinstance(app.screen, VaultImportModal))
        modal = app.screen
        modal.query_one("#vault_import_local", Button).press()
        await wait_until(lambda: modal._picker().total == KEY_COUNT)
        if state == "filtered":
            # Local files start selected; clear them so only the filtered rows show as chosen.
            modal.query_one("#vault_import_none", Button).press()
            await wait_until(lambda: modal._picker().selected == [])
            modal.query_one("#vault_import_search", Input).value = "key-1"
            await wait_until(lambda: modal._picker().shown == 4)
            modal.query_one("#vault_import_all", Button).press()
            await wait_until(lambda: "selected of" in str(modal.query_one("#vault_import_count").render())
                             and modal._picker().selected == [0, 9, 10, 11])
        await pilot.pause()
        _harness.freeze_cursors(app)

    with patch("servonaut.screens.vault_import_modal.scan_directory", _local_keys):
        screen_snapshot(app, size, scene)


@pytest.mark.parametrize("size", [(160, 50), (100, 30)], ids=["160x50", "100x30"])
def test_delete_duplicate_copies_note(screen_snapshot, size) -> None:
    service = _copies(4, fingerprints=["SHA256:same", "SHA256:same", "SHA256:same", "SHA256:other"])
    _with_overview(service, {"k1": _FREE, "k2": _BOUND, "k3": _FREE, "k4": _FREE})
    app = _VaultHost(service)

    async def scene(pilot) -> None:
        screen = await _loaded(app, pilot)
        screen.action_delete_keys()
        await wait_until(lambda: isinstance(app.screen, BulkActionModal)
                         and bool(app.screen.query("#bulk_action_list"))
                         and app.screen.query_one("#bulk_action_list", SelectionList).option_count == 4)
        modal = app.screen
        modal.query_one("#bulk_action_preset", Button).press()
        await wait_until(lambda: bool(str(modal.query_one("#bulk_action_note").render())))
        await pilot.pause()
        _harness.freeze_cursors(app)

    screen_snapshot(app, size, scene)

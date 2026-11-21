"""The picker dialogs' search box under the app's real stylesheet.

Plain screen tests load no CSS, and the app-wide ``Input`` frame once left the
compact search box a border and no content row, so neither the placeholder nor
typed text showed. These mount each dialog with the bundle the app loads.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App
from textual.widgets import Input, SelectionList

from servonaut.screens.bulk_action import BulkActionModal
from servonaut.screens.bw_key_import import BwKeyImportModal
from servonaut.screens.vault_import_modal import VaultImportModal
from servonaut.services.bw_key_import import ScannedKey
from servonaut.styles import CSS_FILES
from servonaut.widgets.filterable_selection import FilterableSelection
from tests._async_bounds import wait_until

SIZES = [(160, 50), (100, 30)]
KEY_COUNT = 40


def _scanned() -> list[ScannedKey]:
    return [
        ScannedKey(
            path=Path(f"/keys/key-{n}"), filename=f"key-{n}", encrypted=False,
            key_type="ssh-ed25519", fingerprint=f"SHA256:fp{n}",
        )
        for n in range(1, KEY_COUNT + 1)
    ]


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self, dialog: str) -> None:
        super().__init__()
        self.dialog = dialog

    async def push_screen_wait(self, _screen):
        return True

    def on_mount(self) -> None:
        if self.dialog == "bulk":
            self.push_screen(BulkActionModal(
                "Delete vault keys", "Delete selected keys from this vault only.",
                [(f"k{n}", f"key-{n}") for n in range(1, KEY_COUNT + 1)],
                action_label="Delete", confirm_text="DELETE",
            ))
        elif self.dialog == "import":
            service = MagicMock()
            service.stored_keys = AsyncMock(return_value={})
            self.push_screen(VaultImportModal(service, "11111111-1111-4111-8111-111111111111", Path("/keys")))
        else:
            session = MagicMock()
            session.list_items = AsyncMock(return_value=[])
            self.config_manager = MagicMock()
            self.push_screen(BwKeyImportModal(Path("/keys"), session_service=session))


def _line(widget) -> str:
    return widget.render_line(0).text


async def _open(app: App, pilot, dialog: str) -> FilterableSelection:
    screens = {"bulk": BulkActionModal, "import": VaultImportModal, "bw": BwKeyImportModal}
    await wait_until(lambda: isinstance(app.screen, screens[dialog]))
    if dialog == "import":
        await pilot.click("#vault_import_local")
    picker = app.screen.query_one(FilterableSelection)
    await wait_until(lambda: picker.total == KEY_COUNT)
    return picker


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES, ids=["160x50", "100x30"])
@pytest.mark.parametrize("dialog", ["bulk", "import", "bw"])
async def test_the_search_box_shows_its_placeholder_and_typed_text(dialog: str, size) -> None:
    app = _Host(dialog)
    with patch("servonaut.screens.vault_import_modal.scan_directory", return_value=_scanned()), \
            patch("servonaut.screens.bw_key_import.scan_directory", return_value=_scanned()):
        async with app.run_test(size=size) as pilot:
            picker = await _open(app, pilot, dialog)
            search = picker.query_one(f"#{dialog_prefix(dialog)}_search", Input)
            assert search.content_region.height >= 1
            await wait_until(lambda: "Type to filter" in _line(search))
            await pilot.press("slash")
            await wait_until(lambda: search.has_focus)
            await pilot.press(*"key-1")
            await wait_until(lambda: search.value == "key-1" and "key-1" in _line(search))
            assert "Type to filter" not in _line(search)
            assert search.content_region.height >= 1


def dialog_prefix(dialog: str) -> str:
    return {"bulk": "bulk_action", "import": "vault_import", "bw": "bw_import"}[dialog]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES, ids=["160x50", "100x30"])
async def test_the_delete_confirmation_keeps_list_rows_under_the_real_stylesheet(size) -> None:
    app = _Host("bulk")
    async with app.run_test(size=size) as pilot:
        await _open(app, pilot, "bulk")
        listing = app.screen.query_one("#bulk_action_list", SelectionList)
        rows = 12 if size == (160, 50) else 6
        await wait_until(lambda: listing.content_region.height >= rows)

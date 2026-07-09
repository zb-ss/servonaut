"""Tests for :class:`servonaut.screens.bw_item_picker.BwItemPickerModal`.

Covers the entitlement gate, row-selection result shape (item_id + display
name + defaulted collection/vault), and a ``run_test`` pilot smoke test that an
entitled+unlocked session renders the SSH-item table.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.screens.bw_item_picker import BwItemPickerModal
from servonaut.services.bw_session_service import BwAuthState, BwItemSummary


def test_modal_optional_dict_typed():
    bases = [str(b) for b in getattr(BwItemPickerModal, "__orig_bases__", [])]
    assert any("dict" in b for b in bases)


class TestRowSelection:
    def _screen(self, **kw):
        screen = BwItemPickerModal(**kw)
        screen.dismiss = MagicMock()
        return screen

    def test_select_returns_item_id_and_name(self):
        screen = self._screen()
        screen._name_by_id = {"ssh-1": "prod web key"}
        event = SimpleNamespace(row_key=SimpleNamespace(value="ssh-1"))
        screen.on_data_table_row_selected(event)
        screen.dismiss.assert_called_once()
        result = screen.dismiss.call_args.args[0]
        assert result["item_id"] == "ssh-1"
        assert result["item_name"] == "prod web key"

    def test_select_defaults_collection_and_vault(self):
        screen = self._screen(
            default_collection_id="col-abc",
            default_vault_url="https://vault.example.com",
        )
        screen._name_by_id = {"ssh-1": "key"}
        screen.on_data_table_row_selected(SimpleNamespace(row_key=SimpleNamespace(value="ssh-1")))
        result = screen.dismiss.call_args.args[0]
        assert result["collection_id"] == "col-abc"
        assert result["vault_url"] == "https://vault.example.com"

    def test_empty_row_is_ignored(self):
        screen = self._screen()
        screen.on_data_table_row_selected(SimpleNamespace(row_key=SimpleNamespace(value="__empty__")))
        screen.dismiss.assert_not_called()

    def test_none_row_key_is_ignored(self):
        screen = self._screen()
        screen.on_data_table_row_selected(SimpleNamespace(row_key=None))
        screen.dismiss.assert_not_called()


class TestEntitlementGate:
    def _patched(self, screen, app):
        return patch.object(type(screen), "app", property(lambda self: app))

    def test_unentitled_renders_card_and_returns_false(self):
        screen = BwItemPickerModal()
        screen._render_upgrade_card = MagicMock()
        app = MagicMock()
        app.entitlement_guard.check.return_value = (False, "Requires Solo or Teams.")
        with self._patched(screen, app):
            allowed = screen._check_entitled()
        assert allowed is False
        screen._render_upgrade_card.assert_called_once_with("Requires Solo or Teams.")

    def test_entitled_returns_true_no_card(self):
        screen = BwItemPickerModal()
        screen._render_upgrade_card = MagicMock()
        app = MagicMock()
        app.entitlement_guard.check.return_value = (True, "OK")
        with self._patched(screen, app):
            allowed = screen._check_entitled()
        assert allowed is True
        screen._render_upgrade_card.assert_not_called()

    def test_no_guard_renders_card(self):
        screen = BwItemPickerModal()
        screen._render_upgrade_card = MagicMock()
        app = MagicMock()
        app.entitlement_guard = None
        with self._patched(screen, app):
            allowed = screen._check_entitled()
        assert allowed is False
        screen._render_upgrade_card.assert_called_once()


@pytest.mark.asyncio
async def test_entitled_unlocked_renders_table():
    from textual.app import App
    from textual.widgets import DataTable

    svc = MagicMock()
    svc.status = AsyncMock(return_value=BwAuthState.UNLOCKED)
    svc.ensure_servonaut_folder = AsyncMock(return_value="fld-1")
    svc.list_items = AsyncMock(
        return_value=[
            BwItemSummary(id="ssh-1", name="prod key", type=5, has_ssh_key=True),
            BwItemSummary(id="ssh-2", name="bastion key", type=5, has_ssh_key=True),
        ]
    )

    class _Host(App):
        def on_mount(self) -> None:
            self.entitlement_guard = SimpleNamespace(check=lambda f: (True, "OK"))
            self.config_manager = SimpleNamespace(
                get=lambda: SimpleNamespace(bw_vault_folder="Servonaut")
            )
            self.push_screen(BwItemPickerModal(session_service=svc))

    app = _Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.pause()
        await pilot.pause()
        table = app.screen.query_one("#bw_picker_table", DataTable)
        assert table.row_count == 2
    svc.ensure_servonaut_folder.assert_awaited()
    svc.list_items.assert_awaited()


@pytest.mark.asyncio
async def test_unentitled_shows_no_table():
    from textual.app import App
    from textual.widgets import DataTable

    svc = MagicMock()

    class _Host(App):
        def on_mount(self) -> None:
            self.entitlement_guard = SimpleNamespace(check=lambda f: (False, "Solo required"))
            self.config_manager = SimpleNamespace(
                get=lambda: SimpleNamespace(bw_vault_folder="Servonaut")
            )
            self.push_screen(BwItemPickerModal(session_service=svc))

    app = _Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.pause()
        assert not list(app.screen.query(DataTable))

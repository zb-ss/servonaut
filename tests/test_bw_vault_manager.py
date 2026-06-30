"""Tests for :class:`servonaut.screens.bw_vault_manager.BwVaultManagerScreen`.

Covers the N-lookup join (vault items × referencing instances × verify status),
the verify/servers cell formatting, the entitlement gate, and a ``run_test``
pilot smoke that an entitled+unlocked session renders the joined table.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.screens.bw_vault_manager import BwVaultManagerScreen
from servonaut.services.bw_session_service import BwAuthState, BwItemSummary


def _ref(item_id="ssh-1", instance_id="i-1", name="web-1", status="verified"):
    return {"item_id": item_id, "provider": "aws", "instance_id": instance_id,
            "name": name, "verify_status": status}


class TestCells:
    def test_verify_cell_all_verified_green(self):
        cell = BwVaultManagerScreen._verify_cell([_ref(status="verified")])
        assert "green" in cell and "verified" in cell

    def test_verify_cell_failed_red(self):
        cell = BwVaultManagerScreen._verify_cell(
            [_ref(status="verified"), _ref(status="auth_failed")]
        )
        assert "red" in cell and "auth_failed" in cell

    def test_verify_cell_none_is_dash(self):
        assert "—" in BwVaultManagerScreen._verify_cell([])

    def test_verify_cell_unknown_is_unverified(self):
        cell = BwVaultManagerScreen._verify_cell([_ref(status=None)])
        assert "unverified" in cell

    def test_servers_cell_counts_and_truncates(self):
        refs = [_ref(instance_id=f"i-{n}", name=f"web-{n}") for n in range(5)]
        cell = BwVaultManagerScreen._servers_cell(refs, None)
        assert cell.startswith("5:")
        assert "+2" in cell  # only first 3 shown

    def test_servers_cell_empty(self):
        assert "—" in BwVaultManagerScreen._servers_cell([], None)

    def test_short_id(self):
        assert BwVaultManagerScreen._short_id("a1b2c3d4-e5f6-7890") == "a1b2c3d4…"
        assert BwVaultManagerScreen._short_id("abc123") == "abc123"


class TestEntitlementGate:
    def test_unentitled_sets_upgrade_status_and_no_worker(self):
        screen = BwVaultManagerScreen()
        screen._set_status = MagicMock()
        screen.run_worker = MagicMock()
        app = MagicMock()
        app.entitlement_guard.check.return_value = (False, "Solo required")
        with patch.object(type(screen), "app", property(lambda self: app)):
            screen._refresh()
        screen.run_worker.assert_not_called()
        msg = screen._set_status.call_args.args[0]
        assert "Upgrade required" in msg

    def test_entitled_starts_worker(self):
        screen = BwVaultManagerScreen()
        screen._set_status = MagicMock()
        screen.run_worker = MagicMock()
        app = MagicMock()
        app.entitlement_guard.check.return_value = (True, "OK")
        app.bw_session_service = MagicMock()
        with patch.object(type(screen), "app", property(lambda self: app)):
            screen._refresh()
        screen.run_worker.assert_called_once()
        # Close the un-awaited coroutine handed to the mocked run_worker.
        coro = screen.run_worker.call_args.args[0]
        if asyncio.iscoroutine(coro):
            coro.close()


class TestJoin:
    def test_n_lookup_groups_instances_by_item(self):
        screen = BwVaultManagerScreen()
        bw_cfg = MagicMock()
        bw_cfg.get_personal_config = AsyncMock(return_value=None)
        bw_cfg.list_personal_instances = AsyncMock(
            return_value=[
                {"provider": "aws", "instance_id": "i-1", "ssh_verify_status": "verified"},
                {"provider": "aws", "instance_id": "i-2", "ssh_verify_status": "not_found"},
                {"provider": "ovh", "instance_id": "i-3", "ssh_verify_status": "verified"},
            ]
        )

        async def _ref_lookup(provider, instance_id):
            mapping = {
                "i-1": "ssh-A",
                "i-2": "ssh-A",  # two servers share one key
                "i-3": "ssh-B",
            }
            return {"ssh_credential_ref": {"item_id": mapping[instance_id]}}

        bw_cfg.get_personal_instance_ref = AsyncMock(side_effect=_ref_lookup)

        app = MagicMock()
        app.bw_ssh_config_service = bw_cfg
        app.instances = [
            {"id": "i-1", "name": "web-1"},
            {"id": "i-2", "name": "web-2"},
            {"id": "i-3", "name": "db-1"},
        ]
        with patch.object(type(screen), "app", property(lambda self: app)):
            grouped = asyncio.run(screen._join_referencing_instances())

        assert set(grouped) == {"ssh-A", "ssh-B"}
        assert len(grouped["ssh-A"]) == 2
        assert {r["instance_id"] for r in grouped["ssh-A"]} == {"i-1", "i-2"}
        assert grouped["ssh-A"][0]["name"] in {"web-1", "web-2"}
        assert grouped["ssh-B"][0]["instance_id"] == "i-3"

    def test_no_config_service_returns_empty(self):
        screen = BwVaultManagerScreen()
        app = MagicMock()
        app.bw_ssh_config_service = None
        with patch.object(type(screen), "app", property(lambda self: app)):
            grouped = asyncio.run(screen._join_referencing_instances())
        assert grouped == {}

    def test_caches_vault_base_from_config(self):
        screen = BwVaultManagerScreen()
        bw_cfg = MagicMock()
        bw_cfg.get_personal_config = AsyncMock(
            return_value={"config": {"vault_url": "https://vault.example.com/"}}
        )
        bw_cfg.list_personal_instances = AsyncMock(return_value=[])
        app = MagicMock()
        app.bw_ssh_config_service = bw_cfg
        app.instances = []
        with patch.object(type(screen), "app", property(lambda self: app)):
            asyncio.run(screen._join_referencing_instances())
        assert screen._vault_base == "https://vault.example.com"


@pytest.mark.asyncio
async def test_pilot_renders_joined_table():
    from textual.app import App
    from textual.widgets import DataTable

    svc = MagicMock()
    svc.status = AsyncMock(return_value=BwAuthState.UNLOCKED)
    svc.ensure_servonaut_folder = AsyncMock(return_value="fld-1")
    svc.list_items = AsyncMock(
        return_value=[
            BwItemSummary(id="ssh-A", name="prod key", type=5, has_ssh_key=True),
            BwItemSummary(id="ssh-B", name="bastion key", type=5, has_ssh_key=True),
        ]
    )
    bw_cfg = MagicMock()
    bw_cfg.get_personal_config = AsyncMock(return_value=None)
    bw_cfg.list_personal_instances = AsyncMock(
        return_value=[{"provider": "aws", "instance_id": "i-1", "ssh_verify_status": "verified"}]
    )
    bw_cfg.get_personal_instance_ref = AsyncMock(
        return_value={"ssh_credential_ref": {"item_id": "ssh-A"}}
    )

    class _Host(App):
        def on_mount(self) -> None:
            self.entitlement_guard = SimpleNamespace(check=lambda f: (True, "OK"))
            self.config = SimpleNamespace(bw_vault_folder="Servonaut")
            self.bw_session_service = svc
            self.bw_ssh_config_service = bw_cfg
            self.instances = [{"id": "i-1", "name": "web-1"}]
            self.push_screen(BwVaultManagerScreen(session_service=svc))

    app = _Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.pause()
        await pilot.pause()
        table = app.screen.query_one("#bw_vault_mgr_table", DataTable)
        assert table.row_count == 2
    bw_cfg.get_personal_instance_ref.assert_awaited()

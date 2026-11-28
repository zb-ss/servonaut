"""Screenshots for the workflow-first navigation, onboarding, and modal surfaces."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.widgets import Button, DataTable, Static, TabbedContent

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.services.cache_service import CacheService

from . import _harness
from .test_teams import _SignedIn

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


class _EmptyFleetSnapshotApp(_harness.SnapshotApp):
    """Real app with no configured cloud providers and an empty inventory."""

    def _init_services(self) -> None:
        super()._init_services()
        self.ovh_service = None
        self.hetzner_service = None

    def provider_available(self, provider: str) -> bool:
        return False


class _InlineBindService:
    """Vault service stub exposing inline Create vault and Import key actions."""

    async def vault_choices(self, *, team=None):
        del team
        return [{"vault_id": "11111111-1111-4111-8111-111111111111", "label": "Personal", "kind": "personal"}]

    async def list_vaults(self):
        return []

    async def creatable_vaults(self, vaults):
        del vaults
        return [{"team": None, "label": "Personal vault"}]

    async def create_vault(self, *, team, name, grant_policy):
        del team, name, grant_policy
        return {"vault_id": "11111111-1111-4111-8111-111111111111"}

    async def ssh_key_choices(self, *, vault_id: str):
        del vault_id
        return []

    async def import_keys(self, **_kwargs):
        return {}

    def records_new_host_keys(self) -> bool:
        return False


@sizes
def test_add_server_modal(screen_snapshot: Any, size: str) -> None:
    """AddServerModal fits compact provider choices cleanly at both sizes."""

    async def scenario(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        pilot.app.screen.action_add_server()
        modal = await _harness.wait_for_screen(pilot, "AddServerModal")
        await _harness.wait_until(
            pilot,
            lambda: modal.query_one("#add_server_custom", Button).region.height > 0,
            "the AddServerModal buttons",
        )
        _harness.freeze_cursors(pilot.app)

    def check(pilot: Any) -> None:
        modal = pilot.app.screen
        frame = modal.query_one("#add_server_modal")
        for btn in modal.query("Button"):
            assert btn.region.height > 0
            assert frame.region.contains_region(btn.region), btn.id

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], scenario, check=check)


@sizes
def test_team_bind_prompt_modal(screen_snapshot: Any, size: str) -> None:
    """_TeamBindPromptModal renders legible prompt actions at both sizes."""
    from servonaut.screens.team_management import _TeamBindPromptModal

    async def scenario(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        pilot.app.push_screen(_TeamBindPromptModal("web-1"))
        modal = await _harness.wait_for_screen(pilot, "_TeamBindPromptModal")
        await _harness.wait_until(
            pilot,
            lambda: modal.query_one("#team_bind_prompt_confirm", Button).region.width > 0,
            "the team bind prompt buttons",
        )
        _harness.freeze_cursors(pilot.app)

    def check(pilot: Any) -> None:
        modal = pilot.app.screen
        assert modal.query_one("#team_bind_prompt_confirm", Button).region.height > 0
        assert modal.query_one("#team_bind_prompt_cancel", Button).region.height > 0

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], scenario, check=check)


@sizes
def test_teams_servers_onboarding_and_vault_col(screen_snapshot: Any, size: str) -> None:
    """Teams shared-servers card keeps onboarding prose legible and avoids sideways scroll."""
    from servonaut.screens.team_management import TeamManagementScreen

    team_svc = SimpleNamespace(
        list_teams=AsyncMock(
            return_value=[{"id": "team-1", "slug": "ops", "name": "Ops Team", "role": "owner", "member_count": 2}]
        ),
        get_team=AsyncMock(
            return_value={
                "name": "Ops Team",
                "slug": "ops",
                "role": "owner",
                "max_seats": 5,
                "members": [
                    {"invitation_email": "lead@example.com", "role": "admin", "is_accepted": True},
                    {"invitation_email": "dev@example.com", "role": "member", "is_accepted": True},
                ],
            }
        ),
        list_shared_servers=AsyncMock(
            return_value=[
                {"id": "srv-1", "name": "web-1", "hostname": "10.0.1.5", "region": "eu-west-1"},
                {
                    "id": "srv-2",
                    "name": "db-1",
                    "hostname": "10.0.1.6",
                    "region": "eu-west-1",
                    "credential_binding": {"source": "servonaut_vault", "key_name": "ops-key"},
                },
            ]
        ),
        list_team_configs=AsyncMock(return_value=[]),
        get_team_agent_rules=AsyncMock(return_value={}),
    )

    async def scenario(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        app = pilot.app
        app.vault_available = True
        app.auth_service = _SignedIn(app.auth_service)
        app.team_service = team_svc
        app.push_screen(TeamManagementScreen())
        screen = await _harness.wait_for_screen(pilot, "TeamManagementScreen")
        teams_tbl = screen.query_one("#teams_table", DataTable)
        await _harness.wait_until(pilot, lambda: teams_tbl.row_count == 1, "teams row")
        screen.query_one("#btn_view_team", Button).press()
        servers_tbl = screen.query_one("#servers_table", DataTable)
        await _harness.wait_until(
            pilot,
            lambda: screen._loaded_team_slug == "ops" and servers_tbl.row_count == 2,
            "shared servers rows",
        )
        screen.query_one("#team_management_container").scroll_to_widget(
            screen.query_one("#servers_section"), animate=False, top=True,
        )
        await pilot.pause()
        _harness.freeze_cursors(app)

    def check(pilot: Any) -> None:
        screen = pilot.app.screen
        tbl = screen.query_one("#servers_table", DataTable)
        assert [str(col.label.plain) for col in tbl.columns.values()] == ["Name", "Hostname", "Region", "Vault key"]
        assert tbl.max_scroll_x == 0
        assert screen.query_one("#team_onboarding_strip").display is True
        assert screen.query_one("#team_onboarding_text", Static).region.width >= 35

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], scenario, check=check)


@sizes
def test_empty_fleet_onboarding_card(screen_snapshot: Any, size: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty fleet shows its onboarding card with quick entry buttons."""
    from servonaut.services.aws_service import AWSService

    ConfigManager().save(AppConfig())
    CacheService.CACHE_PATH.unlink(missing_ok=True)
    monkeypatch.setattr(AWSService, "get_cached_instances", lambda _self: [])
    monkeypatch.setattr(AWSService, "fetch_instances_cached", AsyncMock(return_value=[]))

    async def scenario(pilot: Any) -> None:
        screen = await _harness.wait_for_screen(pilot, "InstanceListScreen")
        card = screen.query_one("#empty_fleet_card")
        await _harness.wait_until(pilot, lambda: card.display and card.region.height > 0, "empty fleet card")
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    def check(pilot: Any) -> None:
        card = pilot.app.screen.query_one("#empty_fleet_card")
        assert card.display is True and card.region.height > 0
        assert pilot.app.screen.query_one("#btn_empty_add_custom", Button).region.height > 0

    screen_snapshot(_EmptyFleetSnapshotApp(), _harness.SIZES[size], scenario, check=check)


@sizes
def test_custom_servers_post_save_row(screen_snapshot: Any, size: str) -> None:
    """CustomServersScreen reveals its post-save workflow bar clearly above the fold."""
    from servonaut.screens.custom_servers import CustomServersScreen

    async def scenario(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        app = pilot.app
        app.vault_available = True
        app.vault_command_service = MagicMock()
        app.push_screen(CustomServersScreen())
        screen = await _harness.wait_for_screen(pilot, "CustomServersScreen")
        screen._show_post_save_row("web-1")
        screen.query_one("#btn_custom_share_team", Button).display = True
        await _harness.wait_until(
            pilot,
            lambda: screen.query_one("#custom_post_save_row").display
            and screen.query_one("#btn_custom_open_server", Button).region.bottom <= _harness.SIZES[size][1],
            "post-save workflow row in view",
        )
        await pilot.pause()
        _harness.freeze_cursors(app)

    def check(pilot: Any) -> None:
        row = pilot.app.screen.query_one("#custom_post_save_row")
        open_btn = pilot.app.screen.query_one("#btn_custom_open_server", Button)
        assert row.display is True
        assert 0 <= row.region.y and open_btn.region.bottom <= _harness.SIZES[size][1]
        assert pilot.app.screen.query_one("#custom_post_save_text", Static).region.width >= 50

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], scenario, check=check)


@sizes
def test_vault_binding_modal_inline_actions(screen_snapshot: Any, size: str) -> None:
    """VaultBindingModal surfaces inline Create vault and Import SSH key actions."""
    from servonaut.screens.server_actions import VaultBindingModal

    async def scenario(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        app = pilot.app
        app.vault_available = True
        modal = VaultBindingModal(_InlineBindService(), dict(_harness.FOCUS_SERVER))
        app.push_screen(modal)
        await _harness.wait_for_screen(pilot, "VaultBindingModal")
        await _harness.wait_until(
            pilot,
            lambda: not modal.query_one("#vault_bind_vault_actions").has_class("-hidden")
            and not modal.query_one("#vault_bind_key_actions").has_class("-hidden")
            and not modal.query_one("#vault_bind_import_key", Button).disabled,
            "inline vault create and import actions",
        )
        await pilot.pause()
        _harness.freeze_cursors(app)

    def check(pilot: Any) -> None:
        modal = pilot.app.screen
        assert not modal.query_one("#vault_bind_vault_actions").has_class("-hidden")
        assert not modal.query_one("#vault_bind_key_actions").has_class("-hidden")
        assert modal.query_one("#vault_bind_create_vault", Button).region.height > 0
        assert modal.query_one("#vault_bind_import_key", Button).region.height > 0

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], scenario, check=check)


@sizes
def test_fleet_memory_tabbed_workspace(screen_snapshot: Any, size: str) -> None:
    """FleetMemoryScreen shows Fleet, Sync, Drift, and Export tabs when entitled."""
    from servonaut.screens.fleet_memory import FleetMemoryScreen

    async def scenario(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        app = pilot.app
        app.auth_service = SimpleNamespace(
            is_authenticated=True,
            has_feature=lambda f: f in {"memory_sync", "memory_drift", "memory_compliance_export"},
            email="admin@example.com",
            plan="team",
        )
        app.memory_sync_service = SimpleNamespace(
            is_configured=True,
            is_enrolled_locally=lambda: True,
            get_key_material=lambda: b"test-key-material",
        )
        app.drift_service = SimpleNamespace(list_drift=AsyncMock(return_value=[]))
        app.push_screen(FleetMemoryScreen())
        screen = await _harness.wait_for_screen(pilot, "FleetMemoryScreen")
        await _harness.wait_until(
            pilot,
            lambda: not any(w.group == "memory_fleet" for w in app.workers)
            and screen.query_one("#fleet-memory-table", DataTable).row_count >= 3,
            "fleet memory rows and tabs",
        )
        await pilot.pause()
        _harness.freeze_cursors(app)

    def check(pilot: Any) -> None:
        tabs = pilot.app.screen.query_one("#memory_tabs", TabbedContent)
        for tab_id in ("mem_tab_fleet", "mem_tab_sync", "mem_tab_drift", "mem_tab_export"):
            assert tabs.get_tab(tab_id).display is True

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], scenario, check=check)

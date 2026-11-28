"""Targeted regression tests for the workflow-first sidebar IA and cross-screen bridges."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.config.schema import CustomServer
from servonaut.screens._fleet_filter import FleetFilter, facets
from servonaut.screens.custom_servers import CustomServersScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.server_actions import VaultBindingModal
from servonaut.screens.team_management import TeamManagementScreen
from servonaut.styles import CSS_FILES
from servonaut.widgets.fleet_values import instance_values
from servonaut.widgets.memory_views import MemoryViewsBar
from servonaut.widgets.sidebar import Sidebar

pytestmark = pytest.mark.usefixtures("navigation_open")


class _SidebarBottomHost(App):
    vault_available = False
    vault_update_required = False

    def __init__(self, *, team_workspaces: bool = True, ssh_ca: bool = False) -> None:
        super().__init__()
        self.auth_service = SimpleNamespace(
            is_authenticated=True,
            has_feature=lambda f: (
                (f == "team_workspaces" and team_workspaces)
                or (f == "ssh_ca" and ssh_ca)
            ),
        )

    def on_mount(self) -> None:
        class _S(Screen):
            def compose(self) -> ComposeResult:
                yield Sidebar()

        self.push_screen(_S())


@pytest.mark.asyncio
async def test_sidebar_pins_settings_in_bottom_and_gates_ca_on_feature() -> None:
    app = _SidebarBottomHost(team_workspaces=True, ssh_ca=False)
    app.vault_available = True
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        sidebar = app.screen.query_one(Sidebar)
        bottom = sidebar.query_one("#sidebar-bottom")
        nav_settings = sidebar.query_one("#nav_settings", Button)
        assert bottom in nav_settings.ancestors
        assert nav_settings.display is True
        assert sidebar.query_one("#nav_vault", Button).display is True
        assert sidebar.query_one("#nav_ca", Button).display is False
        assert sidebar.query_one("#section_team").display is True


def test_app_on_user_logout_resets_vault_available_and_refreshes_sidebar() -> None:
    from servonaut.app import ServonautApp

    app = ServonautApp()
    app.vault_available = True
    app.vault_update_required = True
    sidebar = MagicMock(spec=Sidebar)
    screen = MagicMock()
    screen.query.return_value = [sidebar]
    with (
        patch.object(type(app), "screen", new=property(lambda self: screen)),
        patch.object(type(app), "screen_stack", new=property(lambda self: [screen])),
        patch.object(app, "notify"),
    ):
        app.on_user_logout()
    assert app.vault_available is False
    assert app.vault_update_required is False
    sidebar.refresh_auth_gates.assert_called_once_with()


def test_fleet_filter_includes_folded_shared_rows_under_team_chip_o4() -> None:
    own_shared = {"id": "i-1", "provider": "aws", "state": "running"}
    cloud_only = {"id": "i-2", "is_hetzner": True, "provider": "hetzner", "state": "running"}
    team_only = {"id": "s-3", "is_shared": True, "provider": "Team", "state": "unknown"}
    shared_ids = frozenset({id(own_shared)})
    rows = [own_shared, cloud_only, team_only]

    filt = FleetFilter().with_provider("shared")
    assert filt.matches(own_shared, shared_ids=shared_ids) is True
    assert filt.matches(cloud_only, shared_ids=shared_ids) is False
    assert filt.matches(team_only, shared_ids=shared_ids) is True

    counts = facets(rows, FleetFilter(), shared_ids=shared_ids)
    assert counts.providers["aws"] == 1
    assert counts.providers["hetzner"] == 1
    assert counts.providers["shared"] == 2


def test_fleet_values_shows_team_name_only_on_shared_rows_o3() -> None:
    own_vals = instance_values({"id": "i-1", "name": "web-1", "team_name": "Ops"})
    assert "team_name" not in own_vals
    shared_vals = instance_values({"id": "s-1", "name": "web-1", "is_shared": True, "team_name": "Ops"})
    assert shared_vals["team_name"] == "Ops"


@pytest.mark.asyncio
async def test_memory_views_bar_gates_drift_and_export_and_switches() -> None:
    switched: list[str] = []

    class _BarHost(App):
        def __init__(self, entitled: bool, configured: bool) -> None:
            super().__init__()
            self.auth_service = SimpleNamespace(
                is_authenticated=entitled,
                has_feature=lambda _f: entitled,
            )
            self.memory_sync_service = SimpleNamespace(is_configured=configured)

        def switch_screen(self, screen) -> None:  # type: ignore[override]
            switched.append(type(screen).__name__)

        def on_mount(self) -> None:
            class _S(Screen):
                def compose(self) -> ComposeResult:
                    yield MemoryViewsBar(active="fleet")

            self.push_screen(_S())

    app = _BarHost(entitled=False, configured=False)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        bar = app.screen.query_one(MemoryViewsBar)
        assert bar.query_one("#memory_view_fleet").display is True
        assert bar.query_one("#memory_view_sync").display is True
        assert bar.query_one("#memory_view_drift").display is False
        assert bar.query_one("#memory_view_export").display is False
        await pilot.click("#memory_view_sync")
        assert switched == ["MemorySyncSetupScreen"]


@pytest.mark.asyncio
async def test_custom_servers_open_add_form_and_rename_without_duplicate() -> None:
    stored: list[CustomServer] = [
        CustomServer(name="web-old", host="10.0.1.5", username="ubuntu", ssh_key="", port=22),
    ]

    class _CustomHost(App):
        demo_mode = False
        redaction_service = None
        vault_available = False
        vault_command_service = None
        auth_service = None
        instances: list = []

        def __init__(self, open_add: bool) -> None:
            super().__init__()
            self._open_add = open_add
            self.ssh_service = SimpleNamespace(list_available_keys=lambda: [])
            self.custom_server_service = SimpleNamespace(
                list_servers=lambda: list(stored),
                get_server=lambda name: next((s for s in stored if s.name == name), None),
                add_server=lambda srv: stored.append(srv),
                remove_server=lambda name: [
                    stored.remove(s) for s in list(stored) if s.name == name
                ]
                and True,
                update_server=lambda name, srv: False,
                list_as_instances=lambda: [],
            )

        def on_mount(self) -> None:
            self.push_screen(CustomServersScreen(open_add_form=self._open_add))

    app = _CustomHost(open_add=True)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert screen.query_one("#add_form").display is True
        # Cancel, select row, edit and rename
        await pilot.click("#btn_cancel_form")
        await pilot.pause()
        screen.query_one("#custom_servers_table", DataTable).move_cursor(row=0)
        await pilot.press("e")
        await pilot.pause()
        assert screen._editing_name == "web-old"
        screen.query_one("#input_name", Input).value = "web-new"
        screen._save_server()
        await pilot.pause()
        assert [s.name for s in stored] == ["web-new"]
        assert screen.query_one("#custom_post_save_row").display is True


@pytest.mark.asyncio
async def test_team_management_fourth_vault_column_and_onboarding_strip() -> None:
    team_svc = SimpleNamespace(
        list_teams=AsyncMock(return_value=[{"slug": "ops", "name": "Ops", "role": "owner", "member_count": 1}]),
        get_team=AsyncMock(return_value={"slug": "ops", "name": "Ops", "role": "owner", "max_seats": 5, "members": []}),
        list_shared_servers=AsyncMock(return_value=[
            {"id": "s1", "name": "app-1", "hostname": "10.0.1.1", "region": "us-east-1"},
            {
                "id": "s2",
                "name": "app-2",
                "hostname": "10.0.1.2",
                "region": "us-east-1",
                "credential_binding": {"source": "servonaut_vault"},
            },
        ]),
        list_team_configs=AsyncMock(return_value=[]),
        get_team_agent_rules=AsyncMock(return_value={}),
    )

    class _TeamHost(App):
        CSS_PATH = CSS_FILES
        demo_mode = False
        redaction_service = None
        vault_available = True
        vault_command_service = None
        instances: list = []

        def __init__(self) -> None:
            super().__init__()
            self.auth_service = SimpleNamespace(is_authenticated=True, has_feature=lambda _f: True)
            self.team_service = team_svc

        def on_mount(self) -> None:
            self.push_screen(TeamManagementScreen())

    app = _TeamHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        for _ in range(40):
            await pilot.pause()
            if screen.query_one("#teams_table", DataTable).row_count > 0:
                break
        btn = screen.query_one("#btn_view_team", Button)
        btn.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        await pilot.click("#btn_view_team")
        tbl = screen.query_one("#servers_table", DataTable)
        for _ in range(40):
            await pilot.pause()
            if screen._has_team_detail and tbl.row_count == 2:
                break
        assert [str(c.label.plain) for c in tbl.columns.values()] == ["Name", "Hostname", "Region", "Vault key"]
        assert str(tbl.get_row_at(0)[3]) == "Not bound"
        assert str(tbl.get_row_at(1)[3]) == "Bound"
        assert screen.query_one("#btn_bind_shared_key", Button).display is True
        assert screen.query_one("#team_onboarding_strip").display is True
        await pilot.click("#btn_team_onboarding_dismiss")
        assert screen.query_one("#team_onboarding_strip").display is False


@pytest.mark.asyncio
async def test_vault_bind_modal_inline_create_and_import_and_default_selection() -> None:
    vault_id = "11111111-1111-4111-8111-111111111111"
    key_id = "22222222-2222-4222-8222-222222222222"

    class _InlineService:
        def __init__(self) -> None:
            self.vaults: list[dict] = []
            self.keys: dict[str, list[dict]] = {}

        async def vault_choices(self, *, team=None):
            return list(self.vaults)

        async def list_vaults(self):
            return list(self.vaults)

        async def creatable_vaults(self, vaults):
            return [] if vaults else [{"team": None, "label": "Personal vault"}]

        async def create_vault(self, *, team, name, grant_policy):
            self.vaults = [{"vault_id": vault_id, "label": "Personal", "kind": "personal"}]
            self.keys[vault_id] = [{"item_id": key_id, "label": "deploy"}]
            return {"vault_id": vault_id}

        async def ssh_key_choices(self, *, vault_id: str):
            return self.keys.get(vault_id, [])

        async def import_keys(self, **_kwargs):
            return {}

        def records_new_host_keys(self) -> bool:
            return False

    svc = _InlineService()
    instance = {"id": "i-1", "name": "web-1", "public_ip": "1.1.1.1", "username": "ubuntu", "port": 22}

    class _BindHost(App):
        def on_mount(self) -> None:
            self.push_screen(VaultBindingModal(svc, instance))

    app = _BindHost()
    async with app.run_test(size=(160, 50)) as pilot:
        for _ in range(40):
            await pilot.pause()
            if not app.screen.query_one("#vault_bind_vault_actions").has_class("-hidden"):
                break
        create_btn = app.screen.query_one("#vault_bind_create_vault", Button)
        assert create_btn.variant == "primary"
        with patch.object(app, "push_screen_wait", AsyncMock(return_value={"team": None, "label": "Personal vault"})):
            await app.screen._create_vault_inline()
        await pilot.pause()
        for _ in range(40):
            await pilot.pause()
            if not app.screen.query_one("#vault_bind_item", Select).disabled:
                break
        assert app.screen.query_one("#vault_bind_vault", Select).value == vault_id
        assert app.screen.query_one("#vault_bind_item", Select).value == key_id


@pytest.mark.asyncio
async def test_instance_list_launch_ssh_resolves_bw_ref_o1() -> None:
    screen = object.__new__(InstanceListScreen)
    mock_app = SimpleNamespace(
        bw_ssh_config_service=object(),
        team_service=None,
        ssh_service=MagicMock(),
    )
    resolved = SimpleNamespace(source="personal", item_id="bw-item-1")
    with (
        patch.object(InstanceListScreen, "app", new=property(lambda self: mock_app)),
        patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=({}, resolved))),
        patch("servonaut.screens.instance_list.resolve_bw_ssh_key_path", AsyncMock(return_value="/tmp/bw-key")),
    ):
        result = await screen._resolve_bw_key_if_configured({"id": "i-1"})
    assert result == "/tmp/bw-key"

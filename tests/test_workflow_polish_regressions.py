"""Regression tests for workflow polish, gating, and narrow layouts."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, CustomServer
from servonaut.screens.custom_servers import CustomServersScreen
from servonaut.screens.instance_list import AddServerModal, InstanceListScreen
from servonaut.screens.key_management import KeyManagementScreen
from servonaut.screens.secrets import SecretsScreen
from servonaut.screens.server_actions import ServerActionsScreen, VaultBindingModal
from servonaut.screens.settings.panels.backups import BackupsPanel
from servonaut.screens.settings.panels.bw_ssh import BwSshPanel
from servonaut.screens.settings.registry import PANELS
from servonaut.screens.team_management import TeamManagementScreen, _TeamBindPromptModal
from servonaut.services.secrets_status import SecretsStatusSummary
from servonaut.services.ssh_host_keys import home_relative
from servonaut.styles import CSS_FILES
from servonaut.widgets.sidebar import Sidebar

pytestmark = pytest.mark.usefixtures("navigation_open")


class _PanelHost(App):
    CSS_PATH = CSS_FILES

    def __init__(self, widget, *, authenticated: bool = False, features: set[str] | None = None, with_auth: bool = True) -> None:
        super().__init__()
        self._widget = widget
        feats = features or set()
        if with_auth:
            self.auth_service = SimpleNamespace(
                is_authenticated=authenticated,
                has_feature=lambda f: f in feats,
            )
        else:
            self.auth_service = None
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = AppConfig()
        self.bw_ssh_config_service = None
        self.bw_session_service = None
        self.config_sync_service = None
        self.backup_service = None
        self.vault_available = False

    def on_mount(self) -> None:
        widget = self._widget

        class _S(Screen):
            def compose(self) -> ComposeResult:
                yield widget

        self.push_screen(_S())


@pytest.mark.asyncio
async def test_bw_ssh_panel_gates_open_vault_button_by_feature_and_press() -> None:
    panel = BwSshPanel()
    app = _PanelHost(panel, authenticated=False, features=set())
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        btn = panel.query_one("#btn_bw_open_vault", Button)
        assert btn.display is False
        with patch.object(app, "push_screen") as push_mock:
            panel.on_button_pressed(Button.Pressed(btn))
        push_mock.assert_not_called()

    panel_ok = BwSshPanel()
    app_ok = _PanelHost(panel_ok, authenticated=True, features={"secrets_management"})
    async with app_ok.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert panel_ok.query_one("#btn_bw_open_vault", Button).display is True


@pytest.mark.asyncio
async def test_secrets_screen_gates_bw_vault_action_and_binding() -> None:
    summary = SecretsStatusSummary(
        authenticated=True,
        plan="team",
        entitled_secrets_management=True,
        entitlement_reason="OK",
        entitled_secrets_team_shared=True,
        active_provider_name="bitwarden",
        config_source="user",
        bitwarden_project_id="11111111-1111-4111-8111-111111111111",
        bitwarden_token_env_var="BWS_ACCESS_TOKEN",
        bws_path="/usr/bin/bws",
        bws_token_set=True,
        local_secrets_path=None,
        cache_present=True,
        cache_fresh=True,
        cache_updated_at="2026-01-01T00:00:00+00:00",
        cache_fetched_at=1700000000.0,
        has_health_warning=False,
    )

    class _SecretsHost(App):
        CSS_PATH = CSS_FILES
        demo_mode = False
        redaction_service = None
        vault_available = False
        vault_update_required = False

        def __init__(self, features: set[str]) -> None:
            super().__init__()
            self.auth_service = SimpleNamespace(is_authenticated=True, has_feature=lambda f: f in features)
            self.entitlement_guard = object()

        def on_mount(self) -> None:
            self.push_screen(SecretsScreen())

    with patch("servonaut.screens.secrets.compute_secrets_status", return_value=summary):
        app_no = _SecretsHost(set())
        async with app_no.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app_no.screen
            assert screen.check_action("bw_vault", ()) is False
            assert not screen.query("#secrets_action_b")

        app_yes = _SecretsHost({"secrets_management"})
        async with app_yes.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app_yes.screen
            assert screen.check_action("bw_vault", ()) is True
            assert screen.query("#secrets_action_b")


@pytest.mark.asyncio
async def test_backups_panel_hides_snapshots_only_when_auth_disallows() -> None:
    # Signed-out auth hides the launcher and warns on direct trigger.
    panel_signed_out = BackupsPanel()
    app_out = _PanelHost(panel_signed_out, authenticated=False, features=set(), with_auth=True)
    app_out.config_sync_service = object()
    async with app_out.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert panel_signed_out.query_one("#backups_open_snapshots", Button).display is False
        with patch.object(app_out, "notify") as notify_mock:
            panel_signed_out._open_snapshot_manager()
        assert "Sign in to manage config snapshots." in str(notify_mock.call_args.args[0])

    # Auth-less host hides snapshots (both auth_service and config_sync_service absent).
    panel_no_auth = BackupsPanel()
    app_none = _PanelHost(panel_no_auth, with_auth=False)
    async with app_none.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert panel_no_auth.query_one("#backups_open_snapshots", Button).display is False

    # Entitled signed-in account with config_sync_service unset still hides snapshots.
    panel_no_sync = BackupsPanel()
    app_no_sync = _PanelHost(panel_no_sync, authenticated=True, features={"config_sync"}, with_auth=True)
    async with app_no_sync.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert panel_no_sync.query_one("#backups_open_snapshots", Button).display is False

    # Entitled signed-in account with config_sync_service present shows the launcher.
    panel_ok = BackupsPanel()
    app_ok = _PanelHost(panel_ok, authenticated=True, features={"config_sync"}, with_auth=True)
    app_ok.config_sync_service = object()
    async with app_ok.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert panel_ok.query_one("#backups_open_snapshots", Button).display is True


@pytest.mark.asyncio
async def test_add_server_modal_hides_unconfigured_providers_and_routes_to_settings(tmp_path) -> None:
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())

    class _ModalHost(App):
        CSS_PATH = CSS_FILES

        def __init__(self, *, hetzner: bool = False) -> None:
            super().__init__()
            self.config_manager = cm
            self.provider_available = lambda p: p == "hetzner" and hetzner
            self.results: list[object] = []

        def on_mount(self) -> None:
            self.push_screen(AddServerModal(), callback=self.results.append)

    with patch("servonaut.widgets.sidebar._aws_switched_on", return_value=False):
        app_none = _ModalHost(hetzner=False)
        async with app_none.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            modal = app_none.screen
            assert modal.query("#add_server_custom")
            assert not modal.query("#add_server_aws")
            assert not modal.query("#add_server_hetzner")
            assert not modal.query("#add_server_ovh")
            connect_btn = modal.query_one("#add_srv_connect_provider", Button)
            assert connect_btn.compact is True
            await pilot.click("#add_srv_connect_provider")
            await pilot.pause()
        assert app_none.results == ["connect_provider"]

        app_hetzner = _ModalHost(hetzner=True)
        async with app_hetzner.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            modal = app_hetzner.screen
            assert modal.query("#add_server_hetzner")
            assert modal.query("#add_srv_connect_provider")


@pytest.mark.asyncio
async def test_instance_list_gates_use_vault_key_when_unavailable_or_busy(tmp_path) -> None:
    from servonaut.app import ServonautApp
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.keyword_store import KeywordStore
    from servonaut.services.ssh_service import SSHService

    app = ServonautApp()
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())

    def _init_services() -> None:
        app.config_manager = cm
        app.custom_server_service = CustomServerService(cm)
        app.connection_service = ConnectionService(cm)
        app.ssh_service = SSHService(cm)
        app.keyword_store = KeywordStore(str(tmp_path / "kw.json"))
        app.cache_service = SimpleNamespace(get_instances=lambda: [], is_fresh=lambda: True, get_age=lambda: None)
        app.aws_service = None
        app.ovh_service = None
        app.hetzner_service = None
        app.auth_service = None
        app.team_service = None
        app.vault_command_service = None
        app.vault_available = False
        app.config_sync_service = None
        app.memory_sync_service = None
        app.bw_ssh_config_service = None
        app.relay_manager = None
        app._apt_monitor = None

    app._init_services = _init_services  # type: ignore[method-assign]
    app._cached_fleet = lambda: []  # type: ignore[method-assign]

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, InstanceListScreen)
        screen._vault_binding = False
        assert screen.check_action("use_vault_key", ()) is False
        app.vault_available = True
        assert screen.check_action("use_vault_key", ()) is False
        app.vault_command_service = SimpleNamespace(close=MagicMock())
        assert screen.check_action("use_vault_key", ()) is True
        screen._vault_binding = True
        assert screen.check_action("use_vault_key", ()) is False


@pytest.mark.asyncio
async def test_servonaut_app_auth_lifecycle_refreshes_gates_and_caches(tmp_path) -> None:
    from textual.widgets import TabbedContent
    from servonaut.app import ServonautApp
    from servonaut.screens._team_share import cached_teams_for, set_cached_teams
    from servonaut.screens.fleet_memory import FleetMemoryScreen
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.keyword_store import KeywordStore
    from servonaut.services.ssh_service import SSHService

    app = ServonautApp()
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())
    team_svc = SimpleNamespace(list_teams=AsyncMock(return_value=[]))

    def _init_services() -> None:
        app.config_manager = cm
        app.custom_server_service = CustomServerService(cm)
        app.connection_service = ConnectionService(cm)
        app.ssh_service = SSHService(cm)
        app.keyword_store = KeywordStore(str(tmp_path / "kw.json"))
        app.cache_service = SimpleNamespace(get_instances=lambda: [], is_fresh=lambda: True, get_age=lambda: None)
        app.aws_service = None
        app.ovh_service = None
        app.hetzner_service = None
        app.auth_service = SimpleNamespace(
            is_authenticated=True,
            has_feature=lambda feat: feat in {"memory_drift", "memory_compliance_export"},
            fetch_entitlements=AsyncMock(return_value={}),
        )
        app.team_service = team_svc
        app.vault_command_service = None
        app.config_sync_service = None
        app.memory_sync_service = SimpleNamespace(
            is_configured=True,
            is_unlocked=False,
            is_enrolled_locally=lambda: False,
            get_key_material=lambda: None,
            clear_local_keypair_cache=MagicMock(),
            lock=MagicMock(),
        )
        app.bw_ssh_config_service = None
        app.relay_manager = None
        app._apt_monitor = None

    app._init_services = _init_services  # type: ignore[method-assign]
    app._cached_fleet = lambda: []  # type: ignore[method-assign]

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        app.vault_available = True
        app.vault_update_required = True
        app._personal_vault_bound_ids = {"i-1"}
        set_cached_teams(app, team_svc, [{"slug": "ops"}])
        assert cached_teams_for(app, team_svc) == [{"slug": "ops"}]

        mem_screen = FleetMemoryScreen(initial_tab="drift")
        mem_screen._drift_client_ready = False
        await app.switch_screen(mem_screen)
        await pilot.pause()
        await pilot.pause()
        tabs = mem_screen.query_one("#memory_tabs", TabbedContent)
        assert tabs.active == "mem_tab_drift"

        # Ending sign-in resets caches, clears _team_list_cache, switches active gated tab to fleet, and hides Drift/Export.
        app.auth_service = SimpleNamespace(
            is_authenticated=False,
            has_feature=lambda _feat: False,
            fetch_entitlements=AsyncMock(return_value={}),
        )
        app._on_sign_in_ended()
        await pilot.pause()
        assert app.vault_available is False
        assert app.vault_update_required is False
        assert app._personal_vault_bound_ids == set()
        assert cached_teams_for(app, team_svc) is None
        assert tabs.active == "mem_tab_fleet"
        assert tabs.get_tab("mem_tab_drift").display is False
        assert tabs.get_tab("mem_tab_export").display is False

        # _refresh_entitlements_on_start also triggers _refresh_navigation_and_tab_gates.
        with patch.object(app, "_refresh_navigation_and_tab_gates") as refresh_mock:
            await app._refresh_entitlements_on_start()
        refresh_mock.assert_called_once()


@pytest.mark.asyncio
async def test_sidebar_keeps_fleet_expanded_on_settings_screen() -> None:
    class _SettingsScreen(Screen):
        pass

    _SettingsScreen.__name__ = "SettingsScreen"

    class _NavHost(App):
        CSS_PATH = CSS_FILES
        vault_available = True
        vault_update_required = False
        auth_service = SimpleNamespace(is_authenticated=True, has_feature=lambda _f: True)

        def on_mount(self) -> None:
            s = _SettingsScreen()
            s.compose = lambda: [Sidebar()]  # type: ignore[method-assign]
            self.push_screen(s)

    app = _NavHost()
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        sidebar = app.screen.query_one(Sidebar)
        sidebar._update_active()
        assert sidebar.query_one("#section_fleet").collapsed is False


@pytest.mark.asyncio
async def test_server_actions_mnemonic_bindings_and_mounted_no_key_jump(tmp_path) -> None:
    from servonaut.app import ServonautApp
    from servonaut.screens.server_actions import _WIDE_FOOTER_KEYS
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.keyword_store import KeywordStore
    from servonaut.services.ssh_service import SSHService

    by_key = {b.key: b.action for b in ServerActionsScreen.BINDINGS}
    assert by_key["s"] == "action_3"
    assert by_key["c"] == "action_2"
    assert by_key["b"] == "action_1"
    assert by_key["t"] == "action_4"
    assert by_key["l"] == "action_6"
    assert by_key["w"] == "toggle_live"
    assert _WIDE_FOOTER_KEYS == ("l", "8")

    app = ServonautApp()
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())

    def _init_services() -> None:
        app.config_manager = cm
        app.custom_server_service = CustomServerService(cm)
        app.connection_service = ConnectionService(cm)
        app.ssh_service = SSHService(cm)
        app.keyword_store = KeywordStore(str(tmp_path / "kw.json"))
        app.cache_service = SimpleNamespace(get_instances=lambda: [], is_fresh=lambda: True, get_age=lambda: None)
        app.aws_service = None
        app.ovh_service = None
        app.hetzner_service = None
        app.auth_service = None
        app.team_service = None
        app.vault_command_service = None
        app.vault_available = True
        app.config_sync_service = None
        app.memory_sync_service = None
        app.bw_ssh_config_service = None
        app.relay_manager = None
        app._apt_monitor = None

    app._init_services = _init_services  # type: ignore[method-assign]
    app._cached_fleet = lambda: []  # type: ignore[method-assign]
    instance = {"id": "i-1", "name": "web-1", "public_ip": "1.1.1.1"}
    resolver = SimpleNamespace(resolve=AsyncMock(return_value=None))

    with patch.object(ServerActionsScreen, "_fetch_rdns", AsyncMock()):
        async with app.run_test(size=(160, 50)) as pilot:
            screen = ServerActionsScreen(instance)
            await app.push_screen(screen)
            await pilot.pause()
            with (
                patch.object(screen, "_ssh_ref_resolver", AsyncMock(return_value=resolver)),
                patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(instance, None))),
                patch.object(screen, "action_use_vault_key") as use_vault_mock,
            ):
                await screen._resolve_and_launch_ssh(MagicMock())
            use_vault_mock.assert_called_once()

            app.vault_available = False
            with (
                patch.object(screen, "_ssh_ref_resolver", AsyncMock(return_value=resolver)),
                patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(instance, None))),
            ):
                await screen._resolve_and_launch_ssh(MagicMock())
            await pilot.pause()
            assert isinstance(app.screen, KeyManagementScreen)


@pytest.mark.asyncio
async def test_vault_bind_modal_race_guard_personal_create_scope_and_scrub() -> None:
    gate_first = asyncio.Event()
    calls = 0

    class _RaceService:
        async def vault_choices(self, *, team=None):
            return [
                {"vault_id": "v1", "label": "Ops-Secret-Vault", "kind": "personal"},
                {"vault_id": "v2", "label": "Second", "kind": "personal"},
            ]

        async def list_vaults(self):
            return []

        async def creatable_vaults(self, vaults):
            return [
                {"team": None, "label": "Personal vault"},
                {"team": "ops", "label": "Team vault"},
            ]

        async def ssh_key_choices(self, *, vault_id: str):
            nonlocal calls
            calls += 1
            if vault_id == "v1":
                await gate_first.wait()
                return [{"item_id": "old-key", "label": "stale"}]
            return [{"item_id": "new-key", "label": "fresh"}]

        def records_new_host_keys(self) -> bool:
            return False

    svc = _RaceService()
    instance = {"id": "i-1", "name": "web-1", "public_ip": "1.1.1.1", "username": "ubuntu"}

    class _BindHost(App):
        demo_mode = True
        redaction_service = SimpleNamespace(
            redact_key_name=lambda v: "redacted-vault",
            redact_name=lambda v: "redacted-name",
            scrub_stream=lambda v: str(v).replace("Ops-Secret-Vault", "redacted-vault"),
        )
        bw_session_service = None

        def on_mount(self) -> None:
            self.push_screen(VaultBindingModal(svc, instance))

    app = _BindHost()
    async with app.run_test(size=(160, 50)) as pilot:
        modal = app.screen
        for _ in range(30):
            await pilot.pause()
            if modal._creatable_vaults:
                break
        # Personal scope filters out team creatable vaults.
        assert all(opt.get("team") is None for opt in modal._creatable_vaults)

        # Out-of-order response from an earlier key load is discarded.
        first_task = asyncio.create_task(modal._load_keys("v1"))
        await asyncio.sleep(0)
        await modal._load_keys("v2")
        gate_first.set()
        await first_task
        assert modal.query_one("#vault_bind_item", Select).value == "new-key"

        # Demo mode scrubs vault_name passed into VaultImportModal.
        captured = {}

        def _fake_import_modal(*_args, **kwargs):
            captured.update(kwargs)
            return MagicMock()

        modal._vault_choices = [{"vault_id": "v2", "label": "Ops-Secret-Vault"}]
        modal.query_one("#vault_bind_vault", Select).value = "v2"
        with (
            patch.object(modal, "_can_import_keys", return_value=True),
            patch("servonaut.screens.vault_import_modal.VaultImportModal", side_effect=_fake_import_modal),
            patch.object(app, "push_screen_wait", AsyncMock(return_value=None)),
        ):
            await modal._import_key_inline()
        assert "Ops-Secret-Vault" not in captured["vault_name"]


@pytest.mark.asyncio
async def test_vault_screen_refresh_after_ssh_import_sets_next_action(tmp_path) -> None:
    from servonaut.app import ServonautApp
    from servonaut.screens.vault import VaultScreen
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.keyword_store import KeywordStore
    from servonaut.services.ssh_service import SSHService

    app = ServonautApp()
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())
    vault_svc = SimpleNamespace(
        is_unlocked=True,
        list_vaults=AsyncMock(return_value=[{"vault_id": "v1", "label": "Personal"}]),
        list_items=AsyncMock(return_value=[]),
        list_devices=AsyncMock(return_value=[]),
        identity_state=AsyncMock(return_value=SimpleNamespace(state="ready", reason="")),
        close=MagicMock(),
    )

    def _init_services() -> None:
        app.config_manager = cm
        app.custom_server_service = CustomServerService(cm)
        app.connection_service = ConnectionService(cm)
        app.ssh_service = SSHService(cm)
        app.keyword_store = KeywordStore(str(tmp_path / "kw.json"))
        app.cache_service = SimpleNamespace(get_instances=lambda: [], is_fresh=lambda: True, get_age=lambda: None)
        app.aws_service = None
        app.ovh_service = None
        app.hetzner_service = None
        app.auth_service = SimpleNamespace(is_authenticated=True, has_feature=lambda _f: True)
        app.team_service = None
        app.vault_command_service = vault_svc
        app.vault_available = True
        app.config_sync_service = None
        app.memory_sync_service = None
        app.bw_ssh_config_service = None
        app.relay_manager = None
        app._apt_monitor = None

    app._init_services = _init_services  # type: ignore[method-assign]
    app._cached_fleet = lambda: []  # type: ignore[method-assign]

    async with app.run_test(size=(160, 50)) as pilot:
        screen = VaultScreen()
        await app.switch_screen(screen)
        await pilot.pause()
        await pilot.pause()
        screen._table_mode = "vaults"
        screen._next_action = ""
        with patch.object(screen, "_render_vaults"):
            await screen._refresh_imported_vault_metadata(
                "v1", 1, 0, [{"source": "ssh", "vault_item_id": "k1"}], 0
            )
        assert screen._next_action == "vault_bind_key"

        # Narrowed try scope: rendering failure is NOT swallowed as a vault-list fetch warning.
        with (
            patch.object(app, "notify") as notify_mock,
            patch.object(screen, "_render_vaults", side_effect=RuntimeError("render boom")),
        ):
            with pytest.raises(RuntimeError, match="render boom"):
                await screen._refresh_imported_vault_metadata(
                    "v1", 1, 0, [{"source": "ssh", "vault_item_id": "k1"}], 0
                )
        assert not any("Failed to refresh vault list" in str(c.args[0]) for c in notify_mock.call_args_list)


@pytest.mark.asyncio
async def test_key_management_filters_custom_and_shared_and_warns_open_perms(tmp_path) -> None:
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())
    open_key = tmp_path / "open_id_ed25519"
    open_key.write_text("PRIVATE KEY\n", encoding="utf-8")
    open_key.chmod(0o644)

    class _KeyHost(App):
        CSS_PATH = CSS_FILES
        demo_mode = False
        redaction_service = None
        vault_available = False

        def __init__(self) -> None:
            super().__init__()
            self.config_manager = cm
            self.ssh_service = SimpleNamespace(
                list_available_keys=lambda: [str(open_key)],
                check_key_permissions=lambda _p: False,
                get_agent_status=lambda: {"running": False, "keys": []},
                check_ssh_agent=lambda: False,
            )
            self.instances = [
                {"id": "i-cloud", "name": "web [bold]1[/bold]", "provider": "aws"},
                {"id": "custom-1", "name": "local-box", "is_custom": True},
                {"id": "team-1", "name": "shared-box", "is_shared": True},
            ]

        def on_mount(self) -> None:
            self.push_screen(KeyManagementScreen())

    app = _KeyHost()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        server_select = screen.query_one("#select_mapping_server", Select)
        values = [opt[1] for opt in server_select._options if isinstance(opt[1], str)]
        assert values == ["i-cloud"]
        avail = screen.query_one("#available_keys_table", DataTable)
        assert "(insecure permissions: expected 0600)" in str(avail.get_row_at(0)[0])
        with patch.object(app, "notify") as notify_mock:
            avail.move_cursor(row=0)
            screen.on_data_table_row_selected(
                DataTable.RowSelected(avail, 0, next(iter(avail.rows.keys())))
            )
        assert any(
            home_relative(str(open_key)) in str(call.args[0]) and call.kwargs.get("severity") == "warning"
            for call in notify_mock.call_args_list
        )


@pytest.mark.asyncio
async def test_custom_servers_key_dropdown_warnings_and_narrow_edit_scroll(tmp_path) -> None:
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())
    stored = [CustomServer(name=f"host-{i}", host=f"10.0.1.{i}", username="ubuntu", ssh_key="", port=22) for i in range(1, 8)]
    open_key_path = Path.home() / ".ssh" / "test_open_key"
    open_key_path.parent.mkdir(parents=True, exist_ok=True)
    open_key_path.write_text("PRIVATE KEY\n", encoding="utf-8")
    open_key_path.chmod(0o644)
    open_key = str(open_key_path)

    class _CustomHost(App):
        CSS_PATH = CSS_FILES
        demo_mode = False
        redaction_service = None
        vault_available = False
        vault_command_service = None
        auth_service = None
        instances: list = []

        def __init__(self) -> None:
            super().__init__()
            self.config_manager = cm
            self.ssh_service = SimpleNamespace(
                list_available_keys=lambda: [open_key],
                check_key_permissions=lambda _p: False,
            )
            self.custom_server_service = SimpleNamespace(
                list_servers=lambda: list(stored),
                get_server=lambda name: next((s for s in stored if s.name == name), None),
                add_server=lambda srv: stored.append(srv),
                update_server=lambda name, srv: True,
                list_as_instances=lambda: [],
            )

        def on_mount(self) -> None:
            self.push_screen(CustomServersScreen())

    app = _CustomHost()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        screen._show_form(stored[0])
        await pilot.pause()
        await pilot.pause()
        select = screen.query_one("#select_custom_ssh_key", Select)
        assert any("~/.ssh/test_open_key" in str(opt[0]) and "insecure permissions" in str(opt[0]) for opt in select._options)
        name_inp = screen.query_one("#input_name", Input)
        assert app.focused is name_inp
        assert 0 <= name_inp.region.y and name_inp.region.bottom <= 30

        screen._hide_form()
        screen._show_post_save_row("host-1")
        await pilot.pause()
        await pilot.pause()
        btn = screen.query_one("#btn_custom_open_server", Button)
        assert app.focused is btn
        assert 0 <= btn.region.y and btn.region.bottom <= 30


@pytest.mark.asyncio
async def test_team_management_bind_guard_matching_own_row_and_share_all_prompt(tmp_path) -> None:
    from servonaut.app import ServonautApp
    from servonaut.screens._team_share import cached_teams_for, set_cached_teams
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.keyword_store import KeywordStore
    from servonaut.services.ssh_service import SSHService

    shared_row = {"id": "s1", "name": "app-1", "hostname": "198.51.100.9"}
    own_row = {"id": "i-99", "name": "app-1", "public_ip": "198.51.100.9", "private_ip": "10.0.1.9"}
    shared_on_fleet = {
        "id": "team:ops:s1",
        "is_shared": True,
        "team_slug": "ops",
        "name": "app-1",
        "hostname": "198.51.100.9",
    }
    team_svc = SimpleNamespace(
        list_teams=AsyncMock(return_value=[{"slug": "ops", "name": "Ops", "role": "owner"}]),
        get_team=AsyncMock(return_value={"slug": "ops", "name": "Ops", "role": "owner", "members": [], "servers": [shared_row]}),
        list_shared_servers=AsyncMock(return_value=[shared_row]),
        list_team_configs=AsyncMock(return_value=[]),
        get_team_agent_rules=AsyncMock(return_value={}),
        remove_member=AsyncMock(return_value=None),
        update_role=AsyncMock(return_value=None),
    )

    app = ServonautApp()
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())

    def _init_services() -> None:
        app.config_manager = cm
        app.custom_server_service = CustomServerService(cm)
        app.connection_service = ConnectionService(cm)
        app.ssh_service = SSHService(cm)
        app.keyword_store = KeywordStore(str(tmp_path / "kw.json"))
        app.cache_service = SimpleNamespace(get_instances=lambda: [own_row], is_fresh=lambda: True, get_age=lambda: None)
        app.aws_service = None
        app.ovh_service = None
        app.hetzner_service = None
        app.auth_service = SimpleNamespace(is_authenticated=True, has_feature=lambda f: f == "team_workspaces")
        app.team_service = team_svc
        app.vault_command_service = SimpleNamespace(close=MagicMock())
        app.vault_available = True
        app.config_sync_service = None
        app.memory_sync_service = None
        app.bw_ssh_config_service = None
        app.relay_manager = None
        app._apt_monitor = None

    app._init_services = _init_services  # type: ignore[method-assign]
    app._cached_fleet = lambda: [own_row]  # type: ignore[method-assign]

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        app.instances = [own_row, shared_on_fleet]
        app._instances_pristine = [own_row, shared_on_fleet]
        screen = TeamManagementScreen()
        await app.switch_screen(screen)
        await pilot.pause()
        await pilot.pause()
        screen._current_team_slug = "ops"
        screen._shared_servers = [shared_row]

        # Demo unresolved guard stops shared-row bind worker.
        app.demo_mode = True
        with (
            patch("servonaut.screens.team_management.refuse_unresolved", return_value=True) as refuse_mock,
            patch.object(screen, "run_worker") as run_worker_mock,
        ):
            screen._start_bind_row(shared_row)
        refuse_mock.assert_called_once()
        run_worker_mock.assert_not_called()

        # Blocker #3: own_twin matches public_ip / id, NEVER private_ip alone or name alone.
        app.demo_mode = False
        assert screen._matching_own_row({"hostname": "198.51.100.9"})["id"] == "i-99"
        assert screen._matching_own_row({"hostname": "10.0.1.9"}) is None
        assert screen._matching_own_row({"hostname": "192.0.2.9", "name": "app-1"}) is None

        # _start_server_operation is refused while _binding_shared_key is True.
        screen._binding_shared_key = True
        op = AsyncMock()
        screen._start_server_operation(op, "Working...")
        op.assert_not_called()
        screen._binding_shared_key = False

        # Role change and member removal clear _team_list_cache.
        set_cached_teams(app, team_svc, [{"slug": "ops", "role": "owner"}])
        await screen._do_remove_member("ops", "m-1", "a@example.com")
        assert cached_teams_for(app, team_svc) is None
        set_cached_teams(app, team_svc, [{"slug": "ops", "role": "owner"}])
        await screen._do_update_role("ops", "m-2", "b@example.com", "admin")
        assert cached_teams_for(app, team_svc) is None

        # _offer_post_share_bind triggers _TeamBindPromptModal for newly shared unbound server.
        app.instances = [own_row, {**shared_on_fleet, "id": "s1"}]
        app._instances_pristine = list(app.instances)
        screen._offer_post_share_bind("ops", "198.51.100.9", "app-1")
        await pilot.pause()
        assert isinstance(app.screen, _TeamBindPromptModal)


@pytest.mark.asyncio
async def test_inspector_key_badges_and_vault_settings_keywords(tmp_path) -> None:
    from servonaut.app import ServonautApp
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.keyword_store import KeywordStore
    from servonaut.services.ssh_service import SSHService

    shared_ca = {"id": "s1", "is_shared": True, "ssh_ca": {"enrolled": True}}
    shared_vault = {"id": "s2", "is_shared": True, "credential_binding": {"source": "servonaut_vault"}}
    shared_local = {"id": "s3", "is_shared": True}
    own_ca = {"id": "i-1", "ssh_ca": {"enrolled": True}}
    own_vault = {"id": "i-2"}
    own_twin_ca = {"id": "i-3", "name": "web-3", "public_ip": "198.51.100.3"}
    own_twin_vault = {"id": "i-4", "name": "web-4", "public_ip": "198.51.100.4"}
    own_twin_local = {"id": "i-5", "name": "web-5", "public_ip": "198.51.100.5"}
    own_private_collision = {"id": "i-6", "name": "web-priv", "public_ip": "198.51.100.6", "private_ip": "10.0.1.99"}

    app = ServonautApp()
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())
    rows = [
        {"id": "t3", "is_shared": True, "instance_id": "i-3", "ssh_ca": {"enrolled": True}},
        {"id": "t4", "is_shared": True, "instance_id": "i-4", "credential_binding": {"source": "servonaut_vault"}},
        {"id": "t5", "is_shared": True, "instance_id": "i-5"},
        {"id": "t6", "is_shared": True, "name": "web-priv", "hostname": "10.0.1.99", "credential_binding": {"source": "servonaut_vault"}},
    ]

    def _init_services() -> None:
        app.config_manager = cm
        app.custom_server_service = CustomServerService(cm)
        app.connection_service = ConnectionService(cm)
        app.ssh_service = SSHService(cm)
        app.keyword_store = KeywordStore(str(tmp_path / "kw.json"))
        app.cache_service = SimpleNamespace(get_instances=lambda: rows, is_fresh=lambda: True, get_age=lambda: None)
        app.aws_service = None
        app.ovh_service = None
        app.hetzner_service = None
        app.auth_service = None
        app.team_service = None
        app.vault_command_service = None
        app.config_sync_service = None
        app.memory_sync_service = None
        app.bw_ssh_config_service = None
        app.relay_manager = None
        app._apt_monitor = None

    app._init_services = _init_services  # type: ignore[method-assign]
    app._cached_fleet = lambda: list(rows)  # type: ignore[method-assign]

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.pause()
        app.instances = list(rows)
        app._instances_pristine = list(rows)
        screen = app.screen
        assert isinstance(screen, InstanceListScreen)
        app._personal_vault_bound_ids = {"i-2"}
        assert screen._inspector_key_badge(shared_ca).plain == "● SSH CA ready"
        assert screen._inspector_key_badge(shared_vault).plain == "● team key ready"
        assert screen._inspector_key_badge(shared_local).plain == "○ Shared · local key"
        assert screen._inspector_key_badge(own_ca).plain == "● SSH CA ready"
        assert screen._inspector_key_badge(own_vault).plain == "● vault key ready"
        assert screen._inspector_key_badge(own_twin_ca).plain == "● SSH CA (via team)"
        assert screen._inspector_key_badge(own_twin_vault).plain == "● team key ready"
        assert screen._inspector_key_badge(own_twin_local).plain == "○ Shared · local key"
        # Private IP or name collision without matching id/public_ip is never treated as a twin.
        assert screen._matching_team_row(own_private_collision) is None
        assert screen._has_team_twin(own_private_collision) is False

    vault_spec = next((spec for spec in PANELS if spec.id == "vault"), None)
    assert vault_spec is not None
    assert "team" in vault_spec.keywords
    assert "team vault" in vault_spec.keywords


def test_memory_sync_pane_exposes_max_drain_batches() -> None:
    from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen
    from servonaut.widgets.memory_panes import MemorySyncPane

    pane = MemorySyncPane()
    assert pane._MAX_DRAIN_BATCHES == MemorySyncSetupScreen._MAX_DRAIN_BATCHES


@pytest.mark.asyncio
async def test_custom_servers_post_save_disables_hidden_form_buttons_and_focuses_open(tmp_path) -> None:
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())
    stored: list[CustomServer] = []

    class _CustomSaveHost(App):
        CSS_PATH = CSS_FILES
        demo_mode = False
        redaction_service = None
        vault_available = False
        vault_command_service = None
        auth_service = None
        instances: list = []

        def __init__(self) -> None:
            super().__init__()
            self.config_manager = cm
            self.ssh_service = SimpleNamespace(
                list_available_keys=lambda: [],
                check_key_permissions=lambda _p: True,
            )
            self.custom_server_service = SimpleNamespace(
                list_servers=lambda: list(stored),
                get_server=lambda name: next((s for s in stored if s.name == name), None),
                add_server=lambda srv: stored.append(srv),
                update_server=lambda name, srv: True,
                list_as_instances=lambda: [
                    {
                        "id": f"custom-{s.name}",
                        "name": s.name,
                        "public_ip": s.host,
                        "private_ip": s.host,
                        "is_custom": True,
                    }
                    for s in stored
                ],
            )

        def on_mount(self) -> None:
            self.push_screen(CustomServersScreen(open_add_form=True))

    app = _CustomSaveHost()
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        screen.query_one("#input_name", Input).value = "web-1"
        screen.query_one("#input_host", Input).value = "10.0.1.99"
        await pilot.click("#btn_save_server")
        await pilot.pause()
        await pilot.pause()
        assert screen.query_one("#btn_save_server").disabled is True
        assert screen.query_one("#btn_cancel_form").disabled is True
        assert app.focused is screen.query_one("#btn_custom_open_server", Button)

        screen.action_add_server()
        await pilot.pause()
        assert screen.query_one("#btn_save_server").disabled is False
        assert screen.query_one("#btn_cancel_form").disabled is False


def _make_offline_app(
    tmp_path: Path,
    *,
    instances: list[dict] | None = None,
    auth_service: object | None = None,
    team_service: object | None = None,
    vault_command_service: object | None = None,
    vault_available: bool = False,
    memory_sync_service: object | None = None,
    drift_service: object | None = None,
    aws_service: object | None = None,
    ovh_service: object | None = None,
    hetzner_service: object | None = None,
):
    from servonaut.app import ServonautApp
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.keyword_store import KeywordStore
    from servonaut.services.ssh_service import SSHService

    app = ServonautApp()
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    cm.save(AppConfig())
    app.config_manager = cm
    rows = list(instances or [])

    def _init_services() -> None:
        app.config_manager = cm
        app.custom_server_service = CustomServerService(cm)
        app.connection_service = ConnectionService(cm)
        app.ssh_service = SSHService(cm)
        app.keyword_store = KeywordStore(str(tmp_path / "kw.json"))
        app.cache_service = SimpleNamespace(get_instances=lambda: list(rows), is_fresh=lambda: True, get_age=lambda: None)
        app.aws_service = aws_service
        app.ovh_service = ovh_service
        app.hetzner_service = hetzner_service
        app.auth_service = auth_service
        app.team_service = team_service
        app.vault_command_service = vault_command_service
        app.vault_available = vault_available
        app.config_sync_service = None
        app.memory_sync_service = memory_sync_service
        app.drift_service = drift_service
        app.bw_ssh_config_service = None
        app.relay_manager = None
        app._apt_monitor = None

    app._init_services = _init_services  # type: ignore[method-assign]
    app._cached_fleet = lambda: list(rows)  # type: ignore[method-assign]
    return app


@pytest.mark.asyncio
async def test_team_cache_ttl_and_share_flow_preserves_other_teams(tmp_path, monkeypatch) -> None:
    from servonaut.screens import _team_share
    from servonaut.screens.server_actions import TeamTargetModal
    from servonaut.services.team_service import ShareResult, SHARED

    now = [100.0]
    monkeypatch.setattr(_team_share, "time", SimpleNamespace(monotonic=lambda: now[0]))

    team_a = {"id": "t-a", "slug": "ops", "name": "Ops", "role": "owner"}
    team_b = {"id": "t-b", "slug": "sec", "name": "Sec", "role": "member"}
    team_b_row = {
        "id": "sh-b",
        "name": "sec-web-1",
        "is_shared": True,
        "team_slug": "sec",
        "team_name": "Sec",
        "hostname": "198.51.100.20",
    }
    team_a_row = {
        "id": "sh-a",
        "name": "ops-web-1",
        "is_shared": True,
        "team_slug": "ops",
        "team_name": "Ops",
        "hostname": "198.51.100.10",
    }
    shared_pushed = [False]

    async def _list_shared(slug: str):
        if slug == "ops":
            return [team_a_row] if shared_pushed[0] else []
        return [team_b_row]

    async def _push_servers(_slug: str, srv_rows):
        shared_pushed[0] = True
        return [ShareResult(payload=srv_rows[0], status=SHARED)]

    team_svc = SimpleNamespace(
        list_teams=AsyncMock(return_value=[team_a, team_b]),
        list_shared_servers=AsyncMock(side_effect=_list_shared),
        push_servers=AsyncMock(side_effect=_push_servers),
    )
    app = _make_offline_app(
        tmp_path,
        instances=[{"id": "i-1", "name": "ops-web-1", "public_ip": "198.51.100.10", "region": "us-east-1"}],
        team_service=team_svc,
    )

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        # Cache hit within TTL avoids extra list_teams RPC, then expires after _TEAM_CACHE_TTL_SECONDS.
        manageable_1, teams_1 = await _team_share.resolve_manageable_teams(app, team_svc)
        manageable_2, _ = await _team_share.resolve_manageable_teams(app, team_svc)
        assert len(manageable_1) == 1 and len(manageable_2) == 1 and len(teams_1) == 2
        assert team_svc.list_teams.await_count == 1

        now[0] += _team_share._TEAM_CACHE_TTL_SECONDS + 1.0
        await _team_share.resolve_manageable_teams(app, team_svc)
        assert team_svc.list_teams.await_count == 2

        # share_server_with_team_flow reloads shared servers across ALL teams, preserving Team B's row.
        with patch.object(
            app,
            "push_screen_wait",
            AsyncMock(side_effect=lambda modal: getattr(modal, "_servers", [])),
        ):
            await _team_share.share_server_with_team_flow(
                app.screen, app.instances[0], team_svc
            )
        assert team_svc.push_servers.await_count == 1
        shared_ids = {r["id"] for r in app.instances if r.get("is_shared")}
        assert shared_ids == {"sh-a", "sh-b"}


@pytest.mark.asyncio
async def test_instance_list_quick_ssh_team_key_bastion_hop_and_bitwarden(tmp_path, monkeypatch) -> None:
    from servonaut.config.schema import ConnectionProfile
    from servonaut.screens import instance_list as il_mod
    from servonaut.services.ssh_credentials import VaultCredentialError
    from servonaut.services.ssh_ref_resolver import ResolvedSshRef

    instance = {
        "id": "i-app",
        "name": "app-1",
        "key_name": "ops-keypair",
        "public_ip": "198.51.100.50",
        "private_ip": "10.0.1.50",
        "username": "deploy",
        "port": 2222,
    }
    team_twin_row = {
        "id": "sh-app",
        "name": "app-1",
        "is_shared": True,
        "team_slug": "ops",
        "team_name": "Ops",
        "instance_id": "i-app",
        "hostname": "198.51.100.50",
        "credential_binding": {"source": "servonaut_vault"},
    }
    bastion_row = {"id": "i-jump", "name": "jump-1", "public_ip": "198.51.100.1"}
    profile = ConnectionProfile(name="via-jump", bastion_host="198.51.100.1", bastion_user="jump")

    app = _make_offline_app(tmp_path, instances=[instance, team_twin_row, bastion_row])
    base_conn = {
        "host": "10.0.1.50",
        "username": "rule-user",
        "key_path": "/keys/orig",
        "proxy_args": ["-J", "jump@198.51.100.1"],
        "port": 2222,
        "extra_options": ["-o", "ServerAliveInterval=30"],
        "profile": profile,
    }

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.pause()
        app.instances = [instance, team_twin_row, bastion_row]
        app._instances_pristine = [instance, team_twin_row, bastion_row]
        screen = app.screen
        assert isinstance(screen, InstanceListScreen)
        app.terminal_service = SimpleNamespace(launch_ssh_in_terminal=MagicMock(return_value=True), last_error=None)
        app.ssh_service = SimpleNamespace(build_ssh_command=MagicMock(return_value=["ssh", "target"]))

        # 1. Lost team key uses scrub_for_display (no NameError) cleanly.
        app.vault_command_service = SimpleNamespace(is_unlocked=True, take_lost_team_key=lambda _row: True, close=MagicMock())
        inst = dict(instance)
        with (
            patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(inst, None))),
            patch("servonaut.services.ssh_credentials.bastion_lease", AsyncMock(return_value=None)),
            patch("servonaut.services.ssh_credentials.bastion_hop_hint", return_value=None),
            patch.object(app, "notify") as notify_mock,
        ):
            await screen._launch_ssh(inst, inst, dict(base_conn))
        assert notify_mock.call_count >= 1
        assert any("team vault" in str(c.args[0]).lower() for c in notify_mock.call_args_list)

        # 2. Resolved None + locked vault triggers team_key_hint via scrub_for_display safely.
        app.vault_command_service = SimpleNamespace(is_unlocked=False, take_lost_team_key=lambda _row: False, close=MagicMock())
        resolver_none = SimpleNamespace(resolve=AsyncMock(return_value=None))
        inst = dict(instance)
        with (
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver", return_value=resolver_none),
            patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(inst, None))),
            patch("servonaut.services.ssh_credentials.bastion_lease", AsyncMock(return_value=None)),
            patch("servonaut.services.ssh_credentials.bastion_hop_hint", return_value=None),
            patch.object(app, "notify") as notify_mock,
        ):
            await screen._launch_ssh(inst, inst, dict(base_conn))
        assert any("Servonaut Vault identity" in str(c.args[0]) for c in notify_mock.call_args_list)

        # 3. Local-key path runs bastion_lease (allow_bastion=True) & catches VaultCredentialError cleanly.
        app.terminal_service.launch_ssh_in_terminal.reset_mock()
        app.vault_command_service = SimpleNamespace(is_unlocked=True, take_lost_team_key=lambda _row: False, close=MagicMock())
        resolver_local = SimpleNamespace(resolve=AsyncMock(return_value=ResolvedSshRef(source="local", local_key_path="/keys/local")))
        inst = dict(instance)
        with (
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver", return_value=resolver_local),
            patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(inst, ResolvedSshRef(source="local", local_key_path="/keys/local")))),
            patch("servonaut.services.ssh_credentials.bastion_lease", AsyncMock(side_effect=VaultCredentialError("untrusted jump key"))),
            patch.object(app, "notify") as notify_mock,
        ):
            await screen._launch_ssh(inst, inst, dict(base_conn))
        assert any("untrusted jump key" in str(c.args[0]) for c in notify_mock.call_args_list)
        app.terminal_service.launch_ssh_in_terminal.assert_not_called()

        # 4a. Local-key path with healthy bastion lease passes hop into connection proxy args.
        hop_sock = tmp_path / "hop.sock"
        hop_sock.touch()
        fake_hop = SimpleNamespace(
            source="vault",
            identity_agent=str(hop_sock),
            identity_file=str(tmp_path / "hop.pub"),
            certificate_path=None,
            known_hosts_path=str(tmp_path / "hop_kh"),
            login_user="jump",
            target_host="198.51.100.1",
            target_port=22,
            close=MagicMock(),
        )
        inst = dict(instance)
        with (
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver", return_value=resolver_local),
            patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(inst, ResolvedSshRef(source="local", local_key_path="/keys/local")))),
            patch("servonaut.services.ssh_credentials.bastion_lease", AsyncMock(return_value=fake_hop)) as bastion_mock,
            patch.object(app.connection_service, "get_proxy_args", wraps=app.connection_service.get_proxy_args) as proxy_spy,
            patch.object(screen, "_maybe_show_memory_prompt"),
            patch.object(screen, "_maybe_pull_annotations"),
        ):
            app.ssh_service.build_ssh_command.reset_mock()
            await screen._launch_ssh(inst, inst, dict(base_conn))
        bastion_mock.assert_awaited_once()
        assert proxy_spy.call_args.kwargs["hop"] is fake_hop
        assert any("ProxyCommand=" in a for a in app.ssh_service.build_ssh_command.call_args.kwargs["proxy_args"])

        # 4b. When bastion_lease returns None, bastion_hop_hint notifies cleanly via scrub_for_display.
        inst = dict(instance)
        with (
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver", return_value=resolver_local),
            patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(inst, ResolvedSshRef(source="local", local_key_path="/keys/local")))),
            patch("servonaut.services.ssh_credentials.bastion_lease", AsyncMock(return_value=None)),
            patch("servonaut.services.ssh_credentials.bastion_hop_hint", return_value="Unlock vault for jump host"),
            patch.object(screen, "_maybe_show_memory_prompt"),
            patch.object(screen, "_maybe_pull_annotations"),
            patch.object(app, "notify") as notify_mock,
        ):
            await screen._launch_ssh(inst, inst, dict(base_conn))
        assert any("Unlock vault for jump host" in str(c.args[0]) for c in notify_mock.call_args_list)

        # 5. Bitwarden path preserves proxy_args, extra_options, profile, and rule username while swapping key_path.
        bw_ref = ResolvedSshRef(source="personal", item_id="bw-item-1")
        inst = dict(instance)
        with (
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver", return_value=SimpleNamespace(resolve=AsyncMock(return_value=bw_ref))),
            patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(inst, bw_ref))),
            patch("servonaut.screens._vault_bind.resolve_bw_ssh_key_path", AsyncMock(return_value="/tmp/bw_key")),
            patch("servonaut.services.ssh_credentials.bastion_lease", AsyncMock(return_value=None)),
            patch("servonaut.services.ssh_credentials.bastion_hop_hint", return_value=None),
            patch.object(screen, "_maybe_show_memory_prompt"),
            patch.object(screen, "_maybe_pull_annotations"),
        ):
            app.ssh_service.build_ssh_command.reset_mock()
            await screen._launch_ssh(inst, inst, dict(base_conn))
        bw_call = app.ssh_service.build_ssh_command.call_args
        assert bw_call.kwargs["key_path"] == "/tmp/bw_key"
        assert bw_call.kwargs["username"] == "rule-user"
        assert bw_call.kwargs["proxy_args"] == ["-J", "jump@198.51.100.1"]
        assert bw_call.kwargs["extra_options"] == ["-o", "ServerAliveInterval=30"]


@pytest.mark.asyncio
async def test_windows_platform_skips_ssh_key_permission_checks(tmp_path, monkeypatch) -> None:
    from servonaut.screens import custom_servers as cs_mod
    from servonaut.screens import key_management as km_mod

    perm_mock = MagicMock(return_value=False)

    app = _make_offline_app(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        app.ssh_service = SimpleNamespace(
            list_available_keys=lambda: [("/keys/id_ed25519", "SSH Key")],
            check_key_permissions=perm_mock,
            set_key_path=lambda *_a, **_kw: None,
            get_key_path=lambda *_a, **_kw: None,
        )
        # Swap os binding only on the two screen modules so stdlib Path stays PosixPath on Linux.
        monkeypatch.setattr(km_mod, "os", SimpleNamespace(name="nt"))
        monkeypatch.setattr(cs_mod, "os", SimpleNamespace(name="nt"))
        km = KeyManagementScreen()
        await app.switch_screen(km)
        await pilot.pause()
        await pilot.pause()
        avail = km.query_one("#available_keys_table", DataTable)
        assert "insecure" not in str(avail.get_row_at(0)[0]).lower()

        cs = CustomServersScreen(open_add_form=True)
        await app.switch_screen(cs)
        await pilot.pause()
        await pilot.pause()
        select = cs.query_one("#select_custom_ssh_key", Select)
        assert select is not None
        assert perm_mock.call_count == 0


@pytest.mark.asyncio
async def test_add_server_modal_connect_provider_picks_first_unconfigured_panel(tmp_path) -> None:
    aws_only = _make_offline_app(tmp_path, aws_service=object())

    async with aws_only.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = aws_only.screen
        assert isinstance(screen, InstanceListScreen)
        with (
            patch("servonaut.widgets.sidebar.provider_ready", side_effect=lambda _app, p: p == "aws"),
            patch.object(aws_only, "open_settings_screen") as open_settings,
        ):
            screen.action_add_server()
            await pilot.pause()
            assert isinstance(aws_only.screen, AddServerModal)
            await pilot.click("#add_srv_connect_provider")
            await pilot.pause()
        open_settings.assert_called_once_with("hetzner")

        with (
            patch("servonaut.widgets.sidebar.provider_ready", side_effect=lambda _app, p: p in {"aws", "hetzner"}),
            patch.object(aws_only, "open_settings_screen") as open_settings,
        ):
            screen.action_add_server()
            await pilot.pause()
            assert isinstance(aws_only.screen, AddServerModal)
            await pilot.click("#add_srv_connect_provider")
            await pilot.pause()
        open_settings.assert_called_once_with("ovh")


@pytest.mark.asyncio
async def test_artifact_selftest_run_tui_passes_with_fleet_section_open(tmp_path) -> None:
    from dataclasses import replace
    from servonaut._artifact_selftest import _create_fixtures, _run_tui
    from servonaut.runtime import detect_runtime

    data_root = tmp_path / ".servonaut"
    config_path, _, _ = _create_fixtures(data_root)
    runtime = replace(detect_runtime(), data_root=data_root)
    result = await _run_tui(runtime, config_path)
    assert result == {"main": True, "sidebar": True, "adjacent": True, "exited": True}


@pytest.mark.asyncio
async def test_fleet_memory_tab_activation_drift_gate_resume_and_reload(tmp_path) -> None:
    from textual.widgets import TabbedContent
    from textual.widgets._tabbed_content import ContentTabs
    from servonaut.screens.fleet_memory import FleetMemoryScreen
    from servonaut.widgets.memory_panes import MemoryDriftPane, MemorySyncPane

    drift_svc = SimpleNamespace(
        list_drift=AsyncMock(return_value=[])
    )
    app = _make_offline_app(
        tmp_path,
        instances=[{"id": "i-1", "name": "web-1", "provider": "aws", "public_ip": "198.51.100.1"}],
        auth_service=SimpleNamespace(
            is_authenticated=True,
            has_feature=lambda f: f in {"memory_sync", "memory_drift", "memory_compliance_export"},
        ),
        memory_sync_service=SimpleNamespace(
            is_configured=True,
            is_enrolled_locally=lambda: True,
            get_key_material=lambda: b"key",
        ),
        drift_service=drift_svc,
    )

    async with app.run_test(size=(160, 50)) as pilot:
        screen = FleetMemoryScreen()
        await app.switch_screen(screen)
        await pilot.pause()
        await pilot.pause()

        # Theme restyle (_render_table) does NOT mark Drift loaded before activation.
        drift_pane = screen.query_one("#memory_drift_pane", MemoryDriftPane)
        drift_pane._render_table()
        assert drift_pane._loaded_once is False

        # Switching to Drift loads list_drift() exactly once (no double activation).
        screen.activate_tab("drift")
        await pilot.pause()
        await pilot.pause()
        assert drift_svc.list_drift.await_count == 1
        assert drift_pane._loaded_once is True

        # Navigation focus blocks drift_ack, drift_unack, refresh_view.
        sidebar = screen.query_one("Sidebar")
        sidebar.enter_navigation_mode()
        await pilot.pause()
        assert screen.navigation_focused is True
        assert screen.check_action("drift_ack", ()) is None
        assert screen.check_action("drift_unack", ()) is None
        assert screen.check_action("refresh_view", ()) is None
        with patch.object(drift_pane, "action_ack_selected") as ack_mock:
            await pilot.press("a")
            await pilot.pause()
        ack_mock.assert_not_called()
        sidebar.exit_navigation_mode()
        await pilot.pause()

        # Arrowing along ContentTabs keeps focus on the tab strip rather than jumping into content.
        tabs = screen.query_one("#memory_tabs", TabbedContent)
        strip = tabs.get_child_by_type(ContentTabs)
        strip.focus()
        await pilot.pause()
        await pilot.press("left")
        await pilot.pause()
        focused = screen.focused
        assert focused is strip or (focused is not None and strip in focused.ancestors)

        # Clicking the Drift tab with the mouse focuses #drift-table (does not get stuck on strip).
        await pilot.click("#--content-tab-mem_tab_drift")
        await pilot.pause()
        await pilot.pause()
        assert screen.focused is screen.query_one("#drift-table")

        # Single merged on_screen_resume refreshes both tab gates and MemorySyncPane state.
        sync_pane = screen.query_one("#memory_sync_pane", MemorySyncPane)
        with (
            patch.object(screen, "refresh_tab_gates") as gates_mock,
            patch.object(sync_pane, "refresh_state") as sync_mock,
        ):
            screen.on_screen_resume()
        gates_mock.assert_called_once()
        sync_mock.assert_called_once()

        # Returning from Sync tab to Fleet tab via nav_memory re-populates fleet rows.
        screen.activate_tab("sync")
        await pilot.pause()
        app.instances.append({"id": "i-2", "name": "edge-1", "provider": "aws", "public_ip": "198.51.100.2"})
        with patch.object(screen, "_launch_populate", wraps=screen._launch_populate) as pop_mock:
            app.on_sidebar_navigation_requested(Sidebar.NavigationRequested("nav_memory"))
            await pilot.pause()
            await pilot.pause()
        assert pop_mock.call_count >= 1
        fleet_table = screen.query_one("#fleet-memory-table", DataTable)
        names = [str(fleet_table.get_row_at(r)[0]) for r in range(fleet_table.row_count)]
        assert "edge-1" in names

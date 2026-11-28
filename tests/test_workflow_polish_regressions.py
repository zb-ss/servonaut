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

    # Auth-less launcher host preserves legacy visible launcher button contract.
    panel_no_auth = BackupsPanel()
    app_none = _PanelHost(panel_no_auth, with_auth=False)
    async with app_none.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert panel_no_auth.query_one("#backups_open_snapshots", Button).display is True

    # Entitled signed-in account shows the launcher.
    panel_ok = BackupsPanel()
    app_ok = _PanelHost(panel_ok, authenticated=True, features={"config_sync"}, with_auth=True)
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


def test_instance_list_gates_use_vault_key_when_unavailable_or_busy() -> None:
    screen = InstanceListScreen()
    screen._vault_binding = False
    mock_app = SimpleNamespace(vault_available=False, vault_command_service=None)
    with patch.object(InstanceListScreen, "app", new=property(lambda self: mock_app)):
        assert screen.check_action("use_vault_key", ()) is False
        mock_app.vault_available = True
        assert screen.check_action("use_vault_key", ()) is False
        mock_app.vault_command_service = object()
        assert screen.check_action("use_vault_key", ()) is True
        screen._vault_binding = True
        assert screen.check_action("use_vault_key", ()) is False


@pytest.mark.asyncio
async def test_servonaut_app_auth_lifecycle_refreshes_gates_and_caches() -> None:
    from servonaut.app import ServonautApp

    app = ServonautApp()
    app.vault_available = True
    app.vault_update_required = True
    app._personal_vault_bound_ids = {"i-1"}
    app._team_share_cache = [{"slug": "ops"}]
    sidebar = MagicMock(spec=Sidebar)
    mem_screen = MagicMock()
    mem_screen.query.return_value = [sidebar]

    with (
        patch.object(type(app), "screen_stack", new=property(lambda self: [mem_screen])),
        patch.object(app, "notify"),
    ):
        app._on_sign_in_ended()
    assert app.vault_available is False
    assert app.vault_update_required is False
    assert app._personal_vault_bound_ids == set()
    sidebar.refresh_auth_gates.assert_called_once()
    mem_screen.refresh_tab_gates.assert_called_once()

    app.auth_service = SimpleNamespace(fetch_entitlements=AsyncMock(return_value={}))
    with (
        patch.object(app, "_refresh_navigation_and_tab_gates") as refresh_mock,
        patch.object(type(app), "screen_stack", new=property(lambda self: [])),
    ):
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


def test_server_actions_mnemonic_bindings_and_mounted_no_key_jump() -> None:
    from servonaut.screens.server_actions import _WIDE_FOOTER_KEYS

    by_key = {b.key: b.action for b in ServerActionsScreen.BINDINGS}
    assert by_key["s"] == "action_3"
    assert by_key["c"] == "action_2"
    assert by_key["b"] == "action_1"
    assert by_key["t"] == "action_4"
    assert by_key["l"] == "action_6"
    assert by_key["w"] == "toggle_live"
    assert _WIDE_FOOTER_KEYS == ("l", "8")

    screen = object.__new__(ServerActionsScreen)
    screen._instance = {"id": "i-1", "name": "web-1", "public_ip": "1.1.1.1"}
    screen._vault_binding_source = None
    screen._busy = MagicMock()
    resolver = SimpleNamespace(resolve=AsyncMock(return_value=None))
    mock_app = SimpleNamespace(
        demo_mode=False,
        redaction_service=None,
        vault_available=True,
        vault_command_service=None,
        team_service=None,
        bw_ssh_config_service=None,
        instances=[],
        notify=MagicMock(),
        push_screen=MagicMock(),
    )
    with (
        patch.object(ServerActionsScreen, "app", new=property(lambda self: mock_app)),
        patch.object(ServerActionsScreen, "is_attached", new=property(lambda self: True)),
        patch.object(ServerActionsScreen, "is_mounted", new=property(lambda self: True)),
        patch.object(screen, "_ssh_ref_resolver", AsyncMock(return_value=resolver)),
        patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(screen._instance, None))),
        patch.object(screen, "_render_server_info"),
        patch.object(screen, "action_use_vault_key") as use_vault_mock,
    ):
        asyncio.run(screen._resolve_and_launch_ssh(MagicMock()))
    use_vault_mock.assert_called_once()

    mock_app.vault_available = False
    with (
        patch.object(ServerActionsScreen, "app", new=property(lambda self: mock_app)),
        patch.object(ServerActionsScreen, "is_attached", new=property(lambda self: True)),
        patch.object(ServerActionsScreen, "is_mounted", new=property(lambda self: True)),
        patch.object(screen, "_ssh_ref_resolver", AsyncMock(return_value=resolver)),
        patch("servonaut.services.ssh_ref_resolver.resolve_target", AsyncMock(return_value=(screen._instance, None))),
        patch.object(screen, "_render_server_info"),
    ):
        asyncio.run(screen._resolve_and_launch_ssh(MagicMock()))
    assert mock_app.push_screen.call_args.args[0].__class__ is KeyManagementScreen


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
async def test_vault_screen_refresh_after_ssh_import_sets_next_action() -> None:
    from contextlib import asynccontextmanager
    from servonaut.screens.vault import VaultScreen

    screen = object.__new__(VaultScreen)
    screen._vaults = []
    screen._table_mode = "vaults"
    screen._next_action = ""
    entered_busy = {"count": 0}

    @asynccontextmanager
    async def _busy(_msg: str):
        entered_busy["count"] += 1
        yield

    screen._busy = _busy
    screen._status = MagicMock()
    screen._render_vaults = MagicMock()
    table = MagicMock()
    svc = SimpleNamespace(list_vaults=AsyncMock(return_value=[{"vault_id": "v1", "label": "Personal"}]))
    screen._service = lambda: svc
    with patch.object(screen, "query_one", return_value=table):
        await screen._refresh_imported_vault_metadata("v1", 1, 0, [{"source": "ssh", "vault_item_id": "k1"}], 0)
    assert entered_busy["count"] == 1
    assert screen._next_action == "vault_bind_key"


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
        assert "(insecure perms: expected 0600)" in str(avail.get_row_at(0)[0])
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


def test_team_management_bind_guard_matching_own_row_and_share_all_prompt() -> None:
    screen = object.__new__(TeamManagementScreen)
    screen._binding_shared_key = False
    screen._current_team_slug = "ops"
    screen._server_busy = False
    shared_row = {"id": "s1", "name": "app-1", "hostname": "10.0.1.9"}
    own_row = {"id": "i-99", "name": "app-1", "public_ip": "10.0.1.9"}
    shared_on_fleet = {"id": "team:ops:s1", "is_shared": True, "team_slug": "ops", "name": "app-1", "hostname": "10.0.1.9"}
    mock_app = SimpleNamespace(
        demo_mode=True,
        redaction_service=object(),
        instances=[own_row, shared_on_fleet],
        _instances_pristine=[own_row, shared_on_fleet],
        notify=MagicMock(),
        run_worker=MagicMock(),
        push_screen=MagicMock(),
    )
    with (
        patch.object(TeamManagementScreen, "app", new=property(lambda self: mock_app)),
        patch("servonaut.screens.team_management.refuse_unresolved", return_value=True) as refuse_mock,
    ):
        screen._start_bind_row(shared_row)
    refuse_mock.assert_called_once()
    mock_app.run_worker.assert_not_called()

    # IP/host and unique-name fallback resolution on _matching_own_row
    with patch.object(TeamManagementScreen, "app", new=property(lambda self: mock_app)):
        assert screen._matching_own_row({"hostname": "10.0.1.9"})["id"] == "i-99"
        assert screen._matching_own_row({"hostname": "192.168.1.9", "name": "app-1"})["id"] == "i-99"

    # _offer_post_share_bind triggers _TeamBindPromptModal for newly shared unbound server.
    mock_app.demo_mode = False
    mock_app.vault_available = True
    mock_app.vault_command_service = object()
    mock_app.instances = [own_row, {**shared_on_fleet, "id": "s1"}]
    screen._shared_servers = [shared_row]
    screen._display_server_name = lambda n: str(n)
    with (
        patch.object(TeamManagementScreen, "app", new=property(lambda self: mock_app)),
        patch.object(TeamManagementScreen, "is_attached", new=property(lambda self: True)),
    ):
        mock_app.screen = screen
        screen._offer_post_share_bind("ops", "10.0.1.9", "app-1")
    assert isinstance(mock_app.push_screen.call_args.args[0], _TeamBindPromptModal)


def test_inspector_key_badges_and_vault_settings_keywords() -> None:
    screen = object.__new__(InstanceListScreen)
    shared_ca = {"id": "s1", "is_shared": True, "ssh_ca": {"enrolled": True}}
    shared_vault = {"id": "s2", "is_shared": True, "credential_binding": {"source": "servonaut_vault"}}
    shared_local = {"id": "s3", "is_shared": True}
    own_ca = {"id": "i-1", "ssh_ca": {"enrolled": True}}
    own_vault = {"id": "i-2"}
    own_twin_ca = {"id": "i-3", "name": "web-3", "public_ip": "10.0.1.3"}
    own_twin_vault = {"id": "i-4", "name": "web-4", "public_ip": "10.0.1.4"}
    own_twin_local = {"id": "i-5", "name": "web-5", "public_ip": "10.0.1.5"}

    mock_app = SimpleNamespace(
        demo_mode=False,
        _personal_vault_bound_ids={"i-2"},
        instances=[
            {"id": "t3", "is_shared": True, "instance_id": "i-3", "ssh_ca": {"enrolled": True}},
            {"id": "t4", "is_shared": True, "instance_id": "i-4", "credential_binding": {"source": "servonaut_vault"}},
            {"id": "t5", "is_shared": True, "instance_id": "i-5"},
        ],
    )
    with patch.object(InstanceListScreen, "app", new=property(lambda self: mock_app)):
        assert screen._inspector_key_badge(shared_ca).plain == "● SSH CA ready"
        assert screen._inspector_key_badge(shared_vault).plain == "● team key ready"
        assert screen._inspector_key_badge(shared_local).plain == "○ Shared · local key"
        assert screen._inspector_key_badge(own_ca).plain == "● SSH CA ready"
        assert screen._inspector_key_badge(own_vault).plain == "● vault key ready"
        assert screen._inspector_key_badge(own_twin_ca).plain == "● SSH CA (via team)"
        assert screen._inspector_key_badge(own_twin_vault).plain == "● team key ready"
        assert screen._inspector_key_badge(own_twin_local).plain == "○ Shared · local key"

    vault_spec = next((spec for spec in PANELS if spec.id == "vault"), None)
    assert vault_spec is not None
    assert "team" in vault_spec.keywords
    assert "team vault" in vault_spec.keywords


def test_memory_sync_pane_exposes_max_drain_batches() -> None:
    from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen
    from servonaut.widgets.memory_panes import MemorySyncPane

    pane = MemorySyncPane()
    assert pane._MAX_DRAIN_BATCHES == MemorySyncSetupScreen._MAX_DRAIN_BATCHES

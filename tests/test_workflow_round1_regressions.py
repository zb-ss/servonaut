"""Real-app and real-service regression tests for workflow IA fixes."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.widgets import Button, DataTable, Input, Static

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import (
    AppConfig,
    ConnectionProfile,
    ConnectionRule,
    CustomServer,
    DBProfile,
    ScanRule,
)
from servonaut.screens.custom_servers import CustomServersScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.scan_confirm import GlobalScanConfirmModal
from servonaut.screens.server_actions import ServerActionsScreen, TeamTargetModal
from servonaut.screens.settings import SettingsScreen
from servonaut.screens.settings.panels.scan import ScanPanel
from servonaut.screens.settings.widgets import StringListEditor
from servonaut.screens.team_management import TeamManagementScreen
from servonaut.services.auth_service import AuthService
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.keyword_store import KeywordStore
from servonaut.services.team_service import SHARED, ShareResult
from servonaut.services.team_sharing import SHARE_ADDRESS
from servonaut.widgets.instance_table import InstanceTable
from tests._async_bounds import wait_until


def _boot_offline_app(
    tmp_path: Path,
    *,
    config: AppConfig | None = None,
    cached_instances: list[dict] | None = None,
) -> ServonautApp:
    """Create a real ServonautApp pointing at *tmp_path* with no network side effects."""
    app = ServonautApp()
    cfg_path = tmp_path / "config.json"
    cm = ConfigManager(config_path=str(cfg_path))
    if config is not None:
        cm.save(config)
    app.config_manager = cm
    app.custom_server_service = CustomServerService(cm)
    app.keyword_store = KeywordStore(str(tmp_path / "keywords.json"))

    def _init_test_services() -> None:
        from servonaut.services.connection_service import ConnectionService
        from servonaut.services.ssh_service import SSHService

        app.config_manager = cm
        app.custom_server_service = CustomServerService(cm)
        app.connection_service = ConnectionService(cm)
        app.ssh_service = SSHService(cm)
        app.cache_service = SimpleNamespace(
            get_instances=lambda: list(cached_instances or []),
            is_fresh=lambda: True,
            is_cache_fresh=lambda: True,
            get_age=lambda: "1s",
        )
        app.aws_service = SimpleNamespace(
            get_cached_instances=lambda: list(cached_instances or []),
            is_cache_fresh=lambda: True,
        )
        app.ovh_service = None
        app.hetzner_service = None
        app.auth_service = AuthService()
        app.team_service = None
        app.vault_command_service = None
        app.config_sync_service = None
        app.memory_sync_service = None
        app.bw_ssh_config_service = None
        app.relay_manager = None
        app._apt_monitor = None

    app._init_services = _init_test_services  # type: ignore[method-assign]
    app._cached_fleet = lambda: list(cached_instances or [])  # type: ignore[method-assign]
    return app


@pytest.mark.asyncio
async def test_server_actions_share_with_team_updates_shared_fleet_handles_errors_and_gates_members(
    tmp_path: Path,
) -> None:
    cfg = AppConfig(
        connection_profiles=[
            ConnectionProfile(name="corp-bastion", bastion_host="jump.example.net")
        ],
        connection_rules=[
            ConnectionRule(
                name="priv-net",
                match_conditions={"name_contains": "app-"},
                profile_name="corp-bastion",
            )
        ],
    )
    own_row = {
        "id": "i-111",
        "name": "app-1",
        "state": "running",
        "public_ip": "1.1.1.1",
        "private_ip": "10.0.1.50",
        "provider": "AWS",
        "region": "us-east-1",
    }
    team = {"id": "t-1", "slug": "ops", "name": "Ops", "role": "owner"}
    pushed_payloads: list[list[dict]] = []
    shared_after_push = [
        {
            "id": "sh-1",
            "name": "app-1",
            "hostname": "10.0.1.50",
            "instance_id": "i-111",
            "region": "us-east-1",
        }
    ]
    team_svc = SimpleNamespace(
        list_teams=AsyncMock(return_value=[team]),
        list_shared_servers=AsyncMock(side_effect=[[], shared_after_push]),
        push_servers=AsyncMock(
            side_effect=lambda slug, rows: pushed_payloads.append(rows)
            or [ShareResult(payload=rows[0], status=SHARED)]
        ),
    )

    app = _boot_offline_app(tmp_path, config=cfg, cached_instances=[own_row])
    async with app.run_test(size=(160, 50)) as pilot:
        app.auth_service = SimpleNamespace(
            is_authenticated=True,
            has_feature=lambda f: f == "team_workspaces",
        )
        app.team_service = team_svc
        actions = ServerActionsScreen(dict(own_row))
        await app.push_screen(actions)
        await wait_until(
            lambda: actions.query_one("#btn_share_team", Button).display is True
        )

        # Successful share resolves bastion private IP and updates shared fleet without ImportError.
        with patch.object(
            app,
            "push_screen_wait",
            AsyncMock(side_effect=lambda modal: getattr(modal, "_servers", [])),
        ):
            await actions._share_with_team_flow(team_svc)

        assert pushed_payloads[0][0]["hostname"] == "10.0.1.50"
        assert any(
            row.get("is_shared") is True and row.get("name") == "app-1"
            for row in app.instances
        )

        # Second ServerActionsScreen with same team_service reuses cached team list (no extra list_teams call).
        calls_before_second = team_svc.list_teams.await_count
        second_actions = ServerActionsScreen(dict(own_row))
        await app.push_screen(second_actions)
        await wait_until(
            lambda: second_actions.query_one("#btn_share_team", Button).display is True
        )
        assert team_svc.list_teams.await_count == calls_before_second

        # Refresh failure after a successful push_servers still reports success (not share failure).
        refresh_fail_svc = SimpleNamespace(
            list_teams=AsyncMock(return_value=[team]),
            list_shared_servers=AsyncMock(return_value=[]),
            push_servers=AsyncMock(
                side_effect=lambda slug, rows: [ShareResult(payload=rows[0], status=SHARED)]
            ),
        )
        refresh_notes: list[tuple[str, str]] = []
        with (
            patch(
                "servonaut.services.shared_servers.load_shared_servers",
                AsyncMock(side_effect=RuntimeError("refresh timed out")),
            ),
            patch.object(
                app,
                "push_screen_wait",
                AsyncMock(side_effect=lambda modal: [{**own_row, SHARE_ADDRESS: "10.0.1.50"}]),
            ),
            patch.object(
                app,
                "notify",
                side_effect=lambda msg, severity="information", **_kw: refresh_notes.append(
                    (severity, msg)
                ),
            ),
        ):
            await second_actions._share_with_team_flow(refresh_fail_svc)
        assert any("Shared with team Ops." in msg and sev == "information" for sev, msg in refresh_notes)
        assert not any("Could not share server" in msg for _, msg in refresh_notes)

        # HTTP / API failure during push_servers notifies cleanly instead of crashing.
        failing_svc = SimpleNamespace(
            list_teams=AsyncMock(return_value=[team]),
            list_shared_servers=AsyncMock(return_value=[]),
            push_servers=AsyncMock(side_effect=RuntimeError("403 Forbidden")),
        )
        notifications: list[tuple[str, str]] = []
        with (
            patch.object(
                app,
                "push_screen_wait",
                AsyncMock(side_effect=lambda modal: [{**own_row, SHARE_ADDRESS: "10.0.1.50"}]),
            ),
            patch.object(
                app,
                "notify",
                side_effect=lambda msg, severity="information", **_kw: notifications.append(
                    (severity, msg)
                ),
            ),
        ):
            await actions._share_with_team_flow(failing_svc)
        assert any(sev == "error" and "403 Forbidden" in msg for sev, msg in notifications)

        # Plain member role hides Share with team button on mount.
        member_svc = SimpleNamespace(
            list_teams=AsyncMock(return_value=[{"id": "t-2", "slug": "ro", "role": "member"}])
        )
        app.team_service = member_svc
        member_actions = ServerActionsScreen(dict(own_row))
        await app.push_screen(member_actions)
        await pilot.pause()
        await member_actions.workers.wait_for_complete()
        assert not member_actions.query("#btn_share_team")


@pytest.mark.asyncio
async def test_team_target_modal_uses_share_heading(tmp_path: Path) -> None:
    app = _boot_offline_app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        modal = TeamTargetModal(
            [{"slug": "ops", "name": "Ops"}, {"slug": "eng", "name": "Eng"}]
        )
        await app.push_screen(modal)
        await pilot.pause()
        title = str(modal.query_one("#team_target_title", Static).render())
        assert "Share server with a team" in title
        assert "Bind vault key" not in title


@pytest.mark.asyncio
async def test_empty_fleet_cloud_settings_and_team_connections_open_real_settings_screen(
    tmp_path: Path,
) -> None:
    app = _boot_offline_app(tmp_path, cached_instances=[])
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        assert app.screen.query_one("#empty_fleet_card").display is True
        await pilot.click("#btn_empty_cloud_settings")
        await wait_until(
            lambda: isinstance(app.screen, SettingsScreen)
            and app.screen._active_id == "aws"
        )
        await pilot.pause()

        app.auth_service = SimpleNamespace(
            is_authenticated=True,
            has_feature=lambda f: f == "team_workspaces",
        )
        app.team_service = SimpleNamespace(
            list_teams=AsyncMock(return_value=[]),
        )
        teams = TeamManagementScreen()
        await app.push_screen(teams)
        await pilot.pause()
        teams._open_connection_settings()
        await wait_until(
            lambda: isinstance(app.screen, SettingsScreen)
            and app.screen._active_id == "connections"
            and bool(app.screen.query("#conn_profiles_table"))
        )
        await pilot.pause()


@pytest.mark.asyncio
async def test_custom_server_real_service_preserves_tags_refuses_dup_and_migrates_rename(
    tmp_path: Path,
) -> None:
    cfg = AppConfig(
        custom_servers=[
            CustomServer(name="srv-1", host="10.0.0.1"),
            CustomServer(name="srv-2", host="10.0.0.2"),
            CustomServer(
                name="srv-3",
                host="10.0.0.3",
                username="deploy",
                tags={"env": "prod", "tier": "web"},
            ),
        ],
        instance_keys={"custom-srv-3": "~/.ssh/prod_key"},
    )
    cfg.memory.per_server_overrides = {
        "custom-srv-3": {"memory_disabled": True},
        "srv-3": {"memory_disabled": True},
    }
    app = _boot_offline_app(tmp_path, config=cfg)
    app.keyword_store.save_results("custom-srv-3", [{"source": "path:~/", "content": "app.log"}])

    async with app.run_test(size=(160, 50)) as pilot:
        screen = CustomServersScreen()
        await app.push_screen(screen)
        await pilot.pause()

        # 1. Edit srv-3 without renaming -> tags survive on disk, cursor remains on srv-3.
        table = screen.query_one("#custom_servers_table", DataTable)
        table.move_cursor(row=2)
        await pilot.press("e")
        await pilot.pause()
        assert screen._editing_name == "srv-3"
        screen.query_one("#input_host", Input).value = "10.0.0.33"
        screen._save_server()
        await pilot.pause()

        reloaded = ConfigManager(config_path=str(tmp_path / "config.json")).get()
        srv3 = next(s for s in reloaded.custom_servers if s.name == "srv-3")
        assert srv3.host == "10.0.0.33"
        assert srv3.tags == {"env": "prod", "tier": "web"}
        assert table.cursor_row == 2

        # 2. Add with existing name srv-1 must be refused without overwriting.
        await pilot.press("n")
        await pilot.pause()
        assert screen._editing_name is None
        screen.query_one("#input_name", Input).value = "srv-1"
        screen.query_one("#input_host", Input).value = "192.0.2.99"
        screen._save_server()
        await pilot.pause()
        assert app.custom_server_service.get_server("srv-1").host == "10.0.0.1"

        # 3. Rename srv-3 -> srv-renamed keeps list order and migrates local state.
        await pilot.click("#btn_cancel_form")
        await pilot.pause()
        table.move_cursor(row=2)
        await pilot.press("e")
        await pilot.pause()
        screen.query_one("#input_name", Input).value = "srv-renamed"
        screen._save_server()
        await pilot.pause()

        reloaded = ConfigManager(config_path=str(tmp_path / "config.json")).get()
        assert [s.name for s in reloaded.custom_servers] == ["srv-1", "srv-2", "srv-renamed"]
        assert "custom-srv-3" not in reloaded.instance_keys
        assert reloaded.instance_keys["custom-srv-renamed"] == "~/.ssh/prod_key"
        assert "custom-srv-3" not in reloaded.memory.per_server_overrides
        assert "srv-3" not in reloaded.memory.per_server_overrides
        assert reloaded.memory.per_server_overrides["custom-srv-renamed"]["memory_disabled"] is True
        assert reloaded.memory.per_server_overrides["srv-renamed"]["memory_disabled"] is True
        assert app.keyword_store.get_results("custom-srv-3") == []
        assert app.keyword_store.get_results("custom-srv-renamed")[0]["content"] == "app.log"

        # 4. Rename with a matching ConnectionRule asks confirmation first.
        cfg_now = app.config_manager.get()
        cfg_now.connection_rules.append(
            ConnectionRule(
                name="exact-name",
                match_conditions={"name_contains": "srv-renamed"},
                profile_name="p1",
            )
        )
        app.config_manager.save(cfg_now)
        table.move_cursor(row=2)
        await pilot.press("e")
        await pilot.pause()
        screen.query_one("#input_name", Input).value = "srv-other"
        screen._save_server()
        await wait_until(
            lambda: app.screen.__class__.__name__ == "_CustomRenameConfirmModal"
            and bool(app.screen.query("#custom_rename_confirm"))
        )
        await pilot.pause()
        await pilot.click("#custom_rename_confirm")
        await wait_until(lambda: app.custom_server_service.get_server("srv-other") is not None)


@pytest.mark.asyncio
async def test_custom_server_share_holds_button_busy_and_ignores_duplicate_press(
    tmp_path: Path,
) -> None:
    cfg = AppConfig(custom_servers=[CustomServer(name="srv-1", host="10.0.0.1")])
    team = {"id": "t-1", "slug": "ops", "name": "Ops", "role": "owner"}
    release = asyncio.Event()
    calls = 0

    async def _slow_list_shared(_slug: str) -> list[dict]:
        nonlocal calls
        calls += 1
        await release.wait()
        return []

    app = _boot_offline_app(tmp_path, config=cfg)
    async with app.run_test(size=(160, 50)) as pilot:
        app.auth_service = SimpleNamespace(
            is_authenticated=True,
            has_feature=lambda f: f == "team_workspaces",
        )
        app.team_service = SimpleNamespace(
            list_teams=AsyncMock(return_value=[team]),
            list_shared_servers=_slow_list_shared,
        )
        screen = CustomServersScreen()
        await app.push_screen(screen)
        await pilot.pause()

        table = screen.query_one("#custom_servers_table", DataTable)
        table.move_cursor(row=0)
        await pilot.press("e")
        await pilot.pause()
        screen._save_server()
        await wait_until(lambda: screen.query_one("#btn_custom_share_team", Button).display is True)

        notifications: list[str] = []
        with (
            patch.object(app, "notify", side_effect=lambda msg, **_kw: notifications.append(msg)),
            patch.object(app, "push_screen_wait", AsyncMock(return_value=None)),
        ):
            screen._share_saved_server_team()
            await wait_until(lambda: screen.query_one("#btn_custom_share_team", Button).disabled is True)
            # Second trigger while busy warns instead of cancelling the active share worker.
            screen._share_saved_server_team()
            await pilot.pause()
            assert calls == 1
            assert any("still in progress" in m for m in notifications)
            release.set()
            await screen.workers.wait_for_complete()
        assert screen.query_one("#btn_custom_share_team", Button).disabled is False


@pytest.mark.asyncio
@pytest.mark.parametrize("delay_s", [0.0, 0.05])
async def test_instance_list_reloads_after_push_custom_server_and_empty_fresh_cache_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    delay_s: float,
) -> None:
    if delay_s > 0:
        orig_commit = CustomServersScreen._commit_save_server
        orig_sync = InstanceListScreen._sync_from_app_instances

        def _delayed_commit(self, editing_name, server) -> None:
            asyncio.get_running_loop().call_later(delay_s, orig_commit, self, editing_name, server)

        def _delayed_sync(self) -> None:
            asyncio.get_running_loop().call_later(delay_s, orig_sync, self)

        monkeypatch.setattr(CustomServersScreen, "_commit_save_server", _delayed_commit)
        monkeypatch.setattr(InstanceListScreen, "_sync_from_app_instances", _delayed_sync)

    app = _boot_offline_app(tmp_path, cached_instances=[])
    async with app.run_test(size=(160, 50)) as pilot:
        fleet = app.screen
        assert isinstance(fleet, InstanceListScreen)
        await wait_until(
            lambda: fleet.query_one("#empty_fleet_card").display is True
            and fleet.query_one("#btn_empty_add_custom", Button).region.width > 0
        )

        await pilot.click("#btn_empty_add_custom")
        await wait_until(
            lambda: isinstance(app.screen, CustomServersScreen)
            and app.screen.query_one("#add_form").display is True
            and not app.screen.query_one("#btn_save_server", Button).disabled
            and app.screen.query_one("#btn_save_server", Button).region.width > 0
        )
        custom_screen = app.screen
        custom_screen.query_one("#input_name", Input).value = "web-added"
        custom_screen.query_one("#input_host", Input).value = "10.0.1.9"
        await pilot.click("#btn_save_server")
        await wait_until(lambda: custom_screen.query_one("#custom_post_save_row").display is True)

        await pilot.press("escape")
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        await wait_until(lambda: fleet.query_one(InstanceTable).row_count == 1)
        assert fleet.query_one("#empty_fleet_card").display is False
        table = fleet.query_one(InstanceTable)
        assert "web-added" in str(table.get_row_at(0)[1])


@pytest.mark.asyncio
async def test_command_palette_gates_teams_and_sync_config_with_sidebar(
    tmp_path: Path,
) -> None:
    app = _boot_offline_app(tmp_path, cached_instances=[])
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        # Signed out
        titles_signed_out = {c.title for c in app.get_system_commands(app.screen)}
        assert "Go to Teams" not in titles_signed_out
        assert "Go to Sync config" not in titles_signed_out

        # Free user (authenticated, no paid features)
        app.auth_service = SimpleNamespace(
            is_authenticated=True, has_feature=lambda _f: False
        )
        app.config_sync_service = object()
        titles_free = {c.title for c in app.get_system_commands(app.screen)}
        assert "Go to Teams" not in titles_free
        assert "Go to Sync config" not in titles_free

        # Entitled user
        app.auth_service = SimpleNamespace(
            is_authenticated=True, has_feature=lambda _f: True
        )
        titles_entitled = {c.title for c in app.get_system_commands(app.screen)}
        assert "Go to Teams" in titles_entitled
        assert "Go to Sync config" in titles_entitled


@pytest.mark.asyncio
async def test_global_scan_confirms_server_count_uses_own_group_and_blocks_dirty_panel(
    tmp_path: Path,
) -> None:
    instances = [
        {"id": "i-1", "name": "web-1", "state": "running", "public_ip": "1.1.1.1"},
        {"id": "i-2", "name": "web-2", "state": "running", "public_ip": "8.8.8.8"},
        {"id": "i-3", "name": "db-off", "state": "stopped", "public_ip": "9.9.9.9"},
    ]
    app = _boot_offline_app(tmp_path, cached_instances=instances)
    app.scan_service = SimpleNamespace(scan_server=AsyncMock(return_value=[]))

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        release = asyncio.Event()

        async def _relay_bg() -> None:
            await release.wait()

        relay_worker = app.run_worker(_relay_bg(), name="relay_start", exclusive=True)
        try:
            app._run_global_scan()
            await wait_until(
                lambda: isinstance(app.screen, GlobalScanConfirmModal)
                and bool(app.screen.query("#scan_confirm_text"))
            )
            await pilot.pause()
            text = str(app.screen.query_one("#scan_confirm_text", Static).render())
            assert "2 servers" in text

            # Cancelling must not call scan_server.
            await pilot.click("#scan_confirm_cancel")
            await wait_until(lambda: not isinstance(app.screen, GlobalScanConfirmModal))
            app.scan_service.scan_server.assert_not_called()

            # Confirming runs global scan in group="global_scan" and leaves relay worker running.
            app._run_global_scan()
            await wait_until(
                lambda: isinstance(app.screen, GlobalScanConfirmModal)
                and bool(app.screen.query("#scan_confirm_run"))
            )
            await pilot.pause()
            await pilot.click("#scan_confirm_run")
            await wait_until(lambda: app.scan_service.scan_server.await_count == 2)
            assert not relay_worker.is_cancelled
        finally:
            release.set()
            await relay_worker.wait()

        # Dirty ScanPanel refuses scanning until changes are saved.
        app.open_settings_screen("scan")
        await wait_until(
            lambda: isinstance(app.screen, SettingsScreen)
            and bool(app.screen.query(ScanPanel))
            and bool(app.screen.query("#scan_default_paths_editor"))
        )
        await pilot.pause()
        panel = app.screen.query_one(ScanPanel)
        panel.query_one("#scan_default_paths_editor", StringListEditor).set_values(["~/changed"])
        await pilot.pause()
        assert panel.is_dirty() is True
        notifications: list[str] = []
        with patch.object(panel, "notify", side_effect=lambda msg, **_kw: notifications.append(msg)):
            await pilot.click("#btn_scan_run_global")
            await pilot.pause()
        assert not isinstance(app.screen, GlobalScanConfirmModal)
        assert any("Save your scan rule changes" in m for m in notifications)

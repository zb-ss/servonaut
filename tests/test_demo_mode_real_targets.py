"""Demo mode changes what is drawn, never what is sent.

Rows carry demo-mode stand-ins while demo mode is on. Every provider call,
probe or ban made from a row must still name the real server; only the text
on screen (titles, confirmations, notifications) shows the stand-in.
"""
from __future__ import annotations

import asyncio
import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from rich.text import Text

from servonaut.app import ServonautApp
from servonaut.services.redaction_service import RedactionService

VPS = {
    "id": "vps-acme01.vps.ovh.net",
    "name": "acme-mail",
    "public_ip": "9.9.9.9",
    "is_ovh": True,
    "provider_type": "vps",
    "provider": "ovh",
}


def _demo_app(row: dict, *, demo: bool = True, **services):
    """A stand-in app whose row is redacted in place, as the real app does."""
    shown = copy.deepcopy(row)
    redaction = RedactionService()
    if demo:
        redaction.redact_instance(shown)
        assert shown["id"] != row["id"] and shown["public_ip"] != row["public_ip"]
    app = SimpleNamespace(
        demo_mode=demo,
        redaction_service=redaction if demo else None,
        _instances_pristine=[copy.deepcopy(row)],
        instances=[shown],
        ovh_audit=MagicMock(),
        push_screen_wait=AsyncMock(return_value=True),
        **services,
    )
    app.real_instance_id = lambda value: ServonautApp.real_instance_id(app, value)
    app.connection_instance = lambda r: ServonautApp.connection_instance(app, r)
    return app, shown


def _plain(markup: str) -> str:
    return Text.from_markup(markup).plain


# ---------------------------------------------------------------------------
# OVH VPS actions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("demo", [True, False])
def test_reinstall_targets_the_real_vps_and_shows_the_row(demo: bool) -> None:
    from servonaut.screens.ovh_reinstall import OVHReinstallScreen

    vps = SimpleNamespace(
        list_images=AsyncMock(return_value=[{"id": "img-1", "name": "debian-12"}]),
        reinstall=AsyncMock(),
    )
    app, shown = _demo_app(VPS, demo=demo, ovh_vps_service=vps)
    screen = OVHReinstallScreen(shown)
    table = MagicMock(cursor_row=0)
    with (
        patch.object(OVHReinstallScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=table),
        patch.object(screen, "notify") as notify,
        patch("servonaut.screens.confirm_action.ConfirmActionScreen") as confirm,
    ):
        asyncio.run(screen._load_images())
        asyncio.run(screen._on_reinstall())

    vps.list_images.assert_awaited_once_with(VPS["id"])
    vps.reinstall.assert_awaited_once_with(VPS["id"], "img-1")
    assert app.ovh_audit.log_action.call_args.kwargs["target"] == VPS["id"]
    confirmation = confirm.call_args.kwargs
    assert shown["name"] in confirmation["description"]
    if demo:
        for real in (VPS["id"], VPS["name"]):
            assert real not in confirmation["description"]
            assert real not in str(notify.call_args_list)


@pytest.mark.parametrize("demo", [True, False])
def test_resize_targets_the_real_vps(demo: bool) -> None:
    from servonaut.screens.ovh_resize import OVHResizeScreen

    vps = SimpleNamespace(
        list_upgrade_models=AsyncMock(return_value=[{"name": "vps-comfort"}]),
        upgrade=AsyncMock(),
    )
    app, shown = _demo_app(VPS, demo=demo, ovh_vps_service=vps)
    screen = OVHResizeScreen(shown)
    with (
        patch.object(OVHResizeScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=MagicMock(cursor_row=0)),
        patch.object(screen, "notify"),
        patch("servonaut.screens.confirm_action.ConfirmActionScreen") as confirm,
    ):
        asyncio.run(screen._load_models())
        asyncio.run(screen._on_upgrade())

    vps.list_upgrade_models.assert_awaited_once_with(VPS["id"])
    vps.upgrade.assert_awaited_once_with(VPS["id"], "vps-comfort")
    if demo:
        assert VPS["name"] not in confirm.call_args.kwargs["description"]


@pytest.mark.parametrize("demo", [True, False])
def test_firewall_manages_the_real_address_and_shows_the_row(demo: bool) -> None:
    from servonaut.screens.ovh_firewall import OVHFirewallScreen

    ip_service = SimpleNamespace(
        get_firewall=AsyncMock(return_value={"enabled": False}),
        list_firewall_rules=AsyncMock(return_value=[]),
        toggle_firewall=AsyncMock(),
    )
    app, shown = _demo_app(VPS, demo=demo, ovh_ip_service=ip_service)
    screen = OVHFirewallScreen(shown)
    queued = []
    with (
        patch.object(OVHFirewallScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=MagicMock()),
        patch.object(screen, "run_worker", side_effect=lambda coro, **kw: queued.append(coro)),
        patch.object(screen, "notify") as notify,
        patch("servonaut.screens.confirm_action.ConfirmActionScreen") as confirm,
    ):
        screen.on_mount()
        for coro in queued:
            asyncio.run(coro)
        queued.clear()
        asyncio.run(screen._on_toggle_firewall())
        for coro in queued:
            asyncio.run(coro)

    ip_service.get_firewall.assert_awaited_once_with(VPS["public_ip"])
    ip_service.list_firewall_rules.assert_awaited_once_with(VPS["public_ip"])
    ip_service.toggle_firewall.assert_awaited_once_with(VPS["public_ip"], True)
    description = confirm.call_args.kwargs["description"]
    assert shown["public_ip"] in description
    if demo:
        assert VPS["public_ip"] not in description
        assert VPS["public_ip"] not in str(notify.call_args_list)


@pytest.mark.parametrize("demo", [True, False])
def test_snapshot_create_and_backup_target_the_real_vps(demo: bool) -> None:
    from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen

    snapshots = SimpleNamespace(
        create_vps_snapshot=AsyncMock(),
        configure_vps_backup=AsyncMock(),
    )
    app, shown = _demo_app(VPS, demo=demo, ovh_snapshot_service=snapshots)
    screen = OVHSnapshotsScreen(shown)
    queued = []
    with (
        patch.object(OVHSnapshotsScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=MagicMock()),
        patch.object(screen, "run_worker", side_effect=lambda coro, **kw: queued.append(coro)),
        patch.object(screen, "notify"),
        patch.object(screen, "_load_vps_snapshots", new_callable=AsyncMock),
        patch.object(screen, "_load_vps_backup_status", new_callable=AsyncMock),
    ):
        asyncio.run(screen._on_create_snapshot())
        asyncio.run(screen._on_configure_backup())
        for coro in queued:
            asyncio.run(coro)

    snapshots.create_vps_snapshot.assert_awaited_once()
    assert snapshots.create_vps_snapshot.await_args.args[0] == VPS["id"]
    assert snapshots.configure_vps_backup.await_args.args[0] == VPS["id"]


def test_cloud_snapshot_is_named_after_the_real_instance() -> None:
    from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen

    cloud = {
        "id": "0acme000000000000000000000000001/987654321",
        "name": "acme-batch",
        "public_ip": "149.112.112.112",
        "is_ovh": True,
        "provider_type": "cloud",
    }
    snapshots = SimpleNamespace(create_cloud_snapshot=AsyncMock())
    app, shown = _demo_app(cloud, ovh_snapshot_service=snapshots)
    screen = OVHSnapshotsScreen(shown)
    queued = []
    with (
        patch.object(OVHSnapshotsScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=MagicMock()),
        patch.object(screen, "run_worker", side_effect=lambda coro, **kw: queued.append(coro)),
        patch.object(screen, "notify") as notify,
        patch.object(screen, "_load_cloud_snapshots", new_callable=AsyncMock),
    ):
        asyncio.run(screen._on_create_snapshot())
        for coro in queued:
            asyncio.run(coro)

    project, instance = cloud["id"].split("/")
    snapshots.create_cloud_snapshot.assert_awaited_once_with(
        project, instance, "acme-batch-snapshot"
    )
    assert "acme-batch" not in str(notify.call_args_list)


# ---------------------------------------------------------------------------
# Server actions screen (OVH, Hetzner and AWS rows)
# ---------------------------------------------------------------------------

HETZNER = {
    "id": "48151623", "name": "acme-cache", "public_ip": "1.1.1.1",
    "is_hetzner": True, "provider": "hetzner", "state": "running",
}
AWS = {
    "id": "i-0acme00000000001", "name": "acme-app", "public_ip": "8.8.8.8",
    "private_ip": "172.31.5.6", "provider": "aws", "state": "running",
}


@pytest.mark.parametrize("row", [VPS, HETZNER, AWS], ids=["ovh", "hetzner", "aws"])
def test_ban_ip_prefills_the_shown_address_and_bans_the_real_one(row: dict) -> None:
    from servonaut.screens.ip_ban import IPBanScreen
    from servonaut.screens.server_actions import ServerActionsScreen

    app, shown = _demo_app(row)
    app.push_screen = MagicMock()
    screen = ServerActionsScreen(shown)
    with patch.object(ServerActionsScreen, "app", new_callable=PropertyMock, return_value=app):
        screen.action_action_8()
    ban_screen = app.push_screen.call_args.args[0]
    assert isinstance(ban_screen, IPBanScreen)
    assert ban_screen._prefill_ip == shown["public_ip"]

    field = MagicMock(value=shown["public_ip"])
    with (
        patch.object(IPBanScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(ban_screen, "query_one", return_value=field),
    ):
        assert ban_screen._input_ip() == row["public_ip"]
        field.value = "9.9.9.9"  # typed by the user: taken as typed
        assert ban_screen._input_ip() == "9.9.9.9"


@pytest.mark.parametrize("row", [VPS, HETZNER, AWS], ids=["ovh", "hetzner", "aws"])
def test_memory_screen_probes_and_reads_the_real_server(row: dict) -> None:
    from servonaut.screens.memory import MemoryScreen

    memory = MagicMock()
    memory.refresh = AsyncMock()
    memory.is_memory_disabled.return_value = False
    app, shown = _demo_app(row, memory_service=memory)
    app.notify = MagicMock()
    screen = MemoryScreen(shown)
    with (
        patch.object(MemoryScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_render_table"),
    ):
        asyncio.run(screen._do_refresh_all())
    probed = memory.refresh.await_args.args[0]
    assert probed["id"] == row["id"]
    assert probed["public_ip"] == row["public_ip"]
    assert screen._instance is shown, "the screen keeps drawing the shown row"


def test_findings_are_scoped_to_the_real_instance() -> None:
    from servonaut.screens.findings import FindingsScreen

    app, shown = _demo_app(AWS)
    screen = FindingsScreen(instance=shown)
    with patch.object(FindingsScreen, "app", new_callable=PropertyMock, return_value=app):
        assert screen._instance_id == AWS["id"]


def test_server_info_resolves_connection_rules_on_the_real_row() -> None:
    from servonaut.screens.server_actions import ServerActionsScreen

    app, shown = _demo_app(AWS)
    profile = SimpleNamespace(bastion_host="bastion.acme-corp.example")
    app.connection_service = MagicMock()
    app.connection_service.resolve_profile.return_value = profile
    screen = ServerActionsScreen(shown)
    with patch.object(ServerActionsScreen, "app", new_callable=PropertyMock, return_value=app):
        info = _plain(screen._build_server_info())
    matched = app.connection_service.resolve_profile.call_args.args[0]
    assert matched["name"] == AWS["name"]
    for real in AWS["name"], AWS["id"], AWS["public_ip"], "bastion.acme-corp.example":
        assert real not in info


# ---------------------------------------------------------------------------
# Provider manager screens
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module", "cls", "service_attr", "row"),
    [
        ("servonaut.screens.hetzner_manager", "HetznerManagerScreen", "hetzner_service", HETZNER),
        ("servonaut.screens.ovh_manager", "OVHManagerScreen", "ovh_service", VPS),
        ("servonaut.screens.aws_manager", "AWSManagerScreen", "aws_service", AWS),
    ],
    ids=["hetzner", "ovh", "aws"],
)
def test_manager_rows_follow_the_toggle_and_act_on_real_ids(
    module: str, cls: str, service_attr: str, row: dict,
) -> None:
    import importlib

    screen_cls = getattr(importlib.import_module(module), cls)
    cached = [copy.deepcopy(row)]
    service = SimpleNamespace(
        fetch_instances_cached=AsyncMock(return_value=cached),
        check_credentials=AsyncMock(return_value=None),
    )
    app = SimpleNamespace(demo_mode=False, redaction_service=None, **{service_attr: service})
    screen = screen_cls()
    with (
        patch.object(screen_cls, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_render_table") as render,
        patch.object(screen, "_set_status"),
    ):
        asyncio.run(screen._load_instances())
        assert screen._instances[0]["name"] == row["name"]

        app.demo_mode, app.redaction_service = True, RedactionService()
        screen.refresh_after_demo_toggle()
        shown = screen._instances[0]
        assert shown["name"] != row["name"] and shown["id"] != row["id"]
        assert screen._api_id(shown) == row["id"]
        assert cached[0] == row, "the provider's cached rows must stay real"

        app.demo_mode, app.redaction_service = False, None
        screen.refresh_after_demo_toggle()
        assert screen._instances[0]["name"] == row["name"]
        assert render.call_count == 3


@pytest.mark.parametrize("demo", [True, False])
def test_cloudwatch_ban_prefills_the_shown_address_and_bans_the_real_one(demo: bool) -> None:
    from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen

    app = SimpleNamespace(
        demo_mode=demo, redaction_service=RedactionService() if demo else None,
        push_screen=MagicMock(), notify=MagicMock(),
    )
    screen = CloudWatchBrowserScreen.__new__(CloudWatchBrowserScreen)
    screen._top_ips = [{"ip": "9.9.9.9", "count": 3}]
    screen._selected_ip_row = 0
    with patch.object(CloudWatchBrowserScreen, "app", new_callable=PropertyMock, return_value=app):
        screen.action_ban_ip()
    ban = app.push_screen.call_args.args[0]
    assert ban._prefill_real_ip == "9.9.9.9"
    assert (ban._prefill_ip != "9.9.9.9") is demo


@pytest.mark.asyncio
async def test_manager_redraw_keeps_the_cursor_on_the_same_server() -> None:
    from textual.app import App
    from textual.widgets import DataTable, Static

    from servonaut.screens.hetzner_manager import HetznerManagerScreen

    rows = [dict(HETZNER, id=str(48151620 + n), name=f"acme-{n}") for n in range(4)]

    class Host(App):
        demo_mode = False
        redaction_service = None

        def __init__(self) -> None:
            super().__init__()
            self.hetzner_service = SimpleNamespace(
                fetch_instances_cached=AsyncMock(return_value=rows),
            )

        def on_mount(self) -> None:
            self.push_screen(HetznerManagerScreen())

    app = Host()
    with patch("servonaut.screens.hetzner_manager.Sidebar", side_effect=lambda: Static()):
        async with app.run_test(size=(160, 40)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            screen = app.screen
            table = screen.query_one(DataTable)
            table.move_cursor(row=2)
            app.demo_mode, app.redaction_service = True, RedactionService()
            screen.refresh_after_demo_toggle()
            await pilot.pause()
            assert table.cursor_row == 2
            assert screen._api_id(screen._selected_instance()) == rows[2]["id"]


def test_actions_on_a_row_with_no_real_record_are_refused() -> None:
    """An unknown stand-in is never sent to a provider, SSH or a store."""
    from servonaut.screens.server_actions import ServerActionsScreen

    app, shown = _demo_app(VPS)
    app._instances_pristine = []  # nothing real behind the row
    app.has_real_record = lambda row: ServonautApp.has_real_record(app, row)
    app.push_screen = MagicMock()
    app.notify = MagicMock()
    app.run_worker = MagicMock()
    screen = ServerActionsScreen(shown)
    with (
        patch.object(ServerActionsScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "run_worker") as run_worker,
    ):
        for action in (
            screen.action_action_8, screen.action_open_memory, screen.action_open_findings,
            screen.action_scan_db_creds, screen.action_verify_ssh,
            screen.action_manage_ssh_ref,
        ):
            action()
        assert screen._validate_instance_connection() is False
        screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn_ovh_reinstall")))
    app.push_screen.assert_not_called()
    run_worker.assert_not_called()
    messages = [call.args[0] for call in app.notify.call_args_list]
    assert messages and all("ctrl+shift+d" in m for m in messages)

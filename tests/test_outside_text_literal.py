"""Names from a teammate, a server or an AWS caller are drawn literally.

Each test puts an outside name where the screen reads it, with the parser
backstop uninstalled, and checks the three things a safe screen does: the name
is on screen as typed, nothing on screen carries an action or a link, and a
name that is not valid markup does not stop the screen from drawing.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import DataTable, OptionList, Select, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, CustomServer
from tests._literal_probe import (  # noqa: F401 - no_backstop is a fixture
    PAYLOADS, assert_literal, clickable_cells, no_backstop, screen_text,
)

KINDS = list(PAYLOADS)


class _Host(App):
    """The attributes the screens read from the real app, with the real stylesheet."""

    CSS_PATH = ServonautApp.CSS_PATH
    demo_mode = False
    redaction_service = None

    def __init__(self, screen_factory, **attrs) -> None:
        super().__init__()
        self._factory = screen_factory
        self.instances = []
        config = AppConfig()
        self.config_manager = SimpleNamespace(get=lambda: config)
        for key, value in attrs.items():
            setattr(self, key, value)

    def action_ran(self) -> None:
        raise AssertionError("an action named by outside text must not run")

    def on_mount(self) -> None:
        self.push_screen(self._factory())


async def _settle(pilot, rounds: int = 20) -> None:
    for _ in range(rounds):
        await pilot.pause(0.05)


# ---------------------------------------------------------------------------
# Team management, log picker, log viewer, custom servers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_team_management_tables(no_backstop, kind) -> None:  # noqa: F811
    from servonaut.screens.team_management import TeamManagementScreen

    payload = PAYLOADS[kind]
    team_service = MagicMock()
    team_service.list_teams = AsyncMock(return_value=[
        {"slug": "eng", "name": payload, "role": "admin", "member_count": 3},
    ])
    auth = MagicMock()
    auth.is_authenticated = True
    app = _Host(TeamManagementScreen, auth_service=auth, team_service=team_service)
    async with app.run_test(size=(160, 48)) as pilot:
        await _settle(pilot, 30)
        assert_literal(app, payload)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_log_picker_options(no_backstop, kind) -> None:  # noqa: F811
    from servonaut.screens.log_picker import LogPickerModal

    payload = PAYLOADS[kind]
    paths = {
        "available": f"/var/log/{payload}.log",
        "custom": f"/srv/{payload}/app.log",
        "discovered": f"/var/log/app/{payload}.log.1",
    }
    service = SimpleNamespace(get_custom_paths=lambda _instance_id: [paths["custom"]])
    app = _Host(lambda: LogPickerModal(
        available_logs=[paths["available"]],
        discovered_logs=[paths["discovered"]],
        current_log=paths["available"],
        classify_fn=lambda path: "rotated",
        instance={"id": "i-1"},
        log_viewer_service=service,
    ))
    async with app.run_test(size=(160, 48)) as pilot:
        await _settle(pilot)
        assert clickable_cells(app) == []
        text = screen_text(app)
        for path in paths.values():
            assert path in text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_log_viewer_header(no_backstop, kind) -> None:  # noqa: F811
    from servonaut.screens.log_viewer import LogViewerScreen

    payload = PAYLOADS[kind]
    screen = LogViewerScreen({"id": "i-1", "name": payload})
    screen._current_log = f"/var/log/{payload}.log"
    service = SimpleNamespace(
        classify_log_file=lambda path: "active", last_probe_source=None, last_probe_probed_at=None,
        probe_log_paths=AsyncMock(return_value=[]),
        scan_log_directories=AsyncMock(return_value=[]),
    )
    app = _Host(lambda: screen, log_viewer_service=service)
    async with app.run_test(size=(160, 48)) as pilot:
        await _settle(pilot)
        screen._update_header()
        await pilot.pause()
        header = str(screen.query_one("#log_header", Static).render())
        assert payload in header
        assert f"/var/log/{payload}.log" in header
        assert clickable_cells(app) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_custom_servers_table(no_backstop, kind) -> None:  # noqa: F811
    from servonaut.screens.custom_servers import CustomServersScreen

    payload = PAYLOADS[kind]
    server = CustomServer(name=payload, host="web.example.net", username="deploy", port=22)
    service = SimpleNamespace(list_servers=lambda: [server], to_instance_dict=lambda s: {})
    app = _Host(CustomServersScreen, custom_server_service=service)
    async with app.run_test(size=(160, 48)) as pilot:
        await _settle(pilot)
        assert_literal(app, payload)


# ---------------------------------------------------------------------------
# CloudTrail: the caller chooses the user agent, user name and resource name
# ---------------------------------------------------------------------------

def _cloudtrail_event(payload: str) -> dict:
    raw = json.dumps({
        "eventName": "DescribeInstances", "userAgent": payload,
        "errorCode": "AccessDenied", "sourceIPAddress": "9.9.9.9",
    }, indent=2)
    return {
        "event_time": "2026-11-09 08:00:00", "event_name": "DescribeInstances",
        "username": payload, "source_ip": "9.9.9.9", "resource_type": "AWS::EC2::Instance",
        "resource_name": payload, "region": "eu-west-1", "error_code": "AccessDenied",
        "raw_event": raw,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_cloudtrail_table_pickers_and_detail(no_backstop, kind) -> None:  # noqa: F811
    from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
    from servonaut.services.cloudtrail_service import LookupPage

    payload = PAYLOADS[kind]
    event = _cloudtrail_event(payload)
    service = MagicMock()
    service.lookup_page = AsyncMock(return_value=LookupPage(events=[event], next_token=None))
    app = _Host(CloudTrailBrowserScreen, cloudtrail_service=service)
    async with app.run_test(size=(180, 48)) as pilot:
        await _settle(pilot)
        screen = app.screen
        screen.action_fetch()
        for _ in range(60):
            await pilot.pause(0.05)
            if screen._events:
                break
        await _settle(pilot, 5)
        # The column is as wide as the table allows: compare the cells themselves.
        cells = [str(cell) for cell in screen.query_one("#cloudtrail_table", DataTable).get_row_at(0)]
        assert payload in cells
        assert clickable_cells(app) == []

        screen._show_event_detail(event)
        screen.query_one("#event_detail").scroll_end(animate=False)
        await _settle(pilot, 5)
        assert clickable_cells(app) == []
        assert payload in str(screen.query_one("#event_detail_text", Static).render())

        picker = screen.query_one("#ct_select_username", Select)
        picker.value = payload
        await _settle(pilot, 5)
        assert clickable_cells(app) == []
        assert payload in screen_text(app)


# ---------------------------------------------------------------------------
# Memory: values observed on a server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_memory_observed_values(no_backstop, kind, tmp_path) -> None:  # noqa: F811
    from tests.test_memory_screen_shared import SHARED_ROW, _host, _reader

    payload = PAYLOADS[kind]
    row = {"id": "web-1", "name": "web-1", "state": "running", "public_ip": "9.9.9.9", "username": "deploy"}
    app = _host(tmp_path, row, _reader(None))
    app.CSS_PATH = ServonautApp.CSS_PATH
    app.memory_service._store.save_module("web-1", "os", {
        "module": "os", "instance_id": "web-1", "observed": {payload: payload},
        "declared": {}, "probed_at": datetime.now(tz=timezone.utc).isoformat(),
        "ttl_seconds": 86400, "sudo_used": False, "truncated": False, "partial": False,
        "raw_output": "",
    }, provider="aws")
    async with app.run_test(headless=True, size=(160, 48)) as pilot:
        table = None
        for _ in range(200):
            await pilot.pause(0.05)
            table = app.screen.query_one("#memory-table", DataTable)
            if table.row_count:
                break
        assert table is not None and table.row_count
        assert_literal(app, payload)


# ---------------------------------------------------------------------------
# Vault: key names chosen by another member
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_vault_item_names(no_backstop, kind) -> None:  # noqa: F811
    from tests.test_vault_key_names_tui import _Host as VaultHost, _Service, _loaded

    payload = PAYLOADS[kind]
    service = _Service(
        items=[{"item_id": "k1", "type": "ssh_key", "revision": 1, "public_fingerprint": "SHA256:one"}],
        names=[{"item_id": "k1", "name": payload, "fingerprint": "SHA256:one"}],
    )
    app = VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await _loaded(app, pilot)
        assert_literal(app, payload)


# ---------------------------------------------------------------------------
# Status lines that name a provider resource
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("which", ["hetzner", "ovh"])
async def test_deleting_a_key_status_names_it_literally(no_backstop, kind, which) -> None:  # noqa: F811
    from tests.test_cloud_screens_multi_account import _config, _registry, _wait_for
    from tests.test_provider_screens_literal import LiteralHost, _hetzner_keys, _ovh_keys

    payload = PAYLOADS[kind]
    config = _config(hetzner_extra=False, ovh_extra=False)
    accounts = _registry(config)
    if which == "hetzner":
        from servonaut.screens.hetzner_ssh_keys import HetznerSSHKeysScreen as Screen

        _hetzner_keys(accounts, payload)
        for fake in accounts.hetzner.values():
            fake.delete_ssh_key = AsyncMock(side_effect=RuntimeError(f"cannot delete {payload}"))
    else:
        from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen as Screen

        _ovh_keys(accounts, payload)
        for bundle in accounts.bundles.values():
            bundle.cloud.delete_ssh_key = AsyncMock(side_effect=RuntimeError(f"cannot delete {payload}"))

    app = LiteralHost(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = Screen()
        await app.push_screen(screen)
        await _wait_for(pilot, lambda: any(t.row_count for t in screen.query(DataTable)), "rows")
        statuses = []
        original = screen._set_status

        def record(text):
            statuses.append(text)
            original(text)

        screen._set_status = record
        app.push_screen_wait = AsyncMock(return_value=True)
        key = {"name": payload, "id": 7 if which == "hetzner" else "k1"}
        if which == "hetzner":
            await screen._do_delete(screen._project_service(), key)
        else:
            await screen._do_delete(key)
        await pilot.pause(0.1)
        assert statuses, "the delete flow reported nothing"
        assert any(payload in str(text) for text in statuses)
        assert all(not isinstance(text, str) or payload not in text for text in statuses)
        assert clickable_cells(app) == []

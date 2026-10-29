"""Sharing is idempotent and server edits/removal stay explicit."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.widgets import Button, DataTable, Input, Select, SelectionList

from servonaut.screens.team_share_confirm import ShareServersConfirmModal
from servonaut.services.api_client import APIClient, APIError
from servonaut.services.team_service import TeamService
from servonaut.config.schema import AppConfig, ConnectionProfile, ConnectionRule
from servonaut.services.connection_service import ConnectionService
from tests.test_team_management_screen import (
    _WrapperApp, _make_auth_service, _make_team_service, _until,
)
from tests.test_team_share_safeguards import _open_share_all, _open_team

pytestmark = pytest.mark.asyncio

SERVERS = [
    {"id": "i-1", "name": "web-1", "public_ip": "10.0.0.1"},
    {"id": "i-2", "name": "db-1", "public_ip": "10.0.0.2", "username": "ubuntu", "port": 2222, "is_custom": True},
]


@pytest.mark.parametrize("existing", [
    {"instance_id": "i-1", "hostname": "old.example.test"},
    {"hostname": "WEB.EXAMPLE.TEST."},
    {"host": "web.example.test"},
])
async def test_service_refuses_a_duplicate_before_posting(existing):
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={"data": [existing]})
    api.post = AsyncMock()
    service = TeamService(api)
    with pytest.raises(APIError) as caught:
        await service.push_server("example", {
            "instance_id": "i-1", "name": "web-1", "hostname": "web.example.test",
        })
    assert caught.value.status == 409
    api.post.assert_not_awaited()


async def test_overlapping_share_requests_create_one_server():
    rows = []
    api = MagicMock(spec=APIClient)

    async def get(_path):
        await asyncio.sleep(0)
        return {"data": list(rows)}

    async def post(_path, *, json):
        await asyncio.sleep(0)
        rows.append(dict(json))
        return rows[-1]

    api.get = AsyncMock(side_effect=get)
    api.post = AsyncMock(side_effect=post)
    service = TeamService(api)
    payload = {"name": "web-1", "hostname": "web.example.test"}
    results = await asyncio.gather(
        service.push_server("example", payload), service.push_server("example", payload),
        return_exceptions=True,
    )
    assert len(rows) == 1
    assert sum(isinstance(result, APIError) for result in results) == 1


async def test_distinct_ssh_ports_on_one_address_are_distinct_destinations():
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={"data": [{"id": "s1", "name": "web-1", "hostname": "10.0.0.1", "port": 2201}]})
    api.post = AsyncMock(return_value={"data": {"id": "s2", "name": "web-2"}})
    result = await TeamService(api).push_server("example", {"name": "web-2", "hostname": "10.0.0.1", "port": 2202})
    assert result["id"] == "s2"
    api.post.assert_awaited_once()


async def test_removal_encodes_server_id_as_one_path_component():
    api = MagicMock(spec=APIClient)
    api.delete = AsyncMock(return_value={"deleted": True})
    await TeamService(api).remove_shared_server("example", "web / staging?#")
    api.delete.assert_awaited_once_with(
        "/api/v1/teams/example/servers/web%20%2F%20staging%3F%23",
    )


@pytest.mark.parametrize("slug, server_id", [("example", ""), ("example", ".."), ("../example", "s1")])
async def test_removal_rejects_invalid_route_components_before_requesting(slug, server_id):
    api = MagicMock(spec=APIClient)
    api.delete = AsyncMock()
    with pytest.raises(ValueError):
        await TeamService(api).remove_shared_server(slug, server_id)
    api.delete.assert_not_awaited()


async def test_single_share_picker_omits_shared_and_duplicate_inventory_rows():
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service(),
                      instances=[*SERVERS, {**SERVERS[1]}, {**SERVERS[0], "id": "shared", "is_shared": True}])
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_team(app, pilot)
        screen._shared_servers = [{"instance_id": "i-1", "hostname": "10.0.0.1"}]
        screen._action_share_server()
        select = screen.query_one("#select_share_instance", Select)
        assert [value for _label, value in select._options if isinstance(value, str)] == ["i-2"]


async def test_share_counts_each_already_shared_server_once():
    from servonaut.services.team_sharing import share_candidates

    shared = {"id": "s1", "instance_id": "i-1", "name": "web-1", "hostname": "10.0.0.1"}
    imported = {**shared, "id": "shared-s1", "is_shared": True}
    for inventory in ([SERVERS[0], imported], [imported, SERVERS[0]]):
        candidates, existing, missing = share_candidates(inventory, [shared])
        assert (candidates, existing, missing) == ([], 1, 0)


async def test_config_author_uses_member_name_and_redacts_it():
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service())
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._members = [{"user": {"id": 42, "name": "Example Owner", "email": "owner@example.com"}}]
        screen._populate_configs_table([{"id": "c1", "version": 1, "pushed_by": 42}])
        assert screen.query_one("#configs_table", DataTable).get_row_at(0)[3] == "Example Owner"
        from servonaut.services.redaction_service import RedactionService
        app.demo_mode = True
        app.redaction_service = RedactionService()
        screen._populate_configs_table([{"id": "c1", "version": 1, "pushed_by": 42}])
        assert "Example Owner" not in str(screen.query_one("#configs_table", DataTable).get_row_at(0))


async def test_config_authors_and_shared_server_labels_are_literal_and_terminal_safe():
    from rich.text import Text

    app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service())
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._members = [{"user": {"id": 42, "name": "[bold]Owner[/bold]\u202e"}}]
        screen._populate_configs_table([{"id": "c1", "version": 1, "pushed_by": 42, "description": "[bold]Setup[/bold]"}])
        row = screen.query_one("#configs_table", DataTable).get_row_at(0)
        assert Text.from_markup(str(row[1])).plain == "[bold]Setup[/bold]"
        assert Text.from_markup(str(row[3])).plain == "[bold]Owner[/bold]"
        screen._populate_servers_table([{"name": "[bold]web-1[/bold]", "hostname": "host.example.test", "region": "test-1"}])
        cell = screen.query_one("#servers_table", DataTable).get_row_at(0)[0]
        assert Text.from_markup(str(cell)).plain == "[bold]web-1[/bold]"


async def test_share_all_prefills_the_connection_rule_login():
    config = AppConfig(default_username="ubuntu")
    config.connection_profiles = [ConnectionProfile(name="application", username="deploy")]
    config.connection_rules = [ConnectionRule(name="application", match_conditions={"id": "i-1"}, profile_name="application")]
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service(), instances=SERVERS)
    app.config_manager = MagicMock()
    app.config_manager.get.return_value = config
    app.connection_service = ConnectionService(app.config_manager)
    app.ssh_service = MagicMock()
    app.ssh_service.get_key_path.return_value = None
    async with app.run_test(size=(100, 30)) as pilot:
        modal = await _open_share_all(app, pilot)
        assert modal.query_one("#share_confirm_username", Input).value == "deploy"


@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_share_all_edits_each_server_without_changing_inventory(size):
    svc = _make_team_service()
    svc.list_team_configs = AsyncMock(return_value=[])
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=svc, instances=[dict(s) for s in SERVERS])
    async with app.run_test(size=size) as pilot:
        modal = await _open_share_all(app, pilot)
        modal.query_one("#share_confirm_name", Input).value = "application"
        modal.query_one("#share_confirm_username", Input).value = "deploy"
        modal.query_one("#share_confirm_port", Input).value = "2201"
        listing = modal.query_one("#share_confirm_list", SelectionList)
        listing.highlighted = 1
        await _until(pilot, lambda: modal.query_one("#share_confirm_name", Input).value == "db-1", "second server editor")
        assert "application" in str(listing.get_option_at_index(0).prompt)
        assert modal.query_one("#share_confirm_username", Input).value == "ubuntu"
        assert modal.query_one("#share_confirm_port", Input).value == "2222"
        modal.query_one("#share_confirm_port", Input).value = "2202"
        modal.query_one("#share_confirm_share", Button).press()
        await _until(pilot, lambda: svc.push_server.await_count == 2, "both shares")
        payloads = [call.args[1] for call in svc.push_server.await_args_list]
        assert (payloads[0]["name"], payloads[0]["username"], payloads[0]["port"]) == ("application", "deploy", 2201)
        assert (payloads[1]["name"], payloads[1]["username"], payloads[1]["port"]) == ("db-1", "ubuntu", 2202)
        assert app.instances[:2] == SERVERS


async def test_share_all_validates_even_a_nonhighlighted_selected_server():
    svc = _make_team_service()
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=svc, instances=SERVERS)
    async with app.run_test(size=(100, 30)) as pilot:
        modal = await _open_share_all(app, pilot)
        modal.query_one("#share_confirm_port", Input).value = "70000"
        modal.query_one("#share_confirm_list", SelectionList).highlighted = 1
        await pilot.pause()
        modal.query_one("#share_confirm_share", Button).press()
        await pilot.pause()
        assert app.screen is modal
        svc.push_server.assert_not_awaited()
        assert modal.query_one("#share_confirm_list", SelectionList).highlighted == 0


async def test_share_all_shows_progress_and_blocks_reentry_until_refresh_finishes():
    svc = _make_team_service()
    entered, release = asyncio.Event(), asyncio.Event()

    async def push(*_args):
        entered.set()
        await release.wait()
        return {}

    svc.push_server.side_effect = push
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=svc, instances=SERVERS)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_team(app, pilot)
        screen._load_team_detail = AsyncMock()
        modal = await _open_share_all(app, pilot)
        modal.query_one("#share_confirm_share", Button).press()
        try:
            await asyncio.wait_for(entered.wait(), 2)
            busy = screen.query_one("#team_servers_busy")
            assert busy.is_active and "1/2" in busy.message
            assert screen.query_one("#btn_share_all", Button).disabled
            screen._action_share_all_servers()
            assert app.screen is screen
        finally:
            release.set()
        await _until(pilot, lambda: svc.push_server.await_count == 2 and not busy.is_active, "sharing completed")
        assert not screen.query_one("#btn_share_all", Button).disabled


async def test_remove_single_server_cancel_then_confirm():
    svc = _make_team_service()
    svc.remove_shared_server = AsyncMock(return_value={"deleted": True})
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=svc)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_team(app, pilot)
        screen._load_team_detail = AsyncMock()
        screen._shared_servers = [
            {"id": "s1", "name": "web-1", "hostname": "10.0.0.1"},
            {"id": "s2", "name": "web-1", "hostname": "10.0.0.2"},
        ]
        screen._populate_servers_table(screen._shared_servers)
        screen.query_one("#servers_table", DataTable).move_cursor(row=1)
        screen.query_one("#btn_remove_server", Button).press()
        await _until(pilot, lambda: bool(app.screen.query("#confirm_input")), "remove confirmation")
        await pilot.press("escape")
        await _until(pilot, lambda: app.screen is screen, "cancel removal")
        svc.remove_shared_server.assert_not_awaited()
        screen.query_one("#btn_remove_server", Button).press()
        await _until(pilot, lambda: bool(app.screen.query("#confirm_input")), "remove confirmation again")
        app.screen.query_one("#confirm_input", Input).value = "REMOVE"
        await pilot.pause()
        app.screen.query_one("#btn_confirm", Button).press()
        await _until(pilot, lambda: svc.remove_shared_server.await_count == 1, "server removed")
        svc.remove_shared_server.assert_awaited_once_with("eng", "s2")


@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_bulk_remove_uses_ids_and_keeps_going_after_an_individual_failure(size):
    from servonaut.screens.bulk_action import BulkActionModal

    svc = _make_team_service()
    svc.remove_shared_server = AsyncMock(side_effect=[
        {}, APIError(code="forbidden", message="Access denied", status=403), {},
    ])
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=svc)
    async with app.run_test(size=size) as pilot:
        screen = await _open_team(app, pilot)
        screen._load_team_detail = AsyncMock()
        # Duplicate names must still remove the exact records that were selected.
        screen._shared_servers = [{"id": f"s{n}", "name": "same", "hostname": f"10.0.0.{n}"} for n in range(1, 4)]
        notes = []
        screen.notify = lambda message, **kwargs: notes.append(str(message))
        screen.query_one("#btn_remove_servers", Button).press()
        await _until(pilot, lambda: isinstance(app.screen, BulkActionModal)
                     and bool(app.screen.query("#bulk_action_list"))
                     and app.screen.query_one("#bulk_action_list", SelectionList).option_count == 3, "bulk removal picker")
        modal = app.screen
        modal.query_one("#bulk_action_list", SelectionList).select_all()
        modal.query_one("#bulk_action_confirm_input", Input).value = "REMOVE"
        await pilot.pause()
        modal.query_one("#bulk_action_submit", Button).press()
        await _until(pilot, lambda: svc.remove_shared_server.await_count == 3 and not screen._server_busy, "batch removal complete")
        assert [call.args for call in svc.remove_shared_server.await_args_list] == [("eng", "s1"), ("eng", "s2"), ("eng", "s3")]
        assert any("Removed 2" in note and "Failed: 1" in note for note in notes)
        assert any("Access denied" in note for note in notes)


@pytest.mark.parametrize("role", ["member", "viewer"])
async def test_nonmanagers_cannot_remove_even_by_invoking_the_action(role):
    svc = _make_team_service()
    svc.remove_shared_server = AsyncMock()
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=svc)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._current_team_role = role
        screen._shared_servers = [{"id": "s1", "name": "web-1"}]
        screen._refresh_member_buttons()
        assert not screen.query_one("#btn_remove_server", Button).display
        assert not screen.query_one("#btn_remove_servers", Button).display
        screen._action_remove_shared_server()
        screen._action_remove_shared_servers()
        await pilot.pause()
        assert app.screen is screen
        svc.remove_shared_server.assert_not_awaited()

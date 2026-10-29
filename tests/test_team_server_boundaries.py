"""Sharing and removal keep real identities and team boundaries intact."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Input, Select, SelectionList

from servonaut.config.schema import AppConfig
from servonaut.screens._demo_resolve import replace_instances
from servonaut.services.api_client import APIClient, APIError
from servonaut.services.connection_service import ConnectionService
from servonaut.services.redaction_service import RedactionService
from servonaut.services.team_service import TeamService
from servonaut.services.team_sharing import already_shared, share_candidates
from tests.test_team_management_screen import _WrapperApp, _make_auth_service, _make_team_service, _until
from tests.test_team_share_safeguards import _open_share_all, _open_team

pytestmark = pytest.mark.asyncio

SERVER = {"id": "i-0123456789abcdef0", "name": "private-web", "public_ip": "8.8.8.8", "username": "deploy", "login_user": "deploy", "port": 2201}


def _service():
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={"data": []})
    api.post = AsyncMock(return_value={"data": {"id": "shared-new"}})
    service = TeamService(api)
    source = _make_team_service()
    service.list_teams = source.list_teams
    service.get_team = source.get_team
    service.list_shared_servers = AsyncMock(return_value=[])
    service.list_team_configs = AsyncMock(return_value=[])
    return service, api


@pytest.mark.parametrize("batch", [False, True])
async def test_demo_sharing_sends_the_pristine_server_and_connection(batch):
    service, api = _service()
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=service)
    app.demo_mode = True
    app.redaction_service = RedactionService()
    replace_instances(app, None, [SERVER])
    assert app.instances[0]["id"] != SERVER["id"]
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_team(app, pilot)
        if batch:
            modal = await _open_share_all(app, pilot)
            modal.query_one("#share_confirm_share", Button).press()
        else:
            screen._action_share_server()
            await pilot.pause()
            screen.query_one("#btn_confirm_share", Button).press()
        await _until(pilot, lambda: api.post.await_count == 1, "the share request")
        sent = api.post.await_args.kwargs["json"]
        assert (sent["instance_id"], sent["name"], sent["hostname"], sent["username"], sent["port"]) == (
            SERVER["id"], SERVER["name"], SERVER["public_ip"], "deploy", 2201,
        )


@pytest.mark.parametrize("batch", [False, True])
async def test_demo_sharing_refuses_a_fleet_without_real_records(batch):
    service, api = _service()
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=service, instances=[SERVER])
    app.demo_mode = True
    app.redaction_service = RedactionService()
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        # A partially restored demo fleet must never be treated as a real one.
        app._instances_pristine = None
        if batch:
            screen._action_share_all_servers()
        else:
            screen._action_share_server()
        await pilot.pause()
        assert app.screen is screen
        assert not screen.query_one("#share_server_form").display
        api.post.assert_not_awaited()


@pytest.mark.parametrize("instance", [
    {"id": "i-1", "name": "web-1", "public_ip": "8.8.8.8"},
    {"id": "custom-web", "name": "web", "public_ip": "8.8.8.8", "is_custom": True},
    {"id": "42", "name": "web", "public_ip": "8.8.8.8", "is_hetzner": True},
])
async def test_share_defaults_do_not_publish_the_sharers_default_login(instance):
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service(), instances=[instance])
    app.config_manager = MagicMock()
    app.config_manager.get.return_value = AppConfig(default_username="ec2-user")
    app.connection_service = ConnectionService(app.config_manager)
    app.ssh_service = MagicMock()
    app.ssh_service.get_key_path.return_value = None
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        assert not screen._share_defaults(instance).get("username")


async def test_dedupe_preserves_same_named_custom_servers_on_different_hosts():
    local = {"id": "custom-web", "name": "web", "public_ip": "8.8.8.8", "is_custom": True}
    shared = {"instance_id": "custom-web", "name": "web", "hostname": "9.9.9.9"}
    assert not already_shared(local, [shared])
    assert share_candidates([local], [shared])[0] == [local]


async def test_dedupe_preserves_private_addresses_from_distinct_networks():
    first = {"id": "i-aaa", "name": "web-1", "private_ip": "10.0.1.5"}
    second = {"id": "i-bbb", "name": "web-2", "private_ip": "10.0.1.5"}
    assert share_candidates([first, second], [])[0] == [first, second]
    assert not already_shared(first, [{"instance_id": "i-zzz", "hostname": "10.0.1.5"}])
    assert already_shared(first, [{"instance_id": "i-aaa", "hostname": "10.0.1.5"}])


async def test_server_picker_uses_the_same_demo_name_and_address_as_the_table():
    service = _make_team_service()
    rows = [{"id": "s1", "name": "private-web", "hostname": "10.0.1.5"}]
    service.list_shared_servers = AsyncMock(return_value=rows)
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=service)
    app.demo_mode = True
    app.redaction_service = RedactionService()
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._shared_servers = rows
        screen._populate_servers_table(rows)
        cells = [Text.from_markup(str(cell)).plain for cell in screen.query_one("#servers_table", DataTable).get_row_at(0)]
        screen._action_remove_shared_servers()
        await pilot.pause()
        label = str(app.screen.query_one("#bulk_action_list", SelectionList).get_option_at_index(0).prompt)
        assert cells[0] in label and cells[1] in label
        assert "private-web" not in label and "10.0.1.5" not in label


async def test_shown_clean_name_can_be_confirmed_without_hidden_control_characters():
    instance = {"id": "i-1", "name": "web\u202e-1", "public_ip": "8.8.8.8"}
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service(), instances=[instance])
    async with app.run_test() as pilot:
        modal = await _open_share_all(app, pilot)
        cleaned = modal.query_one("#share_confirm_name", Input).value
        modal.query_one("#share_confirm_name", Input).value = ""
        modal.query_one("#share_confirm_name", Input).value = cleaned
        assert modal._chosen_servers()[0]["name"] == "web-1"


async def test_loading_another_team_clears_old_servers_before_the_request_finishes():
    service = _make_team_service()
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=service)
    entered, release = asyncio.Event(), asyncio.Event()
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._shared_servers = [{"id": "a1", "name": "web-a", "hostname": "8.8.8.8"}]
        screen._populate_servers_table(screen._shared_servers)

        async def detail(_slug):
            entered.set()
            await release.wait()
            raise APIError(code="not_found", message="Team not found", status=404)

        service.get_team = AsyncMock(side_effect=detail)
        screen._populate_teams_table([{"slug": "other", "name": "Other", "role": "owner"}])
        screen.query_one("#teams_table", DataTable).move_cursor(row=0)
        screen._action_view_team()
        await asyncio.wait_for(entered.wait(), 2)
        try:
            assert screen._shared_servers == []
            assert screen.query_one("#servers_table", DataTable).row_count == 0
        finally:
            release.set()
        await _until(pilot, lambda: service.get_team.await_count > 0, "new team request")
        await pilot.pause()
        assert screen._shared_servers == []
        assert not screen._can_remove_servers()


async def test_unknown_team_404_is_reported_as_a_failed_removal():
    service = _make_team_service()
    service.remove_shared_server = AsyncMock(side_effect=APIError(code="not_found", message="Team not found", status=404))
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=service)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._load_team_detail = AsyncMock()
        notes = []
        screen.notify = lambda message, **_kwargs: notes.append(str(message))
        await screen._do_remove_shared_servers("missing-team", [{"id": "a1", "name": "web-a"}])
        assert any("Removed 0" in note and "Failed: 1" in note for note in notes)


async def test_team_and_member_labels_are_literal_markup():
    service = _make_team_service()
    service.get_team.return_value = {"name": "[/]", "slug": "eng", "role": "owner", "members": []}
    app = _WrapperApp(auth_service=_make_auth_service(), team_service=service)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._populate_teams_table([{"slug": "eng", "name": "[/]", "role": "owner"}])
        screen._populate_members_table([{"user": {"name": "[bold]Member[/bold]"}, "role": "member"}])
        assert Text.from_markup(str(screen.query_one("#teams_table", DataTable).get_row_at(0)[0])).plain == "[/]"
        assert Text.from_markup(str(screen.query_one("#members_table", DataTable).get_row_at(0)[0])).plain == "[bold]Member[/bold]"

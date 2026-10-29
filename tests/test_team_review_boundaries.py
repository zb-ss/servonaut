"""Malformed labels, stale inventories and large batches stay safe to use."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.widgets import Button, DataTable, Input, SelectionList, Static

from servonaut.services.api_client import APIError
from servonaut.services.team_sharing import already_shared
from tests.test_team_management_screen import _WrapperApp, _make_auth_service, _make_team_service, _until
from tests.test_team_share_safeguards import _open_share_all, _open_team, _text

pytestmark = pytest.mark.asyncio


def _app(service=None, **kwargs):
    return _WrapperApp(auth_service=_make_auth_service(), team_service=service or _make_team_service(), **kwargs)


@pytest.mark.parametrize("name", ["web [/", "[/x", "[$accent]web", "web\\"])
async def test_remove_confirmation_renders_malformed_markup_as_a_literal(name):
    app = _app()
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._shared_servers = [{"id": "s1", "name": name, "hostname": "web.example.com"}]
        screen._populate_servers_table(screen._shared_servers)
        screen._action_remove_shared_server()
        await _until(pilot, lambda: bool(app.screen.query("#modal_description")), "remove confirmation")
        assert name in _text(app.screen.query_one("#modal_description", Static))
        await pilot.press("escape")


@pytest.mark.parametrize("name", ["web [b", "web [/", "[$accent]web", "web\\"])
async def test_share_editor_can_move_rows_after_typing_malformed_markup(name):
    app = _app(instances=[{"id": "i-1", "name": "web-1", "public_ip": "web.example.com"},
                          {"id": "i-2", "name": "web-2", "public_ip": "db.example.com"}])
    async with app.run_test() as pilot:
        modal = await _open_share_all(app, pilot)
        modal.query_one("#share_confirm_name", Input).value = name
        modal.query_one("#share_confirm_list", SelectionList).highlighted = 1
        await _until(pilot, lambda: modal._editing_index == 1, "second editor row")
        await pilot.pause()
        assert name in str(modal.query_one("#share_confirm_list", SelectionList).get_option_at_index(0).prompt)


@pytest.mark.parametrize("name", ["[/bold", "x[/b", "[$accent]web", "web\\"])
async def test_actual_team_detail_load_and_change_role_show_literal_names(name):
    service = _make_team_service()
    service.get_team.return_value = {"name": name, "role": "owner", "members": []}
    app = _app(service)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        await screen._load_team_detail("eng")
        assert screen._loaded_team_slug == "eng"
        assert name in _text(screen.query_one("#team_header", Static))
        screen._show_change_role_form({"id": "m1", "email": name, "role": "member"})
        await pilot.pause()
        assert name in _text(screen.query_one("#change_role_header", Static))


@pytest.mark.parametrize("inventory", ["missing-team", "unavailable", "still-present", "already-gone"])
async def test_removal_404_rechecks_the_loaded_team_before_claiming_success(inventory):
    service = _make_team_service()
    service.remove_shared_server = AsyncMock(side_effect=APIError(code="not_found", message="Missing", status=404))
    app = _app(service)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        server = {"id": "s1", "name": "web-1"}
        if inventory in {"missing-team", "unavailable"}:
            service.list_shared_servers = AsyncMock(side_effect=APIError(code="unavailable", message="Missing", status=404 if inventory == "missing-team" else 503))
        else:
            service.list_shared_servers = AsyncMock(return_value=[server] if inventory == "still-present" else [])
        result = await screen._remove_one_shared_server(service, "eng", server)
        service.remove_shared_server.assert_awaited_once_with("eng", "s1")
        service.list_shared_servers.assert_awaited_once_with("eng")
        assert (result is None) == (inventory == "already-gone")


@pytest.mark.parametrize("provider", ["hetzner", "ovh", "aws"])
async def test_cloud_provider_default_username_is_not_published(provider):
    server = {"id": "42", "name": "web-1", "provider": provider, "username": "provider-default", "public_ip": "web.example.com"}
    app = _app(instances=[server])
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        assert not screen._share_defaults(server).get("username")
        assert screen._share_defaults({**server, "login_user": "verified-login"})["username"] == "verified-login"
        assert screen._share_defaults({**server, "is_custom": True})["username"] == "provider-default"


async def test_same_team_reload_keeps_the_last_view_and_focus_if_it_fails():
    service = _make_team_service()
    app = _app(service)
    entered, release = asyncio.Event(), asyncio.Event()
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        rows = [{"id": "s1", "name": "web-1"}, {"id": "s2", "name": "web-2"}]
        screen._shared_servers = list(rows)
        screen._populate_servers_table(rows)
        screen._show_detail_section()
        table = screen.query_one("#servers_table", DataTable)
        table.move_cursor(row=1)
        table.focus()
        await pilot.pause()

        async def fail(_slug):
            entered.set()
            await release.wait()
            raise APIError(code="unavailable", message="Unavailable", status=503)

        service.get_team = AsyncMock(side_effect=fail)
        task = asyncio.create_task(screen._load_team_detail("eng"))
        await entered.wait()
        try:
            assert screen._shared_servers == rows and table.row_count == 2
            assert app.focused is table and table.cursor_row == 1
        finally:
            release.set()
            await task
        assert screen._shared_servers == rows and table.row_count == 2
        assert screen._loaded_team_slug is None
        assert "refresh" in _text(screen.query_one("#team_header", Static)).lower()


async def test_legacy_idless_private_shared_record_blocks_a_repeat():
    assert already_shared({"id": "i-1", "private_ip": "10.0.1.5"}, [{"hostname": "10.0.1.5"}])


async def test_successful_same_team_reload_preserves_the_focused_server_row():
    service = _make_team_service()
    rows = [{"id": "s1", "name": "web-1"}, {"id": "s2", "name": "web-2"}]
    service.list_shared_servers.return_value = rows
    app = _app(service)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._shared_servers = list(rows)
        screen._populate_servers_table(rows)
        screen._show_detail_section()
        table = screen.query_one("#servers_table", DataTable)
        table.move_cursor(row=1)
        table.focus()
        await pilot.pause()
        await screen._load_team_detail("eng")
        await pilot.pause()
        assert screen._loaded_team_slug == "eng"
        assert app.focused is table and table.cursor_row == 1
        assert screen._shared_servers[table.cursor_row]["id"] == "s2"


async def test_bulk_remove_reports_a_reload_instead_of_silently_dropping_confirmation():
    service = _make_team_service()
    service.remove_shared_server = AsyncMock()
    app = _app(service)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._shared_servers = [{"id": "s1", "name": "web-1"}]
        notes = []
        screen.notify = lambda message, **_kw: notes.append(str(message))
        screen._action_remove_shared_servers()
        await pilot.pause()
        modal = app.screen
        modal.query_one("#bulk_action_list", SelectionList).select_all()
        modal.query_one("#bulk_action_confirm_input", Input).value = "REMOVE"
        screen._loaded_team_slug = None
        await pilot.pause()
        modal.query_one("#bulk_action_submit", Button).press()
        await _until(pilot, lambda: app.screen is screen, "confirmation closed")
        assert any("reload" in note.lower() for note in notes)
        service.remove_shared_server.assert_not_awaited()


async def test_large_failed_removal_batch_has_bounded_details_and_the_full_count(caplog):
    service = _make_team_service()
    service.remove_shared_server = AsyncMock(side_effect=APIError(code="forbidden", message="Forbidden", status=403))
    app = _app(service)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._load_team_detail = AsyncMock()
        notes = []
        screen.notify = lambda message, **_kw: notes.append(str(message))
        await screen._do_remove_shared_servers("eng", [{"id": f"s{n}", "name": f"web-{n}"} for n in range(10)])
        assert len(notes) == 5
        assert "Failed: 10" in notes[0]
        assert "7 more" in notes[-1]
        assert "see the log" in notes[-1]
        assert all(any(f"web-{n}: Forbidden" in record.message for record in caplog.records) for n in range(10))


async def test_share_all_logs_every_failure_before_capping_notifications(caplog):
    service = _make_team_service()
    service.push_server = AsyncMock(side_effect=APIError(code="forbidden", message="Forbidden", status=403))
    app = _app(service)
    async with app.run_test() as pilot:
        screen = await _open_team(app, pilot)
        screen._load_team_detail = AsyncMock()
        await screen._do_share_all("eng", [{"id": f"i-{n}", "name": f"web-{n}", "public_ip": f"web-{n}.example.com"} for n in range(10)], 0, 0)
        assert all(any(f"web-{n} (Forbidden)" in record.message for record in caplog.records) for n in range(10))

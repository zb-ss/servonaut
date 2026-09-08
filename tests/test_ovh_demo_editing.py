"""Demo aliases must stay in the UI while OVH operations retain real targets."""

from __future__ import annotations

import asyncio
import copy
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from rich.text import Text
from textual.app import App
from textual.widgets import Button, DataTable, Input, Static

from servonaut.screens.ovh_dns import OVHDNSScreen
from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
from servonaut.services.redaction_service import RedactionService
from servonaut.styles import CSS_FILES


# Private-address fixtures deliberately exercise redaction (documentation IPs
# are already considered safe and pass through the redactor unchanged).
ENTRY = {"ip": "10.0.0.7", "ip_block": "10.0.0.0/24", "hostname": "mail.example.net"}


@contextmanager
def dns_screen(is_demo: bool) -> Iterator[tuple]:
    service = SimpleNamespace(set_reverse_dns=AsyncMock(), delete_reverse_dns=AsyncMock())
    app = SimpleNamespace(
        demo_mode=is_demo, redaction_service=RedactionService(),
        ovh_ip_service=service, ovh_audit=MagicMock(),
        push_screen_wait=AsyncMock(return_value=False),
    )
    screen = OVHDNSScreen()
    widgets = {key: MagicMock() for key in (
        "#rdns_form", "#rdns_form_ip_label", "#input_rdns_hostname", "#dns_container",
    )}
    queued = []
    with (
        patch.object(OVHDNSScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", side_effect=lambda key, *args: widgets[key]),
        patch.object(screen, "run_worker", side_effect=lambda coro, **kwargs: queued.append(coro)),
        patch.object(screen, "notify") as notify,
        patch.object(screen, "_load_rdns", new_callable=AsyncMock),
        patch.object(screen, "_get_selected_rdns", return_value=ENTRY.copy()),
    ):
        screen._show_rdns_form(ENTRY["ip"], ENTRY["ip_block"], ENTRY["hostname"])
        yield screen, app, widgets, queued, notify
    for coro in queued:
        coro.close()


@pytest.mark.parametrize("is_demo", [False, True])
def test_rdns_form_display_preserves_private_target(is_demo: bool) -> None:
    with dns_screen(is_demo) as (screen, app, widgets, _, _notify):
        label = Text.from_markup(widgets["#rdns_form_ip_label"].update.call_args.args[0]).plain
        hostname = widgets["#input_rdns_hostname"].value
        for value in ENTRY.values():
            shown = app.redaction_service.redact_host(value) if is_demo else value
            assert shown in label + hostname
            if is_demo:
                assert value not in label + hostname
        assert screen._edit_rdns_ip == ENTRY["ip"]
        assert screen._edit_rdns_ip_block == ENTRY["ip_block"]


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("edited", [False, True])
def test_rdns_save_uses_original_or_explicitly_edited_hostname(
    is_demo: bool, edited: bool,
) -> None:
    with dns_screen(is_demo) as (screen, app, widgets, queued, _notify):
        expected = "replacement.example.net" if edited else ENTRY["hostname"]
        if edited:
            widgets["#input_rdns_hostname"].value = expected
        # Whitespace trimming must not turn an unchanged alias into a new PTR.
        widgets["#input_rdns_hostname"].value += " "
        screen._action_rdns_save()
        # Opening another row before the worker runs must not change its target.
        screen._show_rdns_form("10.0.0.8", ENTRY["ip_block"], "other.example.net")
        asyncio.run(queued.pop())
        app.ovh_ip_service.set_reverse_dns.assert_awaited_once_with(
            ENTRY["ip_block"], ENTRY["ip"], expected,
        )


def test_rdns_empty_hostname_stays_open_without_saving() -> None:
    with dns_screen(True) as (screen, app, widgets, queued, notify):
        widgets["#input_rdns_hostname"].value = " "
        screen._action_rdns_save()
        assert widgets["#rdns_form"].display is True
        assert not queued
        app.ovh_ip_service.set_reverse_dns.assert_not_awaited()
        notify.assert_called_once_with("Hostname is required", severity="error")


def test_rdns_cancel_never_saves() -> None:
    with dns_screen(True) as (screen, app, widgets, queued, _notify):
        screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn_rdns_cancel")))
        assert widgets["#rdns_form"].display is False
        assert not queued
        app.ovh_ip_service.set_reverse_dns.assert_not_awaited()


def test_rdns_untouched_empty_hostname_is_rejected() -> None:
    with dns_screen(True) as (screen, app, _widgets, queued, notify):
        screen._show_rdns_form(ENTRY["ip"], ENTRY["ip_block"], "")
        screen._action_rdns_save()
        assert not queued
        app.ovh_ip_service.set_reverse_dns.assert_not_awaited()
        notify.assert_called_once_with("Hostname is required", severity="error")


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("confirmed", [False, True])
def test_rdns_delete_confirmation_uses_alias_but_deletes_real_target(
    is_demo: bool, confirmed: bool,
) -> None:
    with dns_screen(is_demo) as (screen, app, _widgets, queued, _notify):
        app.push_screen_wait.return_value = confirmed
        screen._action_rdns_delete()
        asyncio.run(queued.pop())
        modal = app.push_screen_wait.call_args.args[0]
        expected_ip = app.redaction_service.redact_host(ENTRY["ip"]) if is_demo else ENTRY["ip"]
        assert modal._confirm_text == expected_ip
        if is_demo:
            assert ENTRY["ip"] not in modal._description
            assert ENTRY["hostname"] not in modal._description
        if confirmed:
            app.ovh_ip_service.delete_reverse_dns.assert_awaited_once_with(
                ENTRY["ip_block"], ENTRY["ip"],
            )
        else:
            app.ovh_ip_service.delete_reverse_dns.assert_not_awaited()


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("operation", ["save", "delete"])
def test_rdns_failure_does_not_expose_provider_details(is_demo: bool, operation: str) -> None:
    with dns_screen(is_demo) as (screen, app, _widgets, _queued, notify):
        error = RuntimeError(f"Rejected {ENTRY['hostname']} [invalid]")
        if operation == "save":
            app.ovh_ip_service.set_reverse_dns.side_effect = error
            asyncio.run(screen._save_rdns(ENTRY["ip_block"], ENTRY["ip"], ENTRY["hostname"]))
        else:
            app.ovh_ip_service.delete_reverse_dns.side_effect = error
            asyncio.run(screen._do_delete_rdns(ENTRY["ip_block"], ENTRY["ip"]))
        message = notify.call_args.args[0]
        assert (ENTRY["hostname"] not in message) is is_demo


@contextmanager
def snapshots_screen(is_demo: bool, snapshot: dict, provider_type: str = "vps") -> Iterator[tuple]:
    raw_id = "vps-1234.example.net" if provider_type == "vps" else "12345678/87654321"
    redactor = RedactionService()
    app = SimpleNamespace(
        demo_mode=is_demo, redaction_service=redactor,
        real_instance_id=redactor.real_instance_id,
        push_screen_wait=AsyncMock(return_value=False), ovh_audit=MagicMock(),
        ovh_snapshot_service=SimpleNamespace(
            restore_vps_snapshot=AsyncMock(), delete_vps_snapshot=AsyncMock(),
            delete_cloud_snapshot=AsyncMock(),
        ),
    )
    display_id = redactor.redact_instance_id(raw_id) if is_demo else raw_id
    screen = OVHSnapshotsScreen({"id": display_id, "name": "web-1", "provider_type": provider_type})
    screen._snapshots = [copy.deepcopy(snapshot)]
    table = MagicMock(cursor_row=0)
    queued = []
    with (
        patch.object(OVHSnapshotsScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=table),
        patch.object(screen, "notify"),
        patch.object(screen, "run_worker", side_effect=lambda coro, **kwargs: queued.append(coro)),
        patch.object(screen, "_load_vps_snapshots", new_callable=AsyncMock),
        patch.object(screen, "_load_cloud_snapshots", new_callable=AsyncMock),
    ):
        yield screen, app, table, queued, raw_id
    for coro in queued:
        coro.close()


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("snapshot", [
    {"id": 123456789}, {"id": "snap-opaque"},
    {"id": "snap-opaque", "name": "nightly-web", "description": "web.example.net backup"},
])
def test_snapshot_identity_is_redacted_without_mutating_source(is_demo: bool, snapshot: dict) -> None:
    with snapshots_screen(is_demo, snapshot) as (screen, _app, table, _queued, _raw_id):
        screen._populate_table()
        first_render = table.add_row.call_args.args
        screen._populate_table()
        assert table.add_row.call_args.args == first_render
        assert screen._snapshots == [snapshot]
        name = str(snapshot.get("name") or snapshot["id"])
        if is_demo:
            assert name not in str(first_render)
            if snapshot.get("description"):
                assert snapshot["description"] not in str(first_render)
        else:
            assert first_render[0] == name


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("confirmed", [False, True])
@pytest.mark.parametrize("operation,provider_type", [("restore", "vps"), ("delete", "vps"), ("delete", "cloud")])
def test_snapshot_confirmation_preserves_selected_operation_target(
    is_demo: bool, confirmed: bool, operation: str, provider_type: str,
) -> None:
    snapshot = {"id": "snap-opaque"}
    with snapshots_screen(is_demo, snapshot, provider_type) as (screen, app, table, queued, raw_id):
        app.push_screen_wait.return_value = confirmed
        screen._populate_table()
        alias = table.add_row.call_args.args[0]

        async def run() -> None:
            await getattr(screen, f"_on_{operation}_snapshot")()
            while queued:
                await queued.pop(0)

        asyncio.run(run())
        modal = app.push_screen_wait.call_args.args[0]
        assert alias in modal._description
        audit = app.ovh_audit.log_action.call_args.kwargs
        assert audit["target"] == raw_id
        assert audit["details"]["snapshot_name"] == snapshot["id"]
        assert audit["confirmed"] is confirmed
        if is_demo:
            assert snapshot["id"] not in modal._description + modal._confirm_text
        if operation == "delete":
            assert modal._confirm_text == alias
        service = app.ovh_snapshot_service
        call = getattr(service, f"{operation}_{provider_type}_snapshot")
        if not confirmed:
            call.assert_not_awaited()
        elif provider_type == "cloud":
            call.assert_awaited_once_with(raw_id.split("/")[0], snapshot["id"])
        elif operation == "restore":
            call.assert_awaited_once_with(raw_id, snapshot["id"])
        else:
            call.assert_awaited_once_with(raw_id)


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("operation,provider_type", [("restore", "vps"), ("delete", "vps"), ("delete", "cloud")])
def test_snapshot_operation_error_keeps_provider_identifiers_off_screen(
    is_demo: bool, operation: str, provider_type: str,
) -> None:
    with snapshots_screen(is_demo, {"id": "snap-opaque"}, provider_type) as (screen, app, _table, queued, raw_id):
        app.push_screen_wait.return_value = True
        service_call = getattr(app.ovh_snapshot_service, f"{operation}_{provider_type}_snapshot")
        error = RuntimeError(f"Rejected {raw_id} snap-opaque [invalid]")
        service_call.side_effect = error

        async def run() -> None:
            await getattr(screen, f"_on_{operation}_snapshot")()
            while queued:
                await queued.pop(0)

        asyncio.run(run())
        message = screen.notify.call_args.args[0]
        if is_demo:
            assert raw_id not in message
            assert "snap-opaque" not in message
        else:
            assert str(error) in message


class DNSLayoutApp(App):
    """Exercise the real DNS form and styles with an offline provider."""

    CSS_PATH = CSS_FILES
    CSS = "#sidebar { width: 25; }"
    demo_mode = True

    def __init__(self) -> None:
        super().__init__()
        self.redaction_service = RedactionService()
        self.ovh_ip_service = SimpleNamespace(
            list_ips=AsyncMock(return_value=[{"ip": ENTRY["ip_block"]}]),
            list_reverse_dns=AsyncMock(return_value=[
                {"ipReverse": f"10.0.0.{index}", "reverse": f"web-{index}.example.net"}
                for index in range(1, 7)
            ]),
        )

    def on_mount(self) -> None:
        self.push_screen(OVHDNSScreen())


@pytest.mark.asyncio
async def test_rdns_editor_remains_visible_when_reopened() -> None:
    app = DNSLayoutApp()
    with (
        patch("servonaut.screens.ovh_dns.Sidebar", side_effect=lambda: Static(id="sidebar")),
        patch.object(OVHDNSScreen, "_load_domains", new_callable=AsyncMock),
    ):
        async with app.run_test(size=(166, 47)) as pilot:
            await pilot.pause()
            screen = app.screen
            table = screen.query_one("#rdns_table", DataTable)
            assert table.row_count == 6
            for row in range(table.row_count):
                table.move_cursor(row=row)
                screen.query_one("#btn_rdns_edit", Button).focus()
                await pilot.pause(0.2)
                await pilot.press("enter")
                await pilot.pause(0.3)
                field = screen.query_one("#input_rdns_hostname", Input)
                form = screen.query_one("#rdns_form")
                assert form.content_region.contains_region(field.region)
                assert 0 <= field.region.y < field.region.bottom < app.size.height
                assert app.focused is field
                screen.query_one("#btn_rdns_cancel", Button).focus()
                await pilot.press("enter")
                await pilot.pause()
                assert not form.display

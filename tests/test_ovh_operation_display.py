"""Demo labels must never become provider mutation targets."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.screens.ovh_manager import OVHManagerScreen
from servonaut.screens.ovh_ip_management import OVHIPManagementScreen
from servonaut.screens.ovh_storage import OVHStorageScreen
from servonaut.services.redaction_service import RedactionService


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("attachments", [{"attachedTo": ["12345"]},
                                          {"attachments": [{"serverId": "12345"}]}])
def test_volume_table_keeps_raw_targets_behind_display(is_demo: bool, attachments: dict) -> None:
    screen = OVHStorageScreen()
    volume = {"id": "volume-id", "name": "private-volume", "size": 10,
              **attachments}
    service = SimpleNamespace(list_volumes=AsyncMock(return_value=[volume]))
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService())
    table = MagicMock()
    with (
        patch.object(OVHStorageScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_get_storage_service", return_value=service),
        patch.object(screen, "_get_project_ids", return_value=["project-id"]),
        patch.object(screen, "query_one", return_value=table),
    ):
        asyncio.run(screen._load_volumes())
    row = table.add_row.call_args.args
    assert (row[0] != "private-volume") is is_demo
    assert (row[4] != "12345") is is_demo
    assert screen._attachment_instance_ids(screen._volumes[0]) == ["12345"]


@pytest.mark.parametrize("operation", ["attach", "detach", "delete"])
@pytest.mark.parametrize("is_demo", [False, True])
def test_volume_confirmation_preserves_mutation_target(operation: str, is_demo: bool) -> None:
    screen = OVHStorageScreen()
    redactor = RedactionService()
    volume = {"id": "volume-id", "name": "private-volume", "_project_id": "project-id",
              "attachedTo": ["12345"]}
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=redactor,
                          push_screen_wait=AsyncMock(return_value=True), ovh_audit=None)
    supplied_id = redactor.redact_instance_id("12345") if is_demo else "12345"
    widget = SimpleNamespace(value=supplied_id)
    method = "_submit_attach" if operation == "attach" else "_action_" + operation
    api_method = "_" + operation + "_volume"
    with (
        patch.object(OVHStorageScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_get_selected_volume", return_value=volume),
        patch.object(screen, "query_one", return_value=widget),
        patch.object(screen, "_hide_all_forms"),
        patch.object(screen, "run_worker", side_effect=lambda coro, **kw: asyncio.run(coro)),
        patch.object(screen, api_method, new_callable=AsyncMock) as mutation,
    ):
        getattr(screen, method)()
    confirmation = app.push_screen_wait.call_args.args[0]
    assert ("private-volume" not in confirmation._description) is is_demo
    assert (confirmation._confirm_text != "private-volume") is is_demo
    if operation == "delete":
        mutation.assert_awaited_once_with("project-id", "volume-id", "private-volume")
    else:
        assert ("12345" not in confirmation._description) is is_demo
        mutation.assert_awaited_once_with("project-id", "volume-id", "12345", "private-volume")


@pytest.mark.parametrize("fails", [False, True])
@pytest.mark.parametrize("is_demo", [False, True])
def test_manager_lifecycle_preserves_raw_target(fails: bool, is_demo: bool) -> None:
    screen = OVHManagerScreen()
    # Generated synthetic compact project ID, matching the provider's format.
    identifier = "a" * 32 + "/12345"
    call = AsyncMock(side_effect=RuntimeError(identifier) if fails else None)
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService(),
                          ovh_service=SimpleNamespace(start_instance=call), ovh_audit=None)
    with (
        patch.object(OVHManagerScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_set_status") as status,
        patch.object(screen, "notify") as notify,
        patch.object(screen, "_load_instances", new_callable=AsyncMock),
    ):
        asyncio.run(screen._do_lifecycle("start_instance", identifier, "cloud", "started"))
    call.assert_awaited_once_with(identifier, "cloud")
    visible = str(notify.call_args_list) + str(status.call_args_list)
    assert (("a" * 32) not in visible) is is_demo


def test_compact_project_redaction_is_reversible_and_idempotent() -> None:
    service = RedactionService()
    identifier = "a" * 32 + "/12345"
    display = service.redact_instance_id(identifier)
    assert "a" * 32 not in display
    assert service.redact_instance_id(display) == display
    assert service.real_instance_id(display) == identifier


@pytest.mark.parametrize("is_demo", [False, True])
def test_ip_route_masks_cloud_project_without_changing_selection(is_demo: bool) -> None:
    screen = OVHIPManagementScreen()
    project_id = "a" * 32
    screen._ips = [{"ip": "192.0.2.1", "type": "cloud", "routedTo": {"serviceName": project_id}}]
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService())
    table = MagicMock()
    with (
        patch.object(OVHIPManagementScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=table),
    ):
        screen._populate_table()
    assert (table.add_row.call_args.args[2] != project_id) is is_demo
    assert screen._ips[0]["routedTo"]["serviceName"] == project_id

"""OVH inspection uses real resource IDs while retaining demo display rows."""

from __future__ import annotations

import asyncio
import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.app import ServonautApp
from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
from servonaut.services.redaction_service import RedactionService


def make_app(raw_id: str, provider_type: str, is_demo: bool) -> SimpleNamespace:
    raw_row = {"id": raw_id, "name": "web-1", "provider_type": provider_type}
    shown_row = copy.deepcopy(raw_row)
    redaction = RedactionService()
    if is_demo:
        redaction.redact_instance(shown_row)
        assert shown_row["id"] != raw_id, "Fixture must exercise an actual redacted ID"
    app = SimpleNamespace(
        demo_mode=is_demo,
        redaction_service=redaction if is_demo else None,
        _instances_pristine=[raw_row],
        instances=[shown_row],
        ovh_snapshot_service=SimpleNamespace(),
    )
    app.real_instance_id = lambda value: ServonautApp.real_instance_id(app, value)
    app.connection_instance = lambda row: ServonautApp.connection_instance(app, row)
    return app


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize(
    "provider_type,raw_id,loader,operation,expected_id",
    [
        (
            "vps",
            "vps-abcd1234.example.net",
            "_load_vps_snapshots",
            "list_vps_snapshots",
            "vps-abcd1234.example.net",
        ),
        (
            "vps",
            "vps-abcd1234.example.net",
            "_load_vps_backup_status",
            "get_vps_backup_options",
            "vps-abcd1234.example.net",
        ),
        (
            "cloud",
            "123456789/987654321",
            "_load_cloud_snapshots",
            "list_cloud_snapshots",
            "123456789",
        ),
    ],
)
def test_snapshot_reads_resolve_target(
    is_demo: bool,
    provider_type: str,
    raw_id: str,
    loader: str,
    operation: str,
    expected_id: str,
) -> None:
    app = make_app(raw_id, provider_type, is_demo)
    service_call = AsyncMock(return_value=[])
    setattr(app.ovh_snapshot_service, operation, service_call)
    shown_row = copy.deepcopy(app.instances[0])
    screen = OVHSnapshotsScreen(app.instances[0])
    with (
        patch.object(
            OVHSnapshotsScreen, "app", new_callable=PropertyMock, return_value=app
        ),
        patch.object(screen, "query_one", return_value=MagicMock()),
        patch.object(screen, "_populate_table"),
    ):
        asyncio.run(getattr(screen, loader)())
    service_call.assert_awaited_once_with(expected_id)
    assert screen._instance == shown_row

"""Display provider units correctly and retain raw targets behind demo labels."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.screens.ovh_cloud_create import OVHCloudCreateScreen
from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen
from servonaut.services.redaction_service import RedactionService


def test_wizard_preserves_api_gib_units() -> None:
    screen = OVHCloudCreateScreen()
    screen._project_id = "project"
    # The OVH flavor schema defines RAM in GiB (Gio), unlike EC2's MiB field.
    flavor = {"id": "flavor", "name": "small", "ram": 2, "vcpus": 1, "disk": 25}
    app = SimpleNamespace(ovh_cloud_service=SimpleNamespace(
        list_flavors=AsyncMock(return_value=[flavor]),
    ))
    table = MagicMock()
    with (
        patch.object(OVHCloudCreateScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=table),
    ):
        asyncio.run(screen._load_flavors("UK1"))
    assert table.add_row.call_args.args[2] == "2"


@pytest.mark.parametrize("is_demo", [False, True])
def test_wizard_key_id_is_display_only(is_demo: bool) -> None:
    screen = OVHCloudCreateScreen()
    screen._project_id = "project"
    key = {"id": "private-key-id", "name": "private-key-name"}
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService(),
                          ovh_cloud_service=SimpleNamespace(list_ssh_keys=AsyncMock(return_value=[key])))
    table = MagicMock()
    with (
        patch.object(OVHCloudCreateScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=table),
    ):
        asyncio.run(screen._load_keys())
    assert table.add_row.call_args.args[1] == ("key-001" if is_demo else key["id"])
    assert (table.add_row.call_args.args[0] != key["name"]) is is_demo
    assert screen._keys[0]["id"] == key["id"]


@pytest.mark.parametrize("is_demo", [False, True])
def test_key_deletion_redacts_confirmation_but_preserves_api_target(is_demo: bool) -> None:
    screen = OVHSSHKeysScreen()
    screen._project_id = "private-project"
    key = {"id": "private-key-id", "name": "private-key-name"}
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService(),
                          push_screen_wait=AsyncMock(return_value=True),
                          ovh_cloud_service=SimpleNamespace(delete_ssh_key=AsyncMock()))
    with (
        patch.object(OVHSSHKeysScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_set_status"), patch.object(screen, "notify"),
        patch.object(screen, "_load_keys", new_callable=AsyncMock),
    ):
        asyncio.run(screen._do_delete(key))
    confirmation = app.push_screen_wait.call_args.args[0]
    assert ("private-project" not in confirmation._description) is is_demo
    assert ("private-key-name" not in confirmation._description) is is_demo
    assert ("private-key-name" != confirmation._confirm_text) is is_demo
    app.ovh_cloud_service.delete_ssh_key.assert_awaited_once_with("private-project", "private-key-id")


@pytest.mark.parametrize("is_demo", [False, True])
def test_key_table_masks_fingerprint_and_public_key(is_demo: bool) -> None:
    screen = OVHSSHKeysScreen()
    screen._project_id = "private-project"
    key = {"id": "key-id", "name": "key-name", "fingerprint": "private-fingerprint",
           "public_key": "ssh-ed25519 example-public-key"}
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService(),
                          ovh_cloud_service=SimpleNamespace(list_ssh_keys=AsyncMock(return_value=[key])))
    table = MagicMock()
    with (
        patch.object(OVHSSHKeysScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=table),
        patch.object(screen, "_set_status"), patch.object(screen, "_sync_action_buttons"),
    ):
        asyncio.run(screen._load_keys())
        assert ("private-project" != screen._display_project_id()) is is_demo
    row = table.add_row.call_args.args
    assert (row[1] == "Hidden") is is_demo
    assert (row[2] == "Hidden") is is_demo
    assert screen._keys[0] == key

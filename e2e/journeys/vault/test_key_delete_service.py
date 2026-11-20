"""Deleting vault keys through a service that reports usage and refuses bound keys."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from textual.widgets import Button, DataTable, Input, SelectionList

from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_ID
from e2e.harness.waits import wait_for_async
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from e2e.journeys.vault.test_vault_key_names import _VaultHost, _ed25519_key_pair, _native_service
from servonaut.config.schema import CustomServer
from servonaut.screens.bulk_action import BulkActionModal
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.services.vault.personal_targets import custom_binding_id
from servonaut.styles import CSS_FILES

pytestmark = [pytest.mark.e2e_pr]

CAPABILITIES = ["item_usage", "delete_refuses_bound"]
CUSTOM_SERVERS = [
    CustomServer(name=f"site-{n}", host=f"site-{n}.example.test", username="deploy", provider="custom")
    for n in range(1, 11)
]
SIZES = [(160, 50), (100, 30)]


def _binding_reads(fake_cloud) -> list[dict]:
    return [entry for entry in fake_cloud.requests(method="GET")
            if entry["path"].startswith("/api/v1/me/instances/") and entry["path"].endswith("/credential-binding")]


def _json(result) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _cli_vault_with_key(journey, fake_cloud, cli, account_home, servonaut_cmd, name):
    fake_cloud.vault.set_capabilities(CAPABILITIES)
    _configure_test_custody(journey)
    home = account_home(name, custom_servers=CUSTOM_SERVERS)
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = home.home / "key-1.pem"
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption(),
    ))
    key_path.chmod(0o600)
    item_id = _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path),
                        "--name", "key-1", "--json"))["item_id"]
    return home, vault_id, item_id


def test_cli_delete_of_an_unused_key_uses_one_usage_request_and_no_binding_reads(
    journey, fake_cloud, cli, account_home, servonaut_cmd,
):
    home, vault_id, item_id = _cli_vault_with_key(journey, fake_cloud, cli, account_home, servonaut_cmd, "svc-delete-unused")
    fake_cloud.configure(binding_reads_retry_after=30)
    reads_before = len(_binding_reads(fake_cloud))
    usage_before = len(fake_cloud.requests(method="POST", path=f"/api/v1/vaults/{vault_id}/items/usage"))

    deleted = _json(cli(home, "vault", "delete", item_id, "--vault", vault_id, "--yes", "--json"))

    assert deleted == {"item_id": item_id, "deleted": True}
    assert len(_binding_reads(fake_cloud)) == reads_before
    assert len(fake_cloud.requests(method="POST", path=f"/api/v1/vaults/{vault_id}/items/usage")) - usage_before == 1


def test_cli_delete_of_a_bound_key_needs_unbind_and_then_removes_the_binding(
    journey, fake_cloud, cli, account_home, servonaut_cmd,
):
    home, vault_id, item_id = _cli_vault_with_key(journey, fake_cloud, cli, account_home, servonaut_cmd, "svc-delete-bound")
    binding_key = ("custom", custom_binding_id("site-1"))
    fake_cloud.vault._bindings[binding_key] = {"vault_id": vault_id, "vault_item_id": item_id}

    refused = cli(home, "vault", "delete", item_id, "--vault", vault_id, "--yes")

    assert refused.returncode != 0
    assert "Your servers: site-1" in refused.stderr
    assert "--unbind" in refused.stderr
    assert "Traceback" not in refused.stderr
    listed = _json(cli(home, "vault", "items", "--vault", vault_id, "--json"))
    assert [row["item_id"] for row in listed["data"]] == [item_id]
    assert binding_key in fake_cloud.vault._bindings

    deleted = _json(cli(home, "vault", "delete", item_id, "--vault", vault_id, "--unbind", "--yes", "--json"))

    assert deleted == {"item_id": item_id, "deleted": True}
    listed = _json(cli(home, "vault", "items", "--vault", vault_id, "--json"))
    assert listed["data"] == []
    assert binding_key not in fake_cloud.vault._bindings
    sent = [entry for entry in fake_cloud.requests(method="DELETE") if entry["path"].endswith(f"/items/{item_id}")]
    # The usage review refused the first attempt, so only the unbind request reached the service.
    assert [entry["status"] for entry in sent] == [200]
    assert json.loads(json.dumps(sent[0]["body"]))["unbind"] is True


def test_cli_unbind_without_the_usage_capability_lists_the_servers_and_deletes_nothing(
    journey, fake_cloud, cli, account_home, servonaut_cmd,
):
    """With only the refusal capability the confirmation could not show other members, so unbind is unavailable."""
    home, vault_id, item_id = _cli_vault_with_key(journey, fake_cloud, cli, account_home, servonaut_cmd, "svc-unbind-gated")
    fake_cloud.vault.set_capabilities(["delete_refuses_bound"])
    binding_key = ("custom", custom_binding_id("site-1"))
    fake_cloud.vault._bindings[binding_key] = {"vault_id": vault_id, "vault_item_id": item_id}

    refused = cli(home, "vault", "delete", item_id, "--vault", vault_id, "--unbind", "--yes")

    assert refused.returncode != 0
    assert "Your servers: site-1" in refused.stderr
    assert "unbinding while deleting is not available" in refused.stderr
    assert "Traceback" not in refused.stderr
    assert binding_key in fake_cloud.vault._bindings
    assert not [entry for entry in fake_cloud.requests(method="DELETE") if entry["path"].endswith(f"/items/{item_id}")]


class _ServiceHost(_VaultHost):
    CSS_PATH = CSS_FILES


async def _open_items(app, screen, count):
    table = screen.query_one("#vault_table", DataTable)
    await wait_for_async(lambda: table.row_count == 1, desc="vault listed")
    await wait_for_async(lambda: not screen.query_one("#vault_items", Button).disabled, desc="items enabled")
    screen.query_one("#vault_items", Button).press()
    await wait_for_async(lambda: screen._table_mode == "items" and len(screen._items) == count, desc="keys loaded")
    return table


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_bulk_delete_reviews_usage_in_one_request_and_keeps_the_bound_key(
    fake_cloud, journey, account_home, monkeypatch, size,
):
    fake_cloud.vault.set_capabilities(CAPABILITIES)
    home = account_home("svc-bulk-personal").home
    service = _native_service(fake_cloud, home, monkeypatch)
    vault = await service.create_vault(team=None, name="Keys", grant_policy="auto")
    vault_id = vault["vault_id"]
    items = []
    for index in range(3):
        private_key, _ = _ed25519_key_pair()
        items.append(await service.import_keys(
            source="ssh", vault_id=vault_id, private_key=private_key.encode(), name=f"key-{index + 1}",
        ))
    fake_cloud.vault._bindings[("custom", custom_binding_id("site-1"))] = {
        "vault_id": vault_id, "vault_item_id": items[2]["item_id"],
    }
    fake_cloud.configure(binding_reads_retry_after=30)
    service._remote_executor = MagicMock(side_effect=AssertionError("vault deletion must not contact hosts"))
    instances = [{"id": "site-1", "name": "site-1", "is_custom": True, "provider": "custom",
                  "state": "running", "public_ip": "10.0.0.1"}]
    app = _ServiceHost(service, instances=instances)
    async with app.run_test(size=size):
        screen = app.screen
        await _open_items(app, screen, 3)
        screen.query_one("#vault_delete_keys", Button).press()
        await wait_for_async(lambda: isinstance(app.screen, BulkActionModal)
                             and bool(app.screen.query("#bulk_action_list"))
                             and app.screen.query_one("#bulk_action_list", SelectionList).option_count == 3,
                             desc="bulk picker ready")
        modal = app.screen
        modal.query_one("#bulk_action_list", SelectionList).select_all()
        await wait_for_async(lambda: not modal.query_one("#bulk_action_submit", Button).disabled, desc="keys selected")
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_for_async(lambda: isinstance(app.screen, BulkActionModal) and app.screen is not modal
                             and bool(app.screen.query("#bulk_action_confirm_input")), desc="usage reviewed")
        modal = app.screen
        modal.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await wait_for_async(lambda: not modal.query_one("#bulk_action_submit", Button).disabled, desc="confirmation accepted")
        modal.query_one("#bulk_action_submit", Button).press()
        await wait_for_async(lambda: len(screen._items) == 1 and not screen._busy_work, desc="batch complete")
        assert screen._items[0]["item_id"] == items[2]["item_id"]
        assert any("Deleted 2" in note and "1 kept" in note for note in app.notifications)
        assert any("key-3" in note and "site-1" in note for note in app.notifications)

    service._remote_executor.assert_not_called()
    assert _binding_reads(fake_cloud) == []
    assert len(fake_cloud.requests(method="POST", path=f"/api/v1/vaults/{vault_id}/items/usage")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_single_team_key_delete_asks_to_unbind_and_removes_the_team_binding(
    fake_cloud, journey, account_home, monkeypatch, size,
):
    fake_cloud.vault.set_capabilities(CAPABILITIES)
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[])
    home = account_home("svc-single-team").home
    service = _native_service(fake_cloud, home, monkeypatch)
    team = fake_cloud.account.create_team(name="Example team", owner_user_id=service.auth.user_id, team_id=TEAM_ID)
    vault = await service.create_vault(team=team["slug"], name="Keys", grant_policy="auto")
    vault_id = vault["vault_id"]
    private_key, _ = _ed25519_key_pair()
    item = await service.import_keys(source="ssh", vault_id=vault_id, private_key=private_key.encode(), name="key-1")
    item_id = item["item_id"]
    team_binding = ("team", SERVER_ID)
    fake_cloud.vault._bindings[team_binding] = {"vault_id": vault_id, "vault_item_id": item_id}
    fake_cloud.vault.bind_for_other_members(vault_id, item_id, members=1, servers=2)
    service._remote_executor = MagicMock(side_effect=AssertionError("vault deletion must not contact hosts"))
    team_server_name = fake_cloud.vault._shared_servers(team["slug"])[0]["name"]

    app = _ServiceHost(service, instances=[])
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        table = await _open_items(app, screen, 1)
        table.move_cursor(row=0)
        delete_btn = screen.query_one("#vault_delete_key", Button)
        await wait_for_async(lambda: not delete_btn.disabled, desc="delete key enabled")

        delete_btn.press()
        dialog = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, ConfirmActionScreen) and app.screen.has_class("vault_key_unbind")
            and app.screen.query("#confirm_input") else None,
            desc="unbind confirmation",
        )
        text = " ".join(str(w.render()) for w in dialog.query("Static"))
        assert team_server_name in text
        assert "2 server(s) of 1 other member(s)" in text
        await pilot.press("escape")
        await wait_for_async(lambda: app.screen is screen, desc="cancelled")
        assert fake_cloud.requests(method="DELETE") == []

        delete_btn.press()
        dialog = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, ConfirmActionScreen) and app.screen.has_class("vault_key_unbind")
            and app.screen is not dialog and app.screen.query("#confirm_input") else None,
            desc="unbind confirmation reopened",
        )
        dialog.query_one("#confirm_input", Input).value = "UNBIND AND DELETE"
        await wait_for_async(lambda: not dialog.query_one("#btn_confirm", Button).disabled, desc="typed")
        dialog.query_one("#btn_confirm", Button).press()
        await wait_for_async(lambda: len(screen._items) == 0 and not screen._busy_work, desc="key deleted")

    service._remote_executor.assert_not_called()
    assert team_binding not in fake_cloud.vault._bindings
    assert len(fake_cloud.requests(method="DELETE")) == 1
    assert _binding_reads(fake_cloud) == []

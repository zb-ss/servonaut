"""Bitwarden key names survive import and support safe CLI key management."""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from e2e.harness import fleet
from e2e.harness.bitwarden import FakeBitwarden
from e2e.harness.fake_cloud.routes_account import VAULT_SHARED_SERVER_HOST_KEY
from e2e.harness.fake_cloud.routes_vault import TEAM_ROW
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)

pytestmark = [pytest.mark.e2e_pr]


def _json(result) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def test_bitwarden_name_matches_key_pair_then_can_be_renamed_and_safely_deleted(
    journey, fake_cloud, cli, account_home, servonaut_cmd,
):
    _configure_test_custody(journey)
    fake_cloud.account.configure(teams=[dict(TEAM_ROW)])
    home = account_home("vault-key-names")
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(home, "vault", "create", "--team", "example-team", "--name", "Keys", "--json"))["vault_id"]
    bitwarden = FakeBitwarden(journey.shims, tools=("bw",))
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()).decode("ascii")
    public = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    bw_id = bitwarden.add_ssh_key_item(fleet.EDGE_1.key_name, private, public)
    journey.env_overrides["BW_SESSION"] = bitwarden.session
    imported = _json(cli(home, "vault", "import", "bitwarden", "--vault", vault_id, "--item", bw_id, "--json"))
    item_id = imported["item_id"]
    (fetch,) = bitwarden.calls("bw")
    assert fetch.argv == ["get", "item", bw_id]
    listed = _json(cli(home, "vault", "items", "--vault", vault_id, "--names", "--json"))
    assert listed["data"][0]["name"] == fleet.EDGE_1.key_name
    plan = _json(cli(home, "vault", "auto-bind", "--vault", vault_id, "--dry-run", "--json"))
    matched = next(row for row in plan["servers"] if row["instance_id"] == fleet.EDGE_1.instance_id)
    assert matched["vault_item_id"] == item_id and matched["matched_by"] == "key pair"
    renamed = _json(cli(home, "vault", "rename", item_id, "--vault", vault_id, "--name", "Deploy key", "--json"))
    assert renamed["name"] == "Deploy key" and renamed["revision"] == 2
    assert _json(cli(home, "vault", "items", "--vault", vault_id, "--names", "--json"))["data"][0]["name"] == "Deploy key"
    _json(cli(home, "vault", "bind", "server-1", item_id, "--vault", vault_id, "--team", "example-team",
              "--host-key", VAULT_SHARED_SERVER_HOST_KEY, "--yes", "--json"))
    metadata = _json(cli(home, "vault", "show", item_id, "--vault", vault_id, "--json"))
    bound_name = metadata["bound_server_ids"][0]["name"]
    refused = cli(home, "vault", "delete", item_id, "--vault", vault_id, "--yes")
    assert refused.returncode == 1
    assert bound_name in refused.stderr and "another vault key" in refused.stderr
    unused = _json(cli(home, "vault", "import", "bitwarden", "--vault", vault_id, "--item", bw_id,
                       "--name", "Unused key", "--json"))["item_id"]
    deleted = _json(cli(home, "vault", "delete", unused, "--vault", vault_id, "--yes", "--json"))
    assert deleted == {"item_id": unused, "deleted": True}
    remaining = _json(cli(home, "vault", "items", "--vault", vault_id, "--json"))
    assert [row["item_id"] for row in remaining["data"]] == [item_id]
    fake_cloud.assert_absent_on_wire(private, bitwarden.session)

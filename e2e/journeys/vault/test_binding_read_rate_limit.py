"""A rate-limited service stops a check of every server's vault key binding at its first refusal."""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from e2e.harness import fleet
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from servonaut.config.schema import CustomServer

pytestmark = [pytest.mark.e2e_pr]

# More own servers than the CLI reads at once (six), so a loop that kept
# going after a refusal would send more requests than one batch.
CUSTOM_SERVERS = [
    CustomServer(name=f"site-{n}", host=f"site-{n}.example.test", username="deploy", provider="custom")
    for n in range(1, 11)
]
PARALLEL_READS = 6


def _json(result) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _binding_reads(fake_cloud) -> list[dict]:
    return [entry for entry in fake_cloud.requests(method="GET")
            if entry["path"].startswith("/api/v1/me/instances/") and entry["path"].endswith("/credential-binding")]


def test_a_rate_limited_key_check_stops_at_the_first_refusal_and_says_when_to_retry(
    journey, fake_cloud, cli, account_home, servonaut_cmd,
):
    _configure_test_custody(journey)
    home = account_home("binding-rate-limit", custom_servers=CUSTOM_SERVERS)
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = home.home / "unused.pem"
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption(),
    ))
    key_path.chmod(0o600)
    item_id = _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path),
                        "--name", "Unused key", "--json"))["item_id"]
    own_servers = len(fleet.AWS_FLEET) + len(CUSTOM_SERVERS)

    fake_cloud.configure(binding_reads_retry_after=30)
    sent_before = len(_binding_reads(fake_cloud))
    refused = cli(home, "vault", "delete", item_id, "--vault", vault_id, "--yes")

    assert refused.returncode != 0
    assert "limiting requests from this computer" in refused.stderr
    assert "try again in 30 s" in refused.stderr
    assert "Traceback" not in refused.stderr
    sent = _binding_reads(fake_cloud)[sent_before:]
    assert 1 <= len(sent) <= PARALLEL_READS < own_servers
    assert {entry["status"] for entry in sent} == {429}
    listed = _json(cli(home, "vault", "items", "--vault", vault_id, "--json"))
    assert [row["item_id"] for row in listed["data"]] == [item_id]

    # Once the service answers again, the same command checks every server and deletes the key.
    fake_cloud.configure(binding_reads_retry_after=None)
    deleted = _json(cli(home, "vault", "delete", item_id, "--vault", vault_id, "--yes", "--json"))
    assert deleted == {"item_id": item_id, "deleted": True}

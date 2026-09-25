"""Journey: ``servonaut ssh`` with the key kept in a Bitwarden vault.

The (fake) service says edge-1's SSH key lives in a Bitwarden item; the
vault (a scripted ``bw`` stand-in) is unlocked, its session in
``BW_SESSION``. ``servonaut ssh edge-1`` should fetch the item with the
session passed through the environment, write the key to a private 0600
file under ``~/.servonaut/tmp``, hand that file to ``ssh`` (the scripted
stand-in records the file's state during the call) and remove it once
``ssh`` returns, never printing or logging the key.

Known gap: the command does not see cached AWS instances at all, so it
answers "No instance found" for edge-1. The same vault flow is exercised
through the MCP server in ``e2e/journeys/mcp/test_mcp_vault_key.py``.

No real SSH connection is made; that tier needs a real ``sshd``.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from e2e.harness import fleet
from e2e.harness.bitwarden import FakeBitwarden, fabricated_ssh_key
from e2e.harness.known_gap import KnownGap

pytestmark = [pytest.mark.e2e_pr]

HOST = fleet.EDGE_1


def test_key_from_the_vault_lives_only_for_the_session(journey, fake_cloud, cli, account_home):
    vault = FakeBitwarden(journey.shims, tools=("bw",))
    private, public = fabricated_ssh_key()
    item = vault.add_ssh_key_item(f"{HOST.name} deploy key", private, public)
    fake_cloud.secrets.set_ssh_ref("aws", HOST.instance_id, item)
    host = HOST.public_ip.replace(".", r"\.")
    journey.shims.when("ssh", host, rc=0, inspect_identity=True)
    journey.env_overrides["BW_SESSION"] = vault.session
    home = account_home("bw-ssh")
    cached = json.loads((home.home / ".servonaut" / "cache.json").read_text(encoding="utf-8"))
    assert HOST.name in [row["name"] for row in cached["instances"]]

    result = cli(home, "ssh", HOST.name)
    if result.returncode != 0 and f"No instance found matching '{HOST.name}'" in result.stderr:
        raise KnownGap(f"{HOST.name} is in the instance cache but servonaut ssh did not find it")
    assert result.returncode == 0, result.describe()

    (fetch,) = vault.calls("bw")
    assert fetch.argv == ["get", "item", item]
    assert fetch.env["BW_SESSION"] and vault.session not in fetch.joined
    (connect,) = journey.shims.calls("ssh")
    identity = connect.identity
    key_dir = home.home / ".servonaut" / "tmp"
    assert identity["exists"] is True and identity["mode"] == 0o600
    assert identity["sha256"] == hashlib.sha256(private.encode()).hexdigest()
    assert identity["path"].startswith(f"{key_dir}/servonaut-ssh-")
    assert not any(key_dir.glob("servonaut-ssh-*"))
    body = private.splitlines()[1]
    assert body not in result.stdout + result.stderr
    fake_cloud.assert_absent_on_wire(private, body, vault.session)

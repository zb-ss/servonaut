"""Journey: an MCP client runs a command on a host whose key is in Bitwarden.

The (fake) service says edge-1's SSH key lives in a Bitwarden item and the
vault (a scripted ``bw``) is unlocked, its session in ``BW_SESSION``.
``run_command`` fetches the item with the session passed through the
environment, writes the key to a 0600 file under ``~/.servonaut/tmp``,
hands it to ``ssh`` (the scripted stand-in records the file's state during
the call) and removes it as soon as the call returns; the audit trail notes
that the vault key was used. The key never appears in the tool result, a
request or the log.

With a stale session the vault reports itself locked: the tool falls back
to the local key and no key file is ever written.

No real SSH connection is made; that tier needs a real ``sshd``.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from e2e.harness import fleet
from e2e.harness.bitwarden import FakeBitwarden, fabricated_ssh_key

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

HOST = fleet.EDGE_1
UPTIME = " 10:00:00 up 3 days,  1 user,  load average: 0.01, 0.02, 0.00\n"


def _vault_with_key(journey, fake_cloud) -> tuple[FakeBitwarden, str, str]:
    vault = FakeBitwarden(journey.shims, tools=("bw",))
    private, public = fabricated_ssh_key()
    item = vault.add_ssh_key_item(f"{HOST.name} deploy key", private, public)
    fake_cloud.secrets.set_ssh_ref("aws", HOST.instance_id, item)
    host = HOST.public_ip.replace(".", r"\.")
    journey.shims.when("ssh", f"{host}.*uptime", stdout=UPTIME, inspect_identity=True)
    return vault, item, private


def _key_files(home) -> list:
    tmp = home / ".servonaut" / "tmp"
    return sorted(p.name for p in tmp.iterdir()) if tmp.exists() else []


def _audit(home) -> list[dict]:
    path = home / ".servonaut" / "mcp_audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


async def test_run_command_uses_the_vault_key_per_call(mcp, journey, fake_cloud, account_home):
    vault, item, private = _vault_with_key(journey, fake_cloud)
    journey.env_overrides["BW_SESSION"] = vault.session
    home = account_home("mcp-vault-key")

    async with mcp(home) as session:
        result = await session.call(
            "run_command", {"instance_id": HOST.name, "command": "uptime"}
        )
        assert UPTIME.strip() in result
        # The key file is gone as soon as the call has returned.
        assert _key_files(home.home) == []

    (fetch,) = vault.calls("bw")
    assert fetch.argv == ["get", "item", item]
    assert fetch.env["BW_SESSION"] and vault.session not in fetch.joined

    (connect,) = journey.shims.calls("ssh")
    identity = connect.identity
    key_dir = home.home / ".servonaut" / "tmp"
    assert identity["exists"] is True
    assert identity["mode"] == 0o600
    assert identity["sha256"] == hashlib.sha256(private.encode()).hexdigest()
    assert identity["path"].startswith(f"{key_dir}/bw-")
    assert (key_dir.stat().st_mode & 0o777) == 0o700

    (row,) = [r for r in _audit(home.home) if r.get("tool") == "run_command"]
    assert row.get("key_source") == "bw_personal"

    body = private.splitlines()[1]
    assert body not in result
    assert body not in json.dumps(fake_cloud.requests())
    log = home.home / ".servonaut" / "logs" / "servonaut.log"
    assert not log.exists() or body not in log.read_text(encoding="utf-8")


async def test_locked_vault_falls_back_to_the_local_key(mcp, journey, fake_cloud, account_home):
    vault, item, _ = _vault_with_key(journey, fake_cloud)
    journey.env_overrides["BW_SESSION"] = "bw-session-fake-stale"
    home = account_home("mcp-vault-locked")

    async with mcp(home) as session:
        result = await session.call(
            "run_command", {"instance_id": HOST.name, "command": "uptime"}
        )
    assert UPTIME.strip() in result
    assert [call.argv for call in vault.calls("bw")] == [["get", "item", item]]
    (connect,) = journey.shims.calls("ssh")
    assert connect.identity is None or "/bw-" not in connect.identity["path"]
    assert _key_files(home.home) == []
    (row,) = [r for r in _audit(home.home) if r.get("tool") == "run_command"]
    assert "key_source" not in row

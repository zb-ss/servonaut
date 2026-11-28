"""Journey: the MCP server reads a teammate's shared memory with the key kept in the vault.

Memory Sync is set up in the vault (no passphrase anywhere). A teammate's
memory for the team's db-1 is shared with the account, its data key sealed to the
account's Memory Sync public key. ``servonaut --mcp`` (a child process with the
vault's device key and no keychain) unlocks the key from the vault by itself:
``get_server_memory`` returns the teammate's module, and no key, passphrase or
plaintext crosses the wire.

With the device key removed the vault cannot be opened: the tool says the key is
kept in the vault and what to do about it (never the 30-day option of the
passphrase flow), and the audit row carries ``shared_memory_locked_vault_locked``.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness.vault_custody import seed_incoming_share, setup_vault
from e2e.journeys.custody.wi12b_support import set_up_in_vault

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio, pytest.mark.xdist_group("custody-mcp")]

SLUG = "ops"
TEAM = {"id": "team-ops", "slug": SLUG, "name": "Ops", "role": "member", "member_count": 2}
# A server only the team has: the account's own fleet does not list it.
SHARED_DB = {
    "id": "srv-9", "name": "db-1", "hostname": "db-1.example.com", "port": 22,
    "login_user": "deploy", "username": "deploy", "instance_id": "i-teammate-db-1", "status": "active",
}
REFERENCE = f"{SLUG}/db-1"
TEAMMATE_ID = 7001  # not the account's own id
MARKER = "teammate-vault-marker-5b1e"


def _audit(home) -> list[dict]:
    path = home / ".servonaut" / "mcp_audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


async def test_get_server_memory_reads_the_share_with_the_vault_key(
    tui, mcp, seed, fake_cloud, journey, servonaut_cmd, custody_device, signed_in_home, monkeypatch,
):
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[TEAM], shared_servers={SLUG: [dict(SHARED_DB)]})
    signed_in_home()
    setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)
    async with tui() as t:
        await set_up_in_vault(t)
    key = fake_cloud.memory.enrolled_key()
    assert key["custody"] == "vault"
    # The team's key directory lists the account once its key is registered.
    fake_cloud.memory.add_team_member(SLUG, fake_cloud.entitlements()["user_id"], key["public_key"])

    seed_incoming_share(
        fake_cloud, team_slug=SLUG, from_user_id=TEAMMATE_ID, instance_id=SHARED_DB["instance_id"],
        module="os", observed={"distro": MARKER},
    )
    home = journey.ctx.sandbox

    async with mcp(home) as session:
        result = await session.call("get_server_memory", {"instance_id": REFERENCE})
    assert MARKER in result, result
    rows = [r for r in _audit(home.home) if r.get("tool") == "get_server_memory"]
    assert rows and rows[-1]["allowed"] is True
    assert not (home.home / ".servonaut" / "memory" / "keys.json").exists()
    fake_cloud.assert_absent_on_wire(MARKER)

    # No device key: the vault cannot be opened, and the tool says so.
    journey.env_overrides.pop("SERVONAUT_VAULT_DEVICE_KEY")
    async with mcp(home) as session:
        locked = await session.call("get_server_memory", {"instance_id": REFERENCE})
    assert MARKER not in locked
    assert "kept in your vault" in locked and "SERVONAUT_VAULT_DEVICE_KEY" in locked
    assert "30 days" not in locked
    last = [r for r in _audit(home.home) if r.get("tool") == "get_server_memory"][-1]
    assert last.get("reason") == "shared_memory_locked_vault_locked", last

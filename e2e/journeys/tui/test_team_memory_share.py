"""Journey: share an instance's memory with a team.

On a Teams plan, with app-1's memory synced through Memory Sync, the user
opens Fleet Memory, picks app-1 and shares it with the "ops" team. The
client fetches the members' public keys, re-wraps each stored envelope's
data key for every member the chosen role admits, and creates the grant;
the service never sees a data key in the clear. A teammate holding only
their own private key can then open app-1's shared envelopes, while the
plaintext never crossed the wire. Sharing the same instance again is
refused, and the screen says why.

No screen lists a team's grants yet, so the journey reads the grant the
(fake) service recorded.
"""

from __future__ import annotations

import base64
import json

import pytest

from e2e.harness import fleet
from e2e.harness.memory_seed import seed_memory
from e2e.harness.memory_sync import (
    PASSPHRASE,
    PASSPHRASE_ENV,
    open_envelope,
    open_memory_sync,
    plain,
    sync_all,
    unlock,
)
from e2e.harness.session_seed import seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

HOST = fleet.APP_1
TEAM = "ops"
TEAMMATE = 5151
MARKER = "e2e-share-marker-2b9d"
MODULES = {
    "os": {"distro": "Debian 12", "marker": MARKER},
    "services": {"nginx": "1.24.0", "marker": MARKER},
}


def _teammate(fake_cloud) -> tuple[bytes, bytes]:
    import nacl.public

    key = nacl.public.PrivateKey.generate()
    public = bytes(key.public_key)
    fake_cloud.memory.add_team_member(
        TEAM, TEAMMATE, base64.b64encode(public).decode(), role="member"
    )
    return public, bytes(key)


def _fleet_rows(t) -> list[list[str]]:
    """Name, id, source and memory columns of the Fleet Memory table."""
    return [
        [plain(row[i]) for i in (0, 1, 3, 4)] for row in t.table_rows("#fleet-memory-table")
    ]


async def _share(t) -> None:
    await t.nav("nav_memory")
    await t.wait_for_screen("FleetMemoryScreen")
    await t.wait_until(
        lambda: _fleet_rows(t) == [[HOST.name, HOST.instance_id, "synced", "● Fresh"]],
        desc="app-1 probed here and synced",
    )
    await t.press("S")
    await t.wait_for_screen("ShareInstanceScreen")
    select = t.on_screen("#share-team-select")
    await t.wait_until(lambda: select.value == TEAM, desc="team loaded")
    button = t.on_screen("#share-btn-confirm")
    await t.wait_until(lambda: not button.disabled, desc="Share enabled")
    await t.click(button)


async def test_share_memory_with_the_team(tui, seed, fake_cloud, monkeypatch):
    fake_cloud.configure(plan="teams", mcp_connections=0)
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    seed_memory(seed.home, HOST, MODULES)
    teammate = _teammate(fake_cloud)
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)

    async with tui() as t:
        await open_memory_sync(t)
        await unlock(t)
        assert await sync_all(t) == "Synced 2 envelope(s)."
        before_share = len(fake_cloud.requests())

        await _share(t)
        await t.wait_for_toast(rf"^Shared {HOST.instance_id} with team {TEAM}\.$")
        await t.wait_for_screen("FleetMemoryScreen")

        (grant,) = fake_cloud.memory.grants(TEAM)
        assert (grant["instance_id"], grant["required_role"], grant["status"]) == (
            HOST.instance_id, "viewer", "active"
        )
        assert set(grant["modules"]) >= set(MODULES)
        # One wrap per stored envelope for each member: the owner and the
        # teammate (a member outranks the required viewer role).
        stored = {e["id"]: e for e in fake_cloud.memory.envelopes(HOST.instance_id)}
        owner = fake_cloud.entitlements()["user_id"]
        assert sorted((w["envelope_id"], w["recipient_user_id"]) for w in grant["wraps"]) == sorted(
            (envelope_id, user) for envelope_id in stored for user in (owner, TEAMMATE)
        )

        # The teammate opens every shared envelope with their own key ...
        for wrap in (w for w in grant["wraps"] if w["recipient_user_id"] == TEAMMATE):
            envelope = dict(stored[wrap["envelope_id"]])
            envelope["dek_wraps"] = [
                {"recipient_user_id": TEAMMATE, "wrapped_dek": wrap["wrapped_dek"]}
            ]
            opened = open_envelope(envelope, TEAMMATE, teammate)
            assert opened["observed"] == MODULES[envelope["module"]]
        # ... yet nothing readable crossed the wire while sharing.
        assert MARKER not in json.dumps(fake_cloud.requests()[before_share:])

        # A second share of the same instance is refused, with the reason.
        await _share(t)
        await t.wait_until(
            lambda: "Share failed: A live grant already exists"
            in plain(t.on_screen("#share-status").render()),
            desc="refusal shown",
        )
        assert len(fake_cloud.memory.grants(TEAM)) == 1

"""Journey: share an instance's memory with a team.

On a Teams plan, with app-1's memory synced through Memory Sync, the user
opens Fleet Memory, picks app-1 and shares it with the "ops" team. The
client fetches the members' public keys, re-wraps each stored envelope's
data key for every member the chosen role admits, and creates the grant.
A teammate holding only their own private key can then open app-1's shared
envelopes, while neither the plaintext nor any data or private key crossed
the wire, in any encoding. Sharing the same instance again is refused, and
the screen says why.

Known gap: deselecting a module on the share screen names fewer modules in
the grant, but the client still wraps the data keys of every module for
the team, so the deselected module stays readable to it. The (fake)
service refuses such a grant.

No screen lists a team's grants yet, so the journey reads the grant the
(fake) service recorded.
"""

from __future__ import annotations

import base64

import pytest

from e2e.harness import fleet
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.known_gap import KnownGap
from e2e.harness.memory_seed import seed_memory
from e2e.harness.memory_sync import (
    PASSPHRASE,
    enrolled_keypair,
    envelope_key,
    open_envelope,
    open_memory_sync,
    plain,
    sync_all,
    unlock,
    use_passphrase,
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
GRANT_PATH = f"/api/v1/teams/{TEAM}/memory/grant"
# First set-up on a fresh device, then pulls of notes that were never made.
FIRST_SYNC = expected("no secret store on file", "no keypair enrolled", "no notes to pull")


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


async def _open_share(t) -> None:
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


async def _confirm_share(t) -> None:
    """Tab to Share and press Enter (toasts may cover the button's corner)."""
    button = t.on_screen("#share-btn-confirm")
    await t.wait_until(lambda: not button.disabled, desc="Share enabled")
    for _ in range(12):
        if button.has_focus:
            break
        await t.press("tab")
    assert button.has_focus, t.focused_id()
    await t.press("enter")


async def _deselect(t, module: str) -> None:
    """Tab to the module list, move to *module* and toggle it off."""
    modules = t.on_screen("#share-modules-list")
    for _ in range(8):
        if modules.has_focus:
            break
        await t.press("tab")
    assert modules.has_focus, t.focused_id()
    target = [modules.get_option_at_index(i).value for i in range(modules.option_count)].index(
        module
    )
    await t.wait_until(lambda: modules.highlighted is not None, desc="a module highlighted")
    while modules.highlighted != target:
        await t.press("down" if modules.highlighted < target else "up")
    await t.press("space")
    await t.wait_until(lambda: module not in modules.selected, desc=f"{module} deselected")


async def _synced(t) -> None:
    await open_memory_sync(t)
    await unlock(t)
    assert await sync_all(t) == "Synced 2 envelope(s)."


def _seed(seed, fake_cloud, monkeypatch) -> tuple[bytes, bytes]:
    fake_cloud.configure(plan="teams", mcp_connections=0)
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    seed_memory(seed.home, HOST, MODULES)
    use_passphrase(monkeypatch)
    return _teammate(fake_cloud)


def _teammate_opens(fake_cloud, grant: dict, teammate: tuple[bytes, bytes]) -> dict:
    """What the teammate can decrypt with the wraps the grant gave them."""
    stored = {e["id"]: e for e in fake_cloud.memory.envelopes(HOST.instance_id)}
    opened = {}
    for wrap in (w for w in grant["wraps"] if w["recipient_user_id"] == TEAMMATE):
        envelope = dict(stored[wrap["envelope_id"]])
        envelope["dek_wraps"] = [
            {"recipient_user_id": TEAMMATE, "wrapped_dek": wrap["wrapped_dek"]}
        ]
        opened[envelope["module"]] = open_envelope(envelope, TEAMMATE, teammate)["observed"]
    return opened


async def test_share_memory_with_the_team(tui, seed, fake_cloud, monkeypatch):
    teammate = _seed(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        await _synced(t)
        await _open_share(t)
        await _confirm_share(t)
        await t.wait_for_toast(rf"^Shared {HOST.instance_id} with team {TEAM}\.$")
        await t.wait_for_screen("FleetMemoryScreen")

        (grant,) = fake_cloud.memory.grants(TEAM)
        assert (grant["instance_id"], grant["required_role"], grant["status"]) == (
            HOST.instance_id, "viewer", "active"
        )
        assert set(grant["modules"]) >= set(MODULES)
        # One wrap per stored envelope for each member: the owner and the
        # teammate (a member outranks the required viewer role).
        stored = fake_cloud.memory.envelopes(HOST.instance_id)
        owner = fake_cloud.entitlements()["user_id"]
        assert sorted((w["envelope_id"], w["recipient_user_id"]) for w in grant["wraps"]) == sorted(
            (e["id"], user) for e in stored for user in (owner, TEAMMATE)
        )
        # The teammate opens every shared envelope with their own key ...
        assert _teammate_opens(fake_cloud, grant, teammate) == MODULES
        # ... yet no plaintext, data key or private key crossed the wire.
        keypair = enrolled_keypair(fake_cloud)
        data_keys = [envelope_key(e, owner, keypair[1]) for e in stored]
        fake_cloud.assert_absent_on_wire(MARKER, PASSPHRASE, keypair[1], teammate[1], *data_keys)

        # A second share of the same instance is refused, with the reason.
        await _open_share(t)
        await _confirm_share(t)
        await t.wait_until(
            lambda: "Share failed: A live grant already exists"
            in plain(t.on_screen("#share-status").render()),
            desc="refusal shown",
        )
        assert len(fake_cloud.memory.grants(TEAM)) == 1
    fake_cloud.assert_no_unexpected_errors(*FIRST_SYNC, ("POST", GRANT_PATH, 409))


@pytest.mark.xfail(
    strict=True,
    raises=KnownGap,
    reason="the client wraps every module's data key for the team, including "
    "modules deselected on the share screen",
)
async def test_share_only_the_selected_modules(tui, seed, fake_cloud, monkeypatch):
    teammate = _seed(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        await _synced(t)
        await _open_share(t)
        await _deselect(t, "services")
        await _confirm_share(t)
        outcome = await t.wait_until(
            lambda: fake_cloud.requests(GRANT_PATH, "POST"), desc="the grant request"
        )
        services = {e["id"] for e in fake_cloud.memory.envelopes(HOST.instance_id, "services")}
        sent = outcome[-1]["body"]
        if outcome[-1]["status"] == 422 and any(
            w["envelope_id"] in services for w in sent["wraps"]
        ):
            await t.wait_until(
                lambda: "Share failed" in plain(t.on_screen("#share-status").render()),
                desc="refusal shown",
            )
            raise KnownGap("the deselected module's data key was wrapped for the team")
        await t.wait_for_toast(rf"^Shared {HOST.instance_id} with team {TEAM}\.$")

    (grant,) = fake_cloud.memory.grants(TEAM)
    assert "services" not in grant["modules"] and "os" in grant["modules"]
    assert not any(w["envelope_id"] in services for w in grant["wraps"])
    assert _teammate_opens(fake_cloud, grant, teammate) == {"os": MODULES["os"]}
    fake_cloud.assert_no_unexpected_errors(*FIRST_SYNC)

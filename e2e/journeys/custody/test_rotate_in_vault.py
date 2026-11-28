"""Journey: rotating the Memory Sync key while it is kept in the vault.

With Memory Sync set up in the vault and two modules uploaded, "Rotate keypair"
asks one question (no passphrase), then: a next ``memory_key`` item is made in
the vault, the service switches to the new key (the old row is kept as rotated),
local memory is uploaded again under the new key, and the old item is kept
because older envelopes still carry wraps for it. A second rotation inside that
window is refused with the client's own wording (never the service's), and
changes nothing. Once the history window has passed (the control prunes it) the
next rotation deletes the old item and succeeds.
"""

from __future__ import annotations

import re

import httpx
import pytest

from e2e.harness.fake_cloud.routes_memory import KEYS_PATH
from e2e.harness.memory_sync import status
from e2e.journeys.custody.wi12b_support import (
    HOST, live_memory_items, seed_probed_memory, set_up_in_vault, settle_card, synced,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio, pytest.mark.xdist_group("custody-rotate")]

KEPT = "Your previous key stays in your vault until older memory ages out."
BLOCKED = (
    "Your previous Memory Sync key is still needed for older memory, so it cannot be "
    "changed again yet. Try again after that memory ages out."
)
SERVICE_WORDING = "Your vault already holds two items of this type."
ROTATE_PATH = f"{KEYS_PATH}/rotate"


async def _rotate(t, expect: str, *, refused: bool = False) -> str:
    """Press Rotate keypair, confirm, and return the toast matching *expect*."""
    await settle_card(t, "#msync_btn_rotate")
    seen = len(t.toasts())  # earlier rotations' toasts stay in the list
    await t.click("#msync_btn_rotate")
    await t.wait_for_text("Rotate keypair", "new Memory Sync key", screen_only=True)
    assert "PassphraseEnrolModal" not in t.opened_screens()
    await t.click("#btn_confirm_yes")
    regex = re.compile(expect)
    toast = await t.wait_until(
        lambda: next((m for _, m in t.toasts()[seen:] if regex.search(m)), None),
        desc=f"a new toast /{expect}/",
    )
    if not refused:
        # A refused rotation leaves the busy line on the status row (reported
        # as a product bug), so only a finished one is checked for it.
        await t.wait_until(lambda: status(t) == "● Active", desc="active after the rotation")
    await settle_card(t, "#msync_btn_rotate")
    return toast


def _latest_wrap_fingerprints(fake_cloud, user_id: int) -> set[str]:
    """The key each module's newest envelope is sealed to, for the account."""
    newest = {}
    for envelope in fake_cloud.memory.envelopes(HOST.instance_id):
        newest[envelope["module"]] = envelope
    return {
        w["fingerprint"] for e in newest.values() for w in e["dek_wraps"]
        if w["recipient_user_id"] == user_id
    }


async def test_rotation_keeps_the_old_item_until_older_memory_ages_out(
    tui, seed, fake_cloud, journey, servonaut_cmd, custody_device, signed_in_home, monkeypatch,
):
    # Set-up and each rotation attempt (a refused one too) look the key up once
    # more, so three rotations use up the client's 3-per-hour budget for that
    # call (the service allows 20). The budget is lifted here so the journey
    # reaches the part it is about; the tight budget is reported separately.
    from servonaut.services.memory import rate_limiter

    monkeypatch.setitem(
        rate_limiter._LIMITS, rate_limiter.RateLimitKey.KEYS_ME,
        rate_limiter._Window(capacity=1000, period_seconds=3600.0),
    )
    signed_in_home()
    seed_probed_memory(seed)
    from e2e.harness.vault_custody import setup_vault

    setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)
    user_id = fake_cloud.entitlements()["user_id"]

    async with tui() as t:
        await set_up_in_vault(t)
        assert (await synced(t)).startswith("Synced ")
        first = fake_cloud.memory.enrolled_key()
        assert live_memory_items(fake_cloud) == [first["fingerprint"]]

        # 1. Rotation: new key, new item, old item kept, memory uploaded again.
        toast = await _rotate(t, r"^Keypair rotated\.")
        assert KEPT in toast
        second = fake_cloud.memory.enrolled_key()
        assert second["id"] != first["id"] and second["fingerprint"] != first["fingerprint"]
        assert second["custody"] == "vault" and second["wrapped_private_key"] is None
        assert [k["fingerprint"] for k in fake_cloud.memory.key_history()] == [first["fingerprint"]]
        assert sorted(live_memory_items(fake_cloud)) == sorted([first["fingerprint"], second["fingerprint"]])
        rotations = fake_cloud.requests(ROTATE_PATH, "POST")
        assert [r["status"] for r in rotations] == [201]
        assert "wrapped_private_key" not in rotations[0]["body"] or rotations[0]["body"]["wrapped_private_key"] is None
        assert _latest_wrap_fingerprints(fake_cloud, user_id) == {second["fingerprint"]}

        # 2. A second rotation inside the window: the client's own text, nothing changed.
        toast = await _rotate(t, r"cannot be changed again yet", refused=True)
        assert toast == BLOCKED and SERVICE_WORDING not in toast
        assert fake_cloud.memory.enrolled_key()["id"] == second["id"]
        assert len(fake_cloud.requests(ROTATE_PATH, "POST")) == 1
        assert len(live_memory_items(fake_cloud)) == 2

        # 3. The history window passes: the old key is no longer needed.
        with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as http:
            pruned = http.post("/__e2e/memory/prune-history", json={"older_than_seconds": 0}).json()
        assert pruned["envelopes_removed"] >= 1
        assert not fake_cloud.memory.key_in_use(user_id, first["fingerprint"])

        toast = await _rotate(t, r"^Keypair rotated\.")
        assert KEPT in toast  # the second key is still needed for older envelopes
        third = fake_cloud.memory.enrolled_key()
        assert third["fingerprint"] not in (first["fingerprint"], second["fingerprint"])
        remaining = live_memory_items(fake_cloud)
        assert first["fingerprint"] not in remaining  # deleted this time
        assert sorted(remaining) == sorted([second["fingerprint"], third["fingerprint"]])
        assert [r["status"] for r in fake_cloud.requests(ROTATE_PATH, "POST")] == [201, 201]

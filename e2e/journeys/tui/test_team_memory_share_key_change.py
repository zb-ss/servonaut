"""Journey: sharing a server with a teammate whose memory key changed.

The service flags a member for good once they replaced their key, and the
client used to refuse every share that included such a member. Now:

* Share opens a confirmation instead. Cancel sends nothing and says who
  cannot read the share; ticking the member's key and pressing "Trust and
  share" shares it with a wrap the teammate opens with their NEW key;
* when a teammate replaces their key after the share, the share's panel says
  their key is waiting, "Review changed keys" confirms it and seals the
  latest snapshots for the new key, without revoking anything.
"""

from __future__ import annotations

import base64
import hashlib
import re

import nacl.public
import pytest

from e2e.harness.memory_sync import open_envelope, plain
from e2e.journeys.tui.test_team_memory_share import (
    FIRST_SYNC,
    GRANT_PATH,
    HOST,
    TEAM,
    TEAMMATE,
    _confirm_share,
    _open_share,
    _seed,
    _synced,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

NAME = f"member {TEAMMATE}"
WRAPS_PATH = f"/api/v1/teams/{TEAM}/memory/grant/{{}}/wraps"


def _rotate(fake_cloud) -> tuple[bytes, bytes]:
    """The teammate replaces their key; returns the new (public, private) pair."""
    key = nacl.public.PrivateKey.generate()
    public = bytes(key.public_key)
    fake_cloud.memory.rotate_member_key(TEAM, TEAMMATE, base64.b64encode(public).decode())
    return public, bytes(key)


def _opens_with(fake_cloud, grant: dict, private: bytes, public: bytes) -> dict:
    """What the teammate decrypts with the wraps made for the key they hold now."""
    stored = {e["id"]: e for e in fake_cloud.memory.envelopes(HOST.instance_id)}
    opened = {}
    current = hashlib.sha256(public).hexdigest()
    for wrap in (w for w in grant["wraps"]
                 if w["recipient_user_id"] == TEAMMATE and w.get("fingerprint") == current):
        envelope = dict(stored[wrap["envelope_id"]])
        envelope["dek_wraps"] = [{"recipient_user_id": TEAMMATE, "wrapped_dek": wrap["wrapped_dek"]}]
        opened[envelope["module"]] = open_envelope(envelope, TEAMMATE, (public, private))["observed"]
    return opened


async def _tick_and_trust(t) -> None:
    await t.wait_for_screen("MemberKeyChangeScreen")
    await t.click("#keychange-check-0")
    button = t.on_screen("#keychange-btn-confirm")
    await t.wait_until(lambda: not button.disabled, desc="the confirm button enabled")
    await t.click(button)


async def test_a_rotated_member_is_confirmed_before_the_share(tui, seed, fake_cloud, monkeypatch):
    _seed(seed, fake_cloud, monkeypatch)
    new_public, new_private = _rotate(fake_cloud)
    async with tui() as t:
        await _synced(t)
        await _open_share(t)
        await _confirm_share(t)

        await t.wait_for_screen("MemberKeyChangeScreen")
        await t.wait_for_text(NAME, "New key:", "Key fingerprint", screen_only=True)
        confirm = t.on_screen("#keychange-btn-confirm")
        assert confirm.disabled and plain(confirm.label) == "Trust and share"

        # Cancel (Escape) sends nothing and says who cannot read it.
        await t.press("escape")
        await t.wait_for_screen("ShareInstanceScreen")
        status = t.on_screen("#share-status")
        await t.wait_until(
            lambda: plain(status.render())
            == f"Nothing was changed. {NAME} cannot read it until you confirm the new key.",
            desc="the cancel message")
        assert not fake_cloud.requests(GRANT_PATH, "POST")

        # Share again, tick the key, trust it: the grant holds a wrap for the new key.
        await _confirm_share(t)
        await _tick_and_trust(t)
        await t.wait_for_toast(rf"^Shared {re.escape(HOST.name)} with team Ops\.$")
        await t.wait_for_screen("FleetMemoryScreen")
        (grant,) = fake_cloud.memory.grants(TEAM)
        assert grant["status"] == "active"
        opened = _opens_with(fake_cloud, grant, new_private, new_public)
        assert set(opened) >= {"os", "services"}
    fake_cloud.assert_no_unexpected_errors(*FIRST_SYNC)


async def test_a_member_who_rotates_after_the_share_is_reviewed_and_topped_up(
        tui, seed, fake_cloud, monkeypatch):
    _seed(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        await _synced(t)
        await _open_share(t)
        await _confirm_share(t)
        await t.wait_for_screen("FleetMemoryScreen")
        (grant,) = fake_cloud.memory.grants(TEAM)

        new_public, new_private = _rotate(fake_cloud)
        await t.press("S")
        await t.wait_for_screen("ShareInstanceScreen")
        panel = t.on_screen("#share-existing")
        await t.wait_until(lambda: panel.has_class("-shown"), desc="the existing share shown")
        line = t.on_screen("#share-existing-text")
        await t.wait_until(
            lambda: f"Key changed, waiting for your confirmation: {NAME}" in plain(line.render()),
            desc="the waiting line")

        await t.click("#share-btn-keys")
        await _tick_and_trust(t)
        await t.wait_for_toast(rf"^The latest snapshots are shared with {NAME} now\.$")
        await t.wait_until(
            lambda: "waiting" not in plain(t.on_screen("#share-existing-text").render()),
            desc="the waiting line gone")

        assert len(fake_cloud.requests(WRAPS_PATH.format(grant["id"]), "POST")) == 1
        # The share itself was not touched.
        assert not fake_cloud.requests(f"/api/v1/teams/{TEAM}/memory/grant/{grant['id']}", "DELETE")
        (live,) = fake_cloud.memory.grants(TEAM)
        stamped = {w["fingerprint"] for w in live["wraps"] if w["recipient_user_id"] == TEAMMATE
                   and w["fingerprint"] == hashlib.sha256(new_public).hexdigest()}
        assert stamped  # a wrap exists for the new key
        opened = _opens_with(fake_cloud, live, new_private, new_public)
        assert set(opened) >= {"os", "services"}

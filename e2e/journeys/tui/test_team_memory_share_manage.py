"""Journey: the owner changes and withdraws a team's access to a server's memory.

With app-1 shared with the "ops" team, the owner opens the Share form again.
It shows the share that exists (role, modules) instead of offering a second
one, and:

* Share again revokes it and then shares anew with the same role and
  modules, in that order, and never purges;
* Revoke stops the sharing and leaves the members' copies alone;
* "Revoke and delete members' copies" asks first: Cancel changes nothing,
  and only the confirmation calls the service, which then drops the
  teammate's wraps while the owner's own stay.

Before this change the form offered a second grant the service refused
(``grant_exists``) and nothing in the app could revoke or purge.
"""

from __future__ import annotations

import pytest

from e2e.harness.memory_sync import plain
from e2e.journeys.tui.test_team_memory_share import (
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

GRANTS = f"/api/v1/teams/{TEAM}/memory/grant"


def _writes(fake_cloud) -> list[tuple[str, str]]:
    """Method and path of every grant-changing request, oldest first."""
    return [
        (r["method"], r["path"])
        for r in fake_cloud.requests()
        if r["path"].startswith(GRANTS) and r["method"] in ("POST", "DELETE")
    ]


async def _open_existing_share(t) -> None:
    await t.press("S")
    await t.wait_for_screen("ShareInstanceScreen")
    panel = t.on_screen("#share-existing")
    await t.wait_until(lambda: panel.has_class("-shown"), desc="the existing share shown")


async def test_the_owner_changes_and_withdraws_a_share(tui, seed, fake_cloud, monkeypatch):
    _seed(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        await _synced(t)
        await _open_share(t)
        await _confirm_share(t)
        await t.wait_for_screen("FleetMemoryScreen")
        (first,) = fake_cloud.memory.grants(TEAM)

        # Share again: revoke, then grant, with the settings of the share that exists.
        await _open_existing_share(t)
        text = plain(t.on_screen("#share-existing-text").render())
        assert "role viewer" in text and "os" in text
        await t.click("#share-btn-reshare")
        await t.wait_for_screen("FleetMemoryScreen")
        assert _writes(fake_cloud)[-2:] == [
            ("DELETE", f"{GRANTS}/{first['id']}"),
            ("POST", GRANT_PATH),
        ]
        old, new = fake_cloud.memory.grants(TEAM)
        assert (old["status"], new["status"]) == ("revoked", "active")
        assert (new["required_role"], sorted(new["modules"])) == (
            first["required_role"], sorted(first["modules"]))
        assert not any(w.endswith("/purge") for _, w in _writes(fake_cloud))

        # Revoke stops the sharing; nothing is purged.
        await _open_existing_share(t)
        await t.click("#share-btn-revoke")
        await t.wait_until(lambda: not t.on_screen("#share-existing").has_class("-shown"),
                           desc="the revoked share gone from the form")
        assert fake_cloud.memory.grants(TEAM)[-1]["status"] == "revoked"
        assert not any(w.endswith("/purge") for _, w in _writes(fake_cloud))
        await t.press("escape")
        await t.wait_for_screen("FleetMemoryScreen")

        # Shared once more, then withdrawn together with the members' copies.
        await t.press("S")
        await t.wait_for_screen("ShareInstanceScreen")
        await _confirm_share(t)
        await t.wait_for_screen("FleetMemoryScreen")
        live = [g for g in fake_cloud.memory.grants(TEAM) if g["status"] == "active"][-1]
        assert any(w["recipient_user_id"] == TEAMMATE for w in live["wraps"])

        await _open_existing_share(t)
        await t.click("#share-btn-purge")
        await t.wait_for_screen("PurgeCopiesModal")
        before = len(_writes(fake_cloud))
        await t.click("#purge-btn-cancel")
        await t.wait_for_screen("ShareInstanceScreen")
        assert len(_writes(fake_cloud)) == before  # Cancel changed nothing
        assert any(w["recipient_user_id"] == TEAMMATE
                   for w in fake_cloud.memory.grants(TEAM)[-1]["wraps"])

        await t.click("#share-btn-purge")
        await t.wait_for_screen("PurgeCopiesModal")
        await t.click("#purge-btn-confirm")
        await t.wait_until(
            lambda: any(w.endswith("/purge") for _, w in _writes(fake_cloud)), desc="purge sent")
        final = fake_cloud.memory.grants(TEAM)[-1]
        assert final["status"] == "revoked"
        assert not any(w["recipient_user_id"] == TEAMMATE for w in final["wraps"])
        assert any(w["recipient_user_id"] != TEAMMATE for w in final["wraps"])  # the owner's stay

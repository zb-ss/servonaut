"""Journey: Memory Sync, from unlock to drift, against the (fake) service.

Signed in on a Solo plan, with two modules of app-1 probed on this device
before Memory Sync was set up (plus an operator note and an agent finding),
the user opens Memory Sync and unlocks it with the passphrase from
``SERVONAUT_MEMORY_PASSPHRASE``: a keypair is made on the device, its
private half wrapped with the passphrase, and enrolled. "Sync all local
memory" backfills everything and drains it to the service as envelopes it
cannot read: no probed value, note, passphrase or key crosses the wire in
any encoding, yet the key the client enrolled (unwrapped with the
passphrase) opens every envelope, each under its own data key and nonce.
The note and the finding come back from the service after the sync, as
they would on another device. After a re-probe and a second sync the service
reports drift on one module; the Drift Events screen lists it and
acknowledges it. Opening the event's decrypted diff is a known gap (Enter
on the highlighted event does nothing).

A restart finds the store locked. A wrong passphrase is refused with a
clear message; the right one unlocks from the local key cache, without
asking the service for the key again.

"Remember on this device" needs a real OS keychain (the harness keyring is
the null backend), so it is left to a nightly run with a Secret Service.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.fake_cloud.routes_memory import KEYS_PATH, SYNC_PATH
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.known_gap import KnownGap
from e2e.harness.memory_seed import seed_memory, seed_notes
from e2e.harness.memory_sync import (
    PASSPHRASE,
    enrolled_keypair,
    envelope_key,
    open_envelope,
    open_memory_sync,
    plain,
    status,
    sync_all,
    unlock,
    use_passphrase,
)
from e2e.harness.pilot import JourneyTimeout
from e2e.harness.session_seed import seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WRONG_PASSPHRASE = "Wrong-Horse-Battery-Staple-2030!!"
# Probed values that must never reach the service in the clear.
MARKER = "e2e-probe-marker-7f3a"
HOST = fleet.APP_1
OS_MODULE = {"distro": "Ubuntu 24.04 LTS", "kernel": "6.8.0-e2e", "marker": MARKER}
SERVICES_V1 = {"nginx": "1.24.0", "php-fpm": "8.3", "marker": MARKER}
SERVICES_V2 = {"nginx": "1.26.1", "php-fpm": "8.3", "marker": MARKER}
NOTE = "Restart php-fpm after deploys (e2e-note-marker-4c1b)"
FINDING = "The cache warmer overloads the box at 03:00 (e2e-finding-marker-9d20)"
MODULES = ["annotations", "findings", "os", "services"]
# Every journey here starts with no secret store and no keypair.
FIRST_RUN = expected("no secret store on file", "no keypair enrolled")


def _seed(seed, fake_cloud) -> None:
    # The relay is not part of these journeys: keep it off.
    fake_cloud.configure(mcp_connections=0)
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    seed_memory(seed.home, HOST, {"os": OS_MODULE, "services": SERVICES_V1})
    seed_notes(seed.home, HOST, annotations=NOTE, finding=FINDING)


async def _drift_after_reprobe(t, seed, fake_cloud) -> str:
    """Re-probe one module, sync it, and let the service report drift on it."""
    seed_memory(seed.home, HOST, {"os": OS_MODULE, "services": SERVICES_V2})
    assert await sync_all(t) == "Synced 4 envelope(s)."
    assert len(fake_cloud.memory.envelopes(HOST.instance_id, "services")) == 2
    event_id = fake_cloud.memory.record_drift(HOST.instance_id, "services")
    # Drift Events appears in the sidebar once Memory Sync is active; a
    # sidebar is built with its screen, so it shows from the next screen on.
    await t.nav("nav_list")
    await t.wait_for_screen("InstanceListScreen")
    await t.nav("nav_drift")
    await t.wait_for_screen("MemoryDriftScreen")
    return event_id


def _drift_rows(t) -> list[list[str]]:
    """The drift table without its timestamp column, as plain text."""
    return [[plain(cell) for cell in row[1:]] for row in t.table_rows("#drift-table")]


async def test_unlock_sync_and_drift(tui, seed, fake_cloud, monkeypatch):
    _seed(seed, fake_cloud)
    use_passphrase(monkeypatch)
    async with tui() as t:
        await open_memory_sync(t)
        await t.wait_until(lambda: status(t) == "⚪ Not set up yet", desc="not set up")
        await unlock(t)

        # A keypair was made on the device and enrolled; the private half
        # only ever left it wrapped.
        assert fake_cloud.statuses(f"{KEYS_PATH}/me") == [404]
        assert fake_cloud.statuses(KEYS_PATH) == [201]
        registered = fake_cloud.memory.instances()[HOST.instance_id]
        assert registered["display_name"] == HOST.name

        assert await sync_all(t) == "Synced 4 envelope(s)."
        uploads = fake_cloud.requests(SYNC_PATH, "POST")
        assert uploads and all(r["status"] == 200 for r in uploads)
        envelopes = fake_cloud.memory.envelopes(HOST.instance_id)
        assert sorted(e["module"] for e in envelopes) == MODULES
        assert {e["encryption"] for e in envelopes} == {"aes-256-gcm"}

        # The enrolled key opens every envelope; each has its own data key
        # and nonce.
        keypair = enrolled_keypair(fake_cloud)
        user_id = fake_cloud.entitlements()["user_id"]
        opened = {e["module"]: open_envelope(e, user_id, keypair) for e in envelopes}
        assert opened["os"]["observed"] == OS_MODULE
        assert opened["services"]["observed"] == SERVICES_V1
        assert opened["annotations"]["content"].strip() == NOTE
        assert [f["body"] for f in opened["findings"]["findings"]] == [FINDING]
        data_keys = [envelope_key(e, user_id, keypair[1]) for e in envelopes]
        assert len(set(data_keys)) == len(envelopes)
        assert len({e["iv"] for e in envelopes}) == len(envelopes)

        # The note and the finding were pulled back after the upload.
        for module in ("annotations", "findings"):
            assert fake_cloud.statuses(f"/api/v1/memory/{HOST.instance_id}/{module}") == [200]

        # Nothing readable crossed the wire, in any encoding.
        fake_cloud.assert_absent_on_wire(
            MARKER, "Ubuntu 24.04 LTS", "6.8.0-e2e", NOTE, FINDING, PASSPHRASE,
            keypair[1], *data_keys,
        )

        event_id = await _drift_after_reprobe(t, seed, fake_cloud)
        await t.wait_until(lambda: _drift_rows(t), desc="drift rows")
        assert _drift_rows(t) == [[HOST.instance_id, "services", "medium", "open"]]

        await t.press("a")
        await t.wait_for_toast(r"^Drift event acknowledged\.$")
        await t.wait_until(
            lambda: _drift_rows(t) == [[HOST.instance_id, "services", "medium", "acknowledged"]],
            desc="acknowledged row",
        )
        assert fake_cloud.memory.drift_events()[0]["acknowledged_at"]
        assert fake_cloud.statuses(f"/api/v1/memory/drift/{event_id}/ack") == [200]
    fake_cloud.assert_no_unexpected_errors(*FIRST_RUN)


async def test_drift_event_opens_its_decrypted_diff(tui, seed, fake_cloud, monkeypatch):
    _seed(seed, fake_cloud)
    use_passphrase(monkeypatch)
    async with tui() as t:
        await open_memory_sync(t)
        await unlock(t)
        assert await sync_all(t) == "Synced 4 envelope(s)."
        await _drift_after_reprobe(t, seed, fake_cloud)
        await t.wait_until(lambda: _drift_rows(t), desc="drift rows")
        table = t.on_screen("#drift-table")
        assert table.has_focus and table.cursor_row == 0

        # The footer offers "enter Diff" for the highlighted event.
        await t.press("enter")
        try:
            await t.wait_for_screen("DriftDiffScreen", timeout=3)
        except JourneyTimeout:
            if t.stack_names()[-1] == "MemoryDriftScreen":
                raise KnownGap(
                    "Enter on the highlighted drift event did not open its diff"
                ) from None
            raise
        # The diff is decrypted on the device from the two stored snapshots.
        await t.wait_until(
            lambda: '"nginx": "1.26.1"' in t.rendered_text(), desc="decrypted diff"
        )
        text = t.rendered_text()
        assert '-    "nginx": "1.24.0",' in text
        assert '+    "nginx": "1.26.1",' in text
    fake_cloud.assert_no_unexpected_errors(*FIRST_RUN)


async def test_restart_unlocks_from_the_local_key_cache(tui, seed, fake_cloud, monkeypatch):
    _seed(seed, fake_cloud)
    use_passphrase(monkeypatch)
    async with tui() as t:
        await open_memory_sync(t)
        await unlock(t)
    enrolled = fake_cloud.memory.enrolled_key()
    key_reads = len(fake_cloud.requests(f"{KEYS_PATH}/me"))

    use_passphrase(monkeypatch, WRONG_PASSPHRASE)
    async with tui() as t:
        await open_memory_sync(t)
        await t.wait_until(lambda: status(t) == "⚪ Locked", desc="locked after restart")
        await t.click("#msync_btn_setup")
        await t.wait_for_toast(r"^Wrong passphrase — try again\.$", severity="error")
        await t.wait_until(
            lambda: status(t) == "✗ Wrong passphrase — try again.", desc="refusal shown"
        )

        use_passphrase(monkeypatch)
        await unlock(t)
        assert t.is_reachable(t.on_screen("#msync_btn_sync_now"))

    # Unlocked from the local cache: no key fetch, no second enrolment.
    assert len(fake_cloud.requests(f"{KEYS_PATH}/me")) == key_reads
    assert fake_cloud.statuses(KEYS_PATH) == [201]
    assert fake_cloud.memory.enrolled_key() == enrolled
    fake_cloud.assert_no_unexpected_errors(*FIRST_RUN)

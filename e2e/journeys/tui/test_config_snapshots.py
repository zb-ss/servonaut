"""Journey: config snapshots, pushed encrypted and restored on a new device.

A signed-in Solo user with a custom server in their config opens Sync
Config: there are no snapshots yet. They push one under a label of their
choosing, setting the sync passphrase on the way (a mismatched
confirmation is caught first). The (fake) service receives only the
client-side encrypted envelope: neither the server's address nor the
passphrase crosses the wire, in any encoding. A second push reuses the passphrase and both
snapshots are listed, newest first.

On a new device (fresh home, same account, no custom servers) the latest
snapshot is pulled: a wrong passphrase is refused, the right one restores
the custom server into the local config.
"""

from __future__ import annotations

import shutil

import pytest

from e2e.harness import fleet
from e2e.harness.artifacts import register_secret
from e2e.harness.fake_cloud.routes_configs import CONFIGS
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.session_seed import seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

# Fabricated for the suite.
SYNC_PASSPHRASE = "e2e-sync-31"
WRONG_PASSPHRASE = "e2e-wrong-31"
SERVER = fleet.WEB_1


def _custom_server():
    from servonaut.config.schema import CustomServer

    return CustomServer(
        name=SERVER.name,
        host=SERVER.host,
        username=SERVER.username,
        port=SERVER.port,
        ssh_key=SERVER.ssh_key,
        provider=SERVER.provider,
        group=SERVER.group,
    )


def _device(seed, fake_cloud, **config) -> None:
    seed.config(**config)
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)


def _rows(t) -> list[list[str]]:
    """Label and version of each listed snapshot."""
    return [row[1:3] for row in t.table_rows("#snapshots_table")]


async def _open_snapshots(t) -> None:
    await t.nav("nav_sync_config")
    await t.wait_for_screen("SnapshotManagerScreen")


async def _push(t, label: str) -> None:
    await t.press("p")
    await t.wait_for_screen("LabelInputModal")
    await t.fill("#label_input", label)
    await t.click("#btn_label_save")


async def _pull_latest(t, passphrase: str) -> None:
    await t.press("l")
    await t.wait_for_screen("ConfirmModal")
    await t.click("#btn_confirm_yes")
    await t.wait_for_screen("PassphraseModal")
    assert "Enter Sync Passphrase" in t.rendered_text()
    await t.fill("#input_passphrase", passphrase)
    await t.click("#btn_passphrase_ok")


async def test_push_list_and_restore_on_a_new_device(tui, seed, fake_cloud):
    register_secret(SYNC_PASSPHRASE, WRONG_PASSPHRASE)
    fake_cloud.configure(mcp_connections=0)
    _device(seed, fake_cloud, custom_servers=[_custom_server()])
    async with tui() as t:
        await _open_snapshots(t)
        await t.wait_until(
            lambda: "No snapshots yet" in t.rendered_text(), desc="empty snapshot list"
        )

        await _push(t, "e2e-laptop")
        await t.wait_for_screen("PassphraseModal")
        assert "Set Sync Passphrase" in t.rendered_text()
        await t.fill("#input_passphrase", SYNC_PASSPHRASE)
        await t.fill("#input_passphrase_confirm", SYNC_PASSPHRASE + "x")
        await t.click("#btn_passphrase_ok")
        await t.wait_until(
            lambda: "Passphrases do not match." in t.rendered_text(), desc="mismatch caught"
        )
        await t.fill("#input_passphrase_confirm", SYNC_PASSPHRASE)
        await t.click("#btn_passphrase_ok")
        await t.wait_for_toast(r"^Pushed snapshot: e2e-laptop$")
        await t.wait_until(lambda: _rows(t) == [["e2e-laptop", "1"]], desc="one snapshot")

        # The passphrase is remembered for the session: no second prompt.
        await _push(t, "e2e-desktop")
        await t.wait_for_toast(r"^Pushed snapshot: e2e-desktop$")
        await t.wait_until(
            lambda: _rows(t) == [["e2e-desktop", "2"], ["e2e-laptop", "1"]],
            desc="newest first",
        )

    pushes = fake_cloud.requests(CONFIGS, "POST")
    assert [r["status"] for r in pushes] == [201, 201]
    assert {r["body"]["encryption"] for r in pushes} == {"aes-256-gcm"}
    fake_cloud.assert_absent_on_wire(SERVER.host, SYNC_PASSPHRASE)

    # A new device: same account, a fresh home without the custom server.
    shutil.rmtree(seed.data_dir)
    _device(seed, fake_cloud)
    assert seed.read_config()["custom_servers"] == []
    async with tui() as t:
        await _open_snapshots(t)
        await t.wait_until(
            lambda: _rows(t) == [["e2e-desktop", "2"], ["e2e-laptop", "1"]], desc="listed"
        )
        await _pull_latest(t, WRONG_PASSPHRASE)
        await t.wait_for_toast(r"^Wrong passphrase or corrupted snapshot\.$", severity="error")
        assert seed.read_config()["custom_servers"] == []

        await _pull_latest(t, SYNC_PASSPHRASE)
        await t.wait_for_toast(r"^Snapshot restored\. Restart Servonaut to apply fully\.$")

    restored = seed.read_config()["custom_servers"]
    assert [(s["name"], s["host"], s["port"]) for s in restored] == [
        (SERVER.name, SERVER.host, SERVER.port)
    ]
    fake_cloud.assert_absent_on_wire(SERVER.host, SYNC_PASSPHRASE, WRONG_PASSPHRASE)
    fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file"))

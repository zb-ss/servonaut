"""Journey: a passphrase account moves its Memory Sync key into the vault.

The account enrolled Memory Sync with a passphrase on this device (the key is
wrapped with the passphrase and cached in ``keys.json``; auto-unlock is
switched on) and has config snapshots sealed with a passphrase. It then sets
up its vault and runs ``servonaut memory move-key-to-vault`` with the
recovery key and the passphrase on stdin.

* A good run keeps the service's key row (same id and fingerprint), drops the
  wrapped private key from it, deletes ``keys.json`` and the auto-unlock
  settings, uploads the current config under a vault key and deletes the
  passphrase snapshots. The passphrase, the recovery key, the private key and
  the config's content never cross the wire. The TUI then opens Memory Sync
  unlocked by the vault, with no passphrase dialog.
* When the service refuses the custody switch once (503), nothing changes on
  the account, and a re-run completes the move with the same vault item.
* When the command is killed after the vault item was written and before the
  service confirmed, the service still holds the passphrase key and nothing
  was deleted locally; a re-run completes the move with no second key.
"""

from __future__ import annotations

import base64
import dataclasses
from dataclasses import dataclass
from typing import Any

import pytest

from e2e.harness import fleet
from e2e.harness.fake_cloud.routes_memory import KEYS_PATH
from e2e.harness.interactive import InteractiveCli
from e2e.harness.known_bugs import ProductBug, known_bug
from e2e.harness.memory_seed import seed_memory
from e2e.harness.memory_sync import (
    ACTIVE,
    PASSPHRASE,
    enrolled_keypair,
    open_memory_sync,
    status,
    sync_all,
    unlock,
    use_passphrase,
)
from e2e.harness.vault_custody import CustodySwitchFault, setup_vault

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio, pytest.mark.xdist_group("custody-move")]

HOST = fleet.APP_1
SERVER = fleet.WEB_1
MOVE = ("memory", "move-key-to-vault", "--yes", "--passphrase-stdin", "--recovery-key-stdin")
EXPIRY = "2099-01-01T00:00:00+00:00"
# Shaped like the client-side envelope (16-byte salt, 12-byte iv, 16-byte tag); content is random.
PASSPHRASE_SNAPSHOT = {
    "encryption": "aes-256-gcm", "name": "default",
    "data": base64.b64encode(b"x" * 48).decode(), "salt": base64.b64encode(b"s" * 16).decode(),
    "iv": base64.b64encode(b"i" * 12).decode(), "tag": base64.b64encode(b"t" * 16).decode(),
}


class InterruptedMoveAdopted(ProductBug):
    """The next start treated a half-finished move as vault custody and deleted the local key."""


@dataclass
class Account:
    row_id: int
    fingerprint: str
    private_key: bytes
    recovery_key: str
    user_id: int


def _custom_server():
    from servonaut.config.schema import CustomServer

    return CustomServer(
        name=SERVER.name, host=SERVER.host, username=SERVER.username, port=SERVER.port,
        ssh_key=SERVER.ssh_key, provider=SERVER.provider, group=SERVER.group,
    )


def _keys_json(seed) -> bool:
    return (seed.home / ".servonaut" / "memory" / "keys.json").exists()


def _remember_flags(seed) -> tuple[Any, Any]:
    memory = seed.read_config()["memory"]
    return memory.get("sync_remember_device"), memory.get("sync_remember_expires_at")


def _switch_on_auto_unlock() -> None:
    """The settings "Enable auto-unlock" leaves behind (the harness keyring cannot hold the secret)."""
    from servonaut.config.manager import ConfigManager

    manager = ConfigManager()
    manager.load()
    manager.update(memory=dataclasses.replace(
        manager.get().memory, sync_remember_device=True, sync_remember_expires_at=EXPIRY,
    ))


async def _passphrase_account(tui, seed, fake_cloud, journey, servonaut_cmd, monkeypatch) -> Account:
    """Enrol with a passphrase and sync, then set the vault up and leave two old snapshots."""
    fake_cloud.configure(mcp_connections=0)
    seed.config(custom_servers=[_custom_server()])
    seed.cache(fleet.cache_rows(), fresh=True)
    from e2e.harness.session_seed import seed_session

    seed_session(seed.home, fake_cloud)
    seed_memory(seed.home, HOST, {"os": {"distro": "Ubuntu 24.04 LTS"}})
    use_passphrase(monkeypatch)
    async with tui() as t:
        await open_memory_sync(t)
        await unlock(t)
        assert await sync_all(t) == "Synced 1 envelope(s)."
    key = fake_cloud.memory.enrolled_key()
    assert key["custody"] == "passphrase" and key["wrapped_private_key"]
    assert _keys_json(seed)

    _, recovery_key = setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)
    _switch_on_auto_unlock()
    for _ in range(2):
        assert fake_cloud.configs.push(dict(PASSPHRASE_SNAPSHOT))[0] == 201
    return Account(
        row_id=key["id"], fingerprint=key["fingerprint"], private_key=enrolled_keypair(fake_cloud)[1],
        recovery_key=recovery_key, user_id=fake_cloud.entitlements()["user_id"],
    )


def _move(cli, journey, account: Account, **kwargs):
    return cli(
        journey.ctx.sandbox, *MOVE, stdin=f"{account.recovery_key}\n{PASSPHRASE}\n", timeout=180, **kwargs,
    )


def _assert_untouched(fake_cloud, seed, account: Account) -> None:
    """The account is still a passphrase account, with every local copy in place."""
    key = fake_cloud.memory.enrolled_key()
    assert (key["id"], key["fingerprint"], key["custody"]) == (account.row_id, account.fingerprint, "passphrase")
    assert key["wrapped_private_key"]
    assert _keys_json(seed)
    assert _remember_flags(seed) == (True, EXPIRY)
    assert {s["key_custody"] for s in fake_cloud.configs.all()} == {"passphrase"}


def _assert_moved(fake_cloud, seed, account: Account) -> None:
    key = fake_cloud.memory.enrolled_key()
    # The service's row was switched in place: same id, same key, no wrapped private key.
    assert (key["id"], key["fingerprint"]) == (account.row_id, account.fingerprint)
    assert key["custody"] == "vault" and key["wrapped_private_key"] is None
    assert key["custody_changed_at"]
    assert fake_cloud.vault.app_key_fingerprints(account.user_id, "memory_key") == [account.fingerprint]
    assert len(fake_cloud.memory.key_history()) == 0
    # Nothing of the passphrase custody is left on the device.
    assert not _keys_json(seed)
    assert _remember_flags(seed) == (False, "")
    # The config was uploaded again under a vault key and the old copies are gone.
    snapshots = fake_cloud.configs.all()
    assert snapshots and {s["key_custody"] for s in snapshots} == {"vault"}
    (config_key,) = fake_cloud.vault.app_key_fingerprints(account.user_id, "config_sync_key")
    assert {s["key_id"] for s in snapshots} == {config_key}
    assert len(fake_cloud.requests(KEYS_PATH, "POST")) == 1  # the enrolment, never a second key


def _assert_nothing_secret_on_the_wire(fake_cloud, account: Account, since: int) -> None:
    fake_cloud.assert_absent_on_wire(
        PASSPHRASE, account.recovery_key, account.private_key, SERVER.host, since=since,
    )


async def _assert_tui_unlocked_by_the_vault(tui, seed) -> None:
    async with tui() as t:
        await open_memory_sync(t)
        await t.wait_until(lambda: status(t) == ACTIVE, desc="unlocked from the vault")
        await t.wait_for_text("kept in your vault")
        assert [n for n in t.opened_screens() if "Passphrase" in n] == []
    assert not _keys_json(seed)


async def test_the_move_keeps_the_key_row_and_leaves_nothing_of_the_passphrase(
    tui, seed, fake_cloud, journey, cli, servonaut_cmd, custody_device, monkeypatch,
):
    account = await _passphrase_account(tui, seed, fake_cloud, journey, servonaut_cmd, monkeypatch)
    mark = fake_cloud.wire_mark()

    result = _move(cli, journey, account)

    assert result.returncode == 0, result.describe()
    assert "Memory Sync now keeps its key in your vault." in result.stdout
    assert "Config sync now keeps its key in your vault (2 old snapshot(s) removed)." in result.stdout
    for secret in (PASSPHRASE, account.recovery_key):
        assert secret not in result.stdout + result.stderr
    _assert_moved(fake_cloud, seed, account)
    _assert_nothing_secret_on_the_wire(fake_cloud, account, mark)
    await _assert_tui_unlocked_by_the_vault(tui, seed)


async def test_a_refused_switch_changes_nothing_and_a_rerun_finishes_the_move(
    tui, seed, fake_cloud, journey, cli, servonaut_cmd, custody_device, monkeypatch,
):
    account = await _passphrase_account(tui, seed, fake_cloud, journey, servonaut_cmd, monkeypatch)
    fault = CustodySwitchFault(fake_cloud.memory).install(monkeypatch)
    fault.refuse_once()
    mark = fake_cloud.wire_mark()

    refused = _move(cli, journey, account)

    assert refused.returncode == 6, refused.describe()  # the refusal exit code
    assert (
        "Keeping Memory Sync keys in the vault is not available on this Servonaut service yet. "
        "Nothing was changed. Try again later."
    ) in refused.stderr
    assert "Vault custody for Memory Sync keys is not available yet." not in refused.stdout + refused.stderr
    _assert_untouched(fake_cloud, seed, account)
    # The item the first run stored is harmless: it is reused, never duplicated.
    assert fake_cloud.vault.app_key_fingerprints(account.user_id, "memory_key") == [account.fingerprint]
    assert fake_cloud.configs.all()  # the config part never ran

    finished = _move(cli, journey, account)

    assert finished.returncode == 0, finished.describe()
    assert fault.calls == 2
    _assert_moved(fake_cloud, seed, account)
    _assert_nothing_secret_on_the_wire(fake_cloud, account, mark)


async def test_a_move_killed_after_the_item_write_is_finished_by_a_rerun(
    tui, seed, fake_cloud, journey, servonaut_cmd, custody_device, monkeypatch,
):
    account = await _passphrase_account(tui, seed, fake_cloud, journey, servonaut_cmd, monkeypatch)
    fault = CustodySwitchFault(fake_cloud.memory).install(monkeypatch)
    mark = fake_cloud.wire_mark()

    child = InteractiveCli.start(
        servonaut_cmd, *MOVE, env=journey.child_env(journey.ctx.sandbox), cwd=journey.ctx.sandbox.base,
        armed_log=journey.armed_log, log=journey.children,
    )
    # The vault item is stored before the service is asked to switch; the fake kills the
    # command as that request arrives.
    fault.kill_client_once(child._process.pid)  # noqa: SLF001 - the harness exposes no pid
    child.send(account.recovery_key)
    child.send(PASSPHRASE)
    killed = child.close()

    assert killed.returncode < 0, killed.describe()
    assert fault.calls == 1
    assert fake_cloud.vault.app_key_fingerprints(account.user_id, "memory_key") == [account.fingerprint]
    # Nothing local was deleted and the service still says passphrase.
    _assert_untouched(fake_cloud, seed, account)

    finished = _move_after_kill(journey, servonaut_cmd, account)

    assert finished.returncode == 0, finished.describe()
    _assert_moved(fake_cloud, seed, account)
    _assert_nothing_secret_on_the_wire(fake_cloud, account, mark)


def _move_after_kill(journey, servonaut_cmd, account: Account):
    from e2e.harness.processes import run_cli

    return run_cli(
        servonaut_cmd, *MOVE, env=journey.child_env(journey.ctx.sandbox), cwd=journey.ctx.sandbox.base,
        armed_log=journey.armed_log, stdin=f"{account.recovery_key}\n{PASSPHRASE}\n", timeout=180,
        log=journey.children,
    )


@known_bug(
    "the next start adopts the vault item of an interrupted move as vault custody and deletes "
    "keys.json while the service still says passphrase",
    raises=InterruptedMoveAdopted,
)
async def test_the_next_start_after_a_killed_move_keeps_the_local_key(
    tui, seed, fake_cloud, journey, servonaut_cmd, custody_device, monkeypatch,
):
    account = await _passphrase_account(tui, seed, fake_cloud, journey, servonaut_cmd, monkeypatch)
    fault = CustodySwitchFault(fake_cloud.memory).install(monkeypatch)
    child = InteractiveCli.start(
        servonaut_cmd, *MOVE, env=journey.child_env(journey.ctx.sandbox), cwd=journey.ctx.sandbox.base,
        armed_log=journey.armed_log, log=journey.children,
    )
    fault.kill_client_once(child._process.pid)  # noqa: SLF001
    child.send(account.recovery_key)
    child.send(PASSPHRASE)
    child.close()
    assert fault.calls == 1

    async with tui() as t:
        await open_memory_sync(t)
        await t.wait_until(lambda: status(t) in (ACTIVE, "⚪ Locked"), desc="Memory Sync started")
        await t.settle()
    key = fake_cloud.memory.enrolled_key()
    assert key["custody"] == "passphrase"
    if not _keys_json(seed) or _remember_flags(seed) != (True, EXPIRY):
        raise InterruptedMoveAdopted("keys.json or the auto-unlock settings were deleted")

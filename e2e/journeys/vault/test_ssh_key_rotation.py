"""Journey: an owner rotates an exposed team SSH key on its server.

The owner's real CLI runs against the hermetic FakeCloud and ``server-1``, a
loopback host whose sshd reads the login's ``authorized_keys`` at every
authentication (see ``e2e/harness/ca_sshd.py``). The team vault holds the
shared key, which is bound to ``server-1`` and already in its
``authorized_keys``; a removed member had fetched it, so its exposure is open.

1. The vault key is due for rotation (as after a member left). ``vault
   exposures --rotate-ssh`` rotates it first, then puts the new SSH key on
   the server, saves it, and only then removes the old key; the exposure is
   resolved.
2. The vault key becomes due while the rotation is running, so the service
   refuses to save the new key. The new key is taken off the server again,
   the old key stays, the vault item is unchanged and the exposure stays
   open; the CLI explains this with its own wording, never the service's.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from e2e.harness.ca_sshd import LOGIN, fingerprint, key_lines, start_ca_host
from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_ID, TEAM_SLUG
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.sshd import LOOPBACK
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from e2e.journeys.vault.test_team_member_onboarding import OWNER_ID, _home, _json

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

AUTHORIZED_KEYS = f"/home/{LOGIN}/.ssh/authorized_keys"


@pytest.fixture
def server_1(sshd: Any, journey: Any) -> Any:
    host = start_ca_host(
        log=sshd.log, remote_dir=journey.directory / "remote",
        hidden=[*journey.ctx.protected_dirs, str(journey.ctx.root)],
    )
    yield host
    host.stop()


def _bound_shared_key(journey: Any, fake_cloud: Any, cli: Any, servonaut_cmd: list[str], server_1: Any) -> dict:
    """The owner, the team vault with a shared key bound to server-1, and its open exposure."""
    fake_cloud.configure(plan="teams", mcp_connections=0)
    fake_cloud.account.configure(teams=[])
    fake_cloud.account.create_team(name="Example team", slug=TEAM_SLUG, team_id=TEAM_ID, owner_user_id=OWNER_ID)
    fake_cloud.account.place_shared_server(TEAM_SLUG, SERVER_ID, hostname=LOOPBACK, port=server_1.port)
    _configure_test_custody(journey)

    owner = _home(journey, fake_cloud, "o", signed_in=True)
    setup, _ = _setup_with_recovery_confirmation(journey, owner, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(owner, "vault", "create", "--team", TEAM_SLUG, "--name", "Team vault", "--json"))["vault_id"]

    key = Ed25519PrivateKey.generate()
    key_path = owner.home / "shared_ed25519"
    key_path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    key_path.chmod(0o600)
    public_line = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    item_id = _json(cli(owner, "vault", "import", "ssh", "--vault", vault_id,
                        "--path", str(key_path), "--json"))["item_id"]

    # The server already lets the shared key in, and the owner binds it there.
    server_1.remote.write(AUTHORIZED_KEYS, public_line + "\n", mode=0o600)
    host_key = " ".join(server_1.host_key.export_public_key("openssh").decode("ascii").split()[:2])
    bound = _json(cli(owner, "vault", "bind", SERVER_ID, item_id, "--vault", vault_id, "--team", TEAM_SLUG,
                      "--login", LOGIN, "--host-key", host_key, "--yes", "--json"))
    assert bound["source"] == "servonaut_vault" and bound["valid"] is True, bound

    old_fingerprint = fingerprint(public_line)
    exposure_id = fake_cloud.vault.open_exposure(vault_id, item_id, public_fingerprint=old_fingerprint)
    return {"owner": owner, "vault_id": vault_id, "item_id": item_id, "public_line": public_line,
            "old_fingerprint": old_fingerprint, "exposure_id": exposure_id}


def _rotate(cli: Any, world: dict) -> Any:
    return cli(world["owner"], "vault", "exposures", "--vault", world["vault_id"], "--rotate-ssh", world["item_id"],
               "--team", TEAM_SLUG, "--server", SERVER_ID, "--yes")


def _authorized_fingerprints(server_1: Any) -> list[str]:
    return [fingerprint(line) for line in key_lines(server_1.remote.read_bytes(AUTHORIZED_KEYS).decode("utf-8"))]


def _exposure(fake_cloud: Any, world: dict) -> dict:
    [exposure] = [row for row in fake_cloud.vault._exposures[world["vault_id"]]
                  if row["exposure_id"] == world["exposure_id"]]
    return exposure


def test_a_due_vault_key_is_rotated_first_then_the_ssh_key(journey, fake_cloud, cli, servonaut_cmd, server_1):
    world = _bound_shared_key(journey, fake_cloud, cli, servonaut_cmd, server_1)
    vault_id, item_id = world["vault_id"], world["item_id"]
    fake_cloud.vault.require_rotation(vault_id)

    rotated = _rotate(cli, world)

    assert rotated.returncode == 0, rotated.describe()
    assert "The vault key was rotated first, as the service required" in rotated.stdout, rotated.describe()
    assert f"Exposure {world['exposure_id']} resolved as rotated." in rotated.stdout, rotated.describe()
    # The vault key went first; only then was the new SSH key saved.
    item_path = f"/api/v1/vaults/{vault_id}/items/{item_id}"
    calls = [(entry["method"], entry["path"], entry["status"]) for entry in fake_cloud.requests()]
    rotation_at = calls.index(("POST", f"/api/v1/vaults/{vault_id}/rotate", 200))
    assert rotation_at < calls.index(("PUT", item_path, 200))
    vault = fake_cloud.vault._vaults[vault_id]
    assert vault["current_version"] == 2 and vault["rotation"]["required"] is False
    item = fake_cloud.vault._items[vault_id][item_id]
    assert (item["key_version"], item["revision"]) == (2, 2)
    # The server lets in the new key only, the one the vault item holds now.
    assert _authorized_fingerprints(server_1) == [item["public_fingerprint"]]
    assert item["public_fingerprint"] != world["old_fingerprint"]
    assert _exposure(fake_cloud, world)["status"] == "resolved"
    # The owner's next login uses the rotated key.
    reached = cli(world["owner"], "ssh", "server-1", stdin="hostname\n")
    assert reached.returncode == 0, reached.describe()
    fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file", "no key reference"))


def test_a_refused_save_takes_the_new_key_off_the_server_again(journey, fake_cloud, cli, servonaut_cmd, server_1):
    world = _bound_shared_key(journey, fake_cloud, cli, servonaut_cmd, server_1)
    vault_id, item_id = world["vault_id"], world["item_id"]
    # A member is removed while the rotation is running: the save is refused.
    fake_cloud.vault.require_rotation(vault_id, on_next_item_write=True)
    logins_before = len(server_1.logins)

    refused = _rotate(cli, world)

    assert refused.returncode == 1, refused.describe()
    assert "the vault key must be rotated first, usually because a member left" in refused.stderr, refused.describe()
    assert "Nothing changed on the servers: the old key is still in place" in refused.stderr, refused.describe()
    assert "remove the old key" not in refused.stderr
    assert "Rotate the vault key before changing items" not in refused.stdout + refused.stderr
    # The new key had been added and proven before the save was refused.
    proofs = [login for login in server_1.logins[logins_before:] if login.reason == "authorized_keys"]
    assert any(login.user == LOGIN and login.accepted for login in proofs), server_1.logins[logins_before:]
    assert _authorized_fingerprints(server_1) == [world["old_fingerprint"]]
    item = fake_cloud.vault._items[vault_id][item_id]
    assert (item["revision"], item["public_fingerprint"]) == (1, world["old_fingerprint"])
    assert _exposure(fake_cloud, world)["status"] == "open"
    fake_cloud.assert_no_unexpected_errors(
        *expected("no secret store on file", "no key reference"),
        ("PUT", rf"/api/v1/vaults/{vault_id}/items/{item_id}", 409),
    )

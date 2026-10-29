"""Journey: the hop to a bastion logs in with the bastion's own Servonaut Vault key.

``jump-1`` is a custom server on the loopback bastion and has a personal vault
binding to the key the bastion accepts. ``app-1`` is reachable only at a
private address the bastion forwards, by a connection rule naming the bastion
by address (not the sandbox's ``bastion-1`` alias, whose ssh_config entry would
give the hop a key file by itself). No key file for the bastion exists on this
computer: only the vault key can log the hop in.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

import pytest

from e2e.harness import keygen_lookup_shim, remote_fleet
from e2e.harness.bootstrap import Sandbox
from e2e.harness.seed import HomeSeeder
from e2e.harness.session_seed import seed_relay_config, seed_session
from e2e.harness.sshd import LOOPBACK
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

APP_ADDRESS = "10.9.0.5"
LOGIN = "deploy"


def _json(result: Any) -> Any:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _home(journey: Any, fake_cloud: Any, sshd: Any) -> Sandbox:
    from servonaut.config.schema import ConnectionProfile, ConnectionRule, CustomServer

    # Close to the test root: the private agent's socket lives under it.
    sandbox = Sandbox(journey.ctx.root / f"j{journey.directory.name[:4]}").create()
    journey.homes.append(sandbox.home)
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    seed_relay_config(
        seeder,
        custom_servers=[
            CustomServer(name="jump-1", host=LOOPBACK, username=LOGIN, port=sshd.bastion.port),
            CustomServer(
                name="app-1", host=APP_ADDRESS, username=LOGIN,
                ssh_key=remote_fleet.WEB_1_KEY_PATH,
            ),
        ],
        connection_profiles=[ConnectionProfile(
            name="jump", bastion_host=LOOPBACK, bastion_user=LOGIN, ssh_port=sshd.bastion.port,
        )],
        connection_rules=[ConnectionRule(
            name="private apps", match_conditions={"name_contains": "app-"}, profile_name="jump",
        )],
    )
    seed_session(sandbox.home, fake_cloud)
    # The target's own key; the bastion's key is only in the vault.
    sshd.install_client_key(sandbox.home, remote_fleet.WEB_1_KEY)
    return sandbox


def test_the_hop_logs_in_with_the_bastions_vault_key(journey, fake_cloud, sshd, cli, servonaut_cmd):
    _configure_test_custody(journey)
    keygen = shutil.which("ssh-keygen", path="/usr/bin:/bin:/usr/local/bin")
    assert keygen is not None
    keygen_lookup_shim.install(str(journey.shims.directory), keygen, str(journey.ctx.root))
    sshd.route(APP_ADDRESS)
    sshd.target.remote.write("/etc/hostname", "app-1\n")
    home = _home(journey, fake_cloud, sshd)

    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = home.home / "jump-1.pem"
    key_path.write_bytes(sshd.bastion_key_path.read_bytes())
    key_path.chmod(0o600)
    item_id = _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path), "--json"))["item_id"]
    key_path.unlink()
    # The key type and data only, as --host-key takes it.
    bastion_host_key = " ".join(sshd.bastion.host_key.export_public_key("openssh").decode("ascii").split()[:2])
    _json(cli(
        home, "vault", "bind-personal", "--vault", vault_id, "--item", item_id,
        "--provider", "custom", "--instance-id", "jump-1", "--hostname", LOOPBACK,
        "--port", str(sshd.bastion.port), "--login", LOGIN, "--host-key", bastion_host_key,
        "--yes", "--json",
    ))

    connected = cli(home, "ssh", "app-1", "--", "hostname")

    assert connected.returncode == 0, connected.describe()
    assert connected.stdout.strip() == "app-1"
    # The hop logged in with the vault key only, and forwarded to app-1.
    logins = sshd.bastion.sessions("auth")
    assert logins and logins[-1]["accepted"], logins
    assert logins[-1]["user"] == LOGIN
    assert [f["destination"] for f in sshd.bastion.sessions("forward")] == [f"{APP_ADDRESS}:22"]
    assert sshd.target.commands(user=LOGIN) == ["hostname"]


def test_a_wrong_bastion_pin_stops_before_any_login(journey, fake_cloud, sshd, cli, servonaut_cmd):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    _configure_test_custody(journey)
    keygen = shutil.which("ssh-keygen", path="/usr/bin:/bin:/usr/local/bin")
    assert keygen is not None
    keygen_lookup_shim.install(str(journey.shims.directory), keygen, str(journey.ctx.root))
    sshd.route(APP_ADDRESS)
    home = _home(journey, fake_cloud, sshd)

    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = home.home / "jump-1.pem"
    key_path.write_bytes(sshd.bastion_key_path.read_bytes())
    key_path.chmod(0o600)
    item_id = _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path), "--json"))["item_id"]
    wrong = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    _json(cli(
        home, "vault", "bind-personal", "--vault", vault_id, "--item", item_id,
        "--provider", "custom", "--instance-id", "jump-1", "--hostname", LOOPBACK,
        "--port", str(sshd.bastion.port), "--login", LOGIN, "--host-key", wrong, "--yes", "--json",
    ))

    connected = cli(home, "ssh", "app-1", "--", "hostname")

    assert connected.returncode != 0
    # The pinned key did not match: the hop never tried to log in.
    assert sshd.bastion.sessions("auth") == []
    assert sshd.target.commands() == []


@pytest.mark.asyncio
async def test_an_mcp_agent_reaches_the_server_through_the_bastions_vault_key(
    journey, fake_cloud, sshd, cli, mcp, servonaut_cmd,
):
    _configure_test_custody(journey)
    keygen = shutil.which("ssh-keygen", path="/usr/bin:/bin:/usr/local/bin")
    assert keygen is not None
    keygen_lookup_shim.install(str(journey.shims.directory), keygen, str(journey.ctx.root))
    sshd.route(APP_ADDRESS)
    sshd.target.remote.write("/etc/hostname", "app-1\n")
    home = _home(journey, fake_cloud, sshd)
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = home.home / "jump-1.pem"
    key_path.write_bytes(sshd.bastion_key_path.read_bytes())
    key_path.chmod(0o600)
    item_id = _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path), "--json"))["item_id"]
    key_path.unlink()
    bastion_host_key = " ".join(sshd.bastion.host_key.export_public_key("openssh").decode("ascii").split()[:2])
    _json(cli(
        home, "vault", "bind-personal", "--vault", vault_id, "--item", item_id,
        "--provider", "custom", "--instance-id", "jump-1", "--hostname", LOOPBACK,
        "--port", str(sshd.bastion.port), "--login", LOGIN, "--host-key", bastion_host_key,
        "--yes", "--json",
    ))

    async with mcp(home) as session:
        output = await session.call("run_command", {"instance_id": "app-1", "command": "hostname"})

    assert "app-1" in output, output
    logins = sshd.bastion.sessions("auth")
    assert logins and logins[-1]["accepted"], logins
    assert [f["destination"] for f in sshd.bastion.sessions("forward")] == [f"{APP_ADDRESS}:22"]

"""Vault SSH keys for AWS servers, and binding them by name.

AWS inventory rows carry no provider field. With a vault identity on the
computer, ``servonaut ssh`` used to fail closed for every AWS server
("The configured Vault SSH credential could not be used") instead of using
the local key, and a binding could not be made. Real child commands with
production configuration, custody and signing run against the hermetic
FakeCloud; ``ssh`` and ``ssh-keygen`` are the suite's recording stand-ins.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from e2e.harness import fleet
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)

pytestmark = [pytest.mark.e2e_pr]

SERVER = fleet.EDGE_1  # reached directly at its public address
ROUTE = f"/api/v1/me/instances/aws/{SERVER.instance_id}/credential-binding"


def _json(result) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _private_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())


def _host_key() -> str:
    public = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    return public.decode("ascii")


def _home_with_vault(journey, account_home, servonaut_cmd, name: str):
    _configure_test_custody(journey)
    home = account_home(name)
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    return home


def test_an_unbound_aws_server_connects_with_its_local_key(journey, fake_cloud, cli, account_home, servonaut_cmd):
    home = _home_with_vault(journey, account_home, servonaut_cmd, "vault-aws-local")
    ssh_dir = home.home / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    key = ssh_dir / SERVER.key_name
    key.write_bytes(_private_key())
    key.chmod(0o600)
    journey.shims.when("ssh", SERVER.public_ip, rc=0)

    connected = cli(home, "ssh", SERVER.name, "--", "true")

    assert connected.returncode == 0, connected.describe()
    assert "Vault SSH credential" not in connected.stderr
    assert fake_cloud.statuses(ROUTE) == [404]  # asked as an AWS server; nothing bound
    (call,) = journey.shims.calls("ssh")
    assert str(key) in call.argv and SERVER.public_ip in call.joined


def test_auto_bind_gives_an_aws_server_the_key_named_like_its_key_pair(
    journey, fake_cloud, cli, account_home, servonaut_cmd,
):
    home = _home_with_vault(journey, account_home, servonaut_cmd, "vault-aws-auto-bind")
    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = home.home / f"{SERVER.key_name}.pem"
    key_path.write_bytes(_private_key())
    key_path.chmod(0o600)
    item_id = _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path), "--json"))["item_id"]

    # This computer trusts a host key for the server from an earlier connection
    # (the stable alias SSH stores cloud servers under); no other server has one.
    known_hosts = home.home / ".ssh" / "known_hosts"
    known_hosts.parent.mkdir(mode=0o700, exist_ok=True)
    known_hosts.write_text("", encoding="ascii")
    known_hosts.chmod(0o600)  # a known_hosts file others can change is not trusted
    host_key = _host_key()
    alias = f"aws:{SERVER.region}:{SERVER.instance_id}"
    journey.shims.when("ssh-keygen", rf"-F {alias} ", stdout=f"{alias} {host_key}\n")

    planned = _json(cli(home, "vault", "auto-bind", "--dry-run", "--json"))
    statuses = {server["server"]: server["status"] for server in planned["servers"]}
    assert statuses[SERVER.name] == "ready"
    # The rest of the fleet shares the key pair but has no trusted host key yet.
    assert {status for name, status in statuses.items() if name != SERVER.name} <= {"no_host_keys", "no_address"}
    assert fake_cloud.statuses(ROUTE) == [404]  # a dry run only reads

    bound = _json(cli(home, "vault", "auto-bind", "--yes", "--json"))
    (edge,) = [server for server in bound["servers"] if server["server"] == SERVER.name]
    assert (edge["result"], edge["vault_item_id"], edge["matched_by"]) == ("bound", item_id, "key pair")
    assert (edge["host"], edge["port"]) == (SERVER.public_ip, 22)
    assert fake_cloud.statuses(ROUTE)[-1] == 200  # the signed PUT

    # Running it again leaves the bound server alone.
    again = _json(cli(home, "vault", "auto-bind", "--dry-run", "--json"))
    assert {server["server"]: server["status"] for server in again["servers"]}[SERVER.name] == "bound"

    # ssh now reads the binding and asks for the private agent that would hold
    # the vault key. Starting an agent is disabled in this hermetic suite, so
    # the command stops there with the user-facing message.
    short_tmp = journey.ctx.root / "t"
    short_tmp.mkdir(mode=0o700, exist_ok=True)
    journey.env_overrides["TMPDIR"] = str(short_tmp)
    connected = cli(home, "ssh", SERVER.name, "--", "true")
    assert len(journey.shims.calls("ssh-agent")) == 1
    assert "Could not start the private SSH agent" in connected.stderr
    assert journey.shims.calls("ssh") == []

"""A vault SSH key bound to a custom server is used by ``servonaut ssh``.

Real child commands with production configuration, custody and signing run
against the hermetic FakeCloud; ``ssh`` is the suite's recording stand-in.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from servonaut.config.schema import CustomServer
from servonaut.services.vault.personal_targets import custom_binding_id

pytestmark = [pytest.mark.e2e_pr]

SERVER = CustomServer(name="Web 1", host="192.0.2.50", username="deploy", port=2222, provider="DigitalOcean")


def _json(result) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _host_key() -> str:
    public = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    return public.decode("ascii")


def test_custom_server_uses_its_bound_vault_key(journey, fake_cloud, cli, account_home, servonaut_cmd):
    _configure_test_custody(journey)
    home = account_home("vault-custom-binding", custom_servers=[SERVER])
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)

    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = home.home / "web1_ed25519"
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    key_path.chmod(0o600)
    item_id = _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path), "--json"))["item_id"]

    bound = _json(cli(
        home, "vault", "bind-personal", "--vault", vault_id, "--item", item_id,
        "--provider", "custom", "--instance-id", SERVER.name, "--hostname", SERVER.host,
        "--port", str(SERVER.port), "--login", SERVER.username, "--host-key", _host_key(), "--yes", "--json",
    ))
    route = f"/api/v1/me/instances/custom/{custom_binding_id(SERVER.name)}/credential-binding"
    assert fake_cloud.statuses(route) == [404, 200]  # read before write, then the signed PUT
    assert bound["target"] == f"instance:custom:{custom_binding_id(SERVER.name)}"

    # The journey home is too deep for a Unix socket name, so the private
    # agent falls back to a fresh directory under TMPDIR: keep that short
    # and inside the sandbox.
    short_tmp = journey.ctx.root / "t"
    short_tmp.mkdir(mode=0o700, exist_ok=True)
    journey.env_overrides["TMPDIR"] = str(short_tmp)
    connected = cli(home, "ssh", SERVER.name, "--", "true")

    # ssh read the custom server's binding and asked for the private agent
    # that would hold the vault key. Starting an agent is disabled in this
    # hermetic suite (the suite's stand-in refuses it), so the command stops
    # there with the user-facing message; the agent and the login itself
    # are covered by the private-agent tests that run a real ssh-agent.
    assert fake_cloud.statuses(route)[-1] == 200
    (agent,) = journey.shims.calls("ssh-agent")
    assert agent.argv[0] == "-a" and agent.argv[2] == "-s"
    socket = agent.argv[1]
    assert socket.startswith(f"{short_tmp}/svn-agent-") and socket.endswith(".sock")
    assert connected.returncode != 0
    assert "Could not start the private SSH agent" in connected.stderr
    assert journey.shims.calls("ssh") == []

"""Bulk host-key fetching and auto-binding for unvisited servers."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any

import pytest

from e2e.harness import fleet, keygen_lookup_shim, remote_fleet
from e2e.harness.bootstrap import Sandbox
from e2e.harness.seed import HomeSeeder
from e2e.harness.session_seed import seed_relay_config, seed_session
from e2e.harness.terminal import run_in_terminal
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from servonaut.services.vault.personal_targets import custom_binding_id

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]


def _json(result: Any) -> dict[str, Any]:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def test_auto_bind_fetches_host_keys_reviews_and_connects(
    journey: Any,
    fake_cloud: Any,
    sshd: Any,
    cli: Any,
    servonaut_cmd: list[str],
) -> None:
    _configure_test_custody(journey)
    keygen = shutil.which("ssh-keygen", path="/usr/bin:/bin:/usr/local/bin")
    assert keygen is not None
    keygen_lookup_shim.install(str(journey.shims.directory), keygen, str(journey.ctx.root))
    server = remote_fleet.web_1(sshd)
    sandbox = Sandbox(journey.ctx.root / f"h{journey.directory.name[:4]}").create()
    journey.homes.append(sandbox.home)
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    seed_relay_config(seeder, custom_servers=[server])
    seeder.cache(fleet.cache_rows(), fresh=True)
    seed_session(sandbox.home, fake_cloud)
    sshd.install_client_key(sandbox.home, remote_fleet.WEB_1_KEY)

    setup, _ = _setup_with_recovery_confirmation(journey, sandbox, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)

    vault_id = _json(cli(sandbox, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = sandbox.home / "web-1.pem"
    key_path.write_bytes(sshd.client_key_path.read_bytes())
    key_path.chmod(0o600)
    item_id = _json(cli(sandbox, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path), "--json"))["item_id"]

    # 1. Before fetching: dry-run reports web-1 has no trusted host key
    planned = _json(cli(sandbox, "vault", "auto-bind", "--dry-run", "--json"))
    servers = {s["server"]: s for s in planned["servers"]}
    assert servers["web-1"]["status"] == "no_host_keys"
    assert servers["web-1"]["matched_by"] == "server name"

    route = f"/api/v1/me/instances/custom/{custom_binding_id('web-1')}/credential-binding"
    assert 200 not in fake_cloud.statuses(route)

    # 2. Dry-run with --fetch-host-keys fetches the key, but binds nothing
    fetched_dry = _json(cli(sandbox, "vault", "auto-bind", "--dry-run", "--fetch-host-keys", "--json"))
    servers_dry = {s["server"]: s for s in fetched_dry["servers"]}
    assert servers_dry["web-1"]["status"] == "fetched"
    assert not servers_dry["web-1"]["verified"]
    assert servers_dry["web-1"]["host_key_fingerprints"]
    assert 200 not in fake_cloud.statuses(route)

    known_hosts = sandbox.home / ".servonaut" / "known_hosts"
    known_hosts.unlink(missing_ok=True)

    # 3. Non-interactive without --yes is refused
    refused = cli(sandbox, "vault", "auto-bind", "--fetch-host-keys")
    assert refused.returncode != 0
    assert "Refusing to bind fetched host keys without confirmation" in refused.stderr
    assert 200 not in fake_cloud.statuses(route)

    known_hosts.unlink(missing_ok=True)

    # 4. With --yes, unverified fetched keys are skipped
    skipped_res = _json(cli(sandbox, "vault", "auto-bind", "--fetch-host-keys", "--yes", "--json"))
    servers_skipped = {s["server"]: s for s in skipped_res["servers"]}
    assert servers_skipped["web-1"]["result"] is None
    assert 200 not in fake_cloud.statuses(route)

    known_hosts.unlink(missing_ok=True)

    # 5. Interactive confirmation (typing "y") confirms and binds
    bound = run_in_terminal(
        [*servonaut_cmd, "vault", "auto-bind", "--fetch-host-keys"],
        env=journey.child_env(sandbox),
        cwd=sandbox.base,
        until=lambda text: "[y/N]" in text,
        description="auto-bind confirmation prompt",
        keys=b"y\n",
    )
    assert bound.returncode == 0
    assert "Bound vault keys to 1 of 1 servers." in bound.text
    assert fake_cloud.statuses(route)[-1] == 200

    # 6. Verify dry-run now reports "bound"
    again = _json(cli(sandbox, "vault", "auto-bind", "--dry-run", "--json"))
    servers_again = {s["server"]: s for s in again["servers"]}
    assert servers_again["web-1"]["status"] == "bound"

    # 7. servonaut ssh web-1 connects using the bound vault key
    connected = cli(sandbox, "ssh", "web-1", "--", "hostname")
    assert connected.returncode == 0, connected.describe()
    assert connected.stdout.strip() == sshd.target.name

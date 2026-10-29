"""Journey: team auto-bind fetches a host key by logging in as the user's own server.

The owner shares ``web-1`` (their own custom server on the loopback target)
with their team. The shared row names no key of the owner's: only the own
row's key file logs in. ``vault auto-bind --team --fetch-host-keys`` must
visit the server through that own row, never the shared one, and still
review (and bind) the team's shared server.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

import pytest

from e2e.harness import fleet, keygen_lookup_shim, remote_fleet
from e2e.harness.bootstrap import Sandbox
from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_ID, TEAM_SLUG
from e2e.harness.seed import HomeSeeder
from e2e.harness.session_seed import seed_relay_config, seed_session
from e2e.harness.sshd import LOOPBACK
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

# The scenario account every seeded session signs in as.
OWNER_ID = 4242


def _json(result: Any) -> dict[str, Any]:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def test_team_fetch_logs_in_with_the_users_own_server(
    journey: Any,
    fake_cloud: Any,
    sshd: Any,
    cli: Any,
    servonaut_cmd: list[str],
) -> None:
    fake_cloud.configure(plan="teams", mcp_connections=0)
    fake_cloud.account.configure(teams=[])
    fake_cloud.account.create_team(
        name="Example team", slug=TEAM_SLUG, team_id=TEAM_ID, owner_user_id=OWNER_ID,
    )
    # The team's row for the owner's own web-1: same address, no key of the owner's.
    fake_cloud.account.place_shared_server(
        TEAM_SLUG, SERVER_ID, name=fleet.WEB_1.name, hostname=LOOPBACK, port=sshd.target.port,
        login_user=fleet.WEB_1.username,
    )
    _configure_test_custody(journey)
    keygen = shutil.which("ssh-keygen", path="/usr/bin:/bin:/usr/local/bin")
    assert keygen is not None
    keygen_lookup_shim.install(str(journey.shims.directory), keygen, str(journey.ctx.root))

    owner = Sandbox(journey.ctx.root / f"t{journey.directory.name[:4]}").create()
    journey.homes.append(owner.home)
    seeder = HomeSeeder(owner.home, api_url=fake_cloud.url)
    seed_relay_config(seeder, custom_servers=[remote_fleet.web_1(sshd)])
    seeder.cache(fleet.cache_rows(), fresh=True)
    seed_session(owner.home, fake_cloud)
    sshd.install_client_key(owner.home, remote_fleet.WEB_1_KEY)

    setup, _ = _setup_with_recovery_confirmation(journey, owner, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(owner, "vault", "create", "--team", TEAM_SLUG, "--name", "Team vault", "--json"))[
        "vault_id"
    ]
    key_path = owner.home / "web-1.pem"
    key_path.write_bytes(sshd.client_key_path.read_bytes())
    key_path.chmod(0o600)
    _json(cli(owner, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path), "--json"))

    reviewed = _json(cli(
        owner, "vault", "auto-bind", "--team", TEAM_SLUG, "--dry-run", "--fetch-host-keys", "--json",
    ))
    [server] = reviewed["servers"]
    assert server["server"] == fleet.WEB_1.name
    assert server["status"] == "fetched", server
    # A refused login fails the fetch: only the own row's key file logs in.
    assert server["host_key_fingerprints"], server

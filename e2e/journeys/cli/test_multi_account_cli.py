"""Journey: the command line with two Hetzner projects.

``servonaut`` runs as real child processes against the local Hetzner
stand-in, configured with the primary project and a second one
(``staging``). Both projects have a server named ``web-1``.

``hetzner list`` shows every project: an Account column and
``<project>/<name>`` names, and ``--json`` rows that carry their account.
``--account`` scopes every subcommand to one project: only that project's
token reaches Hetzner. ``destroy`` acts in the project whose servers include
the one named, and refuses the shared name with the candidates instead of
guessing. The other commands that take a server (``servers verify``,
``ssh``) resolve ``staging/web-1`` to that project's server and refuse the
bare shared name.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from e2e.harness.fake_cloud.routes_misc import ssh_ref_item_id
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr]

STAGING = fleet.HETZNER_SECOND_ACCOUNT
PRIMARY = fake_hetzner.PRIMARY_LABEL
STAGING_WEB_1 = fleet.HZ_SECOND_WEB_1
STAGING_LB_1 = fleet.HZ_SECOND_LB_1
PRIMARY_WEB_1 = fleet.HZ_WEB_1
DEPLOY_KEY = ("e2e-deploy", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Edeploykeyonly00000000000000000 deploy")
STAGING_KEY = ("e2e-staging", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Estagingkeyonly000000000000000000 staging")
CI_KEY = ("e2e-ci", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Ecikeyonly0000000000000000000000 ci")
# What the fake vault returns as the key body: never parsed, the ssh probe is a stand-in.
KEY_BODY = "placeholder key for the e2e suite"


def _projects(providers):
    """Both projects in the stand-in; returns the second project's state."""
    fleet.seed_provider_fleet(providers, ovh=False)
    second, _ = fleet.seed_second_accounts(providers, ovh=False)
    providers.hetzner.seed_ssh_key(*DEPLOY_KEY)
    second.seed_ssh_key(*STAGING_KEY)
    return second


def _home(journey, fake_cloud=None):
    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url if fake_cloud else None)
    seeder.config(
        hetzner=seeder.hetzner_config(accounts=[seeder.hetzner_account(STAGING)]),
    )
    return sandbox


def _accounts(providers, **filters) -> list:
    """The account every matching Hetzner request reached, in order."""
    return [e["account"] for e in providers.requests("hetzner", **filters)]


def _table_rows(stdout: str) -> list[list[str]]:
    lines = stdout.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("---")) + 1
    return [line.split() for line in lines[start:] if line.strip()]


def test_list_shows_every_project_and_scopes_to_one(journey, providers, cli):
    _projects(providers)
    sandbox = _home(journey)

    table = cli(sandbox, "hetzner", "list")
    assert table.returncode == 0, table.describe()
    assert "Account" in table.stdout.splitlines()[2]
    shown = {(row[0], row[1]) for row in _table_rows(table.stdout)}
    assert shown == {
        (PRIMARY, f"{PRIMARY}/{fleet.HZ_CACHE_1.name}"),
        (PRIMARY, f"{PRIMARY}/{fleet.HZ_BUILD_1.name}"),
        (PRIMARY, f"{PRIMARY}/{PRIMARY_WEB_1.name}"),
        (STAGING, f"{STAGING}/{STAGING_WEB_1.name}"),
        (STAGING, f"{STAGING}/{STAGING_LB_1.name}"),
    }

    listed = cli(sandbox, "hetzner", "list", "--json")
    assert listed.returncode == 0, listed.describe()
    rows = json.loads(listed.stdout)
    assert sorted((r["account"], r["name"], r["id"]) for r in rows) == sorted([
        (PRIMARY, fleet.HZ_CACHE_1.name, str(fleet.HZ_CACHE_1.server_id)),
        (PRIMARY, fleet.HZ_BUILD_1.name, str(fleet.HZ_BUILD_1.server_id)),
        (PRIMARY, PRIMARY_WEB_1.name, str(PRIMARY_WEB_1.server_id)),
        (STAGING, STAGING_WEB_1.name, str(STAGING_WEB_1.server_id)),
        (STAGING, STAGING_LB_1.name, str(STAGING_LB_1.server_id)),
    ])
    # The display flag stays internal: names in JSON are the plain names.
    assert all("account_qualified" not in r for r in rows)

    listings = _accounts(providers, method="GET", path="/servers")
    scoped = cli(sandbox, "hetzner", "list", "--account", STAGING, "--json")
    assert scoped.returncode == 0, scoped.describe()
    assert sorted(r["name"] for r in json.loads(scoped.stdout)) == [
        STAGING_LB_1.name, STAGING_WEB_1.name,
    ]
    # Only the named project was asked.
    assert _accounts(providers, method="GET", path="/servers")[len(listings):] == [STAGING]

    unknown = cli(sandbox, "hetzner", "list", "--account", "nope")
    assert unknown.returncode == 4, unknown.describe()
    assert "No Hetzner account named 'nope'" in unknown.stderr
    assert STAGING in unknown.stderr
    assert len(_accounts(providers, method="GET", path="/servers")) == len(listings) + 1


def test_account_scopes_every_subcommand(journey, providers, cli):
    second = _projects(providers)
    sandbox = _home(journey)
    key_file = sandbox.base / "e2e_ci.pub"
    key_file.write_text(CI_KEY[1] + "\n", encoding="utf-8")

    keys = cli(sandbox, "hetzner", "ssh-keys", "list", "--account", STAGING, "--json")
    assert keys.returncode == 0, keys.describe()
    assert [k["name"] for k in json.loads(keys.stdout)] == [STAGING_KEY[0]]

    types = cli(sandbox, "hetzner", "server-types", "--account", STAGING)
    assert types.returncode == 0, types.describe()
    probe = cli(sandbox, "hetzner", "test-connection", "--account", STAGING)
    assert probe.returncode == 0, probe.describe()

    added = cli(
        sandbox, "hetzner", "ssh-keys", "add", CI_KEY[0],
        "--public-key-file", str(key_file), "--account", STAGING,
    )
    assert added.returncode == 0, added.describe()
    created = cli(
        sandbox, "hetzner", "create", "web-3", "--ssh-key", STAGING_KEY[0],
        "--no-wait", "--yes", "--json", "--account", STAGING,
    )
    assert created.returncode == 0, created.describe()
    assert json.loads(created.stdout)["name"] == "web-3"

    # Every request reached the staging project, none the primary one.
    assert set(_accounts(providers)) == {STAGING}
    assert second.key_named(CI_KEY[0]) is not None
    assert providers.hetzner.key_named(CI_KEY[0]) is None
    assert second.server_named("web-3") is not None
    assert providers.hetzner.server_named("web-3") is None


def test_destroy_acts_in_the_project_that_has_the_server(journey, providers, cli):
    second = _projects(providers)
    sandbox = _home(journey)
    # Listing caches both projects' servers: that is where destroy looks.
    assert cli(sandbox, "hetzner", "list").returncode == 0

    shared = cli(sandbox, "hetzner", "destroy", PRIMARY_WEB_1.name, "--yes")
    assert shared.returncode == 4, shared.describe()
    assert f"'{PRIMARY_WEB_1.name}' matches 2 servers" in shared.stderr
    assert f"{PRIMARY}/{PRIMARY_WEB_1.name}" in shared.stderr
    assert f"{STAGING}/{STAGING_WEB_1.name}" in shared.stderr
    assert providers.mutations("hetzner") == []

    # A name only one project has: that project, after the typed confirmation.
    by_name = cli(sandbox, "hetzner", "destroy", STAGING_LB_1.name, stdin=f"{STAGING_LB_1.name}\n")
    assert by_name.returncode == 0, by_name.describe()
    assert f"'{STAGING_LB_1.name}' (project {STAGING})" in by_name.stdout

    qualified = cli(sandbox, "hetzner", "destroy", f"{STAGING}/{STAGING_WEB_1.name}", "--yes")
    assert qualified.returncode == 0, qualified.describe()

    deletes = providers.requests("hetzner", method="DELETE")
    assert [(e["account"], e["api_path"]) for e in deletes] == [
        (STAGING, f"/servers/{STAGING_LB_1.server_id}"),
        (STAGING, f"/servers/{STAGING_WEB_1.server_id}"),
    ]
    assert second.server(STAGING_WEB_1.server_id) is None
    assert providers.hetzner.server(PRIMARY_WEB_1.server_id) is not None


def test_commands_taking_a_server_resolve_the_qualified_name(journey, fake_cloud, providers, cli):
    _projects(providers)
    sandbox = _home(journey, fake_cloud)
    assert cli(sandbox, "hetzner", "list").returncode == 0

    # A bare shared name: every such command refuses and lists the candidates.
    ambiguous = cli(sandbox, "ssh", PRIMARY_WEB_1.name, "--", "true")
    assert ambiguous.returncode == 5, ambiguous.describe()
    for reference in (f"{PRIMARY}/{PRIMARY_WEB_1.name}", f"{STAGING}/{STAGING_WEB_1.name}"):
        assert reference in ambiguous.stderr
    assert journey.shims.calls("ssh") == []

    fake_cloud.configure(token_outcomes=["success"])
    login = cli(sandbox, "login", "--no-browser")
    assert login.returncode == 0, login.describe()
    refused = cli(sandbox, "servers", "verify", PRIMARY_WEB_1.name)
    assert refused.returncode == 2, refused.describe()
    assert f"{STAGING}/{STAGING_WEB_1.name}" in refused.stderr
    assert journey.shims.calls("ssh") == []

    # staging/web-1 is probed at that project's address, with its key.
    server_id = str(STAGING_WEB_1.server_id)
    item_id = ssh_ref_item_id("hetzner", server_id)
    fake_cloud.secrets.set_ssh_ref("hetzner", server_id, item_id)
    ssh_script = journey.shims.path_of("ssh").read_text(encoding="utf-8")
    bw = journey.shims.path_of("bw")
    bw.write_text(ssh_script.replace(' ssh "$@"', ' bw "$@"'), encoding="utf-8")
    bw.chmod(0o755)
    journey.shims.when(
        "bw", rf"^get item {item_id}$",
        stdout=json.dumps({"id": item_id, "sshKey": {"privateKey": KEY_BODY}}),
    )
    journey.env_overrides["BW_SESSION"] = "bw-fake-session"
    address = STAGING_WEB_1.public_ip.replace(".", r"\.")
    journey.shims.when("ssh", rf"BatchMode=yes.*root@{address} true$", rc=0)

    verified = cli(sandbox, "servers", "verify", f"{STAGING}/{STAGING_WEB_1.name}")
    assert verified.returncode == 0, verified.describe()
    assert f"[OK] Verified: {STAGING_WEB_1.name} (hetzner/{server_id})" in verified.stdout
    (probe,) = [call.argv for call in journey.shims.calls("ssh")]
    assert f"root@{STAGING_WEB_1.public_ip}" in probe
    reports = fake_cloud.requests(f"/api/v1/me/instances/hetzner/{server_id}/ssh-verify-report")
    assert [r["body"]["status"] for r in reports] == ["verified"]

"""Journey: a second person joins the team and gets to its vault and shared server.

Two people, each with their own home and sign-in, run the real CLI against
the hermetic FakeCloud:

1. the owner sets up their Vault identity, creates the team vault, imports a
   shared SSH key into it, switches on the team's SSH CA and enrols
   ``server-1`` (a loopback host whose sshd honours the CA, see
   ``e2e/harness/ca_sshd.py``);
2. the owner invites the member by e-mail; the member accepts in their
   browser (a FakeCloud control) and signs in with ``servonaut login``, the
   device code approved as themselves;
3. the member runs ``vault setup``: the team vault is listed, but its items
   stay closed until a grant exists;
4. the owner's ``vault grants process`` seals the vault key for the member,
   who can then read the item's metadata and log in to ``server-1`` with a
   certificate the team CA issued for their own device. ``server-1`` is also
   ``edge-1`` of the member's own AWS fleet, whose key pair has no key on
   their computer: by that name too it connects with the team's certificate,
   and so does a memory build of it;
5. removed from the team, the member no longer sees its vault.

FakeCloud answers each person for the token they hold (``FakeCloud.add_user``).
"""

from __future__ import annotations

import json
import shutil
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from e2e.harness import fleet, keygen_lookup_shim
from e2e.harness.bootstrap import Sandbox
from e2e.harness.ca_sshd import HOST_NAME, LOGIN, install_owner_credential, start_ca_host
from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_ID, TEAM_SLUG
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.seed import HomeSeeder
from e2e.harness.session_seed import read_session, seed_relay_config, seed_session
from e2e.harness.sshd import LOOPBACK
from e2e.journeys.vault.test_ca_rollover import _confirmed
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

OWNER_ID = 4242
MEMBER_ID = 4243
MEMBER_EMAIL = "member@example.com"


@pytest.fixture
def server_1(sshd: Any, journey: Any) -> Any:
    host = start_ca_host(
        log=sshd.log, remote_dir=journey.directory / "remote",
        hidden=[*journey.ctx.protected_dirs, str(journey.ctx.root)],
    )
    yield host
    host.stop()


def _json(result: Any) -> Any:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _home(journey: Any, fake_cloud: Any, prefix: str, *, signed_in: bool) -> Sandbox:
    """A child home close to the test root (a certificate login's agent socket lives in it)."""
    sandbox = Sandbox(journey.ctx.root / f"{prefix}{journey.directory.name[:4]}").create()
    journey.homes.append(sandbox.home)
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    seed_relay_config(seeder)
    seeder.cache(fleet.cache_rows(), fresh=True)
    if signed_in:
        seed_session(sandbox.home, fake_cloud)
    return sandbox


def _teams_as(token: str) -> Any:
    """The product's TeamService, signed in with *token* (what the Teams screen calls)."""
    from servonaut.services.api_client import APIClient
    from servonaut.services.team_service import TeamService

    async def no_refresh() -> bool:
        return False

    return TeamService(APIClient(SimpleNamespace(access_token=token, refresh_token=no_refresh)))


def _ssh_key_file(home: Sandbox, name: str = "server-1.pem") -> tuple[str, str]:
    path = home.home / name
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
    ))
    path.chmod(0o600)
    public_line = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    return str(path), public_line


@pytest.mark.asyncio
async def test_an_invited_member_gets_the_team_vault_and_server(
    journey, fake_cloud, cli, servonaut_cmd, server_1,
):
    fake_cloud.configure(plan="teams", mcp_connections=0)
    fake_cloud.account.configure(teams=[])
    fake_cloud.account.create_team(name="Example team", slug=TEAM_SLUG, team_id=TEAM_ID, owner_user_id=OWNER_ID)
    # The team shares the machine the member also lists as edge-1 of their own AWS account.
    fake_cloud.account.place_shared_server(
        TEAM_SLUG, SERVER_ID, hostname=LOOPBACK, port=server_1.port,
        instance_id=fleet.EDGE_1.instance_id,
        login_user=LOGIN,
    )
    fake_cloud.add_user(MEMBER_ID, email=MEMBER_EMAIL, name="Member")
    _configure_test_custody(journey)

    # 1. The owner: Vault identity, team vault with a shared key auto-bound to server-1.
    owner = _home(journey, fake_cloud, "o", signed_in=True)
    install_owner_credential(owner.home, server_1, SERVER_ID)
    setup, _ = _setup_with_recovery_confirmation(journey, owner, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(owner, "vault", "create", "--team", TEAM_SLUG, "--name", "Team vault", "--json"))["vault_id"]
    key_path, public_line = _ssh_key_file(owner, name="server-1.pem")
    item_id = _json(cli(owner, "vault", "import", "ssh", "--vault", vault_id,
                        "--path", key_path, "--json"))["item_id"]
    bootstrap_pub = server_1.bootstrap_key.export_public_key("openssh").decode("ascii")
    server_1.remote.write(f"/home/{LOGIN}/.ssh/authorized_keys", f"{bootstrap_pub}\n{public_line}\n", mode=0o600)
    keygen = shutil.which("ssh-keygen", path="/usr/bin:/bin:/usr/local/bin")
    if keygen:
        keygen_lookup_shim.install(str(journey.shims.directory), keygen, str(journey.ctx.root))

    auto_bound_cmd = cli(owner, "vault", "auto-bind", "--team", TEAM_SLUG, "--yes", "--fetch-host-keys", "--json")
    auto_bound = _json(auto_bound_cmd)
    assert auto_bound["servers"][0]["result"] == "bound", auto_bound

    # 2. The owner invites the member, who accepts and signs in as themselves.
    owner_teams = _teams_as(fake_cloud.tokens()[0])
    invited = await owner_teams.invite_member(TEAM_SLUG, MEMBER_EMAIL, "member")
    assert invited["accept_url"] and invited["is_accepted"] is False
    accepted = fake_cloud.accept_invitation(MEMBER_EMAIL)
    assert (accepted["team"], accepted["user"]["id"]) == (TEAM_SLUG, MEMBER_ID)

    member = _home(journey, fake_cloud, "m", signed_in=False)
    fake_cloud.sign_in_next_as(MEMBER_ID)
    login = cli(member, "login", "--no-browser")
    assert login.returncode == 0, login.describe()
    assert "Signed in successfully (plan: teams)" in login.stdout, login.describe()
    assert read_session(member.home)["user_id"] == MEMBER_ID
    assert read_session(owner.home)["user_id"] == OWNER_ID

    # 3. The member's Vault identity: the team vault is listed, its items still closed.
    setup, _ = _setup_with_recovery_confirmation(journey, member, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    listed = _json(cli(member, "vault", "list", "--json"))
    [team_vault] = [row for row in listed if row["vault_id"] == vault_id]
    assert (team_vault["my_role"], team_vault["my_grant"]) == ("member", None)
    closed = cli(member, "vault", "items", "--vault", vault_id, "--json")
    assert closed.returncode == 1 and "HTTP 403, forbidden" in closed.stderr, closed.describe()

    # 4. The owner's client grants the member; the item and the server open up.
    processed = _json(cli(owner, "vault", "grants", "process", "--yes", "--json"))
    accepted_grants = [grant for result in processed for grant in result["accepted"]]
    assert [grant["recipient_user_id"] for grant in accepted_grants] == [MEMBER_ID], processed
    # The roster names both people as the team does, so a screen never falls back to a user id.
    [team_vault] = [row for row in _json(cli(owner, "vault", "list", "--json")) if row["vault_id"] == vault_id]
    assert all(entry.get("display_name") for entry in team_vault["roster"]), team_vault["roster"]
    items = _json(cli(member, "vault", "items", "--vault", vault_id, "--json"))
    assert [row["item_id"] for row in items["data"]] == [item_id]
    shown = _json(cli(member, "vault", "show", item_id, "--vault", vault_id, "--json"))
    assert "ciphertext" not in shown and "private_key_openssh" not in json.dumps(shown)
    # Nothing is left to grant.
    again = _json(cli(owner, "vault", "grants", "process", "--yes", "--json"))
    assert [grant for result in again for grant in result["accepted"]] == []

    # Member connects with the team vault key bound by auto-bind:
    reached_vault = cli(member, "ssh", HOST_NAME, stdin="hostname\n")
    assert reached_vault.returncode == 0, reached_vault.describe()
    assert reached_vault.stdout.splitlines()[0] == HOST_NAME
    assert "SSH resolution tier: vault" in reached_vault.stderr, reached_vault.describe()
    proofs = [login for login in server_1.logins if login.reason == "authorized_keys"]
    assert proofs and proofs[-1].accepted, server_1.logins

    # Next, the owner enables CA and enrolls server-1:
    assert _json(cli(owner, "ca", "enable", "--team", TEAM_SLUG, "--yes", "--json"))["enabled"] is True
    enrolled = _confirmed(journey, owner, servonaut_cmd, "ca", "enroll", HOST_NAME, "--team", TEAM_SLUG,
                          answer=LOOPBACK)
    assert enrolled.returncode == 0 and "result.status: succeeded" in enrolled.text, enrolled.text

    logins_before = len(server_1.certificate_logins())
    reached = cli(member, "ssh", HOST_NAME, stdin="hostname\n")
    assert reached.returncode == 0, reached.describe()
    assert reached.stdout.splitlines()[0] == HOST_NAME
    assert "SSH resolution tier: ca" in reached.stderr, reached.describe()
    new_logins = server_1.certificate_logins()[logins_before:]
    assert new_logins and new_logins[-1].accepted, new_logins
    issued = [row for row in fake_cloud.vault._ca[TEAM_SLUG]["issued"] if row["cert_type"] == "user"]
    assert issued[-1]["user_id"] == MEMBER_ID and issued[-1]["principals"] == [f"svn:{SERVER_ID}:{LOGIN}"]
    reports = [entry for entry in fake_cloud.requests(
        f"/api/v1/teams/{TEAM_SLUG}/servers/{SERVER_ID}/ssh-verify-report") if entry.get("user_id") == MEMBER_ID]
    assert len(reports) == 2, reports
    assert (reports[0]["status"], reports[0]["body"]["status"], reports[0]["body"]["resolution_tier"]) == (200, "verified", "vault")
    assert (reports[1]["status"], reports[1]["body"]["status"], reports[1]["body"]["resolution_tier"]) == (200, "verified", "ca")

    # The member's own edge-1 is the same machine, and its key pair (ops-key)
    # has no key on this computer: it connects with the team's certificate.
    by_own_name = cli(member, "ssh", fleet.EDGE_1.name, stdin="hostname\n")
    assert by_own_name.returncode == 0, by_own_name.describe()
    assert by_own_name.stdout.splitlines()[0] == HOST_NAME
    assert "No key of your own for 'edge-1' here: connecting with team " \
        "Example team's key" in by_own_name.stderr, by_own_name.describe()
    assert "SSH resolution tier: ca" in by_own_name.stderr, by_own_name.describe()
    assert server_1.certificate_logins()[-1].accepted

    # A memory build of that edge-1 connects the same way: with the team's
    # certificate, not ssh's default keys, which this server refuses.
    logins_before = len(server_1.certificate_logins())
    built = cli(member, "memory", "build", fleet.EDGE_1.name)
    assert built.returncode == 0, built.describe()
    assert "Built memory for" in built.stdout, built.describe()
    memory_logins = server_1.certificate_logins()[logins_before:]
    assert memory_logins and all(login.accepted for login in memory_logins), memory_logins

    # 5. Removed from the team, the member no longer sees its vault.
    member_row = next(m for m in fake_cloud.account.members(TEAM_SLUG) if m["user"] and m["user"]["id"] == MEMBER_ID)
    await owner_teams.remove_member(TEAM_SLUG, str(member_row["id"]))
    assert [row["vault_id"] for row in _json(cli(member, "vault", "list", "--json"))
            if row["vault_id"] == vault_id] == []
    # Every request of the member's CLI was answered for the member.
    member_requests = [entry for entry in fake_cloud.requests() if entry.get("user_id") == MEMBER_ID]
    assert member_requests and all(entry["bearer_ok"] for entry in member_requests)
    fake_cloud.assert_no_unexpected_errors(
        *expected("no secret store on file", "no key reference", "no vault binding"),
        # The member's item read before any grant existed.
        ("GET", rf"/api/v1/vaults/{vault_id}/items", 403),
    )

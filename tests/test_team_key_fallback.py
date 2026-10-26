"""A server of the user's own without its key pair connects with a team's key.

A server listed as the user's own (from their own cloud account) that a team
also shares is listed once, as their own. When the user has no key here for
the key pair it names, every connection path uses the team's vault key or SSH
certificate for the same server instead (``shared_servers.team_key_fallback``).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.screens._demo_resolve import team_rows
from servonaut.services.shared_servers import (
    has_team_access,
    lacks_own_key,
    shared_row,
    team_key_fallback,
    team_key_target,
    with_team_key,
)
from servonaut.services.ssh_credentials import (
    VaultCredentialError,
    VaultLeaseCache,
    resolve_with_vault,
)
from servonaut.services.ssh_ref_resolver import ResolvedSshRef, resolve_target, team_key_hint

OPS = {"slug": "ops", "name": "Ops", "role": "member", "id": "team-1"}
BINDING = {"source": "servonaut_vault", "vault_id": "vault-1", "item_id": "item-1"}

# One of the user's own AWS servers, whose key pair has no key file here.
OWN = {
    "id": "i-abc123", "name": "web-1", "provider": "aws", "public_ip": "9.9.9.9",
    "private_ip": "10.0.0.5", "region": "eu-west-2", "key_name": "prod-key",
}
LOCAL_CONN = {
    "host": "9.9.9.9", "username": "ec2-user", "key_path": None,
    "proxy_args": [], "port": None, "extra_options": [],
}


def _team_row(**changes):
    server = {
        "id": "srv-1", "name": "web-1", "hostname": "9.9.9.9", "instance_id": "i-abc123",
        "credential_binding": dict(BINDING),
    }
    server.update(changes)
    return shared_row(server, OPS)


@pytest.fixture()
def lease(tmp_path):
    agent = tmp_path / "agent.sock"
    agent.touch()
    return SimpleNamespace(
        source="vault", identity_agent=str(agent), identity_file=str(tmp_path / "key.pub"),
        certificate_path=None, known_hosts_path=str(tmp_path / "known_hosts"),
        login_user="deploy", target_host="9.9.9.9", target_port=22,
    )


def _runtime(team_lease=None, own_lease=None, team_error=None):
    """A vault runtime holding *team_lease* for the team's row only."""

    async def resolve_ssh(instance):
        if instance.get("is_shared") is True:
            if team_error is not None:
                raise team_error
            return team_lease
        return own_lease

    runtime = MagicMock()
    runtime.agent_key_ttl_seconds = 3600
    runtime.resolve_ssh = AsyncMock(side_effect=resolve_ssh)
    return runtime


def _no_profile():
    return MagicMock(resolve_profile=MagicMock(return_value=None))


# ---------------------------------------------------------------------------
# Which servers fall back, and to which team row
# ---------------------------------------------------------------------------

class TestHasTeamAccess:
    def test_a_team_vault_key_is_access(self):
        assert has_team_access(_team_row())

    def test_an_enrolled_certificate_host_is_access(self):
        assert has_team_access(_team_row(credential_binding=None, ssh_ca={"enrolled": True}))

    def test_a_host_still_enrolling_is_not(self):
        assert not has_team_access(_team_row(credential_binding=None, ssh_ca={"enrolled": False}))

    def test_a_share_without_a_team_key_is_not(self):
        assert not has_team_access(_team_row(credential_binding=None))

    def test_a_binding_of_another_kind_is_not(self):
        assert not has_team_access(_team_row(credential_binding={"source": "bitwarden"}))


class TestLacksOwnKey:
    def test_an_own_cloud_server_whose_key_pair_has_no_key_here(self):
        assert lacks_own_key(OWN, None)

    def test_a_local_key_for_it_is_the_user_s_own(self):
        assert not lacks_own_key(OWN, "/home/user/.ssh/prod-key.pem")

    def test_a_server_without_a_key_pair_keeps_the_user_s_ssh_setup(self):
        # ssh still tries the agent and the default keys there.
        assert not lacks_own_key({**OWN, "key_name": ""}, None)

    def test_a_custom_server_s_key_name_is_its_key_file(self):
        assert not lacks_own_key({**OWN, "is_custom": True, "key_name": "/keys/web1"}, None)

    def test_a_team_s_row_is_not_the_user_s_own(self):
        assert not lacks_own_key({**_team_row(), "key_name": "prod-key"}, None)


class TestTeamKeyFallback:
    def test_the_team_row_for_the_same_server(self):
        team = team_key_fallback(OWN, [_team_row()], None)
        assert team["id"] == "srv-1" and team["team_slug"] == "ops"

    def test_the_same_public_address_is_the_same_server(self):
        row = _team_row(instance_id=None)
        assert team_key_fallback(OWN, [row], None)["id"] == "srv-1"

    def test_another_server_is_not_used(self):
        row = _team_row(instance_id="i-other", hostname="8.8.8.8")
        assert team_key_fallback(OWN, [row], None) is None

    def test_a_share_without_the_team_s_key_is_not_used(self):
        assert team_key_fallback(OWN, [_team_row(credential_binding=None)], None) is None

    def test_the_first_team_with_access_wins(self):
        plain = _team_row(id="srv-0", credential_binding=None)
        first = _team_row(id="srv-1")
        second = shared_row(
            {"id": "srv-2", "name": "web-1", "hostname": "9.9.9.9", "instance_id": "i-abc123",
             "credential_binding": dict(BINDING)},
            {"slug": "dev", "name": "Dev", "role": "member"},
        )
        assert team_key_fallback(OWN, [plain, first, second], None)["id"] == "srv-1"

    def test_a_key_of_the_user_s_own_wins(self):
        assert team_key_fallback(OWN, [_team_row()], "/home/user/.ssh/prod-key.pem") is None

    def test_own_rows_in_the_list_are_ignored(self):
        assert team_key_fallback(OWN, [dict(OWN)], None) is None


class TestMark:
    def test_a_marked_row_names_its_team_row(self):
        marked = with_team_key(OWN, _team_row())
        assert team_key_target(marked)["id"] == "srv-1"
        assert marked["id"] == OWN["id"]  # still the user's own server

    def test_an_unmarked_row_has_none(self):
        assert team_key_target(OWN) is None

    def test_a_mark_that_is_not_a_team_row_is_ignored(self):
        assert team_key_target({**OWN, "team_key_row": {"id": "x"}}) is None

    def test_a_team_row_is_never_marked(self):
        other = shared_row({"id": "srv-9", "name": "x"}, {"slug": "dev", "name": "Dev"})
        assert team_key_target({**_team_row(), "team_key_row": other}) is None

    def test_a_team_record_carrying_a_mark_loses_it(self):
        other = shared_row({"id": "srv-9", "name": "x"}, {"slug": "dev", "name": "Dev"})
        row = shared_row({"id": "srv-1", "name": "web-1", "team_key_row": other}, OPS)
        assert "team_key_row" not in row


# ---------------------------------------------------------------------------
# The vault overlay every in-app SSH path applies
# ---------------------------------------------------------------------------

def _resolve(conn, instance, runtime, rows=(), cache=None):
    return asyncio.run(resolve_with_vault(
        conn, instance, vault_runtime=runtime, connection_service=_no_profile(),
        cache=cache, team_rows=rows,
    ))


class TestResolveWithVault:
    def test_an_own_server_without_its_key_pair_uses_the_team_s_key(self, lease):
        runtime = _runtime(team_lease=lease)
        resolved = _resolve(LOCAL_CONN, OWN, runtime, [_team_row()])

        assert resolved["identity_agent"] == lease.identity_agent
        assert resolved["known_hosts_path"] == lease.known_hosts_path
        assert resolved["username"] == "deploy"  # the team key's login, not ec2-user
        assert resolved["key_path"] is None
        asked = [call.args[0] for call in runtime.resolve_ssh.await_args_list]
        assert [row.get("is_shared") is True for row in asked] == [False, True]

    def test_a_local_key_keeps_the_user_s_own_access(self, lease):
        runtime = _runtime(team_lease=lease)
        conn = {**LOCAL_CONN, "key_path": "/home/user/.ssh/prod-key.pem"}
        resolved = _resolve(conn, OWN, runtime, [_team_row()])

        assert resolved == conn
        assert runtime.resolve_ssh.await_count == 1  # only the own server was asked

    def test_the_user_s_own_vault_key_wins(self, lease, tmp_path):
        own_lease = SimpleNamespace(**{**vars(lease), "login_user": "admin"})
        resolved = _resolve(LOCAL_CONN, OWN, _runtime(team_lease=lease, own_lease=own_lease), [_team_row()])
        assert resolved["username"] == "admin"

    def test_without_a_team_row_nothing_changes(self, lease):
        assert _resolve(LOCAL_CONN, OWN, _runtime(team_lease=lease), []) == LOCAL_CONN

    def test_a_team_key_that_cannot_be_used_keeps_the_user_s_own_setup(self):
        # No vault identity yet, a grant still pending: an agent or ssh's
        # default keys may still hold the server's key, as before.
        runtime = _runtime(team_error=RuntimeError("vault locked"))
        assert _resolve(LOCAL_CONN, OWN, runtime, [_team_row()]) == LOCAL_CONN

    def test_the_server_s_own_vault_key_still_fails_closed(self):
        runtime = _runtime()
        runtime.resolve_ssh = AsyncMock(side_effect=RuntimeError("binding signature mismatch"))
        with pytest.raises(VaultCredentialError, match="could not be used"):
            _resolve(LOCAL_CONN, OWN, runtime, [_team_row()])

    def test_it_goes_by_the_team_s_route_and_names_the_team(self, lease):
        own_route = {**LOCAL_CONN, "profile": SimpleNamespace(bastion_host="bastion-1"),
                     "proxy_args": ["-J", "bastion-1"]}
        resolved = _resolve(own_route, OWN, _runtime(team_lease=lease), [_team_row()])

        # The own row's bastion rule is not the way to the team's host.
        assert resolved["proxy_args"] == []
        assert (resolved["host"], resolved["port"]) == ("9.9.9.9", 22)
        assert resolved["key_team"] == "Ops"

    def test_a_marked_row_uses_its_team_s_key_without_the_list(self, lease):
        marked = with_team_key(OWN, _team_row())
        resolved = _resolve(LOCAL_CONN, marked, _runtime(team_lease=lease))
        assert resolved["identity_agent"] == lease.identity_agent

    def test_a_certificate_host_without_a_login_for_the_user_keeps_the_own_setup(self):
        row = _team_row(credential_binding=None, ssh_ca={"enrolled": True})
        assert _resolve(LOCAL_CONN, OWN, _runtime(team_lease=None), [row]) == LOCAL_CONN

    def test_the_team_s_lease_is_reused(self, lease):
        runtime, cache = _runtime(team_lease=lease), VaultLeaseCache()
        _resolve(LOCAL_CONN, OWN, runtime, [_team_row()], cache)
        _resolve(LOCAL_CONN, OWN, runtime, [_team_row()], cache)
        team_asks = [c for c in runtime.resolve_ssh.await_args_list if c.args[0].get("is_shared")]
        assert len(team_asks) == 1


# ---------------------------------------------------------------------------
# The SSH-ref chain (TUI "SSH Connect" and `servonaut ssh`)
# ---------------------------------------------------------------------------

def _resolver(own=None, team=None, team_error=None):
    async def resolve(instance):
        if instance.get("is_shared") is True:
            if team_error is not None:
                raise team_error
            return team
        return own

    return MagicMock(resolve=AsyncMock(side_effect=resolve))


VAULT_REF = ResolvedSshRef(source="vault", login_user="deploy", identity_agent="/agent")
LOCAL_REF = ResolvedSshRef(source="local", local_key_path="/home/user/.ssh/prod-key.pem")


class TestResolveTarget:
    def test_the_own_server_s_key_wins(self):
        row, ref = asyncio.run(resolve_target(_resolver(own=LOCAL_REF, team=VAULT_REF), OWN, [_team_row()]))
        assert (row["id"], ref) == ("i-abc123", LOCAL_REF)

    def test_without_one_the_team_s_row_and_key(self):
        row, ref = asyncio.run(resolve_target(_resolver(team=VAULT_REF), OWN, [_team_row()]))
        assert (row["id"], row["is_shared"], ref) == ("srv-1", True, VAULT_REF)

    def test_nothing_when_no_team_shares_it(self):
        row, ref = asyncio.run(resolve_target(_resolver(team=VAULT_REF), OWN, []))
        assert (row["id"], ref) == ("i-abc123", None)

    def test_nothing_when_the_team_s_key_resolves_nothing(self):
        row, ref = asyncio.run(resolve_target(_resolver(), OWN, [_team_row()]))
        assert (row["id"], ref) == ("i-abc123", None)

    def test_a_team_key_that_cannot_be_used_fails_closed(self):
        resolver = _resolver(team_error=RuntimeError("vault locked"))
        with pytest.raises(RuntimeError, match="vault locked"):
            asyncio.run(resolve_target(resolver, OWN, [_team_row()]))

    def test_a_custom_server_never_falls_back(self):
        custom = {**OWN, "is_custom": True, "key_name": "/keys/web1"}
        row, ref = asyncio.run(resolve_target(_resolver(team=VAULT_REF), custom, [_team_row()]))
        assert ref is None


class TestTeamKeyHint:
    """Nothing resolved, but a team's key would have with a vault identity here."""

    def test_an_own_server_falling_back_says_to_set_up_the_vault(self):
        hint = team_key_hint(OWN, [_team_row()], None)
        assert hint == (
            "Team Ops shares this server with its own key, which needs a Servonaut Vault "
            "identity on this computer: run `servonaut vault setup`, then connect again."
        )

    def test_the_team_s_own_row_says_so_too(self):
        assert "run `servonaut vault setup`" in team_key_hint(_team_row(), [], SimpleNamespace(is_unlocked=False))

    def test_an_unlocked_identity_needs_no_setup(self):
        assert team_key_hint(OWN, [_team_row()], SimpleNamespace(is_unlocked=True)) is None

    def test_a_share_without_the_team_s_key_has_no_hint(self):
        assert team_key_hint(_team_row(credential_binding=None), [], None) is None

    def test_no_team_no_hint(self):
        assert team_key_hint(OWN, [], None) is None


# ---------------------------------------------------------------------------
# The app's team rows, and the TUI paths
# ---------------------------------------------------------------------------

class TestTeamRows:
    def test_the_team_rows_of_the_fleet(self):
        app = SimpleNamespace(demo_mode=False, redaction_service=None, instances=[OWN, _team_row()])
        assert [row["id"] for row in team_rows(app)] == ["srv-1"]

    def test_demo_mode_reads_the_real_records(self):
        app = SimpleNamespace(
            demo_mode=True, redaction_service=object(),
            instances=[{**_team_row(), "credential_binding": None}],
            _instances_pristine=[OWN, _team_row()],
        )
        assert team_rows(app)[0]["credential_binding"] == BINDING


def _app(runtime, rows):
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.instances = rows
    app.vault_command_service = runtime
    app.vault_lease_cache = VaultLeaseCache()
    app.connection_service = _no_profile()
    # No key file for the key pair on this computer.
    app.ssh_service.get_key_path.return_value = None
    app.ssh_service.discover_key.return_value = None
    app.ssh_service.build_ssh_command.return_value = ["ssh"]
    app.terminal_service.launch_ssh_in_terminal.return_value = True
    return app


def _with_app(obj, app):
    return patch.object(type(obj), "app", new_callable=lambda: property(lambda self: app))


def test_quick_ssh_from_the_fleet_uses_the_team_s_key(lease):
    from servonaut.screens.instance_list import InstanceListScreen

    screen = object.__new__(InstanceListScreen)
    app = _app(_runtime(team_lease=lease), [dict(OWN), _team_row()])

    with _with_app(screen, app), patch.object(screen, "_maybe_show_memory_prompt"), \
            patch.object(screen, "_maybe_pull_annotations"):
        asyncio.run(screen._launch_ssh(dict(OWN), dict(OWN), {**LOCAL_CONN, "profile": None}))

    kwargs = app.ssh_service.build_ssh_command.call_args.kwargs
    assert kwargs["identity_agent"] == lease.identity_agent
    assert kwargs["username"] == "deploy"
    assert kwargs.get("key_path") is None
    assert app.notify.call_args.args[0] == "SSH session launched for web-1 with team Ops's key"


def test_ssh_connect_uses_the_team_s_key_and_says_so(lease):
    from servonaut.screens.server_actions import ServerActionsScreen

    screen = object.__new__(ServerActionsScreen)
    screen._instance = dict(OWN)
    app = _app(_runtime(team_lease=lease), [dict(OWN), _team_row()])
    app.config_manager.get.return_value.default_username = "ec2-user"
    app.connection_service.get_target_host.side_effect = lambda inst, profile: inst.get("public_ip")
    app.connection_service.get_extra_options.return_value = []
    resolver = _resolver(team=ResolvedSshRef(
        source="vault", login_user="deploy", lease=lease, identity_agent=lease.identity_agent,
        identity_file=lease.identity_file, known_hosts_path=lease.known_hosts_path,
    ))

    with _with_app(screen, app), patch.object(screen, "_ssh_ref_resolver", AsyncMock(return_value=resolver)):
        asyncio.run(screen._resolve_and_launch_ssh(MagicMock()))

    kwargs = app.ssh_service.build_ssh_command.call_args.kwargs
    assert (kwargs["host"], kwargs["username"]) == ("9.9.9.9", "deploy")
    assert kwargs["identity_agent"] == lease.identity_agent
    message = app.notify.call_args.args[0]
    assert "with team Ops's key" in message


def test_ssh_connect_without_a_vault_identity_says_how_to_get_one():
    from servonaut.screens.server_actions import ServerActionsScreen

    screen = object.__new__(ServerActionsScreen)
    screen._instance = dict(OWN)
    app = _app(None, [dict(OWN), _team_row()])

    with _with_app(screen, app), patch.object(screen, "_ssh_ref_resolver", AsyncMock(return_value=_resolver())):
        asyncio.run(screen._resolve_and_launch_ssh(MagicMock()))

    app.ssh_service.build_ssh_command.assert_not_called()
    assert app.notify.call_args.args[0].startswith("Team Ops shares this server with its own key")


def test_file_transfers_use_the_team_s_key(lease):
    from servonaut.screens.scp_transfer import SCPTransferScreen

    screen = SCPTransferScreen.__new__(SCPTransferScreen)
    screen._transfer_direction = "upload"
    app = _app(_runtime(team_lease=lease), [dict(OWN), _team_row()])
    app.scp_service.build_upload_command.return_value = ["scp"]
    app.config_manager.get.return_value.default_username = "ec2-user"
    app.connection_service.get_extra_options.return_value = []

    with _with_app(screen, app):
        asyncio.run(screen._vault_transfer_command(dict(OWN), "/tmp/a", "/srv/a"))

    kwargs = app.scp_service.build_upload_command.call_args.kwargs
    assert kwargs["identity_agent"] == lease.identity_agent
    assert kwargs["known_hosts_file"] == lease.known_hosts_path
    assert kwargs["username"] == "deploy"


def test_log_access_uses_the_team_s_key(lease):
    from servonaut.services.log_viewer_service import LogViewerService

    service = LogViewerService.__new__(LogViewerService)
    service._vault_runtime = _runtime(team_lease=lease)
    service._vault_leases = VaultLeaseCache()
    with patch.object(LogViewerService, "_resolve_connection", return_value=dict(LOCAL_CONN)):
        conn = asyncio.run(service.resolve_connection(
            dict(OWN), MagicMock(), _no_profile(), team_rows=[_team_row()],
        ))

    assert conn["identity_agent"] == lease.identity_agent


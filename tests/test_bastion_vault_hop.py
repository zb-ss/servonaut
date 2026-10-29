"""A bastion (jump host) with a Servonaut Vault key of its own: the hop logs in with it."""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from servonaut.config.schema import ConnectionProfile, ConnectionRule
from servonaut.services.api_client import APIError
from servonaut.services.connection_service import ConnectionService
from servonaut.services.ssh_credentials import (
    VaultCredentialError,
    VaultLeaseCache,
    bastion_lease,
    bastion_row,
    resolve_with_vault,
)
from servonaut.services.vault.team_vault_client import VaultStateError
from tests.test_ssh_host_keys import (
    _config_manager,
    _contains_run,
    _proxy_command,
    _proxy_command_argv,
    known_hosts,  # noqa: F401 - fixture
    posix_hop,  # noqa: F401 - fixture
)

BASTION = {"id": "i-0b", "name": "bastion-1", "public_ip": "9.9.9.9", "region": "us-east-1"}
APP = {"id": "i-0a", "name": "app-1", "private_ip": "10.0.1.21", "region": "us-east-1"}
PROFILE = ConnectionProfile(name="via-bastion", bastion_host="9.9.9.9", bastion_user="ec2-user")


def _hop(tmp_path, **overrides):
    agent = tmp_path / "bastion-agent.sock"
    agent.touch()
    values = {
        "source": "vault",
        "identity_agent": str(agent),
        "identity_file": str(tmp_path / "bastion.pub"),
        "certificate_path": None,
        "known_hosts_path": str(tmp_path / "bastion_known_hosts"),
        "login_user": "admin",
        "target_host": "9.9.9.9",
        "target_port": 22,
        "close": lambda: None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class _Runtime:
    """The parts of VaultCommandService the leases use, with one lease per server id."""

    def __init__(self, leases=None, *, unlocked=True, raises=None):
        self.leases = dict(leases or {})
        self.is_unlocked = unlocked
        self.raises = raises
        self.asked: list[str] = []

    async def resolve_ssh(self, instance):
        self.asked.append(str(instance.get("id")))
        if self.raises is not None:
            raise self.raises
        return self.leases.get(instance.get("id"))


def _service(*rules, mode="accept-new"):
    manager = _config_manager(mode)
    config = manager.get.return_value
    config.connection_profiles = [PROFILE]
    config.connection_rules = list(rules)
    return ConnectionService(manager)


APP_RULE = ConnectionRule(name="app", match_conditions={"name_contains": "app"}, profile_name="via-bastion")


# ---------------------------------------------------------------------------
# The hop's argv
# ---------------------------------------------------------------------------


class TestVaultHop:
    def test_the_hop_logs_in_with_the_bastions_key_and_pins(self, tmp_path, known_hosts, posix_hop):
        hop = _hop(tmp_path)
        argv = _proxy_command_argv(_service().get_proxy_args(PROFILE, hop=hop))

        # The signed pins come first, so no configurable option can weaken them.
        assert argv[1:5] == [
            "-o", f'UserKnownHostsFile="{hop.known_hosts_path}"', "-o", "StrictHostKeyChecking=yes",
        ]
        assert "accept-new" not in " ".join(argv)
        assert str(known_hosts.servonaut) not in " ".join(argv)
        assert _contains_run(argv, ["-o", f'IdentityAgent="{hop.identity_agent}"', "-o", "IdentitiesOnly=yes"])
        assert _contains_run(argv, ["-o", f'IdentityFile="{hop.identity_file}"'])
        # The binding's login and pinned address, not the profile's bastion_user.
        assert argv[-4:] == ["-W", "[10.0.0.5]:22", "--", "admin@9.9.9.9"]

    def test_a_certificate_and_a_port_go_to_the_hop(self, tmp_path, known_hosts, posix_hop):
        hop = _hop(tmp_path, certificate_path=str(tmp_path / "bastion-cert.pub"), target_port=2222)
        profile = ConnectionProfile(name="p", bastion_host="9.9.9.9", ssh_port=2222)
        argv = _proxy_command_argv(_service().get_proxy_args(profile, hop=hop))

        assert _contains_run(argv, ["-o", f'CertificateFile="{hop.certificate_path}"'])
        assert _contains_run(argv, ["-p", "2222"])
        # The pins are written for the bound address and port.
        assert _contains_run(argv, ["-o", "HostKeyAlias=[9.9.9.9]:2222"])

    def test_a_bastion_named_by_its_server_name_is_dialled_as_named(self, tmp_path, known_hosts, posix_hop):
        # An ssh_config alias of that name keeps routing it (HostName, Port,
        # ProxyJump); its host key is still checked against the pins.
        profile = ConnectionProfile(name="p", bastion_host="bastion-1")
        argv = _proxy_command_argv(_service().get_proxy_args(profile, hop=_hop(tmp_path)))

        assert _contains_run(argv, ["-o", "HostKeyAlias=9.9.9.9"])
        assert "-p" not in argv
        assert argv[-1] == "admin@bastion-1"

    def test_the_hop_is_a_proxy_command_even_with_host_key_checking_off(self, tmp_path, known_hosts, posix_hop):
        args = _service(mode="off").get_proxy_args(PROFILE, hop=_hop(tmp_path))

        assert args[0] == "-o" and args[1].startswith("ProxyCommand=")
        assert "StrictHostKeyChecking=yes" in args[1]

    def test_windows_keeps_the_users_own_jump(self, tmp_path, known_hosts, monkeypatch):
        monkeypatch.setattr("servonaut.services.connection_service.get_os", lambda: "windows")
        args = _service().get_proxy_args(PROFILE, hop=_hop(tmp_path))

        assert args == ["-J", "ec2-user@9.9.9.9"]

    def test_a_percent_in_a_lease_path_survives_both_expansions(self, tmp_path, known_hosts, posix_hop):
        hop = _hop(tmp_path, identity_agent=str(tmp_path / "a%b.sock"))
        command = _proxy_command(_service().get_proxy_args(PROFILE, hop=hop))

        # The outer ssh, then the hop's ssh, each expand "%" once.
        assert f'IdentityAgent="{tmp_path}/a%%%%b.sock"' in command

    @pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client not installed")
    def test_openssh_reads_the_hop_options_as_written(self, tmp_path, known_hosts, posix_hop):
        hop = _hop(tmp_path, certificate_path=str(tmp_path / "c%1.pub"))
        argv = _proxy_command_argv(_service().get_proxy_args(PROFILE, hop=hop))
        resolved = subprocess.run(
            ["ssh", "-F", "/dev/null", "-G", *argv[1:argv.index("-W")], "9.9.9.9"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.splitlines()

        assert f"userknownhostsfile {hop.known_hosts_path}" in resolved
        assert "stricthostkeychecking true" in resolved
        assert f"identityagent {hop.identity_agent}" in resolved
        assert "identitiesonly yes" in resolved
        # -G shows the value before ssh's own expansion at use, once more.
        assert f"certificatefile {tmp_path}/c%%1.pub" in resolved

    def test_without_a_bastion_key_the_hop_keeps_the_users_own_setup(self, tmp_path, known_hosts, posix_hop):
        # Regression: a vault-bound target's hop got the TARGET's vault agent
        # with IdentitiesOnly and no identity file, so OpenSSH offered no key
        # at all and the user's own agent was hidden from the hop.
        service = _service(APP_RULE)
        target_lease = _hop(tmp_path, identity_agent=str(tmp_path / "bastion-agent.sock"), target_host="10.0.1.21")
        resolved = asyncio.run(resolve_with_vault(
            {"host": "10.0.1.21", "username": "ec2-user", "proxy_args": [], "port": None}, APP,
            vault_runtime=_Runtime({"i-0a": target_lease}), connection_service=service, rows=[APP, BASTION],
        ))
        argv = _proxy_command_argv(resolved["proxy_args"])

        assert not any(word.startswith("IdentityAgent") for word in argv)
        assert "IdentitiesOnly=yes" not in argv
        assert argv[-1] == "ec2-user@9.9.9.9"
        # The target itself still uses its lease.
        assert resolved["identity_agent"] == target_lease.identity_agent


# ---------------------------------------------------------------------------
# Which server is the bastion
# ---------------------------------------------------------------------------


class TestBastionRow:
    def test_the_server_at_the_bastions_address(self):
        assert bastion_row(PROFILE, [APP, BASTION]) is BASTION

    def test_the_port_must_match_too(self):
        profile = ConnectionProfile(name="p", bastion_host="9.9.9.9", ssh_port=2222)
        assert bastion_row(profile, [APP, BASTION]) is None
        assert bastion_row(profile, [{**BASTION, "is_custom": True, "host": "9.9.9.9", "port": 2222}])

    def test_a_cloud_servers_private_address_never_matches(self):
        # The same private address exists in many networks.
        profile = ConnectionProfile(name="p", bastion_host="10.0.1.21")
        assert bastion_row(profile, [APP]) is None

    def test_a_bastion_named_by_its_server_name(self):
        profile = ConnectionProfile(name="p", bastion_host="Bastion-1")
        assert bastion_row(profile, [APP, BASTION]) is BASTION

    def test_two_candidates_find_none(self):
        twin = {**BASTION, "id": "i-0c", "region": "eu-west-1"}
        assert bastion_row(PROFILE, [BASTION, twin]) is None

    def test_the_users_own_server_wins_over_a_teams(self):
        shared = {"id": "srv-1", "name": "bastion", "is_shared": True, "team_slug": "devs",
                  "hostname": "9.9.9.9", "public_ip": "9.9.9.9"}
        assert bastion_row(PROFILE, [shared, BASTION]) is BASTION
        assert bastion_row(PROFILE, [shared]) is shared

    def test_the_users_own_server_by_name_wins_over_a_teams_by_address(self):
        # Review finding: the address tier ran over both groups first.
        profile = ConnectionProfile(name="p", bastion_host="bastion-1")
        shared = {"id": "srv-1", "name": "other", "is_shared": True, "team_slug": "devs",
                  "hostname": "bastion-1", "public_ip": "bastion-1"}
        assert bastion_row(profile, [shared, BASTION]) is BASTION

    def test_a_teams_private_address_never_matches(self):
        # The team's 10.0.0.5 is not necessarily the user's 10.0.0.5.
        profile = ConnectionProfile(name="p", bastion_host="10.0.0.5")
        shared = {"id": "srv-1", "name": "jump", "is_shared": True, "team_slug": "devs",
                  "hostname": "10.0.0.5", "public_ip": "10.0.0.5"}
        assert bastion_row(profile, [shared]) is None


# ---------------------------------------------------------------------------
# Leasing the bastion's key
# ---------------------------------------------------------------------------


def _lease(profile, rows, runtime, service=None, cache=None):
    return asyncio.run(bastion_lease(
        profile, rows, vault_runtime=runtime, connection_service=service, cache=cache,
    ))


class TestBastionLease:
    def test_the_bastions_own_lease(self, tmp_path):
        hop = _hop(tmp_path)
        runtime = _Runtime({"i-0b": hop})

        assert _lease(PROFILE, [APP, BASTION], runtime, _service(APP_RULE)) is hop
        assert runtime.asked == ["i-0b"]

    def test_a_locked_vault_or_no_bastion_server_keeps_the_users_setup(self, tmp_path):
        runtime = _Runtime({"i-0b": _hop(tmp_path)}, unlocked=False)
        assert _lease(PROFILE, [BASTION], runtime) is None
        assert _lease(PROFILE, [APP], _Runtime({"i-0b": _hop(tmp_path)})) is None
        assert _lease(PROFILE, [BASTION], None) is None

    def test_a_bastion_behind_its_own_rule_is_not_leased(self, tmp_path):
        # Its binding pins an address reachable only through itself.
        everything = ConnectionRule(name="all", match_conditions={"name_contains": ""}, profile_name="via-bastion")
        runtime = _Runtime({"i-0b": _hop(tmp_path)})

        assert _lease(PROFILE, [BASTION], runtime, _service(everything)) is None
        assert runtime.asked == []

    def test_a_binding_that_fails_verification_stops_the_connection(self):
        runtime = _Runtime(raises=VaultStateError("binding signature is invalid"))

        with pytest.raises(VaultCredentialError, match="The bastion bastion-1"):
            _lease(PROFILE, [BASTION], runtime)

    @pytest.mark.parametrize("failure", [
        APIError(code="unavailable", message="service down", status=503),
        OSError("connection refused"),
        RuntimeError("Server disconnected without sending a response"),
    ])
    def test_a_key_that_cannot_be_used_here_keeps_the_users_setup(self, failure):
        assert _lease(PROFILE, [BASTION], _Runtime(raises=failure)) is None

    def test_a_private_agent_that_cannot_start_keeps_the_users_setup(self):
        # Review finding: on Windows, or without ssh-agent, this failed closed.
        from servonaut.services.vault.ssh_agent import PrivateSshAgentError

        assert _lease(PROFILE, [BASTION], _Runtime(raises=PrivateSshAgentError("no ssh-agent"))) is None

    def test_a_missing_identity_keeps_the_users_setup(self):
        from servonaut.services.vault.team_vault_client import VaultIdentityMissingError

        assert _lease(PROFILE, [BASTION], _Runtime(raises=VaultIdentityMissingError("no identity"))) is None

    def test_a_moved_bastion_stops_the_connection(self):
        from servonaut.services.vault.bindings import BindingDestinationChangedError

        runtime = _Runtime(raises=BindingDestinationChangedError("the server moved since it was bound"))
        with pytest.raises(VaultCredentialError, match="The bastion bastion-1"):
            _lease(PROFILE, [BASTION], runtime)

    def test_windows_never_leases_the_bastions_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr("servonaut.utils.platform_utils.get_os", lambda: "windows")
        runtime = _Runtime({"i-0b": _hop(tmp_path)})

        assert _lease(PROFILE, [BASTION], runtime) is None
        assert runtime.asked == []

    def test_a_bastion_behind_a_proxy_command_is_not_leased(self, tmp_path):
        manager = _config_manager()
        config = manager.get.return_value
        config.connection_profiles = [PROFILE, ConnectionProfile(name="ssm", proxy_command="aws ssm start-session")]
        config.connection_rules = [ConnectionRule(name="b", match_conditions={"name_contains": "bastion"}, profile_name="ssm")]
        runtime = _Runtime({"i-0b": _hop(tmp_path)})

        assert _lease(PROFILE, [BASTION], runtime, ConnectionService(manager)) is None


class TestResolveWithVault:
    def test_a_target_without_a_vault_key_still_hops_with_the_bastions(self, tmp_path, known_hosts, posix_hop):
        service = _service(APP_RULE)
        runtime = _Runtime({"i-0b": _hop(tmp_path)})
        conn = {"host": "10.0.1.21", "username": "ec2-user", "key_path": "/keys/app.pem",
                "proxy_args": service.get_proxy_args(PROFILE), "port": None}

        resolved = asyncio.run(resolve_with_vault(
            conn, APP, vault_runtime=runtime, connection_service=service, rows=[APP, BASTION],
        ))

        assert resolved["key_path"] == "/keys/app.pem"
        assert "IdentityAgent=" in _proxy_command(resolved["proxy_args"])
        assert "admin@9.9.9.9" in _proxy_command(resolved["proxy_args"])

    def test_one_bastion_lease_serves_every_target_behind_it(self, tmp_path, known_hosts, posix_hop):
        service = _service(APP_RULE)
        app_lease = _hop(tmp_path, identity_agent=str(tmp_path / "bastion-agent.sock"), target_host="10.0.1.21")
        runtime = _Runtime({"i-0a": app_lease, "i-0d": app_lease, "i-0b": _hop(tmp_path)})
        cache = VaultLeaseCache()
        app_2 = {**APP, "id": "i-0d", "name": "app-2"}

        for target in (APP, app_2):
            resolved = asyncio.run(resolve_with_vault(
                {"host": "", "username": "", "proxy_args": [], "port": None}, target,
                vault_runtime=runtime, connection_service=service, cache=cache,
                rows=[APP, app_2, BASTION],
            ))
            assert "admin@9.9.9.9" in _proxy_command(resolved["proxy_args"])

        assert runtime.asked.count("i-0b") == 1


# ---------------------------------------------------------------------------
# The MCP server: the hop and the target's own credential are always closed
# ---------------------------------------------------------------------------


class TestMcpHop:
    @staticmethod
    def _tools(service, runtime, shared_rows=None):
        async def shared():
            if isinstance(shared_rows, BaseException):
                raise shared_rows
            return list(shared_rows or [])

        return SimpleNamespace(
            _vault_runtime=runtime, _connection_service=service,
            _directory=SimpleNamespace(custom_rows=lambda: [], cached_provider_rows=lambda p: [BASTION] if p == "aws" else []),
            _shared_server_rows=shared,
        )

    @staticmethod
    def _call(tools, cleanup):
        from servonaut.mcp.tools import ServonautTools

        return asyncio.run(ServonautTools._with_bastion_hop(
            tools, APP, {"proxy_args": [], "host": "10.0.1.21"}, cleanup,
        ))

    def test_the_hop_is_closed_with_the_targets_cleanup(self, tmp_path, known_hosts, posix_hop):
        closed: list[str] = []
        hop = _hop(tmp_path, close=lambda: closed.append("hop"))

        async def cleanup():
            closed.append("target")

        conn, combined = self._call(self._tools(_service(APP_RULE), _Runtime({"i-0b": hop})), cleanup)
        assert "IdentityAgent=" in _proxy_command(conn["proxy_args"])
        asyncio.run(combined())
        assert closed == ["target", "hop"]

    @pytest.mark.parametrize("failure", [VaultStateError("bad signature"), asyncio.CancelledError()])
    def test_a_failure_or_a_cancelled_call_still_cleans_up_the_target(self, failure):
        # Review finding: the caller only cleans up what it receives.
        closed: list[str] = []

        async def cleanup():
            closed.append("target")

        tools = self._tools(_service(APP_RULE), _Runtime(raises=failure if isinstance(failure, VaultStateError) else None),
                            shared_rows=failure if isinstance(failure, asyncio.CancelledError) else None)
        with pytest.raises((RuntimeError, asyncio.CancelledError)):
            self._call(tools, cleanup)
        assert closed == ["target"]


# ---------------------------------------------------------------------------
# servonaut ssh: a refused bastion key closes the target's lease too
# ---------------------------------------------------------------------------


def test_the_cli_closes_the_targets_lease_when_the_bastion_key_is_refused(monkeypatch, capsys):
    from unittest.mock import AsyncMock, MagicMock, patch

    from servonaut.cli import ssh as ssh_mod
    from tests.test_cli_ssh import _app_instance, _make_args, _rule_config

    target_lease = SimpleNamespace(close=MagicMock())
    resolved = SimpleNamespace(source="vault", lease=target_lease, login_user="deploy", identity_agent="/a",
                               identity_file="/a.pub", known_hosts_path="/kh", certificate_path=None)
    config = _rule_config()
    manager = MagicMock()
    manager.get.return_value = config
    from servonaut.services.ssh_service import SSHService

    headless = (config, MagicMock(is_authenticated=True), MagicMock(), MagicMock(),
                MagicMock(), SSHService(manager), MagicMock())
    with (
        patch.object(ssh_mod, "_init_headless_services", return_value=headless),
        patch.object(ssh_mod, "_load_instances", return_value=[_app_instance()]),
        patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as resolver,
        patch.object(ssh_mod, "bastion_lease", AsyncMock(side_effect=VaultCredentialError("The bastion bastion-1: bad"))),
        patch("subprocess.run") as run,
    ):
        resolver.return_value.resolve = AsyncMock(return_value=resolved)
        assert ssh_mod.handle_ssh_command(_make_args("app-1")) != 0

    run.assert_not_called()
    target_lease.close.assert_called_once_with()


def test_a_transfer_without_a_vault_key_keeps_the_bastions_hop(tmp_path, known_hosts, posix_hop):
    # Review finding: the transfer fell back to its own options (and their
    # hop) whenever the target had no vault lease.
    from servonaut.screens.scp_transfer import SCPTransferScreen

    service = _service(APP_RULE)
    app = SimpleNamespace(
        vault_command_service=_Runtime({"i-0b": _hop(tmp_path)}), connection_service=service,
        vault_lease_cache=None, instances=[APP, BASTION], demo_mode=False, redaction_service=None,
    )
    sent: list = []
    screen = SimpleNamespace(
        app=app,
        _transfer_options=lambda conn: {"host": "10.0.1.21", "username": "ec2-user", "key_path": "/keys/app.pem",
                                        "proxy_args": service.get_proxy_args(PROFILE), "port": None},
        _command_for=lambda options, local, remote: sent.append(options) or ["scp"],
    )

    asyncio.run(SCPTransferScreen._vault_transfer_command(screen, dict(APP), "/tmp/a", "/tmp/b"))

    assert "IdentityAgent=" in _proxy_command(sent[0]["proxy_args"])
    assert sent[0]["key_path"] == "/keys/app.pem"

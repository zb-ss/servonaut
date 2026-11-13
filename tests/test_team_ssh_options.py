"""A connection never runs a program a team set, unless the member allowed it."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig, ConnectionProfile, CustomServer
from servonaut.services.connection_service import ConnectionService
from servonaut.services.scp_service import SCPService
from servonaut.services.ssh_service import SSHService
from servonaut.utils.ssh_names import SSHNameError, SSHRefusal
from servonaut.utils.ssh_option_policy import REFUSED_OPTION_VALUE, RefusedOption, SSHOptionRefused

PROXY = "ssh -W %h:%p jump"
EXTRAS = ["LocalCommand=notify-send hi", "PermitLocalCommand=yes", "ServerAliveInterval=60"]
SETTINGS_HINT = 'To allow it, run "servonaut team options" or open Settings > Connections.'


def item(text: str, *, allowed: bool = False, team_name: str = "Acme") -> dict:
    return {"option": text, "team": "7", "team_name": team_name, "allowed": allowed}


def services(config: AppConfig):
    manager = MagicMock()
    manager.get.return_value = config
    return ConnectionService(manager), SSHService(manager), SCPService(config.ssh)


def build(ssh: SSHService, conn: ConnectionService, instance: dict, profile):
    return ssh.build_ssh_command(
        host="10.0.0.5", username="deploy",
        proxy_args=conn.get_proxy_args(profile) if profile else [],
        extra_options=conn.get_extra_options(instance, profile),
    )


def flat(argv) -> str:
    return " ".join(argv)


# --- 5. a recorded proxy command --------------------------------------------

def test_a_recorded_proxy_command_is_not_started_and_the_message_says_how_to_allow_it():
    profile = ConnectionProfile(name="jump", proxy_command=PROXY)
    config = AppConfig(connection_profiles=[profile])
    config.ssh.team_options = [item(f"proxycommand={PROXY}")]
    conn, ssh, _scp = services(config)

    args = conn.get_proxy_args(profile)
    assert args[0] == "-o" and isinstance(args[1], RefusedOption)
    with pytest.raises(SSHOptionRefused) as caught:
        build(ssh, conn, {"id": "i-1"}, profile)
    assert str(caught.value) == (
        "Not connecting: the connection profile 'jump' came from team Acme and sets ProxyCommand, "
        f"which runs a program on this computer. {SETTINGS_HINT}"
    )
    assert isinstance(caught.value, SSHRefusal)


def test_the_refused_command_text_is_in_no_argv():
    profile = ConnectionProfile(name="jump", proxy_command=PROXY)
    config = AppConfig(connection_profiles=[profile])
    config.ssh.team_options = [item(f"proxycommand={PROXY}")]
    conn, _ssh, _scp = services(config)
    assert all(PROXY not in str(word) for word in conn.get_proxy_args(profile))


# --- 6. extra options ---------------------------------------------------------

def test_recorded_extra_options_are_refused_and_allowed_ones_keep_their_order():
    profile = ConnectionProfile(name="jump", extra_ssh_options=list(EXTRAS))
    config = AppConfig(connection_profiles=[profile])
    config.ssh.team_options = [item("localcommand=notify-send hi"), item("permitlocalcommand=yes")]
    conn, ssh, _scp = services(config)
    with pytest.raises(SSHOptionRefused, match="LocalCommand"):
        build(ssh, conn, {"id": "i-1"}, profile)

    config.ssh.team_options = [
        item("localcommand=notify-send hi", allowed=True), item("permitlocalcommand=yes", allowed=True),
    ]
    argv = build(ssh, conn, {"id": "i-1"}, profile)
    positions = [argv.index(option) for option in EXTRAS]
    assert positions == sorted(positions)
    assert REFUSED_OPTION_VALUE not in argv


# --- 7. the member's own entries are untouched ---------------------------------

def test_the_members_own_options_build_exactly_what_they_built_before():
    profile = ConnectionProfile(
        name="mine", proxy_command=PROXY,
        extra_ssh_options=["ProxyCommand=other", "FooBar=1", *EXTRAS],
    )
    server = {"id": "c-1", "name": "web-1", "extra_ssh_options": ["RemoteCommand=id", "Include=x"]}
    conn, ssh, _scp = services(AppConfig(connection_profiles=[profile]))
    got = build(ssh, conn, server, profile)

    manager = MagicMock()
    manager.get.return_value = AppConfig()
    expected = SSHService(manager).build_ssh_command(
        host="10.0.0.5", username="deploy",
        proxy_args=["-o", f"ProxyCommand={PROXY}"],
        extra_options=["ProxyCommand=other", "FooBar=1", *EXTRAS, "RemoteCommand=id", "Include=x"],
    )
    assert got == expected
    assert not any(isinstance(word, RefusedOption) for word in got)


# --- 8. what Servonaut generates -----------------------------------------------

def test_a_team_profiles_own_bastion_route_is_never_judged():
    profile = ConnectionProfile(
        name="gw", bastion_host="bastion.example.net", bastion_user="ec2-user", bastion_key="~/.ssh/b.pem",
    )
    config = AppConfig(connection_profiles=[profile])
    config.ssh.team_options = [item(f"proxycommand={PROXY}")]
    conn, ssh, _scp = services(config)
    argv = build(ssh, conn, {"id": "i-1"}, profile)
    assert any(str(word).startswith("ProxyCommand=ssh ") for word in argv)


def test_a_vault_hop_is_never_judged():
    profile = ConnectionProfile(name="gw", bastion_host="bastion.example.net", bastion_user="ec2-user")
    config = AppConfig(connection_profiles=[profile])
    config.ssh.team_options = [item(f"proxycommand={PROXY}")]
    conn, _ssh, _scp = services(config)
    hop = MagicMock(login_user="ec2-user", target_host="bastion.example.net", target_port=22,
                    identity_agent="/run/agent.sock", identity_file=None, certificate_path=None,
                    known_hosts_path=None)
    args = conn.get_proxy_args(profile, hop=hop)
    assert not any(isinstance(word, RefusedOption) for word in args)
    assert str(args[1]).startswith("ProxyCommand=ssh ")


# --- 9. shared servers ---------------------------------------------------------

def test_a_shared_servers_options_are_the_teams_and_need_an_allowed_record():
    row = {"id": "s-1", "name": "web-1", "is_shared": True, "team_name": "Acme",
           "extra_ssh_options": ["ProxyCommand=x", "ServerAliveInterval=5"]}
    config = AppConfig()
    conn, ssh, _scp = services(config)
    with pytest.raises(SSHOptionRefused) as caught:
        build(ssh, conn, row, None)
    assert str(caught.value) == (
        "Not connecting: team Acme's record of the server 'web-1' sets ProxyCommand, which runs a "
        "program on this computer. Ask the team to remove it, or allow it by adding it to "
        "ssh.team_options in ~/.servonaut/config.json."
    )
    assert conn.get_extra_options({**row, "extra_ssh_options": ["ServerAliveInterval=5"]}, None) == [
        "ServerAliveInterval=5"
    ]

    config.ssh.team_options = [item("proxycommand=x", allowed=True)]
    assert "ProxyCommand=x" in build(ssh, conn, row, None)


# --- 10. the team's key on the member's own server -----------------------------

def test_the_team_key_fallback_hands_the_builder_the_refusal():
    from servonaut.services import ssh_credentials

    team_row = {"id": "s-1", "name": "web-1", "is_shared": True, "team_name": "Acme",
                "extra_ssh_options": ["ProxyCommand=x"]}
    conn_service, ssh, _scp = services(AppConfig())
    extras = conn_service.get_extra_options(team_row, None)
    applied = ssh_credentials.apply_vault_lease(
        {"extra_options": list(extras), "proxy_args": []},
        MagicMock(identity_agent="/run/a.sock", identity_file="/k.pub", certificate_path=None,
                  known_hosts_path="/kh", login_user="deploy", target_host="10.0.0.5", target_port=22),
        instance=team_row, connection_service=conn_service, hop=None,
    )
    with pytest.raises(SSHOptionRefused, match="ProxyCommand"):
        ssh.build_ssh_command(
            host="10.0.0.5", username="deploy", proxy_args=applied["proxy_args"],
            extra_options=applied["extra_options"],
        )


# --- 11. bastion names and ports -----------------------------------------------

def test_a_bastion_host_with_shell_syntax_is_refused():
    profile = ConnectionProfile(name="gw", bastion_host="a;b")
    conn, ssh, _scp = services(AppConfig(connection_profiles=[profile]))
    with pytest.raises(SSHOptionRefused) as caught:
        build(ssh, conn, {"id": "i-1"}, profile)
    assert str(caught.value) == (
        "Not connecting: the bastion host name 'a;b' in the connection profile 'gw' contains a "
        "space, quote, backslash or shell symbol. Correct it in Settings > Connections."
    )


def test_a_bastion_user_with_a_quote_is_refused():
    profile = ConnectionProfile(name="gw", bastion_host="bastion.example.net", bastion_user="a'b")
    conn, ssh, _scp = services(AppConfig(connection_profiles=[profile]))
    with pytest.raises(SSHOptionRefused, match="bastion user name"):
        build(ssh, conn, {"id": "i-1"}, profile)


def test_a_port_that_is_not_a_number_adds_nothing_to_the_jump_string():
    profile = ConnectionProfile(name="gw", bastion_host="bastion.example.net")
    profile.ssh_port = "22 -oX"  # type: ignore[assignment]
    conn, _ssh, _scp = services(AppConfig(connection_profiles=[profile]))
    assert conn.get_proxy_jump_string(profile) == "bastion.example.net"
    profile.ssh_port = 2222
    assert conn.get_proxy_jump_string(profile) == "bastion.example.net:2222"


# --- 12. scp and the verify probe ----------------------------------------------

@pytest.mark.parametrize("direction", ["upload", "download"])
def test_scp_refuses_a_refused_option(direction):
    profile = ConnectionProfile(name="jump", proxy_command=PROXY)
    config = AppConfig(connection_profiles=[profile])
    config.ssh.team_options = [item(f"proxycommand={PROXY}")]
    conn, _ssh, scp = services(config)
    kwargs = dict(
        host="10.0.0.5", username="deploy", proxy_args=conn.get_proxy_args(profile),
        extra_options=conn.get_extra_options({"id": "i-1"}, profile),
    )
    method = scp.build_upload_command if direction == "upload" else scp.build_download_command
    with pytest.raises(SSHOptionRefused):
        method("/tmp/a", "/tmp/b", **kwargs)


def test_the_verify_probe_does_not_start_ssh(monkeypatch):
    from servonaut.cli import servers

    started = []
    monkeypatch.setattr(servers, "run_ssh", lambda *a, **k: started.append(a))
    route = {"profile": None, "proxy_args": ["-o", RefusedOption("Not connecting: x")], "extra_options": []}
    with pytest.raises(SSHOptionRefused):
        servers._run_ssh_probe("/k", "deploy", "10.0.0.5", 22, 5, None, None, route)
    assert started == []


# --- 13. a builder that forgot the check ---------------------------------------

def test_a_carrier_that_reaches_ssh_unchecked_is_an_option_ssh_rejects():
    assert str(RefusedOption("Not connecting: x")) == "ServonautRefusedOption=yes"


# --- MCP and relay ---------------------------------------------------------------

def _custom_row() -> dict:
    return {"id": "custom-1", "name": "web-1", "is_custom": True, "public_ip": "9.9.9.9",
            "private_ip": "9.9.9.9", "username": "deploy", "port": 22, "state": "running",
            "provider": "custom", "extra_ssh_options": ["ProxyCommand=touch /tmp/never"]}


def _real_mcp_tools():
    from tests.test_mcp_tools import make_tools

    tools = make_tools(guard_level="dangerous", custom_instances=[_custom_row()])
    config = AppConfig()
    config.ssh.team_options = [item("proxycommand=touch /tmp/never")]
    manager = MagicMock()
    manager.get.return_value = config
    conn, ssh, scp = services(config)
    tools._ssh_service, tools._connection_service, tools._scp_service = ssh, conn, scp
    tools._config_manager.get.return_value.ssh = config.ssh
    return tools


def test_mcp_run_command_refuses_without_starting_ssh(monkeypatch):
    from servonaut.mcp import tools as mcp_tools

    started = []

    async def boom(*args, **kwargs):
        started.append(args)
        raise AssertionError("ssh must not start")

    monkeypatch.setattr(mcp_tools, "run_ssh_subprocess", boom)
    tools = _real_mcp_tools()
    result = asyncio.run(tools.run_command("custom-1", "uptime"))
    assert result.startswith("Error: Not connecting: the custom server 'web-1' came from team Acme and sets ProxyCommand")
    assert started == []
    reasons = [call.args[4] for call in tools._audit.log.call_args_list if len(call.args) > 4]
    assert "team_option_refused" in reasons
    assert all(call.args[3] is False for call in tools._audit.log.call_args_list if call.args[0] == "run_command")


def test_mcp_transfer_file_refuses_without_starting_scp(tmp_path):
    tools = _real_mcp_tools()
    local = tmp_path / "f.txt"
    local.write_text("x")
    result = asyncio.run(tools.transfer_file("custom-1", str(local), "/tmp/f.txt", "upload"))
    assert result.startswith("Error: Not connecting:")
    tools._scp_service.execute_transfer = MagicMock(side_effect=AssertionError("scp must not start"))
    reasons = [call.args[4] for call in tools._audit.log.call_args_list if len(call.args) > 4]
    assert "team_option_refused" in reasons


def test_the_relay_rejects_and_audits_a_refused_option(monkeypatch):
    from servonaut.services import relay_executors
    from tests.test_relay_executors import make_executors, make_request

    executors = make_executors(custom_instances=[_custom_row()])
    config = AppConfig()
    config.ssh.team_options = [item("proxycommand=touch /tmp/never")]
    conn, ssh, scp = services(config)
    executors._ssh_service, executors._connection_service, executors._scp_service = ssh, conn, scp
    executors._config_manager.get.return_value = config
    executors._audit = MagicMock()

    async def boom(*args, **kwargs):
        raise AssertionError("ssh must not start")

    monkeypatch.setattr(relay_executors, "run_ssh_subprocess", boom)
    response = asyncio.run(executors.execute(
        make_request(target="custom-1", payload={"command": "uptime"})
    ))
    assert response.status == "rejected"
    assert response.error_message.startswith("Not connecting: the custom server 'web-1'")
    row = executors._audit.log.call_args
    assert row.args[4] == "team_option_refused" and row.kwargs["source"] == "relay"


def test_the_relay_rejects_a_refused_transfer(tmp_path):
    from servonaut.services.relay_executors import _TRANSFERS_DIR
    from servonaut.models.relay_messages import CommandType
    from tests.test_relay_executors import make_executors, make_request

    executors = make_executors(custom_instances=[_custom_row()])
    config = AppConfig()
    config.ssh.team_options = [item("proxycommand=touch /tmp/never")]
    conn, ssh, scp = services(config)
    executors._ssh_service, executors._connection_service, executors._scp_service = ssh, conn, scp
    executors._config_manager.get.return_value = config
    executors._audit = MagicMock()
    _TRANSFERS_DIR.mkdir(parents=True, exist_ok=True)
    scp.execute_transfer = MagicMock(side_effect=AssertionError("scp must not start"))
    response = asyncio.run(executors.execute(make_request(
        cmd_type=CommandType.TRANSFER_FILE, target="custom-1",
        payload={"local_path": str(_TRANSFERS_DIR / "f.txt"), "remote_path": "/tmp/f.txt",
                 "direction": "upload"},
    )))
    assert response.status == "rejected"
    assert response.error_message.startswith("Not connecting:")
    assert executors._audit.log.call_args.args[4] == "team_option_refused"


def test_a_refused_get_logs_is_audited_with_the_words_it_was_asked_for(monkeypatch):
    from servonaut.mcp import tools as mcp_tools

    async def boom(*args, **kwargs):
        raise AssertionError("ssh must not start")

    monkeypatch.setattr(mcp_tools, "run_ssh_subprocess", boom)
    tools = _real_mcp_tools()
    result = asyncio.run(tools.get_logs("custom-1", "/var/log/syslog", 5))
    assert result.startswith("Error: Not connecting:")
    row = next(c for c in tools._audit.log.call_args_list if c.args[4:5] == ("team_option_refused",))
    assert row.args[1]["requested_as"] == "reading logs"

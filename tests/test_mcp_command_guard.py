"""Standard-tier command rules: read-only allowlisted commands, optionally piped."""
from __future__ import annotations

import pytest

from servonaut.config.schema import MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel


def _guard(level: str = GuardLevel.STANDARD, **overrides) -> CommandGuard:
    return CommandGuard(MCPConfig(guard_level=level, **overrides))


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "tail -n 100 /var/log/syslog",
        "tail -n 100 -- '/var/log/app one.log'",
        "grep error /var/log/syslog | head -20",
        "ps aux | grep nginx | wc -l",
        "sudo tail -n 50 /var/log/syslog",
        "grep 'a;b' /etc/hosts",
        "grep -E 'x|y' /etc/hosts",
        "grep '$HOME' /etc/profile",
        "find /var/log -name '*.gz'",
        "ip addr show",
        "ip -s link",
        "ip route",
        "date +%s",
        "date -Iseconds",
        "hostname",
        "hostname -f",
        "ifconfig",
        "ifconfig eth0",
        "ifconfig -a",
        "ss -tlnp",
        "ping -c 3 9.9.9.9",
        "sort -n /etc/hosts",
        "df -h",
        "uname -a",
    ],
)
def test_standard_tier_allows_read_only_commands(command):
    allowed, reason = _guard().check_command(command)
    assert allowed, reason


@pytest.mark.parametrize(
    "command",
    [
        "tail -n 1 /var/log/syslog; id",
        "tail -n 1 /var/log/syslog && id",
        "tail -n 1 /var/log/syslog || id",
        "tail -n 1 /var/log/syslog | sh",
        "tail -n 1 /var/log/syslog &",
        "tail -n 1 $(id)",
        "tail -n 1 ${HOME}",
        "tail -n 1 `id`",
        "tail -n 1 /var/log/syslog\nid",
        "tail -n 1 /var/log/syslog\rid",
        "tail -n 1 /var/log/syslog > /tmp/out",
        "tail -n 1 /var/log/syslog 2>&1",
        "tail < /etc/hosts",
        "( id )",
        "tail -n 1 'unbalanced",
        "tail -n 1 /var/log/syslog | ",
        "FOO=1 tail /var/log/syslog",
        "echo hello",
        "sudo",
        "sudo -s",
        "sudo -u root tail /var/log/syslog",
    ],
)
def test_standard_tier_refuses_shell_operators_and_other_commands(command):
    allowed, _ = _guard().check_command(command)
    assert not allowed


@pytest.mark.parametrize(
    "command",
    [
        "find / -exec id {} +",
        "find /tmp -execdir id {} ;",
        "find /tmp -delete",
        "find /tmp -fprint /tmp/list",
        "sort -o /tmp/out /etc/hosts",
        "sort -uo /tmp/out /etc/hosts",
        "sort --output=/tmp/out /etc/hosts",
        "sudo ip route del default",
        "ip link set eth0 down",
        "ip addr flush dev eth0",
        "ip netns exec other id",
        "ip -batch /tmp/commands",
        "ifconfig eth0 down",
        "ifconfig eth0 10.0.0.2 netmask 255.255.255.0",
        "ss -K dst 9.9.9.9",
        "ss -tK",
        "date -s '2020-01-01'",
        "date --set=2020-01-01",
        "date 010112002026",
        "hostname other-name",
        "hostname -F /tmp/name",
        "hostname -b",
        "file -C -m /tmp/magic",
        "ping -f 9.9.9.9",
    ],
)
def test_standard_tier_refuses_state_changing_forms(command):
    allowed, reason = _guard().check_command(command)
    assert not allowed
    assert "standard mode" in reason


def test_refusal_reason_never_echoes_the_full_command():
    command = "tail -n 1 /var/log/syslog; " + "x" * 200
    allowed, reason = _guard().check_command(command)
    assert not allowed
    assert "x" * 50 not in reason


def test_unknown_command_reason_is_bounded():
    allowed, reason = _guard().check_command("y" * 500)
    assert not allowed
    assert len(reason) < 200


def test_added_allowlist_command_gets_operator_checks_only():
    guard = _guard(command_allowlist=["myapp"])
    assert guard.check_command("myapp --anything goes")[0]
    assert not guard.check_command("myapp --status; id")[0]
    assert not guard.check_command("myapp --status | sh")[0]


@pytest.mark.parametrize("command", ["ls -la", "tail -n 1 /var/log/syslog"])
def test_readonly_tier_refuses_every_command(command):
    allowed, reason = _guard(GuardLevel.READONLY).check_command(command)
    assert not allowed
    assert "readonly" in reason


def test_dangerous_tier_allows_operators_but_keeps_the_blocklist():
    guard = _guard(GuardLevel.DANGEROUS)
    assert guard.check_command("tail -n 1 /var/log/syslog; id")[0]
    assert not guard.check_command("ls; rm -rf /tmp/x")[0]


@pytest.mark.parametrize(
    "command",
    [
        "sort --outp=/tmp/out /etc/hosts",
        "sort --compress-program=gzip /etc/hosts",
        "sort --comp=gzip /etc/hosts",
        "date --se=2020-01-01",
        "ss --ki dst 9.9.9.9",
        "ss -D /tmp/dump",
        "ss --diag=/tmp/dump",
        "file --comp -m /tmp/magic",
        "ip a d 10.0.0.1/24 dev eth0",
        "ip link s eth0 down",
        "ip r flush all",
        "ip -ba /tmp/commands",
    ],
)
def test_standard_tier_refuses_abbreviated_and_extra_state_changing_forms(command):
    allowed, _ = _guard().check_command(command)
    assert not allowed


@pytest.mark.parametrize(
    "command",
    ["ip -f inet addr show", "ip route get 1.1.1.1", "ip netns list", "ip -4 route"],
)
def test_ip_accepts_read_verbs_after_value_options(command):
    assert _guard().check_command(command)[0]


@pytest.mark.parametrize(
    ("command", "rendered"),
    [
        ("ls -la /var/log/*.log", "ls -la /var/log/*.log"),
        ("cat ~/.bashrc", "cat ~/.bashrc"),
        ("grep 'a;b' /etc/hosts | head -20", "grep 'a;b' /etc/hosts | head -20"),
        ("tail -n 5 -- '/var/log/app one.log'", "tail -n 5 -- '/var/log/app one.log'"),
        ("grep \"$HOME\" /etc/profile", "grep '$HOME' /etc/profile"),
        ("grep '#x' /etc/hosts", "grep '#x' /etc/hosts"),
    ],
)
def test_standard_commands_are_rebuilt_from_checked_tokens(command, rendered):
    guard = _guard()
    assert guard.check_command(command)[0]
    assert guard.command_for_execution(command) == rendered


def test_dangerous_commands_run_unchanged():
    command = "tail -n 1 /var/log/syslog; uptime"
    assert _guard(GuardLevel.DANGEROUS).command_for_execution(command) == command

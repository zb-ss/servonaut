"""Host and user names with shell syntax are refused before an ssh command is built."""
from __future__ import annotations

import pytest

from servonaut.config.manager import ConfigManager
from servonaut.services.scp_service import SCPService
from servonaut.services.ssh_service import SSHService
from servonaut.utils.ssh_names import SSHNameError, check_ssh_host, check_ssh_user

GOOD_HOSTS = [
    "web-1.example.net", "10.0.0.5", "2001:db8::1", "[2001:db8::1]", "fe80::1%eth0",
    "münchen.example", "host_name", "a",
]
BAD_HOSTS = [
    "x';touch marker;'", "web 1", "web\t1", "web\n1", "a\\b", "$(touch marker)", "`id`",
    "a;b", "a|b", "a&b", 'a"b', "a<b", "a*b", "a\x1bb", "a=b",
]
GOOD_USERS = ["ec2-user", "deploy", "CORP\\jdoe", "jdoe@CORP", "dot.name", "übung"]
BAD_USERS = ["a'b", "a b", "a\nb", "a\x1bb", "a\tb"]


@pytest.mark.parametrize("host", GOOD_HOSTS)
def test_real_host_names_pass(host) -> None:
    check_ssh_host(host)


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_a_host_with_shell_syntax_is_refused_with_a_message_that_says_what_to_fix(host) -> None:
    with pytest.raises(SSHNameError, match="Correct the server's address"):
        check_ssh_host(host)


@pytest.mark.parametrize("user", GOOD_USERS)
def test_real_user_names_pass(user) -> None:
    check_ssh_user(user)


@pytest.mark.parametrize("user", BAD_USERS)
def test_a_user_with_a_quote_or_whitespace_is_refused(user) -> None:
    with pytest.raises(SSHNameError, match="user name"):
        check_ssh_user(user)


def test_the_message_shows_control_characters_as_text() -> None:
    with pytest.raises(SSHNameError) as caught:
        check_ssh_host("a\x1b[8mb")
    assert "\x1b" not in str(caught.value)


def _ssh_service(tmp_path) -> SSHService:
    return SSHService(ConfigManager(config_path=tmp_path / "config.json"))


@pytest.mark.parametrize("host", BAD_HOSTS[:6])
def test_the_ssh_builder_refuses_a_bad_host(tmp_path, host) -> None:
    with pytest.raises(SSHNameError):
        _ssh_service(tmp_path).build_ssh_command(host=host, username="deploy")


def test_the_ssh_builder_refuses_a_bad_user(tmp_path) -> None:
    with pytest.raises(SSHNameError):
        _ssh_service(tmp_path).build_ssh_command(host="9.9.9.9", username="a'b")


def test_the_ssh_builder_still_builds_for_a_good_target(tmp_path) -> None:
    command = _ssh_service(tmp_path).build_ssh_command(host="web-1.example.net", username="CORP\\jdoe")
    assert any(word.startswith("CORP\\jdoe") and word.endswith("web-1.example.net") for word in command)


@pytest.mark.parametrize("host", BAD_HOSTS[:6])
def test_the_scp_builders_refuse_a_bad_host(host) -> None:
    with pytest.raises(SSHNameError):
        SCPService().build_upload_command("/tmp/a", "/srv/a", host, "deploy")
    with pytest.raises(SSHNameError):
        SCPService().build_download_command("/srv/a", "/tmp/a", host, "deploy")


def test_the_cli_prints_the_message_and_exits_with_an_error(monkeypatch, capsys) -> None:
    from servonaut.cli import ssh as cli_ssh

    async def refuse(_args):
        check_ssh_host("x';touch marker;'")
        return 0

    monkeypatch.setattr(cli_ssh, "_handle_ssh_async", refuse)
    assert cli_ssh.handle_ssh_command(object()) == cli_ssh._EXIT_GENERIC_ERROR
    assert "Correct the server's address" in capsys.readouterr().err

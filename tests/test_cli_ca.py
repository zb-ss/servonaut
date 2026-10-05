"""Focused parser and command-boundary tests for ``servonaut ca``."""
from __future__ import annotations

import argparse

import pytest

from servonaut.cli import ca


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand")
    ca.add_ca_parser(subparsers)
    return parser


def test_ca_parser_accepts_enroll() -> None:
    args = _parser().parse_args(["ca", "enroll", "server-1", "--team", "ops"])

    assert ca.is_ca_command(args)
    assert args.ca_command == "enroll"
    assert args.break_glass_item is None


def test_ca_status_dispatches_through_injected_service(capsys) -> None:
    class Service:
        async def ca_status(self, *, team):
            return {"team": team, "enabled": True}

    ca.set_ca_service_factory(Service)
    try:
        args = _parser().parse_args(["ca", "status", "--team", "ops"])
        assert ca.handle_ca_command(args) == 0
    finally:
        ca.set_ca_service_factory(None)

    assert "enabled: True" in capsys.readouterr().out


def test_ca_human_output_shows_nested_policy_as_dotted_rows(capsys) -> None:
    from servonaut.cli import ca as ca_cli

    ca_cli._print({"enabled": True, "policy": {"role_logins": {"member": ["deploy"], "viewer": []},
                                                "max_ttl_seconds": 7200}}, False)

    out = capsys.readouterr().out.splitlines()
    assert "policy.role_logins.member.1: deploy" in out
    assert "policy.role_logins.viewer: []" in out
    assert "policy.max_ttl_seconds: 7200" in out


@pytest.mark.asyncio
async def test_ca_policy_update_sends_fields_at_the_top_level() -> None:
    from unittest.mock import AsyncMock, MagicMock

    from servonaut.services.vault.ca_client import CertificateAuthorityClient

    client = CertificateAuthorityClient.__new__(CertificateAuthorityClient)
    client.team_slug = "team-a"
    client._signed = AsyncMock(return_value={"policy": {}, "hosts_needing_refresh": ["server-1"]})
    client.get_status = AsyncMock(return_value=MagicMock())

    _status, hosts = await client.update_policy({"interactive_ttl_seconds": 3600})

    client._signed.assert_awaited_once_with("PUT", "/api/v1/teams/team-a/ssh-ca/policy", {"interactive_ttl_seconds": 3600})
    assert hosts == ["server-1"]


def test_break_glass_scan_window_out_of_range_is_a_usage_error(capsys) -> None:
    parser = argparse.ArgumentParser()
    ca.add_ca_parser(parser.add_subparsers(dest="subcommand"))
    args = parser.parse_args(["ca", "break-glass-scan", "--team", "team-a", "--hours", "0"])

    assert ca.handle_ca_command(args) == 2
    assert "--hours must be between 1 and 720" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_ca_revoke_posts_a_signed_request_for_the_serial() -> None:
    from unittest.mock import AsyncMock

    from servonaut.services.vault.ca_client import CertificateAuthorityClient

    client = CertificateAuthorityClient.__new__(CertificateAuthorityClient)
    client.team_slug = "team-a"
    client._signed = AsyncMock(return_value={"certificate": {"serial": 28}, "krl_version": 2})

    await client.revoke_certificate(28, note="lost laptop")
    await client.revoke_certificate(29)

    assert client._signed.await_args_list[0].args == (
        "POST", "/api/v1/teams/team-a/ssh-ca/certs/28/revoke", {"note": "lost laptop"},
    )
    assert client._signed.await_args_list[1].args == ("POST", "/api/v1/teams/team-a/ssh-ca/certs/29/revoke", {})


def test_ca_revoke_dispatches_and_says_how_to_deliver_the_krl(capsys) -> None:
    calls = []

    class Service:
        async def ca_revoke(self, *, team, serial, note):
            calls.append((team, serial, note))
            return {"serial": serial, "krl_version": 2}

    ca.set_ca_service_factory(Service)
    try:
        args = _parser().parse_args(["ca", "revoke", "28", "--team", "ops", "--note", "lost laptop", "--yes"])
        assert ca.handle_ca_command(args) == 0
    finally:
        ca.set_ca_service_factory(None)

    captured = capsys.readouterr()
    assert calls == [("ops", 28, "lost laptop")]
    assert "krl_version: 2" in captured.out
    assert "servonaut ca krl --team ops" in captured.err


def test_ca_revoke_needs_confirmation_in_a_non_interactive_shell(capsys, monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    class Service:
        async def ca_revoke(self, **_kwargs):
            raise AssertionError("must not revoke without confirmation")

    ca.set_ca_service_factory(Service)
    try:
        args = _parser().parse_args(["ca", "revoke", "28", "--team", "ops"])
        assert ca.handle_ca_command(args) == 5
    finally:
        ca.set_ca_service_factory(None)

    assert "without --yes" in capsys.readouterr().err


def test_ca_revoke_serial_must_be_positive(capsys) -> None:
    args = _parser().parse_args(["ca", "revoke", "0", "--team", "ops"])

    assert ca.handle_ca_command(args) == 2
    assert "serial must be a positive number" in capsys.readouterr().err

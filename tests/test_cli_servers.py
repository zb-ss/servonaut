"""Tests for ``servonaut servers`` CLI subcommand (``servers verify``).

All network I/O, subprocess calls, and BW resolver invocations are mocked.
The headless init function is patched so that no real filesystem / AWS / API
access occurs during the test run.

Exit-code contract:
    0  — STATUS_VERIFIED
    1  — STATUS_NOT_FOUND or STATUS_AUTH_FAILED (probe ran, key didn't work)
    2  — Fatal: no ref stored, BW CLI missing, session locked, not logged in
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.cli import servers as cli_servers
from servonaut.cli.servers import (
    _EXIT_FATAL,
    _EXIT_SUCCESS,
    _EXIT_VERIFY_FAILED,
    add_servers_parser,
    handle_servers_command,
)
from servonaut.services.bw_ssh_config_service import (
    STATUS_AUTH_FAILED,
    STATUS_NOT_FOUND,
    STATUS_VERIFIED,
    VALID_VERIFY_STATUSES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_argv(argv: list[str]) -> argparse.Namespace:
    """Parse *argv* through a minimal parser that only has servers registered."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand")
    add_servers_parser(subparsers)
    return parser.parse_args(argv)


def _ns(**kwargs) -> argparse.Namespace:
    """Build an :class:`argparse.Namespace` for the ``servers verify`` command."""
    defaults = dict(
        subcommand="servers",
        servers_command="verify",
        instance="i-abc123",
        host=None,
        user=None,
        port=None,
        timeout=5,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_services(
    *,
    authenticated: bool = True,
    personal_ref: Optional[dict] = None,
    team_ref: Optional[dict] = None,
    teams: Optional[list] = None,
    report_result: Optional[dict] = None,
):
    """Build the 6-tuple returned by ``_init_headless_services``."""
    config_manager = MagicMock()
    config = MagicMock()
    config.cache_ttl_seconds = 3600
    config_manager.get.return_value = config

    auth_service = MagicMock()
    auth_service.is_authenticated = authenticated

    api_client = MagicMock()
    api_client.get = AsyncMock()
    api_client.post = AsyncMock()

    bw_ssh_cfg = MagicMock()
    bw_ssh_cfg.get_personal_instance_ref = AsyncMock(return_value=personal_ref)
    bw_ssh_cfg.report_personal_instance_verify = AsyncMock(
        return_value=report_result or {"ok": True}
    )

    team_svc = MagicMock()
    team_svc.list_teams = AsyncMock(return_value=teams or [])
    team_svc.get_team_server_ssh_ref = AsyncMock(return_value=team_ref)
    team_svc.report_team_server_ssh_verify = AsyncMock(
        return_value=report_result or {"ok": True}
    )

    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = []

    return (
        config_manager,
        auth_service,
        api_client,
        bw_ssh_cfg,
        team_svc,
        custom_server_service,
    )


def _patch_init(monkeypatch, services):
    monkeypatch.setattr(cli_servers, "_init_headless_services", lambda: services)


def _make_aws_mock(instances=None):
    """Return a mock AWSService instance whose cache returns *instances*."""
    cache = MagicMock()
    cache.load_any.return_value = instances or []
    aws_mock = MagicMock()
    aws_mock._cache = cache
    return aws_mock


# ---------------------------------------------------------------------------
# Status enum smoke test
# ---------------------------------------------------------------------------


class TestStatusEnum:
    def test_valid_statuses_are_present(self):
        assert STATUS_VERIFIED in VALID_VERIFY_STATUSES
        assert STATUS_NOT_FOUND in VALID_VERIFY_STATUSES
        assert STATUS_AUTH_FAILED in VALID_VERIFY_STATUSES

    def test_status_values(self):
        assert STATUS_VERIFIED == "verified"
        assert STATUS_NOT_FOUND == "not_found"
        assert STATUS_AUTH_FAILED == "auth_failed"


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------


class TestParserWiring:
    def test_servers_verify_minimal(self):
        ns = _parse_argv(["servers", "verify", "i-abc123"])
        assert ns.subcommand == "servers"
        assert ns.servers_command == "verify"
        assert ns.instance == "i-abc123"

    def test_default_timeout_is_5(self):
        ns = _parse_argv(["servers", "verify", "i-abc123"])
        assert ns.timeout == 5

    def test_host_override(self):
        ns = _parse_argv(["servers", "verify", "i-abc123", "--host", "10.0.0.1"])
        assert ns.host == "10.0.0.1"

    def test_user_short_flag(self):
        ns = _parse_argv(["servers", "verify", "i-abc123", "-u", "ubuntu"])
        assert ns.user == "ubuntu"

    def test_port_short_flag(self):
        ns = _parse_argv(["servers", "verify", "i-abc123", "-p", "2222"])
        assert ns.port == 2222

    def test_timeout_flag(self):
        ns = _parse_argv(["servers", "verify", "i-abc123", "--timeout", "10"])
        assert ns.timeout == 10

    def test_missing_instance_raises_systemexit(self):
        with pytest.raises(SystemExit):
            _parse_argv(["servers", "verify"])

    def test_no_subcommand_dispatches_to_fatal(self, capsys):
        ns = argparse.Namespace(subcommand="servers", servers_command=None)
        rc = handle_servers_command(ns)
        assert rc == _EXIT_FATAL

    def test_unknown_subcommand_returns_fatal(self, capsys):
        ns = argparse.Namespace(subcommand="servers", servers_command="frobnicate")
        rc = handle_servers_command(ns)
        assert rc == _EXIT_FATAL


# ---------------------------------------------------------------------------
# Not logged in
# ---------------------------------------------------------------------------


class TestNotLoggedIn:
    def test_not_authenticated_exits_fatal(self, monkeypatch, capsys):
        svc = _make_services(authenticated=False)
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService"), \
             patch("servonaut.cli.servers.CacheService"):
            rc = handle_servers_command(_ns())

        assert rc == _EXIT_FATAL
        out = capsys.readouterr()
        assert "servonaut --login" in out.err


# ---------------------------------------------------------------------------
# Personal probe — happy paths
# ---------------------------------------------------------------------------


_PERSONAL_INSTANCE = {
    "id": "i-abc123",
    "name": "web-01",
    "provider": "aws",
    "public_ip": "1.2.3.4",
    "private_ip": "10.0.0.1",
}

_PERSONAL_REF = {
    "ssh_credential_provider": "bitwarden_pm",
    "ssh_credential_ref": {"item_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
}


class TestPersonalProbeVerified:
    def test_verified_exits_0_and_posts(self, monkeypatch, capsys):
        svc = _make_services(personal_ref=_PERSONAL_REF)
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService") as MockAws, \
             patch("servonaut.cli.servers.CacheService"), \
             patch("servonaut.cli.servers.BwResolver") as MockBwR, \
             patch("servonaut.cli.servers.ephemeral_ssh_key") as mock_ek, \
             patch("servonaut.cli.servers._run_ssh_probe", return_value=0):
            MockAws.return_value._cache.load_any.return_value = [_PERSONAL_INSTANCE]
            MockBwR.return_value.resolve_ssh_key.return_value = "PRIVATE_KEY"
            # ephemeral_ssh_key is a context manager — make it yield a fake path.
            mock_ek.return_value.__enter__ = MagicMock(return_value="/tmp/fake.pem")
            mock_ek.return_value.__exit__ = MagicMock(return_value=False)

            rc = handle_servers_command(_ns())

        assert rc == _EXIT_SUCCESS
        out = capsys.readouterr()
        assert "[OK] Verified:" in out.out
        # Report was POSTed with STATUS_VERIFIED
        _, _, _, bw_cfg, _, _ = svc
        bw_cfg.report_personal_instance_verify.assert_awaited_once()
        args = bw_cfg.report_personal_instance_verify.call_args.args
        assert args[2] == STATUS_VERIFIED


# ---------------------------------------------------------------------------
# Personal probe — BwItemNotFoundError → status=not_found POSTed
# ---------------------------------------------------------------------------


class TestPersonalProbeNotFound:
    def test_bw_item_not_found_posts_not_found(self, monkeypatch, capsys):
        from servonaut.services.bw_resolver import BwItemNotFoundError

        svc = _make_services(personal_ref=_PERSONAL_REF)
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService") as MockAws, \
             patch("servonaut.cli.servers.CacheService"):
            MockAws.return_value._cache.load_any.return_value = [_PERSONAL_INSTANCE]
            with patch("servonaut.cli.servers.BwResolver") as MockBwR:
                MockBwR.return_value.resolve_ssh_key.side_effect = BwItemNotFoundError(
                    "Not found."
                )

                rc = handle_servers_command(_ns())

        assert rc == _EXIT_VERIFY_FAILED
        out = capsys.readouterr()
        assert "[FAIL] not_found:" in out.out
        # Report was POSTed with not_found
        _, _, _, bw_cfg, _, _ = svc
        bw_cfg.report_personal_instance_verify.assert_awaited_once()
        args = bw_cfg.report_personal_instance_verify.call_args.args
        assert args[2] == STATUS_NOT_FOUND


# ---------------------------------------------------------------------------
# Personal probe — SSH exits non-zero → auth_failed
# ---------------------------------------------------------------------------


class TestPersonalProbeAuthFailed:
    def test_ssh_returncode_255_posts_auth_failed(self, monkeypatch, capsys):
        svc = _make_services(personal_ref=_PERSONAL_REF)
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService") as MockAws, \
             patch("servonaut.cli.servers.CacheService"):
            MockAws.return_value._cache.load_any.return_value = [_PERSONAL_INSTANCE]
            with patch("servonaut.cli.servers.BwResolver") as MockBwR, \
                 patch("servonaut.cli.servers._run_ssh_probe", return_value=255):
                MockBwR.return_value.resolve_ssh_key.return_value = "PRIVATE_KEY"

                rc = handle_servers_command(_ns())

        assert rc == _EXIT_VERIFY_FAILED
        out = capsys.readouterr()
        assert "[FAIL] auth_failed:" in out.out
        _, _, _, bw_cfg, _, _ = svc
        bw_cfg.report_personal_instance_verify.assert_awaited_once()
        args = bw_cfg.report_personal_instance_verify.call_args.args
        assert args[2] == STATUS_AUTH_FAILED


# ---------------------------------------------------------------------------
# Personal probe — subprocess.TimeoutExpired → auth_failed (no crash)
# ---------------------------------------------------------------------------


class TestPersonalProbeTimeout:
    def test_ssh_timeout_returns_255(self):
        """_run_ssh_probe catches TimeoutExpired and returns 255."""
        with patch("servonaut.cli.servers.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=5)):
            rc = cli_servers._run_ssh_probe(
                "/tmp/key.pem", "ubuntu", "1.2.3.4", None, 5
            )
        assert rc == 255


# ---------------------------------------------------------------------------
# BwCliMissingError → fatal, no POST
# ---------------------------------------------------------------------------


class TestBwCliMissing:
    def test_bw_cli_missing_exits_fatal_no_post(self, monkeypatch, capsys):
        from servonaut.services.bw_resolver import BwCliMissingError

        svc = _make_services(personal_ref=_PERSONAL_REF)
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService") as MockAws, \
             patch("servonaut.cli.servers.CacheService"):
            MockAws.return_value._cache.load_any.return_value = [_PERSONAL_INSTANCE]
            with patch("servonaut.cli.servers.BwResolver") as MockBwR:
                MockBwR.return_value.resolve_ssh_key.side_effect = BwCliMissingError(
                    "bw not found"
                )

                rc = handle_servers_command(_ns())

        assert rc == _EXIT_FATAL
        _, _, _, bw_cfg, _, _ = svc
        bw_cfg.report_personal_instance_verify.assert_not_awaited()
        err = capsys.readouterr().err
        assert "bw" in err.lower()


# ---------------------------------------------------------------------------
# BwSessionMissingError → fatal, message about bw unlock, no POST
# ---------------------------------------------------------------------------


class TestBwSessionMissing:
    def test_bw_session_missing_exits_fatal_no_post(self, monkeypatch, capsys):
        from servonaut.services.bw_resolver import BwSessionMissingError

        svc = _make_services(personal_ref=_PERSONAL_REF)
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService") as MockAws, \
             patch("servonaut.cli.servers.CacheService"):
            MockAws.return_value._cache.load_any.return_value = [_PERSONAL_INSTANCE]
            with patch("servonaut.cli.servers.BwResolver") as MockBwR:
                MockBwR.return_value.resolve_ssh_key.side_effect = BwSessionMissingError(
                    "Vault is locked. Run `bw unlock`."
                )

                rc = handle_servers_command(_ns())

        assert rc == _EXIT_FATAL
        _, _, _, bw_cfg, _, _ = svc
        bw_cfg.report_personal_instance_verify.assert_not_awaited()
        err = capsys.readouterr().err
        assert "bw unlock" in err


# ---------------------------------------------------------------------------
# No ref stored anywhere → friendly message, no POST, exit 2
# ---------------------------------------------------------------------------


class TestNoRefStored:
    def test_no_ref_anywhere_exits_fatal_no_post(self, monkeypatch, capsys):
        # personal_ref=None means get_personal_instance_ref returns None
        svc = _make_services(personal_ref=None)
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService") as MockAws, \
             patch("servonaut.cli.servers.CacheService"), \
             patch("servonaut.cli.servers.BwResolver"):
            MockAws.return_value._cache.load_any.return_value = [_PERSONAL_INSTANCE]
            rc = handle_servers_command(_ns())

        assert rc == _EXIT_FATAL
        _, _, _, bw_cfg, _, _ = svc
        bw_cfg.report_personal_instance_verify.assert_not_awaited()
        err = capsys.readouterr().err
        assert "No SSH ref" in err


# ---------------------------------------------------------------------------
# Team probe: UUID not in personal cache but team ref exists
# ---------------------------------------------------------------------------

_TEAM_UUID = "550e8400-e29b-41d4-a716-446655440000"
_TEAM_REF = {
    "ssh_credential_provider": "bitwarden_pm",
    "ssh_credential_ref": {"item_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
}


class TestTeamProbe:
    def test_team_path_when_personal_misses(self, monkeypatch, capsys):
        teams_list = [{"slug": "my-team"}]
        svc = _make_services(
            personal_ref=None,
            team_ref=_TEAM_REF,
            teams=teams_list,
        )
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService") as MockAws, \
             patch("servonaut.cli.servers.CacheService"):
            # No instance in cache matching the UUID
            MockAws.return_value._cache.load_any.return_value = []
            with patch("servonaut.cli.servers.BwResolver") as MockBwR, \
                 patch("servonaut.cli.servers._run_ssh_probe", return_value=0):
                MockBwR.return_value.resolve_ssh_key.return_value = "PRIVATE_KEY"

                rc = handle_servers_command(_ns(
                    instance=_TEAM_UUID,
                    host="1.2.3.4",
                    user="ubuntu",
                ))

        assert rc == _EXIT_SUCCESS
        _, _, _, _, team_svc, _ = svc
        team_svc.report_team_server_ssh_verify.assert_awaited_once()
        args = team_svc.report_team_server_ssh_verify.call_args.args
        assert args[2] == STATUS_VERIFIED


# ---------------------------------------------------------------------------
# SSH command construction — BatchMode, ConnectTimeout, -i path, user@host
# ---------------------------------------------------------------------------


class TestSshCommandConstruction:
    def test_standard_command_shape(self):
        with patch("servonaut.cli.servers.subprocess.run") as run_mock:
            run_mock.return_value = MagicMock(returncode=0)
            cli_servers._run_ssh_probe("/tmp/key.pem", "ubuntu", "1.2.3.4", None, 7)

        cmd = run_mock.call_args.args[0]
        assert "ssh" == cmd[0]
        assert "-o" in cmd
        assert "BatchMode=yes" in cmd
        assert "ConnectTimeout=7" in cmd
        assert "-i" in cmd
        assert "/tmp/key.pem" in cmd
        assert "ubuntu@1.2.3.4" in cmd
        assert "true" in cmd

    def test_custom_port_adds_p_flag(self):
        with patch("servonaut.cli.servers.subprocess.run") as run_mock:
            run_mock.return_value = MagicMock(returncode=0)
            cli_servers._run_ssh_probe("/tmp/key.pem", "ubuntu", "1.2.3.4", 2222, 5)

        cmd = run_mock.call_args.args[0]
        assert "-p" in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == "2222"

    def test_port_22_not_added(self):
        with patch("servonaut.cli.servers.subprocess.run") as run_mock:
            run_mock.return_value = MagicMock(returncode=0)
            cli_servers._run_ssh_probe("/tmp/key.pem", "ubuntu", "1.2.3.4", 22, 5)

        cmd = run_mock.call_args.args[0]
        assert "-p" not in cmd


# ---------------------------------------------------------------------------
# checked_by_client includes version string
# ---------------------------------------------------------------------------


class TestCheckedByClient:
    def test_checked_by_client_includes_version(self, monkeypatch, capsys):
        from servonaut import __version__

        svc = _make_services(personal_ref=_PERSONAL_REF)
        _patch_init(monkeypatch, svc)

        with patch("servonaut.cli.servers.AWSService") as MockAws, \
             patch("servonaut.cli.servers.CacheService"), \
             patch("servonaut.cli.servers.BwResolver") as MockBwR, \
             patch("servonaut.cli.servers._run_ssh_probe", return_value=0):
            MockAws.return_value._cache.load_any.return_value = [_PERSONAL_INSTANCE]
            MockBwR.return_value.resolve_ssh_key.return_value = "PRIVATE_KEY"
            handle_servers_command(_ns())

        _, _, _, bw_cfg, _, _ = svc
        call_kwargs = bw_cfg.report_personal_instance_verify.call_args
        checked = call_kwargs.kwargs.get("checked_by_client") or (
            call_kwargs.args[3] if len(call_kwargs.args) > 3 else None
        )
        expected = f"servonaut-cli/{__version__}"
        assert checked == expected, f"Got {checked!r}, expected {expected!r}"

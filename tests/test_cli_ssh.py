"""Tests for cli/ssh.py — parser registration, instance lookup, SSH dispatch."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from servonaut.cli.ssh import (
    add_ssh_parser,
    _find_instance,
    _resolve_username,
    _EXIT_NOT_FOUND,
    _EXIT_AMBIGUOUS,
    _EXIT_NO_CREDENTIAL,
    _EXIT_BW_ERROR,
    _EXIT_SUCCESS,
)
from servonaut.services.bw_resolver import (
    BwCliMissingError,
    BwSessionMissingError,
    BwItemNotFoundError,
    BwItemShapeError,
)
from servonaut.services.ssh_ref_resolver import ResolvedSshRef


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_args(
    instance: str = "i-abc",
    user: Optional[str] = None,
    port: Optional[int] = None,
) -> argparse.Namespace:
    return argparse.Namespace(instance=instance, user=user, port=port)


def _make_instance(
    iid: str = "i-abc",
    name: str = "prod",
    provider: str = "aws",
    username: Optional[str] = None,
    public_ip: str = "1.2.3.4",
    port: Optional[int] = None,
) -> Dict[str, Any]:
    inst: Dict[str, Any] = {
        "id": iid,
        "name": name,
        "provider": provider,
        "public_ip": public_ip,
    }
    if username:
        inst["username"] = username
    if port:
        inst["port"] = port
    return inst


def _make_config(default_username: str = "ec2-user") -> Any:
    cfg = MagicMock()
    cfg.default_username = default_username
    return cfg


def _resolved_local(path: str = "/ssh/id_rsa") -> ResolvedSshRef:
    return ResolvedSshRef(
        source="local",
        item_id=None,
        vault_url=None,
        collection_id=None,
        local_key_path=path,
        team_slug=None,
        server_id=None,
    )


def _resolved_personal(item_id: str = "uuid-bw") -> ResolvedSshRef:
    return ResolvedSshRef(
        source="personal",
        item_id=item_id,
        vault_url="https://vault.bitwarden.com",
        collection_id=None,
        local_key_path=None,
        team_slug=None,
        server_id=None,
    )


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------

class TestAddSshParser:
    def test_registers_ssh_subcommand(self):
        """add_ssh_parser registers 'ssh' with a required 'instance' argument."""
        top = argparse.ArgumentParser()
        subparsers = top.add_subparsers(dest="subcommand")
        add_ssh_parser(subparsers)

        args = top.parse_args(["ssh", "i-abc123"])
        assert args.subcommand == "ssh"
        assert args.instance == "i-abc123"

    def test_user_flag(self):
        top = argparse.ArgumentParser()
        subparsers = top.add_subparsers(dest="subcommand")
        add_ssh_parser(subparsers)

        args = top.parse_args(["ssh", "i-abc", "--user", "ubuntu"])
        assert args.user == "ubuntu"

    def test_port_flag(self):
        top = argparse.ArgumentParser()
        subparsers = top.add_subparsers(dest="subcommand")
        add_ssh_parser(subparsers)

        args = top.parse_args(["ssh", "i-abc", "--port", "2222"])
        assert args.port == 2222

    def test_user_short_flag(self):
        top = argparse.ArgumentParser()
        subparsers = top.add_subparsers(dest="subcommand")
        add_ssh_parser(subparsers)

        args = top.parse_args(["ssh", "i-abc", "-u", "root"])
        assert args.user == "root"

    def test_instance_is_required(self):
        top = argparse.ArgumentParser()
        subparsers = top.add_subparsers(dest="subcommand")
        add_ssh_parser(subparsers)

        with pytest.raises(SystemExit):
            top.parse_args(["ssh"])

    def test_defaults_are_none(self):
        top = argparse.ArgumentParser()
        subparsers = top.add_subparsers(dest="subcommand")
        add_ssh_parser(subparsers)

        args = top.parse_args(["ssh", "i-abc"])
        assert args.user is None
        assert args.port is None


# ---------------------------------------------------------------------------
# Instance lookup
# ---------------------------------------------------------------------------

class TestFindInstance:
    def test_exact_id_match(self):
        instances = [_make_instance("i-abc", "prod"), _make_instance("i-def", "dev")]
        result = _find_instance(instances, "i-abc")
        assert len(result) == 1
        assert result[0]["id"] == "i-abc"

    def test_case_insensitive_name_match(self):
        instances = [_make_instance("i-abc", "MyServer"), _make_instance("i-def", "other")]
        result = _find_instance(instances, "myserver")
        assert len(result) == 1
        assert result[0]["id"] == "i-abc"

    def test_no_match_returns_empty_list(self):
        instances = [_make_instance("i-abc", "prod")]
        result = _find_instance(instances, "i-xyz")
        assert result == []

    def test_multiple_matches_returns_all(self):
        """Same name on two instances → both returned."""
        instances = [
            _make_instance("i-abc", "prod"),
            _make_instance("i-def", "prod"),
        ]
        result = _find_instance(instances, "prod")
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Username resolution
# ---------------------------------------------------------------------------

class TestResolveUsername:
    def test_args_user_takes_priority(self):
        args = _make_args(user="ec2-user")
        inst = _make_instance(username="ubuntu")
        cfg = _make_config(default_username="root")
        assert _resolve_username(args, inst, cfg) == "ec2-user"

    def test_instance_username_second_priority(self):
        args = _make_args(user=None)
        inst = _make_instance(username="ubuntu")
        cfg = _make_config(default_username="root")
        assert _resolve_username(args, inst, cfg) == "ubuntu"

    def test_config_default_third_priority(self):
        args = _make_args(user=None)
        inst = _make_instance()  # no username key
        cfg = _make_config(default_username="centos")
        assert _resolve_username(args, inst, cfg) == "centos"

    def test_final_fallback_is_ubuntu(self):
        args = _make_args(user=None)
        inst = _make_instance()
        cfg = _make_config(default_username="")
        assert _resolve_username(args, inst, cfg) == "ubuntu"


# ---------------------------------------------------------------------------
# handle_ssh_command integration (mocked subprocess + resolver)
# ---------------------------------------------------------------------------

def _patch_headless(
    config=None,
    auth_authenticated=True,
    instances=None,
    resolved=None,
):
    """Context manager factory that patches the main moving parts."""
    if config is None:
        config = _make_config()
    if instances is None:
        instances = [_make_instance()]

    ssh_svc = MagicMock()
    ssh_svc.build_ssh_command.return_value = ["ssh", "-i", "/key", "ubuntu@1.2.3.4"]

    auth_svc = MagicMock()
    auth_svc.is_authenticated = auth_authenticated

    # The headless services tuple
    headless_return = (
        config,        # config
        auth_svc,      # auth_service
        MagicMock(),   # api_client
        MagicMock(),   # bw_ssh_config_service
        MagicMock(),   # team_service
        ssh_svc,       # ssh_service
        MagicMock(),   # custom_server_service
    )

    return headless_return, ssh_svc, instances


class TestHandleSshCommand:
    def _run(self, args, headless_return, instances, resolved):
        """Run handle_ssh_command with patched internals."""
        from servonaut.cli import ssh as ssh_mod

        with (
            patch.object(ssh_mod, "_init_headless_services", return_value=headless_return),
            patch.object(ssh_mod, "_load_instances", return_value=instances),
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as MockResolver,
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=resolved)
            MockResolver.return_value = resolver_instance
            from servonaut.cli.ssh import handle_ssh_command
            return handle_ssh_command(args)

    def test_no_match_returns_not_found(self):
        args = _make_args(instance="i-missing")
        headless, ssh_svc, _ = _patch_headless()
        result = self._run(args, headless, [], _resolved_local())
        assert result == _EXIT_NOT_FOUND

    def test_multiple_matches_returns_ambiguous(self):
        args = _make_args(instance="prod")
        instances = [
            _make_instance("i-abc", "prod"),
            _make_instance("i-def", "prod"),
        ]
        headless, ssh_svc, _ = _patch_headless(instances=instances)
        result = self._run(args, headless, instances, _resolved_local())
        assert result == _EXIT_AMBIGUOUS

    def test_none_resolved_returns_no_credential(self):
        args = _make_args(instance="i-abc")
        instances = [_make_instance("i-abc")]
        headless, ssh_svc, _ = _patch_headless(instances=instances)
        result = self._run(args, headless, instances, None)
        assert result == _EXIT_NO_CREDENTIAL

    def test_local_source_calls_subprocess_with_local_key(self):
        args = _make_args(instance="i-abc")
        instances = [_make_instance("i-abc")]
        headless, ssh_svc, _ = _patch_headless(instances=instances)
        resolved = _resolved_local("/home/user/.ssh/id_rsa")

        from servonaut.cli import ssh as ssh_mod

        with (
            patch.object(ssh_mod, "_init_headless_services", return_value=headless),
            patch.object(ssh_mod, "_load_instances", return_value=instances),
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as MockResolver,
            patch("subprocess.run") as mock_subproc,
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=resolved)
            MockResolver.return_value = resolver_instance
            mock_subproc.return_value = MagicMock(returncode=0)

            # ssh_service is the one inside headless_return
            ssh_svc = headless[5]
            ssh_svc.build_ssh_command.return_value = ["ssh", "ubuntu@1.2.3.4"]

            from servonaut.cli.ssh import handle_ssh_command
            rc = handle_ssh_command(args)

        assert rc == 0
        # ssh_service.build_ssh_command was called with local key path
        ssh_svc.build_ssh_command.assert_called_once()
        call_kwargs = ssh_svc.build_ssh_command.call_args
        assert call_kwargs.kwargs.get("key_path") == "/home/user/.ssh/id_rsa"
        mock_subproc.assert_called_once()

    def test_personal_source_calls_bw_resolver_and_ephemeral_key(self):
        """BW source: BwResolver.resolve_ssh_key called, subprocess called with tmpfile."""
        args = _make_args(instance="i-abc")
        instances = [_make_instance("i-abc")]
        headless, ssh_svc, _ = _patch_headless(instances=instances)
        resolved = _resolved_personal("uuid-bw-item")

        from servonaut.cli import ssh as ssh_mod

        with (
            patch.object(ssh_mod, "_init_headless_services", return_value=headless),
            patch.object(ssh_mod, "_load_instances", return_value=instances),
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as MockResolver,
            patch("servonaut.services.bw_resolver.BwResolver") as MockBwResolver,
            patch("servonaut.utils.ephemeral_key.ephemeral_ssh_key") as mock_eph,
            patch("subprocess.run") as mock_subproc,
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=resolved)
            MockResolver.return_value = resolver_instance

            bw_instance = MagicMock()
            bw_instance.resolve_ssh_key.return_value = "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
            MockBwResolver.return_value = bw_instance

            # ephemeral_ssh_key context manager
            mock_eph.return_value.__enter__ = MagicMock(return_value="/tmp/servonaut-ssh-abc")
            mock_eph.return_value.__exit__ = MagicMock(return_value=False)
            mock_subproc.return_value = MagicMock(returncode=0)

            ssh_svc_inner = headless[5]
            ssh_svc_inner.build_ssh_command.return_value = ["ssh", "ubuntu@1.2.3.4"]

            from servonaut.cli.ssh import handle_ssh_command
            rc = handle_ssh_command(args)

        bw_instance.resolve_ssh_key.assert_called_once_with("uuid-bw-item")
        mock_eph.assert_called_once()
        mock_subproc.assert_called_once()

    def test_bw_cli_missing_prints_friendly_message_and_exits_nonzero(self, capsys):
        args = _make_args(instance="i-abc")
        instances = [_make_instance("i-abc")]
        headless, ssh_svc, _ = _patch_headless(instances=instances)
        resolved = _resolved_personal("uuid-bw-item")

        from servonaut.cli import ssh as ssh_mod

        with (
            patch.object(ssh_mod, "_init_headless_services", return_value=headless),
            patch.object(ssh_mod, "_load_instances", return_value=instances),
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as MockResolver,
            patch("servonaut.services.bw_resolver.BwResolver") as MockBwResolver,
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=resolved)
            MockResolver.return_value = resolver_instance

            bw_instance = MagicMock()
            bw_instance.resolve_ssh_key.side_effect = BwCliMissingError("bw not found")
            MockBwResolver.return_value = bw_instance

            from servonaut.cli.ssh import handle_ssh_command
            rc = handle_ssh_command(args)

        assert rc == _EXIT_BW_ERROR
        captured = capsys.readouterr()
        assert "Bitwarden CLI not found" in captured.err or "not found" in captured.err.lower()

    def test_bw_session_missing_prints_unlock_hint(self, capsys):
        args = _make_args(instance="i-abc")
        instances = [_make_instance("i-abc")]
        headless, ssh_svc, _ = _patch_headless(instances=instances)
        resolved = _resolved_personal("uuid-bw")

        from servonaut.cli import ssh as ssh_mod

        with (
            patch.object(ssh_mod, "_init_headless_services", return_value=headless),
            patch.object(ssh_mod, "_load_instances", return_value=instances),
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as MockResolver,
            patch("servonaut.services.bw_resolver.BwResolver") as MockBwResolver,
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=resolved)
            MockResolver.return_value = resolver_instance

            bw_instance = MagicMock()
            bw_instance.resolve_ssh_key.side_effect = BwSessionMissingError("vault locked")
            MockBwResolver.return_value = bw_instance

            from servonaut.cli.ssh import handle_ssh_command
            rc = handle_ssh_command(args)

        assert rc == _EXIT_BW_ERROR
        captured = capsys.readouterr()
        assert "bw unlock" in captured.err

    def test_bw_item_not_found_friendly_message(self, capsys):
        args = _make_args(instance="i-abc")
        instances = [_make_instance("i-abc")]
        headless, _, _ = _patch_headless(instances=instances)
        resolved = _resolved_personal("uuid-bw")

        from servonaut.cli import ssh as ssh_mod

        with (
            patch.object(ssh_mod, "_init_headless_services", return_value=headless),
            patch.object(ssh_mod, "_load_instances", return_value=instances),
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as MockResolver,
            patch("servonaut.services.bw_resolver.BwResolver") as MockBwResolver,
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=resolved)
            MockResolver.return_value = resolver_instance

            bw_instance = MagicMock()
            bw_instance.resolve_ssh_key.side_effect = BwItemNotFoundError("not found")
            MockBwResolver.return_value = bw_instance

            from servonaut.cli.ssh import handle_ssh_command
            rc = handle_ssh_command(args)

        assert rc == _EXIT_BW_ERROR

    def test_port_override_via_flag(self):
        """--port flag is forwarded to build_ssh_command."""
        args = _make_args(instance="i-abc", port=2222)
        instances = [_make_instance("i-abc")]
        headless, _, _ = _patch_headless(instances=instances)
        resolved = _resolved_local()

        from servonaut.cli import ssh as ssh_mod

        with (
            patch.object(ssh_mod, "_init_headless_services", return_value=headless),
            patch.object(ssh_mod, "_load_instances", return_value=instances),
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as MockResolver,
            patch("subprocess.run") as mock_subproc,
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=resolved)
            MockResolver.return_value = resolver_instance
            mock_subproc.return_value = MagicMock(returncode=0)

            ssh_svc_inner = headless[5]
            ssh_svc_inner.build_ssh_command.return_value = ["ssh", "-p", "2222", "u@h"]

            from servonaut.cli.ssh import handle_ssh_command
            handle_ssh_command(args)

        call_kwargs = ssh_svc_inner.build_ssh_command.call_args
        assert call_kwargs.kwargs.get("port") == 2222

    def test_subprocess_return_code_propagated(self):
        """SSH exit code is forwarded as the CLI exit code."""
        args = _make_args(instance="i-abc")
        instances = [_make_instance("i-abc")]
        headless, _, _ = _patch_headless(instances=instances)
        resolved = _resolved_local()

        from servonaut.cli import ssh as ssh_mod

        with (
            patch.object(ssh_mod, "_init_headless_services", return_value=headless),
            patch.object(ssh_mod, "_load_instances", return_value=instances),
            patch("servonaut.services.ssh_ref_resolver.SshRefResolver") as MockResolver,
            patch("subprocess.run") as mock_subproc,
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=resolved)
            MockResolver.return_value = resolver_instance
            mock_subproc.return_value = MagicMock(returncode=255)

            ssh_svc_inner = headless[5]
            ssh_svc_inner.build_ssh_command.return_value = ["ssh", "ubuntu@h"]

            from servonaut.cli.ssh import handle_ssh_command
            rc = handle_ssh_command(args)

        assert rc == 255

"""Tests for the ``servonaut secrets`` CLI subcommand (Step 8).

Two surfaces:

1. **The install command** (``servonaut secrets install bws``) — pure
   subprocess-orchestration logic. We mock :func:`shutil.which` to
   simulate "bws not installed" / "bws already installed", and we
   mock :func:`subprocess.run` so no real package manager runs in
   CI. The tests pin the policy:
   - Idempotent re-run when bws is present and --force is absent.
   - Refuse to auto-install in a non-interactive shell without --yes.
   - macOS without brew → manual fallback URL.
   - Linux without cargo → manual fallback URL.
   - Windows → always manual fallback URL (no auto-install path).
   - Installer failure → exit code propagated, no false "success".
   - Post-install re-probe catches "ran but bws still not on PATH".

2. **The status command** (``servonaut secrets status``) — read-only
   inspection of the current resolver state. Mocks AuthService +
   EntitlementGuard + the resolver itself; we're testing the
   formatting and dispatch, not the resolver (which has its own
   tests).

Argv-level smoke tests round-trip the parser to make sure
``add_secrets_parser`` registers the tree correctly and
``handle_secrets_command`` dispatches on the right field.
"""
from __future__ import annotations

import argparse
import io
import sys
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from servonaut.cli.secrets import (
    _EXIT_INSTALL_FAILED,
    _EXIT_NOT_FOUND,
    _EXIT_SUCCESS,
    _EXIT_USAGE_ERROR,
    _EXIT_USER_ABORT,
    BWS_INSTALL_DOC_URL,
    _detect_platform,
    _install_command_for,
    add_secrets_parser,
    handle_secrets_command,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_argv(argv: list[str]) -> argparse.Namespace:
    """Round-trip ``argv`` through a parser that has just
    ``add_secrets_parser`` registered. Matches the shape main.py uses."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand")
    add_secrets_parser(subparsers)
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


class TestDetectPlatform:
    """Coarse mapping; we don't care about Ubuntu vs Debian distinctions."""

    @pytest.mark.parametrize("system,expected", [
        ("Darwin", "macos"),
        ("DARWIN", "macos"),  # case-insensitive
        ("Linux", "linux"),
        ("Windows", "windows"),
        ("FreeBSD", "unknown"),
        ("", "unknown"),
    ])
    def test_returns_coarse_key(self, system, expected):
        with patch("servonaut.cli.secrets.platform.system", return_value=system):
            assert _detect_platform() == expected


# ---------------------------------------------------------------------------
# Install command resolution
# ---------------------------------------------------------------------------


class TestInstallCommandFor:
    def test_macos_with_brew(self):
        with patch("servonaut.cli.secrets.shutil.which", return_value="/opt/brew/bin/brew"):
            assert _install_command_for("macos") == ["brew", "install", "bws"]

    def test_macos_without_brew_returns_none(self):
        with patch("servonaut.cli.secrets.shutil.which", return_value=None):
            assert _install_command_for("macos") is None

    def test_linux_with_cargo(self):
        with patch("servonaut.cli.secrets.shutil.which", return_value="/home/user/.cargo/bin/cargo"):
            assert _install_command_for("linux") == ["cargo", "install", "bws"]

    def test_linux_without_cargo_returns_none(self):
        with patch("servonaut.cli.secrets.shutil.which", return_value=None):
            assert _install_command_for("linux") is None

    def test_windows_always_returns_none(self):
        # We do NOT auto-install on Windows — .msi installer is the
        # right path; print manual instructions.
        with patch("servonaut.cli.secrets.shutil.which", return_value="/anywhere"):
            assert _install_command_for("windows") is None

    def test_unknown_platform_returns_none(self):
        with patch("servonaut.cli.secrets.shutil.which", return_value="/anywhere"):
            assert _install_command_for("unknown") is None


# ---------------------------------------------------------------------------
# install bws — full handler flow
# ---------------------------------------------------------------------------


def _ns(**kwargs) -> argparse.Namespace:
    """Build an ``argparse.Namespace`` with sensible defaults for the
    install command's flags."""
    return argparse.Namespace(
        subcommand="secrets",
        secrets_command="install",
        install_target="bws",
        yes=kwargs.pop("yes", False),
        force=kwargs.pop("force", False),
        **kwargs,
    )


class TestInstallBwsIdempotent:
    def test_already_installed_without_force_returns_success(self, capsys):
        with patch("servonaut.cli.secrets._bws_path", return_value="/usr/local/bin/bws"):
            rc = handle_secrets_command(_ns())
        out = capsys.readouterr().out
        assert rc == _EXIT_SUCCESS
        assert "already installed" in out
        assert "/usr/local/bin/bws" in out

    def test_force_re_runs_install_even_if_present(self, capsys):
        # With --force, the "already installed" early-return is
        # skipped; we proceed to the platform-detect path.
        with patch("servonaut.cli.secrets._bws_path", return_value="/usr/local/bin/bws"), \
             patch("servonaut.cli.secrets._detect_platform", return_value="windows"):
            rc = handle_secrets_command(_ns(force=True))
        out = capsys.readouterr().out
        # Windows has no auto-install → manual fallback URL printed.
        assert BWS_INSTALL_DOC_URL in out


class TestInstallBwsManualFallback:
    def test_windows_prints_manual_url(self, capsys):
        with patch("servonaut.cli.secrets._bws_path", return_value=None), \
             patch("servonaut.cli.secrets._detect_platform", return_value="windows"):
            rc = handle_secrets_command(_ns())
        out = capsys.readouterr().out
        assert rc == _EXIT_NOT_FOUND
        assert BWS_INSTALL_DOC_URL in out

    def test_macos_without_brew_prints_manual_with_brew_hint(self, capsys):
        with patch("servonaut.cli.secrets._bws_path", return_value=None), \
             patch("servonaut.cli.secrets._detect_platform", return_value="macos"), \
             patch("servonaut.cli.secrets.shutil.which", return_value=None):
            rc = handle_secrets_command(_ns())
        out = capsys.readouterr().out
        assert rc == _EXIT_NOT_FOUND
        assert "brew install bws" in out
        assert BWS_INSTALL_DOC_URL in out

    def test_linux_without_cargo_prints_manual_with_cargo_hint(self, capsys):
        with patch("servonaut.cli.secrets._bws_path", return_value=None), \
             patch("servonaut.cli.secrets._detect_platform", return_value="linux"), \
             patch("servonaut.cli.secrets.shutil.which", return_value=None):
            rc = handle_secrets_command(_ns())
        out = capsys.readouterr().out
        assert rc == _EXIT_NOT_FOUND
        assert "cargo install bws" in out


class TestInstallBwsAutoInstall:
    def test_non_interactive_without_yes_refuses(self, capsys):
        # Non-TTY stdin + no --yes flag → refuse to run installer.
        with patch("servonaut.cli.secrets._bws_path", return_value=None), \
             patch("servonaut.cli.secrets._detect_platform", return_value="linux"), \
             patch("servonaut.cli.secrets.shutil.which", return_value="/cargo"), \
             patch("servonaut.cli.secrets.sys.stdin") as stdin_mock:
            stdin_mock.isatty.return_value = False
            rc = handle_secrets_command(_ns())
        out = capsys.readouterr().out
        assert rc == _EXIT_USER_ABORT
        assert "non-interactive" in out
        assert "--yes" in out

    def test_yes_flag_skips_prompt(self, capsys):
        # --yes set; should run the installer without asking.
        fake_result = MagicMock(returncode=0)
        with patch("servonaut.cli.secrets._bws_path", side_effect=[None, "/cargo/bin/bws"]), \
             patch("servonaut.cli.secrets._detect_platform", return_value="linux"), \
             patch("servonaut.cli.secrets.shutil.which", return_value="/cargo"), \
             patch("servonaut.cli.secrets.subprocess.run", return_value=fake_result) as run_mock:
            rc = handle_secrets_command(_ns(yes=True))
        out = capsys.readouterr().out
        assert rc == _EXIT_SUCCESS
        # Installer ran, with the right argv.
        run_mock.assert_called_once_with(["cargo", "install", "bws"], check=False)
        assert "/cargo/bin/bws" in out
        # Post-install hints surface.
        assert "BWS_ACCESS_TOKEN" in out

    def test_installer_nonzero_exit_reports_failure(self, capsys):
        fake_result = MagicMock(returncode=2)
        with patch("servonaut.cli.secrets._bws_path", return_value=None), \
             patch("servonaut.cli.secrets._detect_platform", return_value="linux"), \
             patch("servonaut.cli.secrets.shutil.which", return_value="/cargo"), \
             patch("servonaut.cli.secrets.subprocess.run", return_value=fake_result):
            rc = handle_secrets_command(_ns(yes=True))
        out = capsys.readouterr().out
        assert rc == _EXIT_INSTALL_FAILED
        assert "exited with code 2" in out
        assert BWS_INSTALL_DOC_URL in out

    def test_installer_succeeds_but_path_still_missing(self, capsys):
        # Installer ran (returncode 0) but the binary is STILL not on
        # PATH — common with cargo install + non-default CARGO_HOME.
        # We must surface this rather than declare false success.
        fake_result = MagicMock(returncode=0)
        with patch("servonaut.cli.secrets._bws_path", return_value=None), \
             patch("servonaut.cli.secrets._detect_platform", return_value="linux"), \
             patch("servonaut.cli.secrets.shutil.which", return_value="/cargo"), \
             patch("servonaut.cli.secrets.subprocess.run", return_value=fake_result):
            rc = handle_secrets_command(_ns(yes=True))
        out = capsys.readouterr().out
        assert rc == _EXIT_INSTALL_FAILED
        assert "still not on" in out.lower() or "not on path" in out.lower()

    def test_package_manager_vanishes_mid_flight(self, capsys):
        # FileNotFoundError on subprocess.run = the package manager
        # was uninstalled between detection and exec. Surface as
        # install-failed.
        with patch("servonaut.cli.secrets._bws_path", return_value=None), \
             patch("servonaut.cli.secrets._detect_platform", return_value="linux"), \
             patch("servonaut.cli.secrets.shutil.which", return_value="/cargo"), \
             patch("servonaut.cli.secrets.subprocess.run", side_effect=FileNotFoundError("cargo gone")):
            rc = handle_secrets_command(_ns(yes=True))
        out = capsys.readouterr().out
        assert rc == _EXIT_INSTALL_FAILED


# ---------------------------------------------------------------------------
# Status command
# ---------------------------------------------------------------------------


class TestStatusCommand:
    def test_unauthenticated_prints_legacy_path(self, capsys):
        # handle_status() now delegates to compute_secrets_status,
        # which itself calls entitlement_guard.check + reads the
        # auth state. Mock the AuthService at its source binding;
        # let the real EntitlementGuard run against the mocked
        # AuthService (it gracefully returns False for an unauthed
        # user).
        auth = MagicMock()
        auth.is_authenticated = False
        auth.plan = "free"
        with patch("servonaut.services.auth_service.AuthService") as AuthCls:
            AuthCls.return_value = auth
            rc = handle_secrets_command(argparse.Namespace(
                subcommand="secrets", secrets_command="status",
            ))
        out = capsys.readouterr().out
        assert rc == _EXIT_SUCCESS
        assert "Authenticated: False" in out
        assert "legacy ~/.ssh discovery" in out

    def test_authenticated_solo_with_local_provider(self, capsys):
        auth = MagicMock()
        auth.is_authenticated = True
        auth.plan = "solo"
        auth.is_secrets_cache_present.return_value = False
        auth.is_secrets_cache_fresh.return_value = False
        auth._token = MagicMock(secrets_fetched_at=0.0)

        from servonaut.config.schema import SecretsConfig
        auth.cached_secrets_config.return_value = SecretsConfig.local_default()

        guard = MagicMock()
        guard.check.return_value = (True, "OK")

        provider = MagicMock()
        provider.provider_name = "local"
        provider.path = "/home/test/.servonaut/secrets.json"

        with patch("servonaut.services.auth_service.AuthService", return_value=auth), \
             patch("servonaut.services.entitlement_guard.EntitlementGuard", return_value=guard), \
             patch("servonaut.services.secret_provider_resolver.resolve_secret_provider", return_value=provider):
            rc = handle_secrets_command(argparse.Namespace(
                subcommand="secrets", secrets_command="status",
            ))
        out = capsys.readouterr().out
        assert rc == _EXIT_SUCCESS
        assert "Plan: solo" in out
        assert "Entitled to secrets_management: True" in out
        assert "Active provider: local" in out
        assert "/home/test/.servonaut/secrets.json" in out


# ---------------------------------------------------------------------------
# Parser smoke tests
# ---------------------------------------------------------------------------


class TestParserWiring:
    def test_install_bws_minimal(self):
        ns = _parse_argv(["secrets", "install", "bws"])
        assert ns.subcommand == "secrets"
        assert ns.secrets_command == "install"
        assert ns.install_target == "bws"
        assert ns.yes is False
        assert ns.force is False

    def test_install_bws_with_yes_and_force(self):
        ns = _parse_argv(["secrets", "install", "bws", "--yes", "--force"])
        assert ns.yes is True
        assert ns.force is True

    def test_status(self):
        ns = _parse_argv(["secrets", "status"])
        assert ns.secrets_command == "status"

    def test_missing_subcommand_raises_systemexit(self):
        # argparse should refuse "servonaut secrets" with no
        # sub-subcommand because we set required=True on the secrets
        # subparser tree.
        with pytest.raises(SystemExit):
            _parse_argv(["secrets"])

    def test_missing_install_target_raises_systemexit(self):
        with pytest.raises(SystemExit):
            _parse_argv(["secrets", "install"])


class TestDispatcher:
    def test_unknown_install_target_returns_usage_error(self, capsys):
        ns = argparse.Namespace(
            subcommand="secrets",
            secrets_command="install",
            install_target="some-future-backend",
        )
        rc = handle_secrets_command(ns)
        assert rc == _EXIT_USAGE_ERROR

    def test_unknown_secrets_command_returns_usage_error(self, capsys):
        ns = argparse.Namespace(
            subcommand="secrets",
            secrets_command="rumour",
        )
        rc = handle_secrets_command(ns)
        assert rc == _EXIT_USAGE_ERROR

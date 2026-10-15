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
from pathlib import Path
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


_DEVELOPER_FIELDS = (
    "Authenticated:", "Plan:", "Entitled to", "secrets_management",
    "SecretsConfig", "Active provider", "LocalProvider", "project_id",
)


def _local_store_path() -> str:
    # The unit suite runs with HOME isolated, so this is under the home folder.
    return str(Path.home() / ".servonaut" / "secrets.json")


def _summary(**overrides):
    """A signed-in Solo user on the default local store, with overrides."""
    from servonaut.services.secrets_status import SecretsStatusSummary

    fields = dict(
        authenticated=True, plan="solo", entitled_secrets_management=True,
        entitlement_reason="OK", entitled_secrets_team_shared=False,
        active_provider_name="local", config_source=None,
        bitwarden_project_id=None, bitwarden_token_env_var=None,
        bws_path=None, bws_token_set=False,
        local_secrets_path=_local_store_path(),
        cache_present=False, cache_fresh=False, cache_updated_at="",
        cache_fetched_at=0.0, has_health_warning=False,
    )
    fields.update(overrides)
    return SecretsStatusSummary(**fields)


def _bitwarden(**overrides):
    fields = dict(
        active_provider_name="bitwarden", config_source="user",
        bitwarden_project_id="proj-servers-1",
        bitwarden_token_env_var="BWS_ACCESS_TOKEN", bws_token_set=True,
        bws_path=str(Path.home() / ".cargo" / "bin" / "bws"),
        local_secrets_path=None,
    )
    fields.update(overrides)
    return _summary(**fields)


def _lines(summary) -> list[str]:
    from servonaut.cli.secrets import _status_lines

    lines = _status_lines(summary)
    for line in lines:
        for field in _DEVELOPER_FIELDS:
            assert field not in line, line
    return lines


def _run_status(capsys, auth, *, guard=None, provider=None, json_out=False):
    patches = [patch("servonaut.services.auth_service.AuthService", return_value=auth)]
    if guard is not None:
        patches.append(patch(
            "servonaut.services.entitlement_guard.EntitlementGuard", return_value=guard,
        ))
    if provider is not None:
        patches.append(patch(
            "servonaut.services.secret_provider_resolver.resolve_secret_provider",
            return_value=provider,
        ))
    for active in patches:
        active.start()
    try:
        rc = handle_secrets_command(argparse.Namespace(
            subcommand="secrets", secrets_command="status", json=json_out,
        ))
    finally:
        for active in patches:
            active.stop()
    return rc, capsys.readouterr().out


def _solo_local_auth():
    from servonaut.config.schema import SecretsConfig

    auth = MagicMock()
    auth.is_authenticated = True
    auth.plan = "solo"
    auth.is_secrets_cache_present.return_value = False
    auth.is_secrets_cache_fresh.return_value = False
    auth._token = MagicMock(secrets_fetched_at=0.0)
    auth.secrets_config_source.return_value = None
    auth.cached_secrets_config.return_value = SecretsConfig.local_default()
    guard = MagicMock()
    guard.check.return_value = (True, "OK")
    provider = MagicMock()
    provider.provider_name = "local"
    provider.path = _local_store_path()
    return auth, guard, provider


class TestStatusCommand:
    def test_unauthenticated_says_how_to_sign_in(self, capsys):
        # handle_status() delegates to compute_secrets_status, which calls
        # entitlement_guard.check + reads the auth state. Mock the
        # AuthService at its source binding; the real EntitlementGuard
        # returns False for an unauthed user.
        auth = MagicMock()
        auth.is_authenticated = False
        auth.plan = "free"
        rc, out = _run_status(capsys, auth)
        assert rc == _EXIT_SUCCESS
        assert out.splitlines() == [
            "Not signed in, so there is no secret store: SSH keys are looked up in ~/.ssh.",
            "Sign in with `servonaut login`. Solo and Teams plans include a secret store.",
        ]

    def test_solo_on_the_local_store_reads_as_sentences(self, capsys):
        auth, guard, provider = _solo_local_auth()
        rc, out = _run_status(capsys, auth, guard=guard, provider=provider)
        assert rc == _EXIT_SUCCESS
        assert out.splitlines() == [
            "Signed in on the Solo plan.",
            "Secrets are kept in the local secret store (~/.servonaut/secrets.json).",
            ("To keep them in Bitwarden Secrets Manager instead, run "
             "`servonaut secrets setup`."),
        ]

    def test_json_prints_the_snapshot_fields(self, capsys):
        import json

        auth, guard, provider = _solo_local_auth()
        rc, out = _run_status(capsys, auth, guard=guard, provider=provider, json_out=True)
        assert rc == _EXIT_SUCCESS
        fields = json.loads(out)
        assert fields["authenticated"] is True
        assert fields["plan"] == "solo"
        assert fields["entitled_secrets_management"] is True
        assert fields["active_provider_name"] == "local"
        assert fields["cache_present"] is False
        # No home folder in the output, as in the sentences.
        assert fields["local_secrets_path"] == "~/.servonaut/secrets.json"

    def test_free_plan_points_at_the_plans(self):
        lines = _lines(_summary(
            plan="free", entitled_secrets_management=False,
            active_provider_name=None, local_secrets_path=None,
        ))
        assert lines == [
            "Signed in on the Free plan.",
            ("Your plan has no secret store (Solo and Teams plans do), so SSH "
             "keys are looked up in ~/.ssh."),
            "Plans: https://servonaut.dev/pricing",
        ]

    def test_working_bitwarden_names_project_token_and_program(self):
        lines = _lines(_bitwarden())
        assert lines == [
            "Signed in on the Solo plan.",
            ("Secrets are kept in Bitwarden Secrets Manager (project "
             "proj-servers-1), chosen by you."),
            "The access token is read from BWS_ACCESS_TOKEN, which is set.",
            "The bws program is at ~/.cargo/bin/bws.",
        ]

    def test_broken_bitwarden_says_what_to_fix(self):
        lines = _lines(_bitwarden(
            plan="teams", config_source="team", bws_path=None, bws_token_set=False,
            has_health_warning=True,
        ))
        assert lines[1] == (
            "Secrets are kept in Bitwarden Secrets Manager (project "
            "proj-servers-1), chosen by your team."
        )
        assert lines[2:] == [
            ("The access token is read from BWS_ACCESS_TOKEN, which is not set: "
             "export it in your shell."),
            "The bws program is not installed: run `servonaut secrets install bws`.",
            "Until that is fixed, SSH keys are looked up in ~/.ssh.",
        ]

    def test_team_setting_shadowing_your_own_is_explained(self):
        lines = _lines(_bitwarden(config_source="team", shadowed_user_project_id="proj-mine"))
        assert (
            "Your own Bitwarden project (proj-mine) is not used: your team's "
            "setting comes first." in lines
        )

    def test_invalid_own_project_id_falls_back_to_the_local_store(self):
        lines = _lines(_summary(
            config_source="user", project_id_invalid=True,
            bitwarden_project_id="<uuid>", has_health_warning=True,
        ))
        assert lines[1:] == [
            ("Secrets are kept in the local secret store (~/.servonaut/secrets.json), "
             "chosen by you."),
            ("Your Bitwarden setting is ignored because its project id (<uuid>) is "
             "not valid. Fix it with `servonaut secrets setup`."),
        ]

    def test_invalid_team_project_id_names_who_can_fix_it(self):
        lines = _lines(_summary(
            plan="teams", project_id_invalid=True, team_config_broken=True,
            bitwarden_project_id="<uuid>", broken_team_project_id="<uuid>",
            has_health_warning=True,
        ))
        assert lines[2:] == [
            ("Your team's Bitwarden setting is ignored because its project id "
             "(<uuid>) is not valid, so the local secret store is used instead. "
             "A team admin can fix it in the team settings."),
            ("To keep them in Bitwarden Secrets Manager instead, run "
             "`servonaut secrets setup`."),
        ]

    def test_team_chosen_local_store_offers_no_switch(self):
        lines = _lines(_summary(plan="teams", config_source="team"))
        assert lines == [
            "Signed in on the Teams plan.",
            ("Secrets are kept in the local secret store (~/.servonaut/secrets.json), "
             "chosen by your team."),
        ]

    def test_fetch_age_is_said_when_settings_came_from_the_account(self):
        import time

        lines = _lines(_bitwarden(cache_present=True, cache_fetched_at=time.time() - 600))
        assert lines[-1] == "Settings last fetched from your account 10m ago."


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
        assert ns.json is False

    def test_status_json(self):
        ns = _parse_argv(["secrets", "status", "--json"])
        assert ns.json is True

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

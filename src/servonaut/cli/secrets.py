"""CLI subcommand handlers for ``servonaut secrets``.

Part of the secrets-management feature.

MVP surface — kept deliberately small:

``servonaut secrets install bws``
    Detect or install Bitwarden's ``bws`` CLI for the user's
    platform. Runs the upstream install script via the standard
    "one-line install" path each platform documents. No surprises:
    if anything looks off, we print the manual command and exit
    so the user finishes the install themselves.

``servonaut secrets status``
    Show which provider is active, where the cache came from, and
    when it was last refreshed. Useful for "is my team's BWS config
    actually being used?" debugging — no other side effects.

Future commands (NOT in MVP — listed here so the dispatch shape is
forward-compatible):

- ``servonaut secrets refresh`` — force a refetch of the team's
  :class:`SecretsConfig` from the API.
- ``servonaut secrets get <name>`` / ``set <name>`` / ``delete <name>``
  / ``list`` — direct provider CRUD from the CLI for headless
  workflows.

Design choices:

- The installer NEVER runs anything as root. We invoke the upstream
  installer with the user's own permissions. If the installer needs
  ``sudo`` (Homebrew might), it asks for it itself. Cleaner audit
  trail than us escalating from inside Python.
- ``shutil.which("bws")`` is the single source of truth for "is bws
  installed". After install, we re-probe and surface the path so the
  user can verify.
- Exit codes follow the same scheme :mod:`cli.memory` uses so a CI
  wrapper that catches ``servonaut secrets install bws`` failures
  treats them the same as any other subcommand failure.
"""
from __future__ import annotations

import argparse
import logging
import platform
import shutil
import subprocess
import sys
from typing import List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exit codes — same scheme as cli/memory.py for CI consistency
# ---------------------------------------------------------------------------

_EXIT_SUCCESS = 0
_EXIT_NOT_FOUND = 1
_EXIT_USAGE_ERROR = 4
_EXIT_USER_ABORT = 5
_EXIT_GENERIC_ERROR = 6
_EXIT_INSTALL_FAILED = 7


# ---------------------------------------------------------------------------
# Public docs URLs — kept here so the help text and error messages
# share one source of truth. If Bitwarden moves their docs we update
# this constant, not every error message.
# ---------------------------------------------------------------------------

BWS_INSTALL_DOC_URL = "https://bitwarden.com/help/secrets-manager-cli/"
BWS_RELEASES_URL = "https://github.com/bitwarden/sdk-sm/releases"


# ---------------------------------------------------------------------------
# Platform → install method
# ---------------------------------------------------------------------------

def _detect_platform() -> str:
    """Return a coarse install-method key for the running platform.

    Coarser than :func:`platform.system` because we don't actually
    care about (e.g.) Ubuntu vs Debian — both use the same install
    script. Returns one of: ``"macos"``, ``"linux"``, ``"windows"``,
    or ``"unknown"``.
    """
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    if system == "windows":
        return "windows"
    return "unknown"


def _bws_path() -> Optional[str]:
    """``shutil.which("bws")`` wrapper, kept as a function so tests
    can monkey-patch this single name rather than ``shutil.which``
    globally."""
    return shutil.which("bws")


# ---------------------------------------------------------------------------
# Install methods — each returns (command_to_run, manual_fallback_text).
# Commands are lists for ``subprocess.run(check=True)`` (no shell);
# manual_fallback_text is what we print if we refuse to auto-run the
# install (CI environments, non-interactive shells, unknown platforms).
# ---------------------------------------------------------------------------

def _install_command_for(plat: str) -> Optional[List[str]]:
    """Return the install command for ``plat``, or ``None`` if we
    don't have an auto-install path on this platform.

    Returning ``None`` is NOT a failure — :func:`_handle_install_bws`
    falls back to printing the manual install URL and exiting with
    a non-zero code so the user follows the official path.

    Auto-install policy:
    - **macos**: ``brew install bws`` (Homebrew is the dominant package
      manager + bws is in homebrew-core). We DON'T pipe ``curl |
      bash`` from a random URL.
    - **linux**: ``cargo install bws`` IF cargo is on PATH (matches
      the upstream Rust-source path). No ``curl | sh`` automation
      for the same security reason as macos.
    - **windows**: no auto-install. Direct user to the GitHub Releases
      page; .msi installer is the right path.

    The conservative policy means most users will get the
    "follow the upstream docs" output rather than a one-button
    install. That's deliberate: a successful manual install + a
    clear "now re-run `servonaut secrets install bws` to verify"
    flow is safer than us shipping a do-anything-curl-bash command
    that future Bitwarden security advisories couldn't easily call
    back from.
    """
    if plat == "macos":
        if shutil.which("brew") is None:
            return None
        return ["brew", "install", "bws"]
    if plat == "linux":
        if shutil.which("cargo") is None:
            return None
        return ["cargo", "install", "bws"]
    # windows / unknown → manual.
    return None


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _handle_install_bws(args: argparse.Namespace) -> int:
    """``servonaut secrets install bws`` — detect or install bws.

    Flow:

    1. If ``bws`` is already on PATH AND ``--force`` was not passed,
       print the path and exit 0. Idempotent re-runs are cheap.
    2. Detect platform + look up the auto-install command.
       - Have one + ``--yes`` passed (or stdin is a TTY and user
         confirms) → run it.
       - No auto-install command for this platform → print manual
         instructions + URL and exit non-zero.
    3. After auto-install, re-probe :func:`_bws_path`. If still
       missing → exit non-zero ("install ran but bws still not
       found — check the installer output").
    """
    if not args.force:
        path = _bws_path()
        if path:
            print(f"bws is already installed: {path}")
            print(
                "(Run with `--force` to re-install; otherwise nothing to do.)"
            )
            return _EXIT_SUCCESS

    plat = _detect_platform()
    cmd = _install_command_for(plat)

    if cmd is None:
        # No auto-install path — direct user at the docs.
        print(
            "Servonaut does not auto-install bws on your platform.\n"
            f"Please follow the manual instructions: {BWS_INSTALL_DOC_URL}\n"
            f"Or download a release binary: {BWS_RELEASES_URL}\n"
        )
        if plat == "linux":
            print(
                "Heads-up: `cargo install bws` is supported automatically "
                "if you install the Rust toolchain first (`curl --proto "
                "'=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` is "
                "the upstream recommendation — verify it yourself "
                "before running)."
            )
        elif plat == "macos":
            print(
                "Heads-up: `brew install bws` is supported automatically "
                "if you install Homebrew first (https://brew.sh)."
            )
        return _EXIT_NOT_FOUND

    # We have an auto-install path. Confirm before running.
    print(f"Detected platform: {plat}")
    print(f"Proposed install command: {' '.join(cmd)}")
    if not args.yes:
        if not sys.stdin.isatty():
            print(
                "Refusing to auto-install in a non-interactive shell "
                "without --yes. Re-run with --yes to confirm, OR run "
                f"the proposed command manually: {' '.join(cmd)}"
            )
            return _EXIT_USER_ABORT
        try:
            reply = input("Proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return _EXIT_USER_ABORT
        if reply not in {"y", "yes"}:
            print("Aborted.")
            return _EXIT_USER_ABORT

    # Run the installer with the user's own permissions. Capture
    # the subprocess result for an informative failure message.
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=False)
    except FileNotFoundError as exc:
        # The package manager itself vanished between detection
        # and exec — vanishingly rare but real (Homebrew uninstalled
        # mid-flight).
        print(f"Install command not found: {exc}")
        return _EXIT_INSTALL_FAILED
    if result.returncode != 0:
        print(
            f"\n`{' '.join(cmd)}` exited with code {result.returncode}.\n"
            f"See {BWS_INSTALL_DOC_URL} for manual install instructions."
        )
        return _EXIT_INSTALL_FAILED

    # Re-probe — the installer may have succeeded but landed bws in
    # a directory that's not on this shell's PATH (common with
    # ``cargo install`` and a non-default CARGO_HOME).
    final_path = _bws_path()
    if final_path is None:
        print(
            "\nInstaller reported success but `bws` is still not on "
            "PATH. Common causes:\n"
            "  - cargo's `bin` directory (~/.cargo/bin) isn't in your "
            "PATH; add it to your shell profile.\n"
            "  - Homebrew's bin dir isn't on PATH for this user.\n"
            "Open a fresh shell and run `which bws` to confirm."
        )
        return _EXIT_INSTALL_FAILED

    print(f"\nbws installed: {final_path}")
    print(
        "Next steps:\n"
        f"  1. Set your BWS access token: `export BWS_ACCESS_TOKEN=<...>`\n"
        f"  2. Ask your team admin to configure the team's Bitwarden\n"
        "     project in the Servonaut settings, OR\n"
        "  3. Use bws directly: `bws secret list --project-id <uuid>`."
    )
    return _EXIT_SUCCESS


def _handle_status(args: argparse.Namespace) -> int:
    """``servonaut secrets status`` — print which provider is active.

    Thin renderer around :func:`compute_secrets_status` — both the
    CLI subcommand and the TUI :class:`SecretsScreen` read from the
    same frozen snapshot so the two surfaces stay in sync. If a
    future field gets added to :class:`SecretsStatusSummary`, both
    surfaces light it up via this single function.
    """
    from servonaut.services.auth_service import AuthService
    from servonaut.services.entitlement_guard import EntitlementGuard
    from servonaut.services.secrets_status import (
        compute_secrets_status,
        format_relative_age,
    )

    auth = AuthService()
    guard = EntitlementGuard(auth)
    s = compute_secrets_status(auth, guard)

    print(f"Authenticated: {s.authenticated}")
    if not s.authenticated:
        print("Plan: free (anonymous)")
        print("Active provider: none (legacy ~/.ssh discovery)")
        return _EXIT_SUCCESS

    print(f"Plan: {s.plan}")
    print(
        f"Entitled to secrets_management: "
        f"{s.entitled_secrets_management} ({s.entitlement_reason})"
    )

    if s.cache_present:
        age = format_relative_age(s.cache_fetched_at)
        print(
            f"Cached SecretsConfig: provider={s.active_provider_name} "
            f"updated_at={s.cache_updated_at or '(none)'} "
            f"fresh={s.cache_fresh} fetched={age}"
        )
    else:
        print("Cached SecretsConfig: none (would fetch on next refresh)")

    if s.active_provider_name is None:
        print("Active provider: none (legacy ~/.ssh discovery)")
    else:
        print(f"Active provider: {s.active_provider_name}")
        if s.bitwarden_project_id:
            print(f"  Bitwarden project_id: {s.bitwarden_project_id}")
            print(
                f"  Token env var: {s.bitwarden_token_env_var} "
                f"({'set' if s.bws_token_set else 'NOT SET'})"
            )
            print(
                f"  bws CLI: {s.bws_path if s.bws_path else 'not installed'}"
            )
        if s.local_secrets_path:
            print(f"  LocalProvider path: {s.local_secrets_path}")
        if s.has_health_warning:
            print(
                "  ⚠ Health: missing bws CLI or token. CLI falls back to "
                "~/.ssh discovery until fixed."
            )
    return _EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Parser wiring — exported so ``main.py`` can hook it into
# ``argparse``'s subparser tree, same shape as cli/hetzner.py.
# ---------------------------------------------------------------------------

def add_secrets_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``secrets`` subcommand tree on ``subparsers``."""
    secrets = subparsers.add_parser(
        "secrets",
        help=(
            "Manage the secrets-management feature: install the bws CLI "
            "and inspect the active provider."
        ),
    )
    secrets_sub = secrets.add_subparsers(
        dest="secrets_command",
        required=True,
    )

    install = secrets_sub.add_parser(
        "install",
        help="Install a secrets-management backend (currently: bws).",
    )
    install_sub = install.add_subparsers(
        dest="install_target",
        required=True,
    )

    install_bws = install_sub.add_parser(
        "bws",
        help=(
            "Install Bitwarden's `bws` CLI via the platform's "
            "package manager. macOS: brew. Linux: cargo. "
            "Other platforms: prints manual instructions."
        ),
    )
    install_bws.add_argument(
        "--yes", action="store_true",
        help="Skip the y/N confirmation (non-interactive use).",
    )
    install_bws.add_argument(
        "--force", action="store_true",
        help="Re-run the install even if bws is already on PATH.",
    )

    secrets_sub.add_parser(
        "status",
        help="Show the active secret provider, plan, and cache state.",
    )


def handle_secrets_command(args: argparse.Namespace) -> int:
    """Dispatch entry-point. Returns a process exit code."""
    cmd = getattr(args, "secrets_command", None)
    if cmd == "install":
        target = getattr(args, "install_target", None)
        if target == "bws":
            return _handle_install_bws(args)
        print(f"Unknown install target: {target}")
        return _EXIT_USAGE_ERROR
    if cmd == "status":
        return _handle_status(args)
    print(f"Unknown secrets subcommand: {cmd}")
    return _EXIT_USAGE_ERROR

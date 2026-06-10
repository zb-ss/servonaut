"""``servonaut login`` — headless device-flow sign-in (RFC 8628).

Drives the same OAuth2 device-flow endpoints the TUI login screen uses
(``POST /api/oauth/device`` → user verifies in any browser on any device →
poll ``POST /api/oauth/token``), so headless boxes (CI runners, agent-only
MCP installs) can authenticate without ever opening the TUI. Tokens land in
``~/.servonaut/auth.json`` exactly as with a TUI login and are shared by
every CLI subcommand and the MCP server.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Any

logger = logging.getLogger(__name__)

_EXIT_SUCCESS = 0
_EXIT_ERROR = 1
_EXIT_CANCELLED = 130  # 128 + SIGINT, matching the shell convention

# Upper bound on how long we wait for the user to approve in a browser.
# The server's device-code lifetime (``expires_in``) is the real budget;
# this only caps a pathologically large value.
_MAX_POLL_WAIT_SECONDS = 900


def add_login_parser(subparsers: Any) -> None:
    """Register the ``login`` subcommand on the top-level parser."""
    parser = subparsers.add_parser(
        'login',
        help='Sign in to servonaut.dev via device flow — works headless, '
             'no TUI needed.',
    )
    parser.add_argument(
        '--no-browser', action='store_true',
        help="Don't try to open the verification URL locally; just print it "
             "(default behaviour on boxes without a browser).",
    )
    parser.add_argument(
        '--force', action='store_true',
        help='Run the device flow even if a valid session already exists.',
    )


def add_logout_parser(subparsers: Any) -> None:
    """Register the ``logout`` subcommand on the top-level parser."""
    subparsers.add_parser(
        'logout',
        help='Sign out: revoke the session at servonaut.dev (best-effort) '
             'and delete ~/.servonaut/auth.json.',
    )


def handle_logout_command(args: argparse.Namespace) -> int:
    """Implement ``servonaut logout``. Returns a process exit code."""
    from servonaut.services.auth_service import AuthService

    _load_env_overrides()
    auth = AuthService()
    if not auth.is_authenticated:
        print("Not signed in — nothing to do.")
        return _EXIT_SUCCESS

    try:
        asyncio.run(auth.logout())
    except Exception as exc:  # noqa: BLE001 — single-line CLI error
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    print("Signed out — session revoked and ~/.servonaut/auth.json removed.")
    return _EXIT_SUCCESS


def _load_env_overrides() -> None:
    """Load ``~/.secrets/servonaut.env`` into the environment.

    ``AuthService`` reads ``SERVONAUT_API_URL`` at request time, and other
    entry points get the env file loaded as a side effect of constructing
    ``ConfigManager``. login/logout never build a ConfigManager, so without
    this call they would target the production API even when the user has
    overridden the URL (e.g. to staging) in the secrets env file.
    """
    from servonaut.config.secrets import load_secrets_env
    load_secrets_env()


def handle_login_command(args: argparse.Namespace) -> int:
    """Implement ``servonaut login``. Returns a process exit code."""
    from servonaut.services.auth_service import AuthService

    _load_env_overrides()
    auth = AuthService()
    if auth.is_authenticated and not getattr(args, 'force', False):
        print(
            f"Already signed in (plan: {auth.plan}). "
            "Run `servonaut login --force` to re-authenticate."
        )
        return _EXIT_SUCCESS

    try:
        return asyncio.run(
            _do_login(auth, no_browser=bool(getattr(args, 'no_browser', False)))
        )
    except KeyboardInterrupt:
        print("\nSign-in aborted.", file=sys.stderr)
        return _EXIT_CANCELLED


async def _do_login(auth: Any, *, no_browser: bool) -> int:
    """Run the device flow: print URL + code, poll until approved."""
    try:
        flow = await auth.start_device_flow()
    except Exception as exc:  # noqa: BLE001 — single-line CLI error
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    device_code = flow.get("device_code", "")
    user_code = flow.get("user_code", "")
    verification_uri = flow.get("verification_uri", "")
    verification_uri_complete = flow.get("verification_uri_complete", "")
    interval = int(flow.get("interval") or 5)
    expires_in = int(flow.get("expires_in") or 300)

    if not device_code or not user_code or not verification_uri:
        print(
            "Error: device-flow response was missing device_code, "
            "user_code, or verification_uri.",
            file=sys.stderr,
        )
        return _EXIT_ERROR

    # flush=True throughout the pre-poll output: when stdout is redirected
    # (CI logs, `servonaut login | tee`), block buffering would otherwise
    # hold back the URL + code until process exit — after the user needed
    # them.
    print("To sign in, open this URL in any browser (any device works):",
          flush=True)
    print(f"\n    {verification_uri}\n", flush=True)
    print(f"and enter the code: {user_code}\n", flush=True)

    # Best-effort convenience on desktop; the printed URL is the real path
    # on headless boxes. Only ever auto-open URLs our own API returned over
    # https — never an http or scheme-less value.
    open_target = verification_uri_complete or verification_uri
    if not no_browser and open_target.startswith("https://"):
        try:
            import webbrowser
            if webbrowser.open(open_target):
                print("(Opened the verification page in your local browser.)",
                      flush=True)
        except Exception:  # noqa: BLE001 — no browser is the expected case
            pass

    wait_seconds = max(interval, min(expires_in, _MAX_POLL_WAIT_SECONDS))
    print(
        f"Waiting for approval (up to {wait_seconds // 60} min, "
        "Ctrl+C to abort)...",
        flush=True,
    )

    success = await auth.poll_for_token(
        device_code, interval=interval, max_wait_seconds=wait_seconds,
    )
    if not success:
        print(
            "Sign-in was not completed (denied, expired, or timed out). "
            "Run `servonaut login` to try again.",
            file=sys.stderr,
        )
        return _EXIT_ERROR

    print(f"Signed in successfully (plan: {auth.plan}).")
    print("Tokens saved to ~/.servonaut/auth.json — all CLI subcommands "
          "and the MCP server now share this session.")
    return _EXIT_SUCCESS

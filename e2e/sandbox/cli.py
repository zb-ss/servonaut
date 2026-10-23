"""Command line of the local QA sandbox (``python -m e2e.sandbox``)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from e2e.sandbox import state

DESCRIPTION = """\
A hermetic sandbox for walking Servonaut like a user: the fakes of the
end-to-end suite (Servonaut API, package index, AWS, CloudTrail, Hetzner,
OVH, SSH servers) plus a seeded home, kept running until `down`. One sandbox
runs per user at a time; every command below finds it through
${XDG_STATE_HOME:-~/.local/state}/servonaut-qa/current.json.
"""

EPILOG = """\
examples:
  python -m e2e.sandbox up --scenario multi-account &
  python -m e2e.sandbox status
  python -m e2e.sandbox run -- servonaut hetzner list
  python -m e2e.sandbox accept-invite member@example.com   # up --teams
  python -m e2e.sandbox run --as member -- login           # up --teams
  python -m e2e.sandbox mcp-call list_instances
  python -m e2e.sandbox desktop
  python -m e2e.sandbox down
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m e2e.sandbox",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    up = commands.add_parser(
        "up", help="start a sandbox and keep it running (foreground; prints SANDBOX READY <state>)"
    )
    up.add_argument("--scenario", choices=state.SCENARIOS, default=state.SINGLE,
                    help="what to seed (default: %(default)s)")
    up.add_argument("--root", type=Path, default=None,
                    help=f"sandbox directory (default: <checkout>/{state.DEFAULT_ROOT_NAME}); "
                         "put another one outside the checkout, or at "
                         f"<checkout>/{state.DEFAULT_ROOT_NAME}-<name>: git ignores only those")
    up.add_argument("--signed-in", action="store_true",
                    help="start signed in to the local Servonaut API")
    up.add_argument("--ssh-ca-off", action="store_true",
                    help="answer like a service with SSH certificates switched off")
    up.add_argument("--ssh-ca-refuse", choices=("frozen", "busy"), default=None,
                    help="refuse every SSH certificates switch-on: frozen = switching on is paused "
                         "(409), busy = another switch-on holds the service (503)")
    up.add_argument("--teams", action="store_true",
                    help="on the Teams plan, owning a team whose shared server (server-1) runs "
                         "an sshd that honours SSH certificates, to walk Team Vault and SSH "
                         "certificates end to end; with a second person, a member to be "
                         "(member@example.com, own home, signed out: run --as member, "
                         "accept-invite); needs a short --root, such as /tmp/svt")
    up.add_argument("--api-delay", type=_api_delay, default=0.0, metavar="SECONDS",
                    help="answer every Servonaut API request after SECONDS (up to 30), "
                         "to see what the app shows while it waits")
    up.add_argument("--account-email", default="", metavar="EMAIL",
                    help="give the signed-in account this e-mail address (use a reserved "
                         "example domain), so screens that show it have one")
    up.add_argument("--verification-uri", default=None, metavar="URL",
                    help="the sign-in page `servonaut login` names, for recordings that must "
                         "not show the local address (display only: the sandbox still approves "
                         "the sign-in itself)")
    up.add_argument("--user-code", default=None, metavar="CODE",
                    help="the sign-in code `servonaut login` shows, for recordings (display "
                         "only, like --verification-uri)")
    up.add_argument("--hostname", default=None, metavar="NAME",
                    help="the machine name every sandbox child sees, so names derived from it "
                         "(relay client IDs, vault device names) do not show the real one")
    up.add_argument("--ai-script", type=Path, default=None, metavar="FILE",
                    help="answer `servonaut ai` from FILE: chat replies, the AI quota and stored "
                         "conversations (see e2e/sandbox/ai_script.py for the format)")
    up.add_argument("--keep", action="store_true",
                    help="keep the sandbox directory after it stops, renamed to "
                         "<root>.kept-<time> (for inspection; delete it yourself)")

    status = commands.add_parser("status", help="describe the running sandbox")
    status.add_argument("--json", action="store_true", help="print state.json")

    run = commands.add_parser("run", help="run the Servonaut CLI in the sandbox: run -- <args>")
    run.add_argument("--as", dest="as_person", default=None, metavar="PERSON",
                     help="run as another person of a --teams sandbox, in their own home: member "
                          "(default: the owner); the member's `login` is approved as the member")
    run.add_argument("args", nargs=argparse.REMAINDER, help="servonaut arguments")

    accept = commands.add_parser(
        "accept-invite",
        help="accept a team invitation as the member of a --teams sandbox (their browser step)",
    )
    accept.add_argument("email", help="the address the invitation was sent to")
    accept.add_argument("--as", dest="as_person", default="member", metavar="PERSON",
                        help="who accepts it (default: %(default)s)")

    mcp_call = commands.add_parser("mcp-call", help="call one tool of the real MCP server")
    mcp_call.add_argument("tool")
    mcp_call.add_argument("arguments", nargs="?", default=None, help="JSON object")
    mcp_call.add_argument("--timeout", type=float, default=60.0, help="seconds (default: 60)")

    commands.add_parser("mcp", help="serve the real MCP server over stdio in the sandbox")

    desktop = commands.add_parser(
        "desktop", help="start the desktop child (headless); print its URL and token"
    )
    desktop.add_argument("--new", action="store_true",
                         help="replace a running desktop child with a new one")
    desktop.add_argument("--json", action="store_true", help="print the details as JSON")

    down = commands.add_parser("down", help="stop the sandbox and wait for its processes")
    down.add_argument("--timeout", type=float, default=60.0,
                      help="seconds to wait for the owner (default: 60)")
    return parser


# The longest --api-delay: longer only makes a walk slow, not more telling.
_MAX_API_DELAY_SECONDS = 30.0


def _api_delay(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of seconds: {value!r}") from None
    if not 0 <= seconds <= _MAX_API_DELAY_SECONDS:
        raise argparse.ArgumentTypeError(f"must be between 0 and {_MAX_API_DELAY_SECONDS:g} seconds")
    return seconds


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "up":
        from e2e.sandbox import owner

        return owner.up(root=args.root, scenario=args.scenario, signed_in=args.signed_in,
                        keep=args.keep, ssh_ca_off=args.ssh_ca_off, ssh_ca_refuse=args.ssh_ca_refuse,
                        api_delay=args.api_delay, teams=args.teams, account_email=args.account_email,
                        verification_uri=args.verification_uri, user_code=args.user_code,
                        hostname=args.hostname, ai_script=args.ai_script)

    from e2e.sandbox import client

    try:
        if args.command == "status":
            return client.status(as_json=args.json)
        if args.command == "run":
            return client.run(args.args, as_person=args.as_person)
        if args.command == "accept-invite":
            return client.accept_invite(args.email, as_person=args.as_person)
        if args.command == "mcp-call":
            return client.mcp_call(args.tool, args.arguments, timeout=args.timeout)
        if args.command == "mcp":
            return client.serve_mcp()
        if args.command == "desktop":
            return client.desktop(new=args.new, as_json=args.json)
        if args.command == "down":
            return client.down(timeout=args.timeout)
    except client.ClientError as exc:
        sys.stderr.write(f"qa-sandbox: {exc}\n")
        return 1
    raise AssertionError(f"unhandled command {args.command}")

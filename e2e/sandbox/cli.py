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
                    help=f"sandbox directory (default: <checkout>/{state.DEFAULT_ROOT_NAME})")
    up.add_argument("--signed-in", action="store_true",
                    help="start signed in to the local Servonaut API")
    up.add_argument("--keep", action="store_true",
                    help="keep the sandbox directory after it stops (for inspection)")

    status = commands.add_parser("status", help="describe the running sandbox")
    status.add_argument("--json", action="store_true", help="print state.json")

    run = commands.add_parser("run", help="run the Servonaut CLI in the sandbox: run -- <args>")
    run.add_argument("args", nargs=argparse.REMAINDER, help="servonaut arguments")

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


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "up":
        from e2e.sandbox import owner

        return owner.up(root=args.root, scenario=args.scenario, signed_in=args.signed_in,
                        keep=args.keep)

    from e2e.sandbox import client

    try:
        if args.command == "status":
            return client.status(as_json=args.json)
        if args.command == "run":
            return client.run(args.args)
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

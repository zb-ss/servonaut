"""CLI subcommand for inspecting MCP / Agent activity audit logs.

Usage::

    servonaut mcp audit [--since 24h] [--origin mcp|ui|relay|proactive]
                        [--remote-only] [--commands-only]
                        [--transport ssh|ssm|scp|none]
                        [--category readonly_inspect]
                        [--host prod-web] [--tool run_command]
                        [--search nginx] [--denied]
                        [--summary] [--json] [--limit 100]
"""
from __future__ import annotations

import argparse
import json
import sys

from servonaut.mcp.audit_query import (
    AuditFilter,
    AuditQueryService,
    format_access_line,
    format_summary_text,
    parse_since,
)


def add_mcp_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``servonaut mcp`` subcommand group."""
    mcp_parser = subparsers.add_parser(
        "mcp",
        help="Inspect MCP and agent activity audit logs.",
    )
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_command")
    mcp_sub.required = True

    audit = mcp_sub.add_parser(
        "audit",
        help="Query local MCP / UI / Relay / Proactive agent activity logs (Apache-style).",
    )
    audit.add_argument(
        "--since",
        default="24h",
        help="Time window to inspect (e.g. 1h, 24h, 7d, all, or ISO-8601; default: 24h).",
    )
    audit.add_argument(
        "--origin",
        choices=["mcp", "ui", "relay", "proactive"],
        default="",
        help="Filter by execution surface (mcp, ui, relay, proactive).",
    )
    audit.add_argument(
        "--remote-only",
        action="store_true",
        help="Show only operations that touched remote hosts (SSH/SSM/SCP/DB).",
    )
    audit.add_argument(
        "--commands-only",
        action="store_true",
        help="Show only shell commands (run_command).",
    )
    audit.add_argument(
        "--transport",
        choices=["ssh", "ssm", "scp", "none"],
        default="",
        help="Filter by actual transport used.",
    )
    audit.add_argument(
        "--category",
        default="",
        help="Filter by command/operation category (e.g. readonly_inspect, service_control, file_write, blocked).",
    )
    audit.add_argument(
        "--tool",
        default="",
        help="Filter by tool name substring.",
    )
    audit.add_argument(
        "--host",
        default="",
        help="Filter by target host / instance ID / name substring.",
    )
    audit.add_argument(
        "--search",
        default="",
        help="Free-text search across command, target, tool, client, and reason.",
    )
    audit.add_argument(
        "--denied",
        action="store_true",
        help="Show only denied or failed calls.",
    )
    audit.add_argument(
        "--summary",
        action="store_true",
        help="Print aggregate summary counts (by origin, transport, category, target).",
    )
    audit.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit matching entries as JSON.",
    )
    audit.add_argument(
        "-n",
        "--limit",
        type=int,
        default=100,
        help="Maximum rows to display (default: 100).",
    )
    audit.add_argument(
        "--audit-path",
        default="",
        help="Override audit log path (defaults to mcp.audit_path from config).",
    )


def _resolve_audit_path(args: argparse.Namespace) -> str:
    override = getattr(args, "audit_path", "")
    if override:
        return override
    from servonaut.config.manager import ConfigManager

    config_path = getattr(args, "config", None)
    manager = ConfigManager(config_path=config_path, allow_read_only=True)
    return manager.get().mcp.audit_path


def handle_mcp_command(args: argparse.Namespace) -> int:
    """Execute ``servonaut mcp <subcommand>``."""
    if getattr(args, "mcp_command", None) != "audit":
        print("Unknown mcp subcommand.", file=sys.stderr)
        return 2

    try:
        since_dt = parse_since(args.since)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    scope = "all"
    if args.commands_only:
        scope = "commands"
    elif args.remote_only:
        scope = "remote"
    elif args.denied:
        scope = "denied"

    flt = AuditFilter(
        since=since_dt,
        origin=args.origin,
        scope=scope,
        category=args.category,
        transport=args.transport,
        tool=args.tool,
        host=args.host,
        search=args.search,
        denied_only=bool(args.denied),
    )

    service = AuditQueryService(_resolve_audit_path(args))
    page = service.query(flt, page=0, page_size=max(1, int(args.limit)))

    if args.as_json:
        payload = {
            "total_matches": page.total_matches,
            "summary": {
                "total": page.summary.total,
                "allowed": page.summary.allowed,
                "denied": page.summary.denied,
                "remote_exec": page.summary.remote_exec,
                "by_origin": page.summary.by_origin,
                "by_transport": page.summary.by_transport,
                "by_category": page.summary.by_category,
                "by_tool": page.summary.by_tool,
                "by_target": page.summary.by_target,
                "elapsed_ms": page.summary.elapsed_ms,
            },
            "entries": page.entries,
        }
        print(json.dumps(payload, indent=2))
        return 0

    if args.summary:
        print(format_summary_text(page.summary))
        if not page.entries:
            return 0
        print("")

    if not page.entries:
        print("No matching audit entries found.")
        return 0

    for entry in page.entries:
        print(format_access_line(entry))

    if page.total_matches > len(page.entries):
        print(
            f"\nShowing {len(page.entries)} of {page.total_matches} matching entries "
            f"(use --limit to show more)."
        )
    return 0

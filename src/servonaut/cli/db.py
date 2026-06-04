"""``servonaut db setup`` — interactive DB credential setup.

The deterministic, no-model-context companion to the ``db_setup_scan`` /
``db_setup_save`` MCP tools: it drives the same ``ServonautTools`` logic
(on-box read-only scan → secret store → db_profile) but the user picks the
candidate at the keyboard, so no secret or prompt ever transits an LLM.

Reuses ``ServonautTools`` directly so the scan/stage/save behaviour is
identical across the MCP, chat and CLI surfaces.
"""
from __future__ import annotations

import argparse
import asyncio
import logging

logger = logging.getLogger(__name__)


def add_db_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "db", help="Database tooling (credential setup for db_processlist etc.)",
    )
    sub = parser.add_subparsers(dest="db_command")
    setup = sub.add_parser(
        "setup",
        help="Discover and store DB credentials for an instance.",
    )
    setup.add_argument("instance", help="Instance name or ID.")
    setup.add_argument(
        "--search-path", default="",
        help="Directory on the box to search (or a local .env path).",
    )
    setup.add_argument(
        "--source", choices=["auto", "ssh", "local"], default="auto",
        help="Where to scan: auto/ssh read the box (default), local reads --search-path.",
    )


def handle_db_command(args: argparse.Namespace) -> int:
    if getattr(args, "db_command", None) != "setup":
        print("Usage: servonaut db setup <instance> [--search-path PATH] "
              "[--source auto|ssh|local]")
        return 1
    try:
        return asyncio.run(_run_setup(args))
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130


def _build_tools():
    """Construct a minimal ServonautTools for the CLI (user-authorized)."""
    from dataclasses import replace

    from servonaut.config.manager import ConfigManager
    from servonaut.services.cache_service import CacheService
    from servonaut.services.aws_service import AWSService
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.scp_service import SCPService
    from servonaut.mcp.guards import CommandGuard
    from servonaut.mcp.audit import AuditTrail
    from servonaut.mcp.tools import ServonautTools

    config_manager = ConfigManager()
    config = config_manager.get()
    cache_service = CacheService(ttl_seconds=config.cache_ttl_seconds)

    # The user is at the keyboard and explicitly ran this command, so the
    # guard must permit the standard-tier setup tools regardless of the MCP
    # guard_level configured for headless agents.
    guard = CommandGuard(replace(config.mcp, guard_level="dangerous"), config_manager)

    secret_provider = None
    try:
        from servonaut.services.auth_service import AuthService
        from servonaut.services.entitlement_guard import EntitlementGuard
        from servonaut.services.secret_provider_resolver import resolve_secret_provider
        auth = AuthService()
        secret_provider = resolve_secret_provider(auth, EntitlementGuard(auth))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Secret provider unavailable: %s", exc)

    return ServonautTools(
        config_manager=config_manager,
        aws_service=AWSService(cache_service),
        custom_server_service=CustomServerService(config_manager),
        cache_service=cache_service,
        ssh_service=SSHService(config_manager),
        connection_service=ConnectionService(config_manager),
        scp_service=SCPService(),
        guard=guard,
        audit=AuditTrail(config.mcp.audit_path),
        secret_provider=secret_provider,
    ), secret_provider


async def _run_setup(args: argparse.Namespace) -> int:
    tools, secret_provider = _build_tools()
    if secret_provider is None:
        print("No secret store is active. Run `servonaut login` first (the "
              "secret store is a Solo/Teams feature), then retry.")
        return 1

    print(f"Scanning {args.instance} for DB credentials (read-only)...")
    scan_out = await tools.db_setup_scan(
        args.instance, search_path=args.search_path, source=args.source,
    )
    print("\n" + scan_out)

    if "token=" not in scan_out:
        return 0  # nothing found / error already printed

    token = input("\nToken to save (blank to cancel): ").strip()
    if not token:
        print("Cancelled.")
        return 0

    confirm = input(
        f"Store credentials for '{args.instance}' from {token} into your "
        "secret store and write a db_profile? [y/N]: "
    ).strip().lower()
    if confirm not in ("y", "yes"):
        print("Cancelled.")
        return 0

    save_out = await tools.db_setup_save(token, instance_id=args.instance)
    print("\n" + save_out)
    return 0 if save_out.startswith("Saved") else 1

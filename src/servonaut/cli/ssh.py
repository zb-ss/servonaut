"""CLI subcommand handler for ``servonaut ssh <instance>``.

Resolves SSH credentials through the three-tier chain
(personal BW ref → team BW ref → local ~/.ssh) and opens an interactive
SSH session with the resolved key.

Registration:
    :func:`add_ssh_parser` is called from ``main.py`` once, passing the
    top-level ``subparsers`` action.  The corresponding dispatch line in
    ``main.py`` calls :func:`handle_ssh_command` and exits with the returned
    integer.

Non-goals (handled elsewhere):
    - ``servonaut servers ssh-ref set`` — BW ref CRUD
    - ``servonaut auth login`` / ``servonaut auth logout`` — auth flows
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
_EXIT_SUCCESS = 0
_EXIT_NOT_FOUND = 1
_EXIT_NO_CREDENTIAL = 2
_EXIT_BW_ERROR = 3
_EXIT_GENERIC_ERROR = 4
_EXIT_AMBIGUOUS = 5


# ---------------------------------------------------------------------------
# Async helper
# ---------------------------------------------------------------------------

def _run_async(coro: Any) -> Any:
    """Run *coro* synchronously via ``asyncio.run``."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------

def add_ssh_parser(subparsers: Any) -> None:
    """Register the ``servonaut ssh <instance>`` subcommand."""
    p = subparsers.add_parser(
        "ssh",
        help="Connect to a managed instance, resolving the SSH key from Bitwarden if configured.",
    )
    p.add_argument(
        "instance",
        help="Instance name or id (case-insensitive match).",
    )
    p.add_argument(
        "--user", "-u",
        default=None,
        help="Override SSH username (default: per-instance config).",
    )
    p.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Override SSH port (default: 22 or per-instance config).",
    )


# ---------------------------------------------------------------------------
# Headless service initialisation
# ---------------------------------------------------------------------------

def _init_headless_services() -> Tuple[Any, Any, Any, Any, Any, Any, Any]:
    """Construct the minimum service set needed for the ssh subcommand.

    Returns:
        ``(config, auth_service, api_client, bw_ssh_config_service,
        team_service, ssh_service, custom_server_service)``

    When the user is not logged in, ``api_client``, ``bw_ssh_config_service``,
    and ``team_service`` are returned as ``None``.  In that case only the local
    ``~/.ssh`` fallback is available.
    """
    from servonaut.config.manager import ConfigManager
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.auth_service import AuthService

    config_manager = ConfigManager()
    config = config_manager.get()
    ssh_service = SSHService(config_manager)
    custom_server_service = CustomServerService(config_manager)
    auth_service = AuthService()

    api_client = None
    bw_ssh_config_service = None
    team_service = None

    if auth_service.is_authenticated:
        try:
            from servonaut.services.api_client import APIClient
            from servonaut.services.bw_ssh_config_service import BwSshConfigService
            from servonaut.services.team_service import TeamService

            api_client = APIClient(auth_service)
            bw_ssh_config_service = BwSshConfigService(api_client)
            team_service = TeamService(api_client)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not initialise API-backed services: %s — only local ~/.ssh keys available.",
                exc,
            )
    else:
        logger.info("Not logged in — only local ~/.ssh keys available")

    return (
        config,
        auth_service,
        api_client,
        bw_ssh_config_service,
        team_service,
        ssh_service,
        custom_server_service,
    )


# ---------------------------------------------------------------------------
# Instance lookup
# ---------------------------------------------------------------------------

def _load_instances(
    custom_server_service: Any,
) -> List[Dict[str, Any]]:
    """Return merged list of cached AWS + custom instances."""
    instances: List[Dict[str, Any]] = []

    # AWS — load from disk cache (no network round-trip for the CLI)
    try:
        from servonaut.config.manager import ConfigManager
        from servonaut.services.cache_service import CacheService
        from servonaut.services.aws_service import AWSService

        _config_manager = ConfigManager()
        _config = _config_manager.get()
        _cache_service = CacheService(ttl_seconds=_config.cache_ttl_seconds)
        _aws_service = AWSService(_cache_service)
        cached = _aws_service._cache.load_any()
        if cached:
            instances.extend(cached)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load AWS cached instances: %s", exc)

    # Custom servers
    try:
        instances.extend(custom_server_service.list_as_instances())
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load custom server instances: %s", exc)

    return instances


def _find_instance(instances: List[Dict[str, Any]], search: str) -> List[Dict[str, Any]]:
    """Return all instances whose ``id`` or ``name`` match *search* (case-insensitive)."""
    needle = search.lower()
    return [
        inst for inst in instances
        if (inst.get("id") or "").lower() == needle
        or (inst.get("name") or "").lower() == needle
    ]


# ---------------------------------------------------------------------------
# Username resolution
# ---------------------------------------------------------------------------

def _resolve_username(args: Any, instance: Dict[str, Any], config: Any) -> str:
    """Resolve SSH username in priority order.

    Priority: args.user > instance username > config default_username > 'ubuntu'
    """
    if args.user:
        return args.user
    inst_username = instance.get("username")
    if inst_username:
        return inst_username
    config_default = getattr(config, "default_username", None)
    if config_default:
        return config_default
    return "ubuntu"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def handle_ssh_command(args: Any) -> int:
    """Entry point for ``servonaut ssh <instance>``.

    Returns an integer exit code suitable for ``sys.exit()``.
    """
    return _run_async(_handle_ssh_async(args))


async def _handle_ssh_async(args: Any) -> int:
    from servonaut.services.ssh_ref_resolver import SshRefResolver
    from servonaut.services.bw_resolver import (
        BwResolver,
        BwCliMissingError,
        BwSessionMissingError,
        BwItemNotFoundError,
        BwItemShapeError,
    )
    from servonaut.utils.ephemeral_key import cleanup_stale_bw_keys, ephemeral_ssh_key

    # Startup sweep for crash-left decrypted Bitwarden key files (>24 h old)
    # from ~/.servonaut/tmp/ — the abnormal-exit backstop shared by every
    # surface that materializes vault keys. Best-effort, never blocks connect.
    try:
        cleanup_stale_bw_keys()
    except Exception as exc:  # noqa: BLE001 — sweep must never break connect
        logger.debug("Stale BW key sweep failed: %s", exc)

    # --- Init services ---
    (
        config,
        auth_service,
        api_client,
        bw_ssh_config_service,
        team_service,
        ssh_service,
        custom_server_service,
    ) = _init_headless_services()

    # --- Load instances ---
    instances = _load_instances(custom_server_service)

    # --- Find instance ---
    matches = _find_instance(instances, args.instance)
    if not matches:
        print(
            f"No instance found matching {args.instance!r}. "
            "Run `servonaut servers list` to see available instances.",
            file=sys.stderr,
        )
        return _EXIT_NOT_FOUND

    if len(matches) > 1:
        print(
            f"Multiple instances match {args.instance!r}. Be more specific:",
            file=sys.stderr,
        )
        for i, inst in enumerate(matches, 1):
            iid = inst.get("id", "?")
            iname = inst.get("name", "?")
            print(f"  {i}. {iname} ({iid})", file=sys.stderr)
        return _EXIT_AMBIGUOUS

    instance = matches[0]
    iid = instance.get("id") or instance.get("name") or args.instance

    # --- Build resolver ---
    teams_supplier = None
    if team_service is not None and auth_service.is_authenticated:
        # Lazy loader — called at most once during resolve()
        _teams_cache: Optional[List[dict]] = None

        async def _load_teams_async() -> List[dict]:
            nonlocal _teams_cache
            if _teams_cache is None:
                try:
                    _teams_cache = await team_service.list_teams()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Could not load teams list: %s", exc)
                    _teams_cache = []
            return _teams_cache

        # teams_supplier must be synchronous (SshRefResolver contract)
        # We run it before constructing resolver and pass a frozen callable.
        _teams: List[dict] = []
        try:
            _teams = await _load_teams_async()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Team list fetch failed, skipping team tier: %s", exc)

        def _teams_supplier_fn() -> List[dict]:
            return _teams

        teams_supplier = _teams_supplier_fn

    resolver = SshRefResolver(
        bw_ssh_config_service=bw_ssh_config_service or _NullBwService(),
        team_service=team_service or _NullTeamService(),
        ssh_service=ssh_service,
        teams_supplier=teams_supplier,
    )

    # --- Resolve ---
    resolved = await resolver.resolve(instance)

    if resolved is None:
        print(
            f"No SSH key configured for {iid!r}. "
            "Add one with `servonaut servers ssh-ref set <id>` "
            "or place a key in ~/.ssh/.",
            file=sys.stderr,
        )
        return _EXIT_NO_CREDENTIAL

    # --- Determine host ---
    host = (
        instance.get("public_ip")
        or instance.get("private_ip")
        or instance.get("host")
        or iid
    )

    # --- Determine username ---
    username = _resolve_username(args, instance, config)

    # --- Determine port ---
    port = args.port or instance.get("port")

    # --- Build + run SSH ---
    if resolved.source in ("personal", "team"):
        if not resolved.item_id:
            print(
                f"BW ref for {iid!r} is missing item_id — the stored ref may be corrupt. "
                "Re-register with `servonaut servers ssh-ref set <id>`.",
                file=sys.stderr,
            )
            return _EXIT_BW_ERROR

        bw_resolver = BwResolver()
        try:
            key_body = bw_resolver.resolve_ssh_key(resolved.item_id)
        except BwCliMissingError as exc:
            print(
                f"Bitwarden CLI not found: {exc.message}\n"
                "Install it from https://bitwarden.com/help/cli/ and ensure it is on your PATH.",
                file=sys.stderr,
            )
            return _EXIT_BW_ERROR
        except BwSessionMissingError as exc:
            print(
                f"Bitwarden vault is locked: {exc.message}\n"
                "Run `bw unlock` and export the BW_SESSION environment variable, then retry.",
                file=sys.stderr,
            )
            return _EXIT_BW_ERROR
        except BwItemNotFoundError as exc:
            print(
                f"Bitwarden item not found: {exc.message}\n"
                "Verify the item UUID or re-register with `servonaut servers ssh-ref set <id>`.",
                file=sys.stderr,
            )
            return _EXIT_BW_ERROR
        except BwItemShapeError as exc:
            print(
                f"Bitwarden item has unexpected shape: {exc.message}\n"
                "Ensure it is a native SSH item (BW 2023.10+) with .sshKey.privateKey.",
                file=sys.stderr,
            )
            return _EXIT_BW_ERROR

        with ephemeral_ssh_key(key_body) as tmpfile:
            cmd = ssh_service.build_ssh_command(
                host=host,
                username=username,
                key_path=tmpfile,
                port=port,
            )
            logger.debug("Running SSH (BW key): %s", " ".join(cmd))
            result = subprocess.run(cmd)  # interactive — inherit stdin/stdout/stderr
            return result.returncode

    else:
        # source == "local"
        cmd = ssh_service.build_ssh_command(
            host=host,
            username=username,
            key_path=resolved.local_key_path,
            port=port,
        )
        logger.debug("Running SSH (local key): %s", " ".join(cmd))
        result = subprocess.run(cmd)
        return result.returncode


# ---------------------------------------------------------------------------
# Null object stubs used when API services are unavailable
# ---------------------------------------------------------------------------

class _NullBwService:
    """Drop-in for BwSshConfigService when not logged in.

    Every method that the resolver calls returns None immediately so the
    personal tier gracefully passes through to local fallback.
    """

    async def get_personal_instance_ref(
        self, provider: str, instance_id: str
    ) -> None:
        return None


class _NullTeamService:
    """Drop-in for TeamService when not logged in."""

    async def get_team_server_ssh_ref(
        self, slug: str, server_id: str
    ) -> None:
        return None

"""CLI subcommand handlers for ``servonaut servers``.

Currently exposes one action: ``servonaut servers verify <id>``

The verify flow probes whether the configured Bitwarden Password Manager SSH
key can actually SSH into a managed instance, then POSTs the outcome to the
server-side audit endpoint.  Three outcomes per the locked wire contract:

- ``verified``   — ``bw get item`` returns the key AND ``ssh -o BatchMode=yes``
                   connects successfully.
- ``not_found``  — ``bw get item`` reports the item does not exist in the vault.
- ``auth_failed``— ``bw get item`` returns the key but ``ssh`` exits non-zero.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

from servonaut.services.aws_service import AWSService
from servonaut.services.bw_resolver import (
    BwResolver,
    BwCliMissingError,
    BwSessionMissingError,
)
from servonaut.services.cache_service import CacheService
from servonaut.utils.ephemeral_key import ephemeral_ssh_key

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
_EXIT_SUCCESS = 0
_EXIT_VERIFY_FAILED = 1   # BW or SSH probe returned a non-verified status
_EXIT_FATAL = 2           # No ref stored / BW CLI missing / session locked / not logged in

# UUID-v4 regex for detecting team SharedServer ids.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Async wrapper
# ---------------------------------------------------------------------------

def _run_async(coro: Any) -> Any:
    """Run *coro* synchronously via ``asyncio.run``."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Headless service initialisation
# ---------------------------------------------------------------------------

def _init_headless_services() -> Tuple[Any, Any, Any, Any, Any, Any]:
    """Initialise services needed by ``servers verify``.

    Returns:
        ``(config_manager, auth_service, api_client,
           bw_ssh_config_service, team_service, custom_server_service)``
    """
    from servonaut.config.manager import ConfigManager
    from servonaut.services.auth_service import AuthService
    from servonaut.services.api_client import APIClient
    from servonaut.services.bw_ssh_config_service import BwSshConfigService
    from servonaut.services.team_service import TeamService
    from servonaut.services.custom_server_service import CustomServerService

    config_manager = ConfigManager()
    auth_service = AuthService()
    api_client = APIClient(auth_service)
    bw_ssh_config_service = BwSshConfigService(api_client)
    team_service = TeamService(api_client)
    custom_server_service = CustomServerService(config_manager)

    return (
        config_manager,
        auth_service,
        api_client,
        bw_ssh_config_service,
        team_service,
        custom_server_service,
    )


# ---------------------------------------------------------------------------
# Instance resolution helpers
# ---------------------------------------------------------------------------

def _load_all_instances(
    aws_service: Any,
    custom_server_service: Any,
) -> List[Dict[str, Any]]:
    """Return combined list of cached AWS + custom server instances."""
    instances: List[Dict[str, Any]] = []
    try:
        cached = aws_service._cache.load_any()
        if cached:
            instances.extend(cached)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load AWS cached instances: %s", exc)
    try:
        instances.extend(custom_server_service.list_as_instances())
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load custom server instances: %s", exc)
    return instances


def _find_instance(
    id_or_name: str,
    instances: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Case-insensitive match on ``id`` or ``name`` across the instance list."""
    needle = id_or_name.lower()
    for inst in instances:
        if str(inst.get("id", "")).lower() == needle:
            return inst
        if str(inst.get("name", "")).lower() == needle:
            return inst
    return None


# ---------------------------------------------------------------------------
# SSH probe
# ---------------------------------------------------------------------------

def _run_ssh_probe(
    key_path: str,
    user: str,
    host: str,
    port: Optional[int],
    timeout: int,
) -> int:
    """Run ``ssh -o BatchMode=yes ... true`` and return the exit code.

    Treats :class:`subprocess.TimeoutExpired` as a connection failure (returns
    255 — same as ssh's own timeout exit code — so the caller maps it to
    ``auth_failed`` without crashing).
    """
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", key_path,
        f"{user}@{host}",
        "true",
    ]
    if port is not None and port != 22:
        # Insert -p <port> right after "ssh"
        cmd[1:1] = ["-p", str(port)]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 5,
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        logger.debug("SSH probe timed out for %s@%s:%s", user, host, port)
        return 255


# ---------------------------------------------------------------------------
# Personal probe
# ---------------------------------------------------------------------------

async def _probe_personal(
    bw_ssh_cfg: Any,
    bw_resolver: Any,
    instance: Dict[str, Any],
    host: str,
    user: str,
    port: Optional[int],
    timeout: int,
) -> Optional[str]:
    """Probe personal instance.  Returns a status string or None if no ref stored.

    ``None`` means the caller should exit with a friendly "no ref stored" message
    rather than POSTing anything.

    Raises :class:`BwCliMissingError` or :class:`BwSessionMissingError` when
    the BW CLI is unusable — the caller handles these without POSTing.
    """
    from servonaut.services.bw_resolver import BwItemNotFoundError
    from servonaut.services.bw_ssh_config_service import (
        STATUS_VERIFIED,
        STATUS_NOT_FOUND,
        STATUS_AUTH_FAILED,
    )

    provider = instance.get("provider", "aws")
    instance_id = instance["id"]

    ref = await bw_ssh_cfg.get_personal_instance_ref(provider, instance_id)
    if ref is None:
        return None

    item_id = ref["ssh_credential_ref"]["item_id"]

    try:
        key_body = bw_resolver.resolve_ssh_key(item_id)
    except BwItemNotFoundError:
        return STATUS_NOT_FOUND
    except (BwCliMissingError, BwSessionMissingError):
        raise

    with ephemeral_ssh_key(key_body) as key_path:
        rc = _run_ssh_probe(key_path, user, host, port, timeout)

    return STATUS_VERIFIED if rc == 0 else STATUS_AUTH_FAILED


# ---------------------------------------------------------------------------
# Team probe
# ---------------------------------------------------------------------------

async def _probe_team(
    team_svc: Any,
    bw_resolver: Any,
    slug: str,
    server_id: str,
    host: str,
    user: str,
    port: Optional[int],
    timeout: int,
) -> str:
    """Probe a team SharedServer.  Always returns a status string.

    Raises :class:`BwCliMissingError` or :class:`BwSessionMissingError` for
    unusable BW CLI — caller handles without POSTing.
    """
    from servonaut.services.bw_resolver import BwItemNotFoundError
    from servonaut.services.bw_ssh_config_service import (
        STATUS_VERIFIED,
        STATUS_NOT_FOUND,
        STATUS_AUTH_FAILED,
    )

    ref = await team_svc.get_team_server_ssh_ref(slug, server_id)
    if ref is None:
        return None  # type: ignore[return-value]  # caller checks for None

    item_id = ref["ssh_credential_ref"]["item_id"]

    try:
        key_body = bw_resolver.resolve_ssh_key(item_id)
    except BwItemNotFoundError:
        return STATUS_NOT_FOUND
    except (BwCliMissingError, BwSessionMissingError):
        raise

    with ephemeral_ssh_key(key_body) as key_path:
        rc = _run_ssh_probe(key_path, user, host, port, timeout)

    return STATUS_VERIFIED if rc == 0 else STATUS_AUTH_FAILED


# ---------------------------------------------------------------------------
# Resolve connection details for an instance
# ---------------------------------------------------------------------------

def _resolve_host(instance: Dict[str, Any], host_override: Optional[str]) -> Optional[str]:
    """Return the effective target host. None if neither override nor IP are available."""
    if host_override:
        return host_override
    host = instance.get("public_ip") or instance.get("private_ip")
    return host or None


def _resolve_user(instance: Dict[str, Any], user_override: Optional[str]) -> str:
    """Return the effective SSH username."""
    if user_override:
        return user_override
    return instance.get("username") or "ec2-user"


# ---------------------------------------------------------------------------
# Main verify handler
# ---------------------------------------------------------------------------

async def _cmd_verify(args: Any) -> int:
    """Async body of ``servers verify``."""
    from servonaut import __version__
    from servonaut.services.bw_ssh_config_service import STATUS_VERIFIED

    checked_by_client = f"servonaut-cli/{__version__}"

    (
        config_manager,
        auth_service,
        api_client,
        bw_ssh_cfg,
        team_svc,
        custom_server_service,
    ) = _init_headless_services()

    if not auth_service.is_authenticated:
        print(
            "Not logged in. Run `servonaut --login` first.",
            file=sys.stderr,
        )
        return _EXIT_FATAL

    config = config_manager.get()
    cache_service = CacheService(ttl_seconds=config.cache_ttl_seconds)
    aws_service = AWSService(cache_service)

    instance_arg: str = args.instance
    host_override: Optional[str] = getattr(args, "host", None)
    user_override: Optional[str] = getattr(args, "user", None)
    port_override: Optional[int] = getattr(args, "port", None)
    timeout: int = getattr(args, "timeout", 5)

    bw_resolver = BwResolver()

    # ------------------------------------------------------------------
    # Resolution: personal first, then teams
    # ------------------------------------------------------------------

    # Determine whether this looks like a team SharedServer UUID.
    is_uuid = bool(_UUID_RE.match(instance_arg))

    personal_instance: Optional[Dict[str, Any]] = None
    team_slug: Optional[str] = None
    team_server_id: Optional[str] = None

    if not is_uuid:
        # Must be a personal instance id/name — look it up in cached lists.
        all_instances = _load_all_instances(aws_service, custom_server_service)
        personal_instance = _find_instance(instance_arg, all_instances)
        if personal_instance is None:
            print(
                f"Instance not found: {instance_arg!r}",
                file=sys.stderr,
            )
            return _EXIT_FATAL
    else:
        # UUID: try personal first (provider unknown — try each allowed provider).
        # Walk the instance list to find a matching entry; if found use its provider.
        all_instances = _load_all_instances(aws_service, custom_server_service)
        personal_instance = _find_instance(instance_arg, all_instances)

        if personal_instance is None:
            # Not in local cache by uuid — try team lookup.
            try:
                teams = await team_svc.list_teams()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not list teams: %s", exc)
                teams = []

            for team in teams:
                slug = team.get("slug") or team.get("team_slug", "")
                if not slug:
                    continue
                ref = await team_svc.get_team_server_ssh_ref(slug, instance_arg)
                if ref is not None:
                    team_slug = slug
                    team_server_id = instance_arg
                    break

    # ------------------------------------------------------------------
    # Determine host/user for the probe
    # ------------------------------------------------------------------

    if personal_instance is not None:
        host = _resolve_host(personal_instance, host_override)
        user = _resolve_user(personal_instance, user_override)
        port = port_override
        label = (
            f"{personal_instance.get('name') or personal_instance.get('id')} "
            f"({personal_instance.get('provider', 'unknown')}/{personal_instance.get('id')})"
        )
    elif team_slug is not None:
        host = host_override
        user = user_override or "root"
        port = port_override
        label = f"team:{team_slug}/{team_server_id}"
    else:
        # UUID not in any local cache and not in any team — no ref stored.
        print(
            f"No SSH ref stored for instance {instance_arg!r}. "
            "Run `servonaut bw link` to register a Bitwarden item ref first.",
            file=sys.stderr,
        )
        return _EXIT_FATAL

    if host is None:
        print(
            f"No target host available for {instance_arg!r}. "
            "Pass --host to override.",
            file=sys.stderr,
        )
        return _EXIT_FATAL

    # ------------------------------------------------------------------
    # Run the appropriate probe
    # ------------------------------------------------------------------

    status: Optional[str] = None

    try:
        if personal_instance is not None:
            status = await _probe_personal(
                bw_ssh_cfg, bw_resolver,
                personal_instance, host, user, port, timeout,
            )
            if status is None:
                print(
                    f"No SSH ref stored for {label}. "
                    "Run `servonaut bw link` to register a Bitwarden item ref first.",
                    file=sys.stderr,
                )
                return _EXIT_FATAL
            # POST result
            provider = personal_instance.get("provider", "aws")
            instance_id = personal_instance["id"]
            await bw_ssh_cfg.report_personal_instance_verify(
                provider, instance_id, status,
                checked_by_client=checked_by_client,
            )
        else:
            # Team path
            status = await _probe_team(
                team_svc, bw_resolver,
                team_slug, team_server_id,  # type: ignore[arg-type]
                host, user, port, timeout,
            )
            if status is None:
                print(
                    f"No SSH ref stored for {label}. "
                    "Run `servonaut bw link` to register a Bitwarden item ref first.",
                    file=sys.stderr,
                )
                return _EXIT_FATAL
            await team_svc.report_team_server_ssh_verify(
                team_slug, team_server_id,  # type: ignore[arg-type]
                status,
                checked_by_client=checked_by_client,
            )

    except BwCliMissingError as exc:
        print(
            f"Bitwarden CLI not found: {exc.message}",
            file=sys.stderr,
        )
        return _EXIT_FATAL
    except BwSessionMissingError as exc:
        print(
            f"Bitwarden vault is locked: {exc.message}\n"
            "Run `bw unlock` and export BW_SESSION, then retry.",
            file=sys.stderr,
        )
        return _EXIT_FATAL

    # ------------------------------------------------------------------
    # Human-readable summary
    # ------------------------------------------------------------------

    if status == STATUS_VERIFIED:
        print(f"[OK] Verified: {label}")
        return _EXIT_SUCCESS
    else:
        print(f"[FAIL] {status}: {label}")
        return _EXIT_VERIFY_FAILED


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------

def add_servers_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``servers`` subcommand group with a ``verify`` action."""
    servers = subparsers.add_parser("servers", help="Manage servers and SSH access.")
    servers_sub = servers.add_subparsers(dest="servers_command")

    verify = servers_sub.add_parser(
        "verify",
        help="Probe whether the configured BW SSH key actually opens this server.",
    )
    verify.add_argument("instance", help="Instance id or name.")
    verify.add_argument(
        "--host",
        default=None,
        help="Override target host (default: instance.public_ip or private_ip).",
    )
    verify.add_argument(
        "--user", "-u",
        default=None,
        help="Override SSH username.",
    )
    verify.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Override SSH port.",
    )
    verify.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="SSH connection timeout in seconds (default: 5).",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def handle_servers_command(args: Any) -> int:
    """Dispatch ``servers`` sub-subcommands.  Returns an integer exit code."""
    servers_command = getattr(args, "servers_command", None)
    if servers_command is None:
        print(
            "Error: specify a servers subcommand. Use --help for usage.",
            file=sys.stderr,
        )
        return _EXIT_FATAL

    if servers_command == "verify":
        return _run_async(_cmd_verify(args))

    print(
        f"Error: unknown servers subcommand {servers_command!r}",
        file=sys.stderr,
    )
    return _EXIT_FATAL

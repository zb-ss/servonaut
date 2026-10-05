"""CLI subcommand handler for ``servonaut ssh <instance> [-- <command>...]``.

Resolves SSH credentials through the native chain
(CA → native vault → personal BW → team BW → local ~/.ssh) and opens an interactive
SSH session with the resolved key, or runs a remote command and exits with
its status when one follows the instance.

Registration:
    :func:`add_ssh_parser` is called from ``main.py`` once, passing the
    top-level ``subparsers`` action.  The corresponding dispatch line in
    ``main.py`` calls :func:`handle_ssh_command` and exits with the returned
    integer.

Non-goals (handled elsewhere):
    - BW ref CRUD — the TUI's SSH Ref editor (instance list, ``k``)
    - ``servonaut login`` / ``servonaut logout`` — auth flows
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from servonaut.services.connection_service import (
    ConnectionService,
    profile_route,
    rule_username,
)
from servonaut.utils.instance_resolver import describe_candidate, match_instances

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

# There is no CLI command for assigning a Bitwarden SSH key to a server; the
# TUI's instance list has an editor for it on the ``k`` key.
_ASSIGN_KEY_HINT = "in the Servonaut TUI (run `servonaut`, select the server, press k)"
_RESOLUTION_TIERS = frozenset({"ca", "vault", "personal", "team", "local"})
_PERSONAL_PROVIDERS = frozenset({"aws", "ovh", "hetzner"})


# ---------------------------------------------------------------------------
# Async helper
# ---------------------------------------------------------------------------

def _run_async(coro: Any) -> Any:
    """Run *coro* synchronously via ``asyncio.run``."""
    return asyncio.run(coro)


async def _report_successful_ssh(
    instance: Dict[str, Any],
    resolution_tier: str,
    bw_ssh_config_service: Any,
    team_service: Any,
) -> None:
    """Best-effort audit of a completed, successful CLI SSH connection."""
    if resolution_tier not in _RESOLUTION_TIERS:
        return
    try:
        from servonaut import __version__

        checked_by_client = f"servonaut-cli/{__version__}"
        if instance.get("is_shared") is True:
            slug = instance.get("team_slug")
            server_id = instance.get("shared_server_id") or instance.get("id")
            report = getattr(team_service, "report_team_server_ssh_verify", None)
            if (
                isinstance(slug, str)
                and slug
                and isinstance(server_id, str)
                and server_id
                and callable(report)
            ):
                await report(
                    slug, server_id, "verified",
                    checked_by_client=checked_by_client,
                    resolution_tier=resolution_tier,
                )
            return

        provider = str(instance.get("provider", "aws") or "aws").lower()
        instance_id = instance.get("id")
        report = getattr(bw_ssh_config_service, "report_personal_instance_verify", None)
        if (
            provider in _PERSONAL_PROVIDERS
            and isinstance(instance_id, str)
            and instance_id
            and callable(report)
        ):
            await report(
                provider, instance_id, "verified",
                checked_by_client=checked_by_client,
                resolution_tier=resolution_tier,
            )
    except Exception as exc:  # Reporting must not change an SSH exit result.
        logger.debug("SSH verification reporting failed: %s", type(exc).__name__)


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------

class _RemoteCommandParser(argparse.ArgumentParser):
    """``ssh`` sub-parser that hands everything after a bare ``--`` to the remote.

    argparse's own ``--`` handling differs between Python releases: 3.10 and
    3.11 reject ``ssh web-1 --user root -- uname -a`` and drop every ``--``
    inside the command. Splitting before argparse sees the tokens keeps the
    remote command verbatim on every supported version.
    """

    def parse_known_args(  # type: ignore[override]
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
    ) -> Tuple[argparse.Namespace, List[str]]:
        tokens = list(sys.argv[1:] if args is None else args)
        trailing: List[str] = []
        if "--" in tokens:
            cut = tokens.index("--")
            tokens, trailing = tokens[:cut], tokens[cut + 1:]
        parsed, extras = super().parse_known_args(tokens, namespace)
        parsed.remote_command = list(getattr(parsed, "remote_command", None) or []) + trailing
        return parsed, extras


def add_ssh_parser(subparsers: Any) -> None:
    """Register the ``servonaut ssh <instance> [-- <command>...]`` subcommand."""
    p = subparsers.add_parser(
        "ssh",
        help="Connect to a managed instance, resolving the SSH key from Bitwarden if configured.",
        description=(
            "Open an interactive SSH session, or run COMMAND on the instance "
            "and exit with its status. Put the command after `--` so its own "
            "flags are not read as servonaut options."
        ),
    )
    # argparse has no per-subparser class hook; the subclass only overrides
    # parse_known_args, so re-classing the fresh instance is layout-safe.
    p.__class__ = _RemoteCommandParser
    p.add_argument(
        "instance",
        help=(
            "Instance name or id (case-insensitive match); "
            "<account>/<name> picks the server of one provider account."
        ),
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
    p.add_argument(
        "remote_command",
        nargs="*",
        metavar="COMMAND",
        help=(
            "Command to run on the instance instead of an interactive shell. "
            "Put it after `--` when it has its own flags: "
            "servonaut ssh web-1 -- uname -a"
        ),
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

async def _load_instances(
    custom_server_service: Any,
    config: Any,
    reference: str,
) -> List[Dict[str, Any]]:
    """Every server *reference* could mean is among these rows.

    Every account's cached servers (AWS, OVH, Hetzner) and the custom ones,
    plus each account never listed on this machine, read once (see
    ``CachedFleet.checked_rows``). An account whose servers could not be
    checked gets a note on stderr.
    """
    from servonaut.services.accounts.headless import CachedFleet

    checked = await CachedFleet.from_config(config, custom_server_service).checked_rows(reference)
    for note in checked.notes:
        print(note, file=sys.stderr)
    return checked.rows


async def _load_shared_instances(team_service: Any, teams: List[dict]) -> List[Dict[str, Any]]:
    """Load shared-server rows before matching a CLI SSH target.

    Shared inventory is not part of :class:`CachedFleet`; loading it here
    carries its signed ``credential_binding`` into native Vault resolution.
    A failed team inventory request must not hide rows from another team or
    prevent ordinary local inventory from remaining usable.
    """
    rows: List[Dict[str, Any]] = []
    for team in teams:
        slug = team.get("slug") if isinstance(team, dict) else None
        if not isinstance(slug, str) or not slug:
            continue
        try:
            shared_rows = await team_service.list_shared_servers(slug)
        except Exception as exc:  # noqa: BLE001 — another team may still load
            logger.warning("Could not load shared servers for %s: %s", slug, exc)
            continue
        rows.extend(row for row in shared_rows if isinstance(row, dict))
    return rows


def _find_instance(instances: List[Dict[str, Any]], search: str) -> List[Dict[str, Any]]:
    """Return every instance *search* could mean (id, name or ``<account>/<name>``)."""
    return match_instances(search, instances)


# ---------------------------------------------------------------------------
# Username resolution
# ---------------------------------------------------------------------------

def _resolve_username(
    args: Any, instance: Dict[str, Any], config: Any, profile: Any = None,
) -> str:
    """Resolve SSH username in priority order.

    Priority: args.user > the matching connection rule's username (not for
    a custom server) > instance username > config default_username > 'ubuntu'
    """
    if args.user:
        return args.user
    profile_username = rule_username(instance, profile)
    if profile_username:
        return profile_username
    inst_username = instance.get("username")
    if inst_username:
        return inst_username
    config_default = getattr(config, "default_username", None)
    if config_default:
        return config_default
    return "ubuntu"


def _remote_command_string(args: Any) -> Optional[str]:
    """Join the words after the instance into one remote command, or ``None``.

    OpenSSH joins its trailing arguments with single spaces and hands the
    result to the remote shell; doing the same keeps ``servonaut ssh web-1
    -- <cmd>`` behaving exactly like ``ssh host <cmd>``.
    """
    words = getattr(args, "remote_command", None) or []
    command = " ".join(words)
    return command if command.strip() else None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def handle_ssh_command(args: Any) -> int:
    """Entry point for ``servonaut ssh <instance>``.

    Returns an integer exit code suitable for ``sys.exit()``.
    """
    return _run_async(_handle_ssh_async(args))


async def _handle_ssh_async(args: Any) -> int:
    from servonaut.services.accounts import UnknownAccountError
    from servonaut.services.accounts.headless import (
        check_configured_reference,
        with_ovh_login,
    )
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

    # --- Find instance ---
    try:
        check_configured_reference(config, args.instance)
    except UnknownAccountError as exc:
        # "<account>/<name>" where that account cannot connect: say why.
        print(str(exc), file=sys.stderr)
        return _EXIT_NOT_FOUND
    instances = await _load_instances(custom_server_service, config, args.instance)

    # Shared rows hold the team binding itself. They must be visible before
    # target matching so a CLI invocation can reach the CA/native-vault tier.
    teams: List[dict] = []
    if team_service is not None and auth_service.is_authenticated:
        try:
            loaded_teams = await team_service.list_teams()
            teams = [team for team in loaded_teams if isinstance(team, dict)]
            instances.extend(await _load_shared_instances(team_service, teams))
        except Exception as exc:  # noqa: BLE001 — preserve local discovery
            logger.warning("Could not load shared server inventory: %s", exc)
    matches = _find_instance(instances, args.instance)
    if not matches:
        print(
            f"No instance found matching {args.instance!r}. "
            "Run `servonaut` to see the available instances.",
            file=sys.stderr,
        )
        return _EXIT_NOT_FOUND

    if len(matches) > 1:
        print(
            f"Multiple instances match {args.instance!r}. Use one of these references:",
            file=sys.stderr,
        )
        for i, inst in enumerate(matches, 1):
            print(f"  {i}. {describe_candidate(inst, matches)}", file=sys.stderr)
        return _EXIT_AMBIGUOUS

    instance = with_ovh_login(matches[0], config)
    iid = instance.get("id") or instance.get("name") or args.instance

    # --- Build resolver ---
    teams_supplier = None
    if team_service is not None and auth_service.is_authenticated:
        def _teams_supplier_fn() -> List[dict]:
            return teams

        teams_supplier = _teams_supplier_fn

    resolver = SshRefResolver(
        bw_ssh_config_service=bw_ssh_config_service or _NullBwService(),
        team_service=team_service or _NullTeamService(),
        ssh_service=ssh_service,
        teams_supplier=teams_supplier,
        vault_runtime=_vault_runtime_for_cli(),
    )

    # --- Resolve ---
    try:
        resolved = await resolver.resolve(instance)
    except Exception as exc:  # A configured native binding must fail closed.
        logger.warning("Native Vault SSH resolution failed: %s", type(exc).__name__)
        from servonaut.services.vault.errors import vault_failure_reason

        print(
            f"The configured Vault SSH credential could not be used ({vault_failure_reason(exc)}).",
            file=sys.stderr,
        )
        return _EXIT_GENERIC_ERROR

    if resolved is None:
        print(
            f"No SSH key configured for {iid!r}. "
            f"Assign a Bitwarden SSH key {_ASSIGN_KEY_HINT}, "
            "or place a key in ~/.ssh/.",
            file=sys.stderr,
        )
        return _EXIT_NO_CREDENTIAL

    print(f"SSH resolution tier: {resolved.source}", file=sys.stderr)
    if resolved.source == "local":
        print(
            "Notice: using the local ~/.ssh fallback; no managed credential was selected.",
            file=sys.stderr,
        )

    # --- Route: the matching connection rule, as the TUI and MCP apply it ---
    # Through a bastion the target is the private address, reached by a
    # proxy hop; the extra options pin a cloud instance by its host-key
    # alias, then add the profile's and the server's own.
    route = profile_route(instance, ConnectionService.for_config(config))
    host = route["host"] or instance.get("host") or instance.get("hostname") or iid

    # --- Determine username ---
    username = (
        args.user
        or resolved.login_user
        or _resolve_username(args, instance, config, route["profile"])
    )

    # --- Determine port ---
    port = args.port or instance.get("port")

    # --- Remote command (None = interactive shell) ---
    remote_command = _remote_command_string(args)

    # --- Build + run SSH ---
    if resolved.source in ("ca", "vault"):
        if (
            resolved.lease is None
            or not resolved.identity_agent
            or not resolved.identity_file
            or not resolved.known_hosts_path
        ):
            print("The configured Vault SSH credential is incomplete.", file=sys.stderr)
            return _EXIT_GENERIC_ERROR
        # Connect exactly where the pinned known_hosts entry points.
        host = getattr(resolved.lease, "target_host", None) or host
        port = getattr(resolved.lease, "target_port", None) or port
        try:
            proxy_args = route["proxy_args"]
            if route["profile"]:
                proxy_args = ConnectionService.for_config(config).get_proxy_args(
                    route["profile"], identity_agent=resolved.identity_agent
                )
            cmd = ssh_service.build_ssh_command(
                host=host,
                username=username,
                proxy_args=proxy_args,
                port=port,
                remote_command=remote_command,
                extra_options=route["extra_options"],
                identity_agent=resolved.identity_agent,
                identity_file=resolved.identity_file,
                certificate_file=resolved.certificate_path,
                known_hosts_file=resolved.known_hosts_path,
            )
            logger.debug("Running SSH (%s credential): %s", resolved.source, " ".join(cmd))
            result = subprocess.run(cmd).returncode
            if result == _EXIT_SUCCESS:
                await _report_successful_ssh(
                    instance, resolved.source, bw_ssh_config_service, team_service,
                )
            return result
        finally:
            close = getattr(resolved.lease, "close", None)
            if callable(close):
                close()

    if resolved.source in ("personal", "team"):
        if not resolved.item_id:
            print(
                f"BW ref for {iid!r} is missing item_id — the stored ref may be corrupt. "
                f"Re-assign the key {_ASSIGN_KEY_HINT}.",
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
                f"Verify the item UUID or re-assign the key {_ASSIGN_KEY_HINT}.",
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
                proxy_args=route["proxy_args"],
                port=port,
                remote_command=remote_command,
                extra_options=route["extra_options"],
            )
            logger.debug("Running SSH (BW key): %s", " ".join(cmd))
            # Inherit stdin/stdout/stderr: interactive shells, piped stdin and
            # a remote command's output all pass straight through.
            result = subprocess.run(cmd)
            if result.returncode == _EXIT_SUCCESS:
                await _report_successful_ssh(
                    instance, resolved.source, bw_ssh_config_service, team_service,
                )
            return result.returncode

    else:
        # source == "local"
        cmd = ssh_service.build_ssh_command(
            host=host,
            username=username,
            key_path=resolved.local_key_path,
            proxy_args=route["proxy_args"],
            port=port,
            remote_command=remote_command,
            extra_options=route["extra_options"],
        )
        logger.debug("Running SSH (local key): %s", " ".join(cmd))
        result = subprocess.run(cmd)
        if result.returncode == _EXIT_SUCCESS:
            await _report_successful_ssh(
                instance, resolved.source, bw_ssh_config_service, team_service,
            )
        return result.returncode


def _vault_runtime_for_cli() -> Any:
    """Build the optional native-Vault boundary for headless SSH."""
    try:
        from servonaut.services.vault.command_service import VaultCommandService

        return VaultCommandService.from_local_session()
    except Exception as exc:  # Logged-out and older server compatibility.
        logger.debug("Native Vault runtime is unavailable in the CLI: %s", type(exc).__name__)
        return None


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

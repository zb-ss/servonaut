"""Headless commands for SSH certificate authority administration."""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Any, Optional

from servonaut.services.api_client import APIError
from servonaut.services.vault.display import terminal_safe
from servonaut.services.vault.errors import vault_failure_reason

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_USAGE = 2
_EXIT_ABORTED = 5
CaServiceFactory = Callable[[], Any]
_service_factory: Optional[CaServiceFactory] = None


def set_ca_service_factory(factory: Optional[CaServiceFactory]) -> None:
    global _service_factory
    _service_factory = factory


def is_ca_command(args: argparse.Namespace) -> bool:
    return getattr(args, "subcommand", None) == "ca"


def add_ca_parser(subparsers: Any) -> None:
    ca = subparsers.add_parser("ca", help="Manage team SSH certificate authority access.")
    commands = ca.add_subparsers(dest="ca_command")
    commands.required = True
    enable = commands.add_parser("enable", help="Enable the SSH CA for a team.")
    enable.add_argument("--team", required=True)
    enable.add_argument("--yes", action="store_true")
    status = commands.add_parser("status", help="Show CA status and pins.")
    status.add_argument("--team", required=True)
    policy = commands.add_parser("policy", help="Show or update CA policy JSON.")
    policy.add_argument("--team", required=True)
    policy.add_argument("--set", dest="policy_json", default=None, help="Policy JSON object.")
    enroll = commands.add_parser("enroll", help="Create and execute a host enrollment job.")
    enroll.add_argument("server")
    enroll.add_argument("--team", required=True)
    enroll.add_argument("--break-glass-item", default=None)
    refresh = commands.add_parser("refresh", help="Refresh an enrolled host certificate.")
    refresh.add_argument("server")
    refresh.add_argument("--team", required=True)
    refresh.add_argument("--yes", action="store_true")
    unenroll = commands.add_parser("unenroll", help="Remove managed CA configuration from a host.")
    unenroll.add_argument("server")
    unenroll.add_argument("--team", required=True)
    unenroll.add_argument("--yes", action="store_true")
    krl = commands.add_parser("krl", help="Fetch and deliver the current revocation list.")
    krl.add_argument("--team", required=True)
    krl.add_argument("--server", action="append", default=[])
    scan = commands.add_parser(
        "break-glass-scan",
        help="Read enrolled hosts' SSH logs for break-glass logins and report new ones.",
    )
    scan.add_argument("--team", required=True)
    scan.add_argument("--server", action="append", default=[], help="Limit to this server; repeat for each.")
    scan.add_argument("--hours", type=int, default=24, help="How far back to look (1-720, default 24).")
    revoke = commands.add_parser("revoke", help="Revoke one issued certificate by its serial.")
    revoke.add_argument("serial", type=int)
    revoke.add_argument("--team", required=True)
    revoke.add_argument("--note", default=None, help="Reason recorded with the revocation.")
    revoke.add_argument("--yes", action="store_true")
    audit = commands.add_parser("audit", help="Verify the CA issuance audit chain.")
    audit.add_argument("--team", required=True)
    jobs = commands.add_parser(
        "jobs", help="List SSH certificate jobs waiting for you to carry them out, such as a rollover's refreshes.",
    )
    jobs.add_argument("--team", required=True)
    trust = commands.add_parser(
        "trust", help="Accept the team's changed SSH CA after comparing its fingerprints.",
    )
    trust.add_argument("--team", required=True)
    ca.add_argument("--json", action="store_true", help="Emit metadata JSON.")
    _add_json_to_subcommands(ca)


def _add_json_to_subcommands(parser: argparse.ArgumentParser) -> None:
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for child in action.choices.values():
            if "--json" not in child._option_string_actions:
                child.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
            _add_json_to_subcommands(child)


def _run(coro: Awaitable[Any]) -> Any:
    return asyncio.run(coro)


def _default_services() -> Any:
    from servonaut.services.vault.command_service import VaultCommandService
    return VaultCommandService.from_local_session()


async def _invoke(services: Any, method: str, /, **kwargs: Any) -> Any:
    target = getattr(services, method, None)
    if target is None and isinstance(services, Mapping):
        target = services.get(method)
    if target is None:
        raise RuntimeError(f"CA command service does not provide {method}().")
    value = target(**kwargs)
    return await value if hasattr(value, "__await__") else value


def _plain(value: Any) -> Any:
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    return value


def _print(value: Any, as_json: bool) -> None:
    payload = _plain(value)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    elif isinstance(payload, Mapping):
        for key, item in _flatten(payload):
            print(f"{key}: {item}")
    else:
        print(payload)


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Dotted ``key: value`` rows, so nested policy and host data are shown too."""
    if isinstance(value, Mapping):
        rows: list[tuple[str, Any]] = []
        for key, item in value.items():
            rows.extend(_flatten(item, f"{prefix}{key}."))
        return rows if rows or not prefix else [(prefix[:-1], "{}")]
    if isinstance(value, list):
        if not value:
            return [(prefix[:-1], "[]")] if prefix else []
        rows = []
        for index, item in enumerate(value, start=1):
            rows.extend(_flatten(item, f"{prefix}{index}."))
        return rows
    return [(prefix[:-1], value)]


def _confirm(args: argparse.Namespace, action: str) -> bool:
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        print(f"Refusing in a non-interactive shell without --yes: {action}", file=sys.stderr)
        return False
    return input(f"{action} [y/N] ").strip().lower() in {"y", "yes"}


async def _handle(args: argparse.Namespace) -> int:
    if args.ca_command == "break-glass-scan" and not 1 <= args.hours <= 720:
        print("Error: --hours must be between 1 and 720.", file=sys.stderr)
        return _EXIT_USAGE
    if args.ca_command == "revoke" and args.serial < 1:
        print("Error: the serial must be a positive number.", file=sys.stderr)
        return _EXIT_USAGE
    try:
        services = (_service_factory or _default_services)()
        if args.ca_command == "enable":
            if not _confirm(args, "Enable SSH CA issuance for this team"):
                return _EXIT_ABORTED
            value = await _invoke(services, "ca_enable", team=args.team)
        elif args.ca_command == "status":
            value = await _invoke(services, "ca_status", team=args.team)
        elif args.ca_command == "policy":
            policy = None
            if args.policy_json is not None:
                parsed = json.loads(args.policy_json)
                if not isinstance(parsed, dict):
                    raise ValueError("--set must be a JSON object.")
                policy = parsed
            value = await _invoke(services, "ca_policy", team=args.team, policy=policy)
        elif args.ca_command in {"enroll", "refresh", "unenroll"}:
            if not sys.stdin.isatty():
                # Checked before any job exists: the host name has to be typed.
                print(
                    f"Refusing in a non-interactive shell: an SSH certificate {args.ca_command} "
                    "needs the host name typed to confirm it.",
                    file=sys.stderr,
                )
                return _EXIT_ABORTED
            if args.ca_command == "enroll":
                value = await _invoke(
                    services,
                    "ca_enroll",
                    team=args.team,
                    server=args.server,
                    break_glass_item_id=args.break_glass_item,
                    confirmation=_confirm_hostname,
                )
            else:
                if not _confirm(args, f"{args.ca_command.title()} CA access for {args.server}"):
                    return _EXIT_ABORTED
                value = await _invoke(
                    services, f"ca_{args.ca_command}", team=args.team, server=args.server,
                    confirmation=_confirm_hostname,
                )
            outcome = _job_outcome(value)
            if outcome != "succeeded":
                _print(value, bool(args.json))
                consequence = (
                    "the host keeps its previous setup" if outcome == "rolled_back" else
                    "the host may be partly changed; check its SSH configuration (sshd -t) before you rely on it"
                )
                print(f"The {args.ca_command} did not complete ({outcome}); {consequence}.", file=sys.stderr)
                return _EXIT_ERROR
            if isinstance(value, Mapping) and value.get("resumed") is True:
                print(f"Carried out the {args.ca_command} job that was waiting for this server.", file=sys.stderr)
        elif args.ca_command == "krl":
            value = await _invoke(services, "ca_deliver_krl", team=args.team, servers=args.server)
        elif args.ca_command == "break-glass-scan":
            value = await _invoke(
                services, "ca_break_glass_scan", team=args.team, servers=args.server or None, since_hours=args.hours,
            )
        elif args.ca_command == "revoke":
            if not _confirm(args, f"Revoke certificate serial {args.serial} for team {args.team}"):
                return _EXIT_ABORTED
            value = await _invoke(services, "ca_revoke", team=args.team, serial=args.serial, note=args.note)
            print(
                f"Enrolled hosts refuse it once the revocation list is delivered: "
                f"servonaut ca krl --team {args.team}",
                file=sys.stderr,
            )
        elif args.ca_command == "audit":
            value = await _invoke(services, "ca_audit", team=args.team)
        elif args.ca_command == "jobs":
            value = await _invoke(services, "ca_jobs", team=args.team)
            if not args.json:
                _print_jobs(value)
                return _EXIT_OK
        elif args.ca_command == "trust":
            value = await _invoke(services, "ca_trust", team=args.team, confirmation=_confirm_trust)
            if isinstance(value, Mapping) and value.get("declined") is True:
                print("Nothing changed.", file=sys.stderr)
                return _EXIT_ABORTED
        else:
            raise ValueError(f"Unknown CA command: {args.ca_command}")
        _print(value, bool(args.json))
    except APIError as exc:
        print(f"CA request failed ({vault_failure_reason(exc)}).", file=sys.stderr)
        return _EXIT_ERROR
    except Exception as exc:
        print(f"CA operation failed ({vault_failure_reason(exc)}).", file=sys.stderr)
        return _EXIT_ERROR
    return _EXIT_OK


def handle_ca_command(args: argparse.Namespace) -> int:
    return _run(_handle(args))


def _job_outcome(value: Any) -> str:
    result = value.get("result") if isinstance(value, Mapping) else None
    status = result.get("status") if isinstance(result, Mapping) else None
    return status if isinstance(status, str) and status else "unknown"


def _print_jobs(value: Any) -> None:
    jobs = value.get("jobs") if isinstance(value, Mapping) else None
    if not jobs:
        print("No SSH certificate jobs are waiting for you in this team.")
        return
    for job in jobs:
        print(f"{job['kind']} {job['server']}: run `{job['command']}`")


def _confirm_trust(summary: Mapping[str, Any]) -> bool:
    """A person compares the pinned and presented CA fingerprints, then decides.

    There is deliberately no ``--yes``: a changed CA must be checked by a human,
    and a changed host CA needs part of its new fingerprint typed back.
    """
    if not sys.stdin.isatty():
        print("Refusing in a non-interactive shell: trusting a changed SSH CA needs a person.", file=sys.stderr)
        return False
    pinned = summary.get("pinned") if isinstance(summary.get("pinned"), Mapping) else {}
    presented = summary.get("presented") if isinstance(summary.get("presented"), Mapping) else {}
    for label, key in (("User CA", "user_ca_fingerprint"), ("Host CA", "host_ca_fingerprint")):
        print(f"{label}: pinned {pinned.get(key) or 'none'}", file=sys.stderr)
        print(f"{' ' * len(label)}  now    {presented.get(key)}", file=sys.stderr)
    print(
        "Compare these with the User CA and Host CA fingerprints on the team's SSH access page "
        "in the web app before you continue.",
        file=sys.stderr,
    )
    if summary.get("host_ca_changed") is True:
        expected = str(presented.get("host_ca_fingerprint") or "")[-8:]
        print(
            "The HOST CA changed. Servers prove who they are with it, so only accept this if the team "
            "owner confirms the change outside Servonaut.",
            file=sys.stderr,
        )
        print("Type the last 8 characters of the new host CA fingerprint: ", end="", file=sys.stderr, flush=True)
        return bool(expected) and sys.stdin.readline().strip() == expected
    print(f"Trust this SSH CA for team {summary.get('team')}? [y/N] ", end="", file=sys.stderr, flush=True)
    return sys.stdin.readline().strip().lower() in {"y", "yes"}


def _confirm_hostname(summary: Mapping[str, Any]) -> str:
    """Require typed hostname after the service fetched verified enrollment data."""
    hostname = str(summary.get("hostname") or "")
    if not hostname or not sys.stdin.isatty():
        return ""
    params = summary.get("params")
    params = params if isinstance(params, Mapping) else {}
    server = params.get("server") if isinstance(params.get("server"), Mapping) else {}
    user_cas = params.get("user_ca_public_keys") or []
    host_ca = params.get("host_ca_public_key") or ""
    principals = params.get("principals_by_login") if isinstance(params.get("principals_by_login"), Mapping) else {}
    break_glass = params.get("break_glass") if isinstance(params.get("break_glass"), Mapping) else None
    roles = summary.get("user_ca_roles") if isinstance(summary.get("user_ca_roles"), Mapping) else {}
    print(f"SSH certificate job: {terminal_safe(summary.get('kind') or params.get('kind') or 'enroll')}")
    print(f"Enrollment target: {terminal_safe(hostname)}")
    print("User CA fingerprints:")
    for key in user_cas:
        fingerprint = _fingerprint_line(str(key))
        role = roles.get(fingerprint)
        print(f"  {fingerprint}" + (f"  ({role})" if role else "  (not a known team CA)"))
    print(f"Host CA fingerprint: {_fingerprint_line(str(host_ca))}")
    print("Login principals:")
    for login, values in principals.items():
        print(f"  {terminal_safe(login)}: {', '.join(terminal_safe(value) for value in values)}")
    from servonaut.services.vault.ca_enrollment import BREAK_GLASS_AUTHORIZED_KEYS, MANAGED_PATHS_SUMMARY

    print(f"Managed paths: {MANAGED_PATHS_SUMMARY}")
    if break_glass is not None:
        print(
            f"Break-glass key: {break_glass.get('public_fingerprint') or break_glass.get('item_id', 'configured')} "
            f"for root, from {', '.join(map(str, break_glass.get('from_cidrs') or [])) or 'anywhere'} "
            f"(appended to {BREAK_GLASS_AUTHORIZED_KEYS})"
        )
    else:
        print("Break-glass key: none")
    return input(f"Type {terminal_safe(hostname)} to continue: ").strip()


def _fingerprint_line(public_line: str) -> str:
    """Render an OpenSSH fingerprint without trusting a server-provided label."""
    try:
        from servonaut.services.vault.crypto import openssh_fingerprint
        parts = public_line.split()
        if len(parts) < 2:
            raise ValueError("missing public key blob")
        return openssh_fingerprint(base64.b64decode(parts[1], validate=True))
    except Exception:
        return "invalid public key"

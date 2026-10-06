"""Headless commands for the native encrypted vault.

The command module deliberately contains presentation and explicit terminal
confirmation only.  Cryptography, HTTP and state changes remain in the vault
services, which makes this surface safe to exercise with injected fakes.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import math
import secrets
import sys
import unicodedata
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Any, Optional

from servonaut.services.api_client import APIError
from servonaut.services.vault.errors import vault_failure_reason

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_USAGE = 2
_EXIT_ABORTED = 5

VaultServiceFactory = Callable[[], Any]
_service_factory: Optional[VaultServiceFactory] = None


def set_vault_service_factory(factory: Optional[VaultServiceFactory]) -> None:
    """Install a command-service factory; intended for app wiring and tests."""
    global _service_factory
    _service_factory = factory


def _warn_incomplete_rotation(rotation: Any) -> None:
    """Say plainly which hosts may still accept the exposed key."""
    hosts = rotation.get("hosts", []) if isinstance(rotation, Mapping) else []
    unfinished = [
        str(host.get("server_id")) for host in hosts
        if isinstance(host, Mapping) and host.get("status") != "old_key_removed"
    ]
    print(
        "Warning: the SSH key rotation did not finish. The exposed key may still log in to: "
        + (", ".join(unfinished) or "the selected servers")
        + ". Do not treat the exposure as closed, even if it shows as resolved; "
        "remove the old key from those servers, then run the rotation again.",
        file=sys.stderr,
    )


def _host_keys_are_well_formed(host_keys: list[str] | None) -> bool:
    """Check --host-key values before anything is sent; explain a bad one."""
    for value in host_keys or []:
        fields = value.split()
        if len(fields) != 2 or not fields[0].startswith(("ssh-", "ecdsa-", "sk-")):
            print(
                "Error: --host-key takes one OpenSSH public key without a host name or "
                "comment, for example 'ssh-ed25519 AAAAC3…'. Copy it from "
                "`ssh-keyscan` output without the leading host field.",
                file=sys.stderr,
            )
            return False
    return True


def is_vault_command(args: argparse.Namespace) -> bool:
    return getattr(args, "subcommand", None) == "vault"


def add_vault_parser(subparsers: Any) -> None:
    """Register the complete ``servonaut vault`` command group."""
    vault = subparsers.add_parser("vault", help="Manage encrypted personal and team vaults.")
    commands = vault.add_subparsers(dest="vault_command")
    commands.required = True

    commands.add_parser("status", help="Show identity, device and vault status.")
    setup = commands.add_parser("setup", help="Create or restore a vault identity.")
    setup.add_argument("--device-name", default=None)
    setup.add_argument("--platform", default=None)
    setup.add_argument("--yes", action="store_true", help="Confirm recovery-key display requirements.")

    recover = commands.add_parser("recover", help="Restore a device with the recovery key.")
    recover.add_argument("--device-name", default=None)
    recover.add_argument("--platform", default=None)
    identity = commands.add_parser("identity", help="Manage identity confirmation.")
    identity_sub = identity.add_subparsers(dest="vault_identity_command", required=True)
    identity_sub.add_parser("confirm", help="Refresh identity confirmation after login with MFA.")

    reset = commands.add_parser("reset-identity", help="Start an identity reset.")
    reset.add_argument("--reason", required=True, choices=("lost_all_devices", "compromised", "rotate"))
    reset.add_argument("--yes", action="store_true", help="Confirm the recovery consequences.")
    recovery_key = commands.add_parser("recovery-key", help="Manage the recovery key.")
    recovery_sub = recovery_key.add_subparsers(dest="vault_recovery_command", required=True)
    recovery_sub.add_parser("rotate", help="Replace the recovery key.")

    devices = commands.add_parser("devices", help="List, approve, or revoke devices.")
    device_sub = devices.add_subparsers(dest="vault_devices_command", required=True)
    device_sub.add_parser("list", help="List current and recently finished devices.")
    add = device_sub.add_parser("add", help="Register this device and wait for approval on another device.")
    add.add_argument("--device-name", default=None)
    add.add_argument("--platform", default=None)
    approve = device_sub.add_parser("approve", help="Approve a pending device after comparing its SAS.")
    approve.add_argument("device_id")
    revoke = device_sub.add_parser("revoke", help="Revoke a device.")
    revoke.add_argument("device_id")
    revoke.add_argument("--reason", required=True, choices=("retired", "lost", "compromised"))
    revoke.add_argument("--yes", action="store_true")

    create = commands.add_parser("create", help="Create a personal or team vault.")
    create.add_argument("--team", default=None, help="Team slug; omit for a personal vault.")
    create.add_argument("--name", default=None)
    create.add_argument("--grant-policy", choices=("auto", "approval"), default="auto")
    commands.add_parser("list", help="List readable vaults.")
    items = commands.add_parser("items", help="List item metadata only.")
    items.add_argument("--vault", required=True)
    items.add_argument("--include-deleted", action="store_true")
    show = commands.add_parser("show", help="Show item metadata; --reveal requires confirmation.")
    show.add_argument("item_id")
    show.add_argument("--vault", required=True)
    show.add_argument("--reveal", action="store_true")
    show.add_argument("--yes", action="store_true")

    imports = commands.add_parser("import", help="Import SSH material into the encrypted vault.")
    import_sub = imports.add_subparsers(dest="vault_import_command", required=True)
    import_ssh = import_sub.add_parser("ssh", help="Import selected local SSH keys.")
    import_ssh.add_argument("--vault", required=True)
    import_ssh.add_argument("--path", default=None)
    import_ssh.add_argument(
        "--break-glass", action="store_true",
        help="Store the key as the team's emergency root key for SSH CA enrollment.",
    )
    import_ssh.add_argument(
        "--from-cidr", action="append", default=[],
        help="Source network allowed to use the break-glass key; repeat for each. Required with --break-glass.",
    )
    import_bw = import_sub.add_parser("bitwarden", help="Import SSH keys from Bitwarden without deleting them.")
    import_bw.add_argument("--vault", required=True)
    import_bw.add_argument("--item", required=True, help="Existing Bitwarden SSH item UUID.")
    bind = commands.add_parser("bind", help="Bind a vault SSH item to a server.")
    bind.add_argument("server")
    bind.add_argument("item_id")
    bind.add_argument("--vault", required=True)
    bind.add_argument("--team", default=None)
    bind.add_argument("--login", default=None)
    bind.add_argument("--pin-host-key", action="store_true",
                      help="Pin the host key this machine already trusts for the server.")
    bind.add_argument("--host-key", action="append", default=[],
                      help="Verified OpenSSH host key to pin; repeat for each key.")
    bind.add_argument("--yes", action="store_true")
    bind_personal = commands.add_parser("bind-personal", help="Bind a vault SSH item to a personal server with explicit host pins.")
    bind_personal.add_argument("--vault", required=True)
    bind_personal.add_argument("--item", required=True)
    bind_personal.add_argument("--provider", required=True)
    bind_personal.add_argument("--instance-id", required=True)
    bind_personal.add_argument("--hostname", required=True)
    bind_personal.add_argument("--port", type=int, default=22)
    bind_personal.add_argument("--login", required=True)
    bind_personal.add_argument("--host-key", action="append", required=True, help="Verified OpenSSH host key; repeat for each pin.")
    bind_personal.add_argument("--yes", action="store_true")
    rotate = commands.add_parser("rotate", help="Rotate a vault encryption version.")
    rotate.add_argument("--vault", required=True)
    rotate.add_argument("--yes", action="store_true")
    exposures = commands.add_parser("exposures", help="List, remediate, or resolve key exposure warnings.")
    exposures.add_argument("--vault", required=True)
    exposure_action = exposures.add_mutually_exclusive_group()
    exposure_action.add_argument("--resolve", default=None, metavar="EXPOSURE_ID")
    exposure_action.add_argument("--rotate-ssh", default=None, metavar="ITEM_ID", help="Rotate an exposed SSH item on selected servers.")
    exposures.add_argument("--resolution", choices=("rotated", "accepted_risk", "not_deployed"), default=None)
    exposures.add_argument("--note", default=None)
    exposures.add_argument("--team", default=None, help="Team owning the selected shared servers.")
    exposures.add_argument("--server", action="append", default=[], help="Shared server ID to remediate; repeat for each host.")
    exposures.add_argument("--yes", action="store_true")
    grants = commands.add_parser("grants", help="Process pending eligible member grants.")
    grant_sub = grants.add_subparsers(dest="vault_grants_command", required=True)
    process = grant_sub.add_parser("process", help="Process grants for one vault or all readable vaults.")
    process.add_argument("--vault", default=None)
    process.add_argument("--yes", action="store_true")
    verify = commands.add_parser("verify-member", help="Display a member safety number for out-of-band comparison.")
    verify.add_argument("member")

    escrow = commands.add_parser("escrow", help="Set up or recover a sole-owner escrow key.")
    escrow_sub = escrow.add_subparsers(dest="vault_escrow_command", required=True)
    escrow_setup = escrow_sub.add_parser("setup", help="Create an offline escrow recovery key.")
    escrow_setup.add_argument("--vault", required=True)
    escrow_setup.add_argument("--label", required=True)
    escrow_recover = escrow_sub.add_parser("recover", help="Recover a locked sole-owner vault with an escrow key.")
    escrow_recover.add_argument("--vault", required=True)
    escrow_recover.add_argument("--yes", action="store_true")

    vault.add_argument("--json", action="store_true", help="Emit safe metadata JSON; never emits revealed secret values.")
    _add_json_to_subcommands(vault)


def _add_json_to_subcommands(parser: argparse.ArgumentParser) -> None:
    """Accept ``--json`` after any vault action as users conventionally expect."""
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
    """Build the integration facade lazily, after optional vault modules exist."""
    from servonaut.services.vault.command_service import VaultCommandService
    return VaultCommandService.from_local_session()


def _services() -> Any:
    factory = _service_factory or _default_services
    return factory()


async def _invoke(services: Any, method: str, /, **kwargs: Any) -> Any:
    """Call an async command facade method without leaking implementation details."""
    target = getattr(services, method, None)
    if target is None and isinstance(services, Mapping):
        target = services.get(method)
    if target is None:
        raise RuntimeError(f"Vault command service does not provide {method}().")
    result = target(**kwargs)
    if hasattr(result, "__await__"):
        return await result
    return result


def _structured(value: Any) -> Any:
    """Turn dataclasses into built-in values without changing JSON data."""
    if is_dataclass(value):
        return _structured(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _structured(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_structured(item) for item in value]
    return value


def _plain(value: Any) -> Any:
    """Remove terminal control characters from values written for people."""
    value = _structured(value)
    if isinstance(value, str):
        return "".join(char for char in value if unicodedata.category(char) != "Cc")
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _redact_revealed(value: Any) -> Any:
    """Prevent a `--json` convenience flag from exporting a secret by mistake."""
    sensitive = {"value", "private_key_openssh", "recovery_key", "plaintext", "secret"}
    if isinstance(value, Mapping):
        return {
            key: "[revealed only on terminal]" if key.lower() in sensitive else _redact_revealed(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_revealed(item) for item in value]
    return value


def _print(value: Any, *, json_output: bool, revealed: bool = False) -> None:
    if json_output:
        # JSON is a machine boundary. ``json.dumps`` escapes control
        # characters itself, so retain non-secret metadata exactly rather than
        # applying terminal-oriented stripping before serialisation.
        print(json.dumps(_redact_revealed(_structured(value)), indent=2, sort_keys=True, default=str))
        return
    payload = _plain(value)
    for line in _human_lines(payload, revealed=revealed):
        print(line)


def _human_lines(value: Any, *, revealed: bool, prefix: str = "") -> list[str]:
    """Render nested safe metadata without silently dropping status fields."""
    sensitive = {"value", "private_key_openssh", "plaintext", "secret", "recovery_key"}
    if isinstance(value, Mapping):
        lines: list[str] = []
        for key, item in value.items():
            label = f"{prefix}{key}"
            if key.lower() in sensitive and not revealed:
                continue
            if isinstance(item, (Mapping, list)):
                lines.extend(_human_lines(item, revealed=revealed, prefix=f"{label}."))
            else:
                lines.append(f"{label}: {item}")
        return lines
    if isinstance(value, list):
        return [line for index, item in enumerate(value, 1) for line in _human_lines(item, revealed=revealed, prefix=f"{prefix}{index}.")]
    return [f"{prefix.rstrip('.')}: {value}"]


async def _next_step(services: Any, status: Any) -> Optional[dict[str, Any]]:
    """The user's next vault step; a status read never fails because of it."""
    try:
        step = await _invoke(services, "next_step", status=status)
    except Exception:
        return None
    return dict(step) if isinstance(step, Mapping) else None


def _print_next_step(step: Optional[Mapping[str, Any]]) -> None:
    if not step or step.get("code") == "ready":
        return
    print(f"Next step: {step.get('message')}")
    if step.get("command"):
        print(f"  Run: {step['command']}")


def _print_confirmation(result: Any, *, after_setup: bool) -> None:
    """Say whether the identity is confirmed, and how to confirm it if not."""
    confirmation = result.get("confirmation") if isinstance(result, Mapping) else None
    state = confirmation.get("state") if isinstance(confirmation, Mapping) else None
    if state == "confirmed":
        print("Your vault identity is confirmed.")
    elif state == "email_sent":
        expires = confirmation.get("expires_at")
        until = f" (valid until {expires})" if isinstance(expires, str) and expires else ""
        print(f"We e-mailed you a new confirmation link{until}. Open it to confirm your vault identity.")
        print("  To confirm here instead, sign in again with two-factor (`servonaut login`) "
              "and run `servonaut vault identity confirm`.")
    elif state == "pending_confirmation" and after_setup:
        print("Confirm your vault identity: open the link we e-mailed to you, or run `servonaut login` "
              "again (with two-factor) and then `servonaut vault identity confirm`.")


def _confirm(args: argparse.Namespace, prompt: str) -> bool:
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        print(f"Refusing in a non-interactive shell without --yes: {prompt}", file=sys.stderr)
        return False
    print(f"{prompt} [y/N] ", end="", file=sys.stderr, flush=True)
    return sys.stdin.readline().strip().lower() in {"y", "yes"}


def _read_secret(prompt: str) -> str:
    value = getpass.getpass(prompt, stream=sys.stderr)
    if not value:
        raise ValueError("No value entered.")
    return value


def _confirm_recovery_key(recovery_key: str) -> bool:
    """Display a generated recovery key once and prove the user recorded it."""
    if not sys.stdin.isatty():
        print("A terminal is required to record and confirm the recovery key.", file=sys.stderr)
        return False
    groups = [group for group in recovery_key.replace(" ", "-").split("-") if group]
    secret_indices = [
        index for index, group in enumerate(groups)
        if group.upper() not in {"SVRK1", "SVTR1"}
    ]
    if len(secret_indices) < 2:
        print("Recovery key format could not be confirmed.", file=sys.stderr)
        return False
    first, second = sorted(secrets.SystemRandom().sample(secret_indices, 2))
    print("Record this recovery key offline. It will not be shown again:", file=sys.stderr)
    print(recovery_key, file=sys.stderr)
    try:
        return (
            getpass.getpass(f"Re-enter recovery group {first + 1}: ", stream=sys.stderr).strip().upper() == groups[first].upper()
            and getpass.getpass(f"Re-enter recovery group {second + 1}: ", stream=sys.stderr).strip().upper() == groups[second].upper()
        )
    finally:
        # The immutable input cannot be zeroed, but is never logged or written.
        pass


def _confirm_sas(sas: str) -> bool:
    """Ask only after the service has derived and displayed the SAS."""
    if not sys.stdin.isatty():
        print("A terminal is required to compare the device safety number.", file=sys.stderr)
        return False
    print(f"Safety number: {sas}", file=sys.stderr)
    print("Does the other device show exactly this safety number? [y/N] ", end="", file=sys.stderr, flush=True)
    return sys.stdin.readline().strip().lower() in {"y", "yes"}


def _approval_poll_delay(services: Any, attempt: int) -> float:
    """Use the facade's validated exponential delay for approval and reset polling."""
    delay_for = getattr(services, "approval_poll_delay", None)
    if not callable(delay_for):
        raise RuntimeError("Vault approval polling is not configured.")
    delay = delay_for(attempt)
    if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not math.isfinite(delay) or delay <= 0:
        raise RuntimeError("Vault approval polling is not configured.")
    return float(delay)


async def _handle(args: argparse.Namespace) -> int:
    command = args.vault_command
    output = bool(getattr(args, "json", False))
    services: Any = None
    try:
        services = _services()
        if command == "status":
            status = await _invoke(services, "status")
            step = await _next_step(services, status)
            if output:
                _print({**status, "next_step": step} if isinstance(status, Mapping) else status, json_output=True)
            else:
                _print(status, json_output=False)
                _print_next_step(step)
        elif command == "setup":
            result = await _invoke(
                services,
                "setup",
                device_name=args.device_name,
                platform=args.platform,
                recovery_confirmation=_confirm_recovery_key,
            )
            _print(result, json_output=output)
            if not output:
                _print_confirmation(result, after_setup=True)
        elif command == "recover":
            recovery_key = _read_secret("Vault recovery key: ")
            _print(await _invoke(services, "recover", recovery_key=recovery_key, device_name=args.device_name, platform=args.platform), json_output=output)
        elif command == "identity":
            result = await _invoke(services, "confirm_identity")
            _print(result, json_output=output)
            if not output:
                _print_confirmation(result, after_setup=False)
        elif command == "reset-identity":
            if not _confirm(args, "Resetting an identity can remove vault access"):
                return _EXIT_ABORTED
            reset = await _invoke(
                services,
                "reset_identity",
                reason=args.reason,
                recovery_confirmation=_confirm_recovery_key,
            )
            if not output:
                _print(reset, json_output=False)
            attempt = 0
            while True:
                status = await _invoke(services, "poll_reset_identity")
                if isinstance(status, Mapping) and status.get("state") == "confirmed":
                    _print(status, json_output=output)
                    break
                await asyncio.sleep(_approval_poll_delay(services, attempt))
                attempt += 1
        elif command == "recovery-key":
            _print(
                await _invoke(
                    services,
                    "rotate_recovery_key",
                    recovery_confirmation=_confirm_recovery_key,
                ),
                json_output=output,
            )
        elif command == "devices":
            if args.vault_devices_command == "list":
                _print(await _invoke(services, "list_devices"), json_output=output)
            elif args.vault_devices_command == "add":
                pending = await _invoke(services, "add_device", device_name=args.device_name, platform=args.platform)
                if not output:
                    _print(pending, json_output=False)
                identity = pending.get("identity") if isinstance(pending, Mapping) else None
                expires_at = pending.get("expires_at") if isinstance(pending, Mapping) else None
                if not identity or not expires_at:
                    raise RuntimeError("pending-device registration did not return approval state")
                attempt = 0
                while True:
                    approval = await _invoke(services, "poll_pending_device", identity=identity, expires_at=expires_at)
                    state = approval.get("state") if isinstance(approval, Mapping) else None
                    if state == "revealed":
                        print(f"Safety number: {_plain(approval.get('safety_number'))}", file=sys.stderr)
                    if state == "approved":
                        approved_payload = approval.get("approval") if isinstance(approval, Mapping) else None
                        if not isinstance(approved_payload, Mapping):
                            raise RuntimeError("pending-device approval payload is malformed")
                        _print(
                            await _invoke(
                                services,
                                "finish_pending_device",
                                approval=approved_payload,
                                identity=identity,
                            ),
                            json_output=output,
                        )
                        break
                    await asyncio.sleep(_approval_poll_delay(services, attempt))
                    attempt += 1
            elif args.vault_devices_command == "approve":
                _print(await _invoke(services, "approve_device", device_id=args.device_id, confirmation=_confirm_sas), json_output=output)
            else:
                if not _confirm(args, f"Revoke device {args.device_id} as {args.reason}"):
                    return _EXIT_ABORTED
                _print(await _invoke(services, "revoke_device", device_id=args.device_id, reason=args.reason), json_output=output)
        elif command == "create":
            _print(await _invoke(services, "create_vault", team=args.team, name=args.name, grant_policy=args.grant_policy), json_output=output)
        elif command == "list":
            _print(await _invoke(services, "list_vaults"), json_output=output)
        elif command == "items":
            _print(await _invoke(services, "list_items", vault_id=args.vault, include_deleted=args.include_deleted), json_output=output)
        elif command == "show":
            if args.reveal and not _confirm(args, "Reveal this secret in your terminal"):
                return _EXIT_ABORTED
            item = await _invoke(services, "show_item", vault_id=args.vault, item_id=args.item_id, reveal=args.reveal)
            _print(item, json_output=output, revealed=args.reveal)
        elif command == "import":
            if args.vault_import_command == "bitwarden":
                from servonaut.services.bw_resolver import BwResolver
                private_key = await asyncio.to_thread(BwResolver(session_getter=None).resolve_ssh_key, args.item)
                _print(await _invoke(services, "import_keys", source="bitwarden", vault_id=args.vault, private_key=private_key, source_ref=args.item), json_output=output)
            else:
                if args.from_cidr and not args.break_glass:
                    print("Error: --from-cidr is only used with --break-glass.", file=sys.stderr)
                    return _EXIT_USAGE
                if args.break_glass and not args.from_cidr:
                    print("Error: --break-glass needs at least one --from-cidr source network.", file=sys.stderr)
                    return _EXIT_USAGE
                _print(await _invoke(
                    services, "import_keys", source="ssh", vault_id=args.vault, path=args.path,
                    break_glass_from_cidrs=args.from_cidr if args.break_glass else None,
                ), json_output=output)
        elif command == "bind":
            if not _host_keys_are_well_formed(args.host_key):
                return _EXIT_USAGE
            if (args.pin_host_key or args.host_key) and not _confirm(args, "Trust and pin the server's host keys"):
                return _EXIT_ABORTED
            _print(await _invoke(services, "bind", vault_id=args.vault, server=args.server, item_id=args.item_id, team=args.team, login=args.login, pin_host_key=args.pin_host_key, host_keys=tuple(args.host_key)), json_output=output)
        elif command == "bind-personal":
            if not _host_keys_are_well_formed(args.host_key):
                return _EXIT_USAGE
            if not _confirm(args, "Trust and pin the supplied personal-server host keys"):
                return _EXIT_ABORTED
            _print(
                await _invoke(
                    services,
                    "bind_personal",
                    vault_id=args.vault,
                    item_id=args.item,
                    provider=args.provider,
                    instance_id=args.instance_id,
                    hostname=args.hostname,
                    port=args.port,
                    login=args.login,
                    host_keys=args.host_key,
                ),
                json_output=output,
            )
        elif command == "rotate":
            if not _confirm(args, "Rotate the vault key version"):
                return _EXIT_ABORTED
            _print(await _invoke(services, "rotate", vault_id=args.vault), json_output=output)
        elif command == "exposures":
            if args.rotate_ssh:
                if not args.team or not args.server:
                    print("Error: --team and at least one --server are required with --rotate-ssh.", file=sys.stderr)
                    return _EXIT_USAGE
                if not _confirm(args, "Rotate the exposed SSH key on every selected server"):
                    return _EXIT_ABORTED
                rotation = await _invoke(
                    services,
                    "rotate_ssh_key",
                    vault_id=args.vault,
                    item_id=args.rotate_ssh,
                    team=args.team,
                    servers=args.server,
                )
                _print(rotation, json_output=output)
                if not (isinstance(rotation, Mapping) and rotation.get("rotated") is True):
                    _warn_incomplete_rotation(rotation)
                    return _EXIT_ERROR
            elif args.resolve:
                if not args.resolution:
                    print("Error: --resolution is required with --resolve.", file=sys.stderr)
                    return _EXIT_USAGE
                _print(await _invoke(services, "resolve_exposure", vault_id=args.vault, exposure_id=args.resolve, resolution=args.resolution, note=args.note), json_output=output)
            else:
                _print(await _invoke(services, "list_exposures", vault_id=args.vault), json_output=output)
        elif command == "grants":
            _print(await _invoke(services, "process_grants", vault_id=args.vault, interactive=not args.yes), json_output=output)
        elif command == "verify-member":
            _print(await _invoke(services, "verify_member", member=args.member), json_output=output)
        elif command == "escrow":
            if args.vault_escrow_command == "setup":
                _print(
                    await _invoke(
                        services,
                        "setup_escrow",
                        vault_id=args.vault,
                        label=args.label,
                        recovery_confirmation=_confirm_recovery_key,
                    ),
                    json_output=output,
                )
            else:
                if not _confirm(args, "Recover this vault with the offline escrow key"):
                    return _EXIT_ABORTED
                escrow_key = _read_secret("Escrow recovery key: ")
                _print(await _invoke(services, "recover_escrow", vault_id=args.vault, escrow_key=escrow_key), json_output=output)
        else:
            raise ValueError(f"Unknown vault command: {command}")
    except APIError as exc:
        print(f"Vault request failed ({vault_failure_reason(exc)}).", file=sys.stderr)
        return _EXIT_ERROR
    except Exception as exc:  # avoid server/local exception text leaking secret material
        print(f"Vault operation failed ({vault_failure_reason(exc)}).", file=sys.stderr)
        return _EXIT_ERROR
    finally:
        close = getattr(services, "close", None)
        if callable(close):
            try:
                result = close()
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                # Runtime cleanup is best effort and must not replace the
                # command's safe, user-facing outcome with local details.
                pass
    return _EXIT_OK


def handle_vault_command(args: argparse.Namespace) -> int:
    """Run a parsed vault command and return a process exit code."""
    return _run(_handle(args))

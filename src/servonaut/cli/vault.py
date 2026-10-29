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
import logging
import math
import secrets
import sys
import unicodedata
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Optional

from servonaut.services.api_client import APIError
from servonaut.services.vault.display import (
    VAULT_KEY_ROTATED_FIRST,
    grant_summary,
    member_approval_lines,
    ssh_rotation_failure,
    terminal_safe,
)
from servonaut.services.vault.errors import VaultKeyInUse, VaultUserError, vault_failure_reason
from servonaut.services.vault.identity_client import DEVICE_PLATFORMS

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_USAGE = 2
_EXIT_ABORTED = 5
_VAULT_HELP = "Vault id, or the vault's name as `servonaut vault list` shows it."
# Wrong passphrases accepted before an import gives up.
_PASSPHRASE_ATTEMPTS = 3

logger = logging.getLogger(__name__)

VaultServiceFactory = Callable[[], Any]
_service_factory: Optional[VaultServiceFactory] = None


def set_vault_service_factory(factory: Optional[VaultServiceFactory]) -> None:
    """Install a command-service factory; intended for app wiring and tests."""
    global _service_factory
    _service_factory = factory


def _warn_incomplete_rotation(rotation: Any) -> None:
    """Say why the rotation stopped and what is left on which hosts."""
    print(f"Warning: {ssh_rotation_failure(rotation, retry='run the rotation again')}", file=sys.stderr)


def _report_exposure_resolution(rotation: Mapping[str, Any], vault_id: str) -> bool:
    """Say what happened to the rotated item's exposures; ``False`` when one needs attention."""
    outcome = rotation.get("exposures")
    if not isinstance(outcome, Mapping):
        return True
    for exposure_id in outcome.get("resolved") or []:
        print(f"Exposure {exposure_id} resolved as rotated.")
    if outcome.get("needs_owner"):
        print("Rotation done; ask an owner or admin to resolve the exposure.", file=sys.stderr)
    failed = [entry for entry in outcome.get("failed") or [] if isinstance(entry, Mapping)]
    for entry in failed:
        exposure_id = entry.get("exposure_id")
        target = f"exposure {exposure_id}" if exposure_id else "the exposure"
        how = (
            f"`servonaut vault exposures --vault {vault_id} --resolve {exposure_id} --resolution rotated`"
            if exposure_id else f"`servonaut vault exposures --vault {vault_id}`"
        )
        print(
            f"Warning: the rotation is done, but {target} could not be marked resolved "
            f"({entry.get('reason')}); resolve it with {how}.",
            file=sys.stderr,
        )
    return not failed


def _note_replaced_keys(listed: Any) -> None:
    """An exposure whose key was replaced in the vault is not closed yet."""
    rows = listed.get("data", []) if isinstance(listed, Mapping) else []
    for row in rows:
        if isinstance(row, Mapping) and row.get("key_replaced") is True:
            print(
                f"Note: exposure {row.get('exposure_id')}: key replaced in the vault; "
                "the old key may still be on servers."
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
    setup.add_argument("--platform", default=None, choices=DEVICE_PLATFORMS)
    setup.add_argument("--yes", action="store_true", help="Confirm recovery-key display requirements.")

    recover = commands.add_parser("recover", help="Restore a device with the recovery key.")
    recover.add_argument("--device-name", default=None)
    recover.add_argument("--platform", default=None, choices=DEVICE_PLATFORMS)
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
    add.add_argument("--platform", default=None, choices=DEVICE_PLATFORMS)
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
    items.add_argument("--vault", required=True, help=_VAULT_HELP)
    items.add_argument("--include-deleted", action="store_true")
    items.add_argument("--names", action="store_true", help="Decrypt SSH key names locally and include them.")
    show = commands.add_parser("show", help="Show item metadata; --reveal requires confirmation.")
    show.add_argument("item_id")
    show.add_argument("--vault", required=True, help=_VAULT_HELP)
    show.add_argument("--reveal", action="store_true")
    show.add_argument("--yes", action="store_true")

    rename = commands.add_parser("rename", help="Rename a vault SSH key.")
    rename.add_argument("item_id")
    rename.add_argument("--vault", required=True, help=_VAULT_HELP)
    rename.add_argument("--name", required=True, help="New SSH key name (1 to 200 characters).")
    delete = commands.add_parser("delete", help="Remove an unused SSH key from the vault only.")
    delete.add_argument("item_id")
    delete.add_argument("--vault", required=True, help=_VAULT_HELP)
    delete.add_argument("--yes", action="store_true")

    imports = commands.add_parser("import", help="Import SSH material into the encrypted vault.")
    import_sub = imports.add_subparsers(dest="vault_import_command", required=True)
    import_ssh = import_sub.add_parser("ssh", help="Import a local SSH private key file.")
    import_ssh.add_argument("--vault", required=True, help=_VAULT_HELP)
    import_ssh.add_argument("--name", default=None, help="Key name; defaults to the file name.")
    import_ssh.add_argument(
        "--path", required=True,
        help="Private key file, e.g. ~/.ssh/id_ed25519; asks for its passphrase when it has one.",
    )
    import_ssh.add_argument(
        "--break-glass", action="store_true",
        help="Store the key as the team's emergency root key for SSH CA enrollment.",
    )
    import_ssh.add_argument(
        "--from-cidr", action="append", default=[],
        help="Source network allowed to use the break-glass key; repeat for each. Required with --break-glass.",
    )
    import_bw = import_sub.add_parser("bitwarden", help="Import SSH keys from Bitwarden without deleting them.")
    import_bw.add_argument("--vault", required=True, help=_VAULT_HELP)
    import_bw.add_argument("--name", default=None, help="Key name; defaults to the Bitwarden item name.")
    import_bw.add_argument("--item", required=True, help="Existing Bitwarden SSH item UUID.")
    bind = commands.add_parser("bind", help="Bind a vault SSH item to a server.")
    bind.add_argument("server")
    bind.add_argument("item_id")
    bind.add_argument("--vault", required=True, help=_VAULT_HELP)
    bind.add_argument("--team", required=True, help="Team the server is shared with.")
    bind.add_argument("--login", default=None)
    bind.add_argument("--pin-host-key", action="store_true",
                      help="Pin the host key this machine already trusts for the server.")
    bind.add_argument("--host-key", action="append", default=[],
                      help="Verified OpenSSH host key to pin; repeat for each key.")
    bind.add_argument("--yes", action="store_true")
    bind_personal = commands.add_parser("bind-personal", help="Bind a vault SSH item to a personal server with explicit host pins.")
    bind_personal.add_argument("--vault", required=True, help=_VAULT_HELP)
    bind_personal.add_argument("--item", required=True)
    bind_personal.add_argument(
        "--provider", required=True, help="aws, ovh, hetzner, or custom for a custom server.",
    )
    bind_personal.add_argument(
        "--instance-id", required=True,
        help="The instance id; for --provider custom, the custom server's name as shown in Servonaut.",
    )
    bind_personal.add_argument("--hostname", required=True)
    bind_personal.add_argument("--port", type=int, default=22)
    bind_personal.add_argument("--login", required=True)
    bind_personal.add_argument("--host-key", action="append", required=True, help="Verified OpenSSH host key; repeat for each pin.")
    bind_personal.add_argument("--yes", action="store_true")
    auto_bind = commands.add_parser(
        "auto-bind",
        help="Bind personal-vault SSH keys to the servers named like them (key pair name, then server name).",
    )
    auto_bind.add_argument("--vault", default=None, help=f"{_VAULT_HELP} Default: your personal vault.")
    auto_bind.add_argument("--team", default=None, help="Bind a team vault's keys to that team's shared servers.")
    auto_bind.add_argument("--dry-run", action="store_true", help="Show what would be bound and change nothing.")
    auto_bind.add_argument(
        "--yes", action="store_true",
        help="Pin the host keys this computer already trusts and bind without asking.",
    )
    auto_bind.add_argument(
        "--fetch-host-keys", action="store_true",
        help="Connect once to record host keys for servers missing them (still connects once per server with --dry-run).",
    )
    rotate = commands.add_parser("rotate", help="Rotate a vault encryption version.")
    rotate.add_argument("--vault", required=True, help=_VAULT_HELP)
    rotate.add_argument("--yes", action="store_true")
    exposures = commands.add_parser("exposures", help="List, remediate, or resolve key exposure warnings.")
    exposures.add_argument("--vault", required=True, help=_VAULT_HELP)
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
    process.add_argument("--vault", default=None, help=_VAULT_HELP)
    process.add_argument(
        "--yes", action="store_true",
        help="Do not ask: members who need your approval (safety number) stay pending.",
    )
    verify = commands.add_parser("verify-member", help="Display a member safety number for out-of-band comparison.")
    verify.add_argument("member")

    escrow = commands.add_parser("escrow", help="Set up or recover a sole-owner escrow key.")
    escrow_sub = escrow.add_subparsers(dest="vault_escrow_command", required=True)
    escrow_setup = escrow_sub.add_parser("setup", help="Create an offline escrow recovery key.")
    escrow_setup.add_argument("--vault", required=True, help=_VAULT_HELP)
    escrow_setup.add_argument("--label", required=True)
    escrow_recover = escrow_sub.add_parser("recover", help="Recover a locked sole-owner vault with an escrow key.")
    escrow_recover.add_argument("--vault", required=True, help=_VAULT_HELP)
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


def _vault_kind(vault: Mapping[str, Any]) -> str:
    """"personal", or "team <slug>" for a team's vault."""
    team = vault.get("team")
    slug = team.get("slug") if isinstance(team, Mapping) else None
    if vault.get("kind") == "team" and slug:
        return f"team {terminal_safe(slug)}"
    return terminal_safe(vault.get("kind") or "")


def _print_vaults(vaults: Any) -> None:
    """``vault list`` for people: one line per vault, the columns the Vault screen shows."""
    rows = [vault for vault in vaults if isinstance(vault, Mapping)] if isinstance(vaults, list) else []
    if not rows:
        print("You have no vaults yet: run `servonaut vault create`.")
        return
    table = [("Name", "Kind", "Items", "Open exposures", "Vault ID")]
    for vault in rows:
        counts = vault.get("counts") if isinstance(vault.get("counts"), Mapping) else {}
        table.append((
            terminal_safe(vault.get("name") or "Unnamed vault"), _vault_kind(vault),
            str(counts.get("items", 0)), str(counts.get("open_exposures", 0)),
            terminal_safe(vault.get("vault_id") or ""),
        ))
    widths = [max(len(row[column]) for row in table) for column in range(len(table[0]))]
    for row in table:
        print("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip())


def _print_created_vault(vault: Any) -> None:
    """``vault create`` for people: what was created and what to do next."""
    if not isinstance(vault, Mapping):
        _print(vault, json_output=False)
        return
    name = terminal_safe(vault.get("name") or "Unnamed vault")
    vault_id = terminal_safe(vault.get("vault_id") or "")
    kind = _vault_kind(vault)
    if kind.startswith("team "):
        print(f'Created the team vault "{name}" for {kind[len("team "):]} (ID {vault_id}).')
    else:
        print(f'Created your personal vault "{name}" (ID {vault_id}).')
    print(f"Next: import an SSH key with `servonaut vault import ssh --vault {vault_id} --path ~/.ssh/<key>`.")


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


async def _vault_id(services: Any, reference: str) -> str:
    """A vault id as given, or the id of the vault with that name."""
    try:
        uuid.UUID(reference)
    except ValueError:
        return await _invoke(services, "resolve_vault_id", reference=reference)
    return reference


def _wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _read_import_key(path: Path) -> Optional[bytearray]:
    """The private key at *path* as unencrypted OpenSSH text, or ``None`` when cancelled.

    Same normalisation as the TUI import, so PEM and passphrase-protected keys
    work too. The passphrase is asked for on the terminal and never stored.
    """
    from servonaut.services.bw_key_import import (
        KeyImportError, WrongPassphraseError, decrypt_private_key, is_encrypted_key,
        load_unencrypted_key, read_key_bytes,
    )

    raw = bytearray()
    try:
        raw = bytearray(read_key_bytes(path))
        if not is_encrypted_key(bytes(raw)):
            return bytearray(load_unencrypted_key(bytes(raw)).private_key.encode("utf-8"))
        if not sys.stdin.isatty():
            raise VaultUserError("this SSH key has a passphrase; run the import in a terminal to enter it")
        for _attempt in range(_PASSPHRASE_ATTEMPTS):
            passphrase = getpass.getpass(f"Passphrase for {path.name} (Enter to cancel): ", stream=sys.stderr)
            if not passphrase:
                return None
            try:
                return bytearray(decrypt_private_key(bytes(raw), passphrase).private_key.encode("utf-8"))
            except WrongPassphraseError:
                print("Wrong passphrase.", file=sys.stderr)
        raise VaultUserError("the passphrase was wrong three times; nothing was imported")
    except KeyImportError as exc:
        raise VaultUserError(f"could not import {path.name}: {exc.message}") from exc
    finally:
        _wipe(raw)


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


def _confirm_member_sas(entry: Mapping[str, Any], safety_number: str, changed: bool) -> bool:
    """Ask on the terminal whether to let one team member's vault identity in; never by default."""
    for line in member_approval_lines(entry, safety_number, changed):
        print(terminal_safe(line), file=sys.stderr)
    print("Approve this member? [y/N] ", end="", file=sys.stderr, flush=True)
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


def _auto_bind_servers() -> list[dict[str, Any]]:
    """Every cached server of every account, and the custom servers."""
    from servonaut.config.manager import ConfigManager
    from servonaut.services.accounts.headless import CachedFleet
    from servonaut.services.custom_server_service import CustomServerService

    manager = ConfigManager()
    return CachedFleet.from_config(manager.get(), CustomServerService(manager), manager).instances()


def _auto_bind_record(row: Any) -> dict[str, Any]:
    from servonaut.services.vault import crypto

    instance = row.instance
    rec = {
        "server": instance.get("name") or instance.get("id"),
        "instance_id": instance.get("id"),
        "provider": "custom" if instance.get("is_custom") else str(instance.get("provider") or "aws").lower(),
        "vault_item_id": row.match.item_id if row.match is not None else None,
        "key_name": row.match.name if row.match is not None else None,
        "matched_by": row.match.matched_by if row.match is not None else None,
        "login": row.login,
        "login_source": getattr(row, "login_source", None),
        "host": row.host,
        "port": row.port,
        "host_key_fingerprints": [crypto.ssh_public_fingerprint(key) for key in row.host_keys],
        "verified": getattr(row, "verified", False),
        "verification_source": getattr(row, "verification_source", None),
        "fetch_error": getattr(row, "fetch_error", None),
        "mismatch_detail": getattr(row, "mismatch_detail", None),
        "team": getattr(row, "team", None),
        "status": row.status,
        "result": row.result,
        "notes": list(getattr(row, "notes", None) or []),
    }
    if getattr(row, "skipped", None) is not None:
        rec["skipped"] = row.skipped
    return rec


def _print_auto_bind(rows: Sequence[Any], *, results: bool) -> None:
    from servonaut.services.vault.auto_bind import FETCHED

    for row in rows:
        record = _auto_bind_record(row)
        name = terminal_safe(str(record["server"] or "server"))
        status = row.status_text if results or not row.ready else "ready"
        fetch_err = getattr(row, "fetch_error", None)
        mismatch_det = getattr(row, "mismatch_detail", None)
        if row.match is None or row.match.ambiguous:
            print(f"{name}: {status}")
            if fetch_err and str(fetch_err) not in status:
                print(f"    fetch error: {terminal_safe(str(fetch_err))}")
            if mismatch_det and str(mismatch_det) not in status:
                print(f"    mismatch: {terminal_safe(str(mismatch_det))}")
            _print_auto_bind_notes(record)
            continue
        parts = [f"{name}: {terminal_safe(str(record['key_name']))} (by {record['matched_by']})"]
        if record["login"] and record["host"]:
            parts.append(terminal_safe(f"{record['login']}@{record['host']}"))
            if record["login_source"]:
                parts.append(f"(login from {record['login_source']})")
        print(" ".join(parts) + f" - {status}")
        if fetch_err and str(fetch_err) not in status:
            print(f"    fetch error: {terminal_safe(str(fetch_err))}")
        if mismatch_det and str(mismatch_det) not in status:
            print(f"    mismatch: {terminal_safe(str(mismatch_det))}")
        _print_auto_bind_notes(record)
        if row.ready and not results:
            for fingerprint in record["host_key_fingerprints"]:
                if getattr(row, "verified", False):
                    source = getattr(row, "verification_source", None) or "verified by AWS console output"
                    print(f"    host key {fingerprint} ({source})")
                elif row.status == FETCHED:
                    source = getattr(row, "verification_source", None) or "not verified: compare with the server's console or your provider"
                    print(f"    host key {fingerprint} ({source})")
                else:
                    print(f"    host key {fingerprint}")


def _print_auto_bind_notes(record: Mapping[str, Any]) -> None:
    for note in record["notes"]:
        print(f"    note: {terminal_safe(str(note))}")


async def _load_team_shared_servers(
    services: Any, team: str
) -> tuple[int, list[dict[str, Any]], Optional[dict[str, Any]]]:
    team_svc = getattr(services, "teams", None) or getattr(services, "team_service", None)
    if team_svc is None:
        try:
            from servonaut.cli.team import _default_team_service
            team_svc = _default_team_service()
        except Exception:
            team_svc = None
    if team_svc is None:
        print("Team services are unavailable: sign in first.", file=sys.stderr)
        return _EXIT_ERROR, [], None
    try:
        teams = await team_svc.list_teams()
    except Exception as exc:
        print(f"Could not load your teams ({vault_failure_reason(exc)}).", file=sys.stderr)
        return _EXIT_ERROR, [], None

    from servonaut.cli.team import _find_team
    team_rec = _find_team(teams, team)
    if team_rec is None:
        print(f"You are not in a team called {terminal_safe(team)}.", file=sys.stderr)
        return _EXIT_ERROR, [], None

    role = str(team_rec.get("role") or "").lower()
    if role not in {"owner", "admin"}:
        name = terminal_safe(str(team_rec.get("name") or team))
        print(f"Only team owners and admins can bind vault keys for {name}.", file=sys.stderr)
        return _EXIT_ERROR, [], team_rec

    try:
        from servonaut.services.shared_servers import load_shared_servers
        res = await load_shared_servers(team_svc, teams=[team_rec])
        if res.problems:
            print(f"Could not load shared servers for {terminal_safe(team)}: {terminal_safe(res.problems[0])}.", file=sys.stderr)
            return _EXIT_ERROR, [], team_rec
        return _EXIT_OK, list(res.rows), team_rec
    except Exception as exc:
        print(f"Could not load shared servers for team {terminal_safe(team)} ({vault_failure_reason(exc)}).", file=sys.stderr)
        return _EXIT_ERROR, [], team_rec


async def _auto_bind(services: Any, args: argparse.Namespace, output: bool) -> int:
    """Plan, confirm and apply ``vault auto-bind``."""
    from servonaut.services.vault.auto_bind import (
        FETCHED,
        NO_HOST_KEYS,
        apply_auto_bind,
        fetch_host_keys_for_rows,
        plan_auto_bind,
    )

    vault_id = args.vault
    team = getattr(args, "team", None)
    team_rec = None
    servers = list(_auto_bind_servers())
    if team:
        exit_code, shared, team_rec = await _load_team_shared_servers(services, team)
        if exit_code != _EXIT_OK:
            return exit_code
        from servonaut.services.shared_servers import is_shared_row
        own_servers = [s for s in servers if not is_shared_row(s)]
        servers = own_servers + list(shared)

    try:
        vaults = await _invoke(services, "list_vaults")
    except Exception as exc:
        print(f"Could not load vaults ({vault_failure_reason(exc)}).", file=sys.stderr)
        return _EXIT_ERROR

    if vault_id:
        vault_id = await _vault_id(services, vault_id)
        if team:
            target = None
            for v in vaults:
                if isinstance(v, Mapping) and str(v.get("vault_id")) == vault_id:
                    target = v
                    break
            v_team = target.get("team") if isinstance(target, Mapping) and isinstance(target.get("team"), Mapping) else {}
            v_slug = v_team.get("slug") or (target.get("team_slug") if isinstance(target, Mapping) else None)
            if not target or target.get("kind") != "team" or v_slug != team:
                raw_vault = getattr(args, "_raw_vault", None) or getattr(args, "vault", None)
                print(
                    f'"{terminal_safe(raw_vault)}" is not {terminal_safe(team)}\'s team vault: '
                    "leave out --vault to use the team's vault.",
                    file=sys.stderr,
                )
                return _EXIT_ERROR
    else:
        if team:
            team_vault = None
            for v in vaults:
                if isinstance(v, Mapping) and v.get("kind") == "team":
                    team_info = v.get("team") if isinstance(v.get("team"), Mapping) else {}
                    slug = team_info.get("slug") or v.get("team_slug")
                    if slug == team:
                        team_vault = v
                        break
            if not team_vault:
                team_name = terminal_safe(str((team_rec.get("name") if team_rec else None) or team))
                print(f"You have no team vault for {team_name} yet: run `servonaut vault create --team {terminal_safe(team)}`.", file=sys.stderr)
                return _EXIT_ERROR
            if team_vault.get("my_grant") is None:
                team_name = terminal_safe(str((team_rec.get("name") if team_rec else None) or team))
                print(f"Your access to the team vault for {team_name} is still waiting for approval.", file=sys.stderr)
                return _EXIT_ERROR
            vault_id = str(team_vault["vault_id"])
        else:
            personal = [
                choice for choice in vaults
                if isinstance(choice, Mapping) and choice.get("kind") == "personal"
            ]
            if not personal:
                print("You have no personal vault yet: run `servonaut vault create` and import your SSH keys.", file=sys.stderr)
                return _EXIT_ERROR
            vault_id = str(personal[0]["vault_id"])

    keys = await _invoke(services, "ssh_key_choices", vault_id=vault_id, name_limit=None)
    rows = await plan_auto_bind(services, servers, keys, team=team)

    if getattr(args, "fetch_host_keys", False):
        to_fetch = [row for row in rows if row.status == NO_HOST_KEYS]
        if to_fetch:
            accounts = getattr(services, "accounts", None)
            if accounts is None:
                try:
                    from servonaut.config.manager import ConfigManager
                    from servonaut.services.accounts.headless import build_account_registry
                    accounts = build_account_registry(ConfigManager())
                except Exception as exc:
                    logger.debug("Failed to build account registry: %s", exc, exc_info=True)
                    accounts = None
            await fetch_host_keys_for_rows(
                services,
                to_fetch,
                accounts=accounts,
            )

    ready = [row for row in rows if row.ready]
    if output and (args.dry_run or not ready):
        _print({"vault_id": vault_id, "servers": [_auto_bind_record(row) for row in rows]}, json_output=True)
        return _EXIT_OK
    if not output:
        _print_auto_bind(rows, results=False)
    if args.dry_run or not ready:
        if not output:
            print(f"{len(ready)} of {len(rows)} servers can get a vault key.", file=sys.stderr)
        return _EXIT_OK

    is_yes = getattr(args, "yes", False)
    if getattr(args, "fetch_host_keys", False) and not is_yes and not sys.stdin.isatty():
        print(
            "Refusing to bind fetched host keys without confirmation. Run interactively or pass --yes to bind only verified keys.",
            file=sys.stderr,
        )
        return _EXIT_ERROR

    unverified_fetched = [row for row in ready if row.status == FETCHED and not row.verified]
    if is_yes and unverified_fetched:
        for row in unverified_fetched:
            row.skipped = "not verified"
        to_bind = [row for row in ready if row not in unverified_fetched]
        if not output:
            n = len(unverified_fetched)
            word = "servers" if n > 1 else "server"
            print(f"Skipped {n} unverified {word}: run without --yes to check their fingerprints.", file=sys.stderr)
    else:
        to_bind = ready

    if not to_bind:
        if output:
            _print({"vault_id": vault_id, "servers": [_auto_bind_record(row) for row in rows]}, json_output=True)
        else:
            print(f"0 of {len(rows)} servers can get a vault key.", file=sys.stderr)
        return _EXIT_OK

    if not _confirm(args, f"Pin the host keys shown and bind vault keys to {len(to_bind)} servers"):
        return _EXIT_ABORTED
    await apply_auto_bind(services, to_bind, vault_id=vault_id, team=team, reviewed_fetched=True)
    failed = [row for row in to_bind if row.result != "bound"]
    if output:
        _print({"vault_id": vault_id, "servers": [_auto_bind_record(row) for row in rows]}, json_output=True)
    else:
        _print_auto_bind(to_bind, results=True)
        print(f"Bound vault keys to {len(to_bind) - len(failed)} of {len(to_bind)} servers.", file=sys.stderr)
    return _EXIT_ERROR if failed else _EXIT_OK


def _named_row(row: Mapping[str, Any], names: Mapping[str, Any]) -> dict[str, Any]:
    if row.get("type") != "ssh_key":
        return dict(row)
    name = names.get(row.get("item_id"))
    return {**row, "name": terminal_safe(name) if name is not None else None}


async def _items_with_names(services: Any, args: argparse.Namespace) -> dict[str, Any]:
    listed = await _invoke(services, "list_items", vault_id=args.vault, include_deleted=args.include_deleted)
    if not args.names:
        return listed
    choices = await _invoke(services, "ssh_key_choices", vault_id=args.vault, name_limit=None)
    names = {row["item_id"]: row.get("name") for row in choices}
    return {**listed, "data": [_named_row(row, names) for row in listed["data"]]}


async def _delete_ssh_key(services: Any, args: argparse.Namespace, output: bool) -> int:
    servers = _auto_bind_servers()
    usage = await _invoke(services, "ssh_key_usage", vault_id=args.vault, item_id=args.item_id, servers=servers)
    print(f"Vault key: {terminal_safe(usage.get('name') or 'Unnamed SSH key')} "
          f"({terminal_safe(usage.get('fingerprint') or args.item_id)})", file=sys.stderr)
    if usage["team_servers"] or usage["own_servers"] or usage["unchecked"]:
        raise VaultKeyInUse.from_usage(usage)
    print("This removes the key from the vault only. Servers that accept it keep accepting it "
          "until it is removed from their authorized_keys.", file=sys.stderr)
    if not _confirm(args, "Delete this key from the vault"):
        return _EXIT_ABORTED
    _print(await _invoke(services, "delete_ssh_key", vault_id=args.vault, item_id=args.item_id, servers=servers),
           json_output=output)
    return _EXIT_OK


async def _handle(args: argparse.Namespace) -> int:
    command = args.vault_command
    output = bool(getattr(args, "json", False))
    services: Any = None
    try:
        services = _services()
        if getattr(args, "vault", None):
            args._raw_vault = args.vault
            args.vault = await _vault_id(services, args.vault)
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
            created = await _invoke(services, "create_vault", team=args.team, name=args.name, grant_policy=args.grant_policy)
            if output:
                _print(created, json_output=True)
            else:
                _print_created_vault(created)
        elif command == "list":
            vaults = await _invoke(services, "list_vaults")
            if output:
                _print(vaults, json_output=True)
            else:
                _print_vaults(vaults)
        elif command == "items":
            _print(await _items_with_names(services, args), json_output=output)
        elif command == "show":
            if args.reveal and not _confirm(args, "Reveal this secret in your terminal"):
                return _EXIT_ABORTED
            item = await _invoke(services, "show_item", vault_id=args.vault, item_id=args.item_id, reveal=args.reveal)
            _print(item, json_output=output, revealed=args.reveal)
        elif command == "rename":
            renamed = await _invoke(services, "rename_ssh_key", vault_id=args.vault, item_id=args.item_id, name=args.name)
            if output:
                _print(renamed, json_output=True)
            else:
                print(f"Renamed the key to {terminal_safe(renamed['name'])}.")
        elif command == "delete":
            return await _delete_ssh_key(services, args, output)
        elif command == "import":
            if args.vault_import_command == "bitwarden":
                from servonaut.services.bw_resolver import BwResolver
                key_text, item_name = await asyncio.to_thread(BwResolver(session_getter=None).resolve_ssh_item, args.item)
                private_key = bytearray(key_text.encode("utf-8"))
                del key_text
                try:
                    _print(await _invoke(
                        services, "import_keys", source="bitwarden", vault_id=args.vault,
                        private_key=private_key, source_ref=args.item,
                        name=args.name if args.name is not None else item_name,
                    ), json_output=output)
                finally:
                    _wipe(private_key)
            else:
                if args.from_cidr and not args.break_glass:
                    print("Error: --from-cidr is only used with --break-glass.", file=sys.stderr)
                    return _EXIT_USAGE
                if args.break_glass and not args.from_cidr:
                    print("Error: --break-glass needs at least one --from-cidr source network.", file=sys.stderr)
                    return _EXIT_USAGE
                key_path = Path(args.path).expanduser()
                private_key = _read_import_key(key_path)
                if private_key is None:
                    print("Import cancelled; nothing was stored.", file=sys.stderr)
                    return _EXIT_ABORTED
                try:
                    _print(await _invoke(
                        services, "import_keys", source="ssh", vault_id=args.vault, path=str(key_path),
                        private_key=private_key, name=args.name,
                        break_glass_from_cidrs=args.from_cidr if args.break_glass else None,
                    ), json_output=output)
                finally:
                    _wipe(private_key)
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
        elif command == "auto-bind":
            return await _auto_bind(services, args, output)
        elif command == "rotate":
            if not _confirm(args, "Rotate the vault key version"):
                return _EXIT_ABORTED
            _print(await _invoke(services, "rotate", vault_id=args.vault), json_output=output)
        elif command == "exposures":
            if args.rotate_ssh:
                if not args.team or not args.server:
                    print("Error: --team and at least one --server are required with --rotate-ssh.", file=sys.stderr)
                    return _EXIT_USAGE
                if not _confirm(
                    args, "Rotate the exposed SSH key on every selected server (and the vault key first, if it is due)",
                ):
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
                if not output and isinstance(rotation, Mapping) and rotation.get("vault_key_rotated") is True:
                    print(VAULT_KEY_ROTATED_FIRST)
                if not (isinstance(rotation, Mapping) and rotation.get("rotated") is True):
                    _warn_incomplete_rotation(rotation)
                    return _EXIT_ERROR
                if not _report_exposure_resolution(rotation, args.vault):
                    return _EXIT_ERROR
            elif args.resolve:
                if not args.resolution:
                    print("Error: --resolution is required with --resolve.", file=sys.stderr)
                    return _EXIT_USAGE
                _print(await _invoke(services, "resolve_exposure", vault_id=args.vault, exposure_id=args.resolve, resolution=args.resolution, note=args.note), json_output=output)
            else:
                listed = await _invoke(services, "list_exposures", vault_id=args.vault)
                _print(listed, json_output=output)
                if not output:
                    _note_replaced_keys(listed)
        elif command == "grants":
            if not args.yes and sys.stdin.isatty():
                # Members who need a local approval are asked about one by one.
                processed = await _invoke(
                    services, "process_grants", vault_id=args.vault, approval=_confirm_member_sas,
                )
            else:
                # Nobody to ask (or --yes): they stay pending, never approved.
                processed = await _invoke(services, "process_grants", vault_id=args.vault, interactive=not args.yes)
            if output:
                _print(processed, json_output=True)
            else:
                print(grant_summary(_plain(processed)))
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
    except VaultKeyInUse as exc:
        for label, names in (("Team servers", exc.team_servers), ("Your servers", exc.own_servers),
                             ("Could not check", exc.unchecked)):
            if names:
                print(f"{label}: {', '.join(terminal_safe(name) for name in names)}", file=sys.stderr)
        print(f"Vault operation failed ({vault_failure_reason(exc)}).", file=sys.stderr)
        return _EXIT_ERROR
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

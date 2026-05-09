"""CLI subcommand handlers for ``servonaut hetzner ...``.

Mirrors the shape of :mod:`servonaut.cli.memory` and :mod:`servonaut.cli.ai`:

- :func:`add_hetzner_parser` registers the ``hetzner`` parser on the
  top-level subparsers and returns the parser so :mod:`servonaut.main`
  can dispatch on ``args.subcommand == 'hetzner'``.
- :func:`handle_hetzner_command` is the synchronous entry point invoked
  by ``main.py``; it dispatches on ``args.hetzner_command`` and returns
  an integer exit code.

Subcommand tree::

    servonaut hetzner list                       [--json] [--state STATE]
    servonaut hetzner create NAME                [--type cx23]
                                                 [--image ubuntu-22.04]
                                                 [--location fsn1]
                                                 [--ssh-key NAME|ID] (repeatable)
                                                 [--no-wait] [--json]
    servonaut hetzner destroy NAME_OR_ID         [--yes] [--json]
    servonaut hetzner ssh-keys list              [--json]
    servonaut hetzner ssh-keys add NAME --public-key-file PATH [--json]
    servonaut hetzner server-types               [--json]
    servonaut hetzner test-connection            [--json]

Exit codes:

    0 — success
    1 — generic error / API failure
    2 — Hetzner not configured (no enabled flag, or no token)
    3 — typed confirmation declined for destroy
    4 — argparse / validation error (argparse already exits 2 for usage,
        we use 4 to differentiate semantic input-validation failures)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, Coroutine, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
_EXIT_SUCCESS = 0
_EXIT_GENERIC_ERROR = 1
_EXIT_NOT_CONFIGURED = 2
_EXIT_DECLINED = 3
_EXIT_VALIDATION = 4

_HCLOUD_PUBLIC_KEY_PREFIXES = ('ssh-', 'ecdsa-', 'sk-')


def _run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run *coro* synchronously via :func:`asyncio.run`."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------

def add_hetzner_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Add the ``hetzner`` subcommand tree.

    Args:
        subparsers: The action returned by ``parser.add_subparsers(...)``.

    Returns:
        The newly-created ``hetzner`` parser.
    """
    p = subparsers.add_parser(
        'hetzner',
        help='Manage Hetzner Cloud servers (list / create / destroy / SSH keys).',
    )
    sub = p.add_subparsers(dest='hetzner_command')
    sub.required = True

    # hetzner list
    p_list = sub.add_parser('list', help='List Hetzner Cloud servers.')
    p_list.add_argument('--json', action='store_true',
                        help='Emit JSON instead of a table.')
    p_list.add_argument('--state', metavar='STATE',
                        help='Filter by state (running, stopped, ...).')

    # hetzner create
    p_create = sub.add_parser('create', help='Create a Hetzner Cloud server.')
    p_create.add_argument('name', help='Server name (1-253 chars, [a-zA-Z0-9._-]).')
    p_create.add_argument('--type', dest='server_type', metavar='TYPE',
                          help='Server type (cx23, cpx22, ...). '
                               'Defaults to config.hetzner.default_server_type.')
    p_create.add_argument('--image', metavar='IMAGE',
                          help='Image (ubuntu-22.04, debian-12, ...). '
                               'Defaults to config.hetzner.default_image.')
    p_create.add_argument('--location', metavar='LOCATION',
                          help='Datacentre (fsn1, nbg1, hel1, ash, hil). '
                               'Defaults to config.hetzner.default_location.')
    p_create.add_argument('--ssh-key', dest='ssh_keys', metavar='NAME_OR_ID',
                          action='append',
                          help='SSH key name or ID (Hetzner-side). Repeat to inject '
                               'multiple. Defaults to '
                               'config.hetzner.default_hetzner_ssh_key when omitted.')
    p_create.add_argument('--no-wait', action='store_true',
                          help='Do not block until the server reaches running.')
    p_create.add_argument('--json', action='store_true',
                          help='Emit the new instance dict as JSON.')

    # hetzner destroy
    p_destroy = sub.add_parser('destroy', help='Delete a Hetzner Cloud server.')
    p_destroy.add_argument('identifier', help='Server name or numeric ID.')
    p_destroy.add_argument('--yes', '-y', action='store_true',
                           help='Skip the typed-confirmation prompt (non-interactive).')
    p_destroy.add_argument('--json', action='store_true',
                           help='Emit the result as JSON.')

    # hetzner ssh-keys
    p_keys = sub.add_parser('ssh-keys', help='Manage Hetzner Cloud SSH keys.')
    keys_sub = p_keys.add_subparsers(dest='ssh_keys_command')
    keys_sub.required = True

    p_keys_list = keys_sub.add_parser('list', help='List registered SSH keys.')
    p_keys_list.add_argument('--json', action='store_true',
                             help='Emit JSON instead of a table.')

    p_keys_add = keys_sub.add_parser('add', help='Register a new SSH public key.')
    p_keys_add.add_argument('name', help='Display name for the key.')
    src_group = p_keys_add.add_mutually_exclusive_group(required=True)
    src_group.add_argument('--public-key-file', metavar='PATH',
                           help='Path to a public-key file (e.g. ~/.ssh/id_ed25519.pub).')
    src_group.add_argument('--public-key', metavar='STRING',
                           help='Inline public-key text (less safe — quote carefully).')
    p_keys_add.add_argument('--json', action='store_true',
                            help='Emit JSON.')

    # hetzner server-types
    p_types = sub.add_parser('server-types',
                             help='List available server types and prices.')
    p_types.add_argument('--json', action='store_true',
                         help='Emit JSON instead of a table.')

    # hetzner test-connection
    p_test = sub.add_parser('test-connection',
                            help='Validate the configured token by calling Hetzner.')
    p_test.add_argument('--json', action='store_true', help='Emit JSON.')

    return p


# ---------------------------------------------------------------------------
# Headless service initialisation
# ---------------------------------------------------------------------------

def _build_service():
    """Construct a HetznerService outside of the TUI app context.

    Returns:
        HetznerService instance ready to call.

    Raises:
        SystemExit: With code 2 if Hetzner is not configured at all
            (``config.hetzner.enabled`` is False AND no token is
            resolvable through the chain).
    """
    from servonaut.config.manager import ConfigManager
    from servonaut.services.hetzner_service import (
        HetznerService, HetznerNotConfiguredError, HetznerSDKMissingError,
    )

    cm = ConfigManager()
    cfg = cm.get()
    if not getattr(cfg, 'hetzner', None) or not cfg.hetzner.enabled:
        # The CLI is intentionally lenient here: even if ``enabled=False``,
        # if the token chain resolves we let the user run reads. This
        # matches the broader Servonaut convention of "make the CLI
        # always-on for power users" — the TUI / chat panel respect the
        # opt-in flag; the CLI only needs the token.
        try:
            svc = HetznerService(cfg.hetzner)
            svc.resolve_token()
            return svc
        except HetznerNotConfiguredError as exc:
            print(
                f"Hetzner is not configured: {exc}\n"
                "Enable it with `enabled=true` in ~/.servonaut/config.json's "
                "`hetzner` block, or set $HCLOUD_TOKEN, or write the token "
                "to ~/.config/hcloud/token.",
                file=sys.stderr,
            )
            raise SystemExit(_EXIT_NOT_CONFIGURED) from exc
        except HetznerSDKMissingError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(_EXIT_NOT_CONFIGURED) from exc

    try:
        svc = HetznerService(cfg.hetzner)
        # Force the resolution chain so a misconfigured CLI fails fast
        # with a useful message rather than crashing inside hcloud's
        # request layer.
        svc.resolve_token()
        return svc
    except HetznerNotConfiguredError as exc:
        print(f"Hetzner not configured: {exc}", file=sys.stderr)
        raise SystemExit(_EXIT_NOT_CONFIGURED) from exc
    except HetznerSDKMissingError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(_EXIT_NOT_CONFIGURED) from exc


# ---------------------------------------------------------------------------
# Pretty-printers
# ---------------------------------------------------------------------------

def _print_servers_table(servers: List[dict]) -> None:
    if not servers:
        print("No Hetzner Cloud servers in project.")
        return
    print(f"Hetzner Cloud servers ({len(servers)} total):\n")
    header = (f"  {'Name':<24} {'ID':<10} {'Type':<10} "
              f"{'State':<10} {'Public IP':<16} {'Location':<8}")
    print(header)
    print('  ' + '-' * (len(header) - 2))
    for s in servers:
        print(
            f"  {(s.get('name') or '')[:24]:<24} "
            f"{s.get('id', ''):<10} "
            f"{(s.get('type') or ''):<10} "
            f"{(s.get('state') or ''):<10} "
            f"{(s.get('public_ip') or '-'):<16} "
            f"{(s.get('region') or ''):<8}"
        )


def _print_keys_table(keys: List[dict]) -> None:
    if not keys:
        print("No SSH keys registered on the Hetzner project.")
        return
    print(f"Hetzner SSH keys ({len(keys)} total):\n")
    for k in keys:
        print(f"  {k.get('name', ''):<30} "
              f"id={k.get('id', '')}  "
              f"fingerprint={k.get('fingerprint', '')}")


def _print_server_types_table(types: List[dict]) -> None:
    if not types:
        print("No server types returned by the API.")
        return
    print(f"Hetzner server types ({len(types)} total):\n")
    header = (f"  {'Name':<10} {'Cores':<6} {'RAM(GB)':<8} {'Disk(GB)':<9} "
              f"{'Arch':<6} {'Hourly':<10} {'Monthly':<10} {'CCY':<4} Description")
    print(header)
    print('  ' + '-' * (len(header) - 2))
    for t in types:
        print(
            f"  {t.get('name', ''):<10} "
            f"{str(t.get('cores', 0)):<6} "
            f"{str(t.get('memory_gb', 0)):<8} "
            f"{str(t.get('disk_gb', 0)):<9} "
            f"{(t.get('architecture') or ''):<6} "
            f"{(t.get('hourly_price_gross') or '-'):<10} "
            f"{(t.get('monthly_price_gross') or '-'):<10} "
            f"{(t.get('currency') or '-'):<4} "
            f"{(t.get('description') or '')}"
        )


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _cmd_list(args: argparse.Namespace) -> int:
    svc = _build_service()
    try:
        instances = _run_async(svc.fetch_instances_cached(force_refresh=True))
    except Exception as exc:
        print(f"Error listing servers: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if args.state:
        instances = [i for i in instances if i.get('state') == args.state]

    if args.json:
        print(json.dumps(instances, indent=2, default=str))
    else:
        _print_servers_table(instances)
    return _EXIT_SUCCESS


def _cmd_create(args: argparse.Namespace) -> int:
    svc = _build_service()
    try:
        instance = _run_async(svc.create_server(
            name=args.name,
            server_type=args.server_type,
            image=args.image,
            location=args.location,
            ssh_keys=args.ssh_keys,
            wait_until_running=not args.no_wait,
        ))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_VALIDATION
    except Exception as exc:
        print(f"Error creating server: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if args.json:
        print(json.dumps(instance, indent=2, default=str))
    else:
        print(
            f"Created Hetzner server {instance.get('name')!r} "
            f"(id={instance.get('id')}, type={instance.get('type')}, "
            f"location={instance.get('region')}, "
            f"public_ip={instance.get('public_ip') or '-'}, "
            f"state={instance.get('state')})."
        )
    return _EXIT_SUCCESS


def _cmd_destroy(args: argparse.Namespace) -> int:
    svc = _build_service()

    if not args.yes:
        print(f"About to PERMANENTLY DELETE Hetzner server: {args.identifier!r}")
        try:
            confirm = input("Type the server identifier to confirm: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return _EXIT_DECLINED
        if confirm != args.identifier:
            print(
                f"Confirmation mismatch (expected {args.identifier!r}). "
                "Aborting.",
                file=sys.stderr,
            )
            return _EXIT_DECLINED

    try:
        _run_async(svc.delete_server(args.identifier))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_VALIDATION
    except Exception as exc:
        print(f"Error deleting server: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if args.json:
        print(json.dumps(
            {'deleted': args.identifier, 'success': True},
            indent=2,
        ))
    else:
        print(f"Deleted Hetzner server {args.identifier!r}.")
    return _EXIT_SUCCESS


def _cmd_ssh_keys_list(args: argparse.Namespace) -> int:
    svc = _build_service()
    try:
        keys = _run_async(svc.list_ssh_keys())
    except Exception as exc:
        print(f"Error listing SSH keys: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if args.json:
        print(json.dumps(keys, indent=2, default=str))
    else:
        _print_keys_table(keys)
    return _EXIT_SUCCESS


def _cmd_ssh_keys_add(args: argparse.Namespace) -> int:
    svc = _build_service()
    public_key: Optional[str] = None
    if args.public_key_file:
        try:
            path = Path(args.public_key_file).expanduser()
            public_key = path.read_text().strip()
        except OSError as exc:
            print(f"Error reading public key file: {exc}", file=sys.stderr)
            return _EXIT_VALIDATION
    else:
        public_key = (args.public_key or '').strip()

    if not public_key:
        print("Error: public key is empty.", file=sys.stderr)
        return _EXIT_VALIDATION
    if not public_key.startswith(_HCLOUD_PUBLIC_KEY_PREFIXES):
        print(
            "Error: public key must start with an SSH algorithm prefix "
            "(e.g. 'ssh-ed25519 AAA...').",
            file=sys.stderr,
        )
        return _EXIT_VALIDATION

    try:
        result = _run_async(svc.create_ssh_key(args.name, public_key))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_VALIDATION
    except Exception as exc:
        print(f"Error registering SSH key: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(
            f"Registered SSH key {result.get('name')!r} "
            f"(id={result.get('id')}, fingerprint={result.get('fingerprint')})."
        )
    return _EXIT_SUCCESS


def _cmd_server_types(args: argparse.Namespace) -> int:
    svc = _build_service()
    try:
        types = _run_async(svc.list_server_types())
    except Exception as exc:
        print(f"Error fetching server types: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if args.json:
        print(json.dumps(types, indent=2, default=str))
    else:
        _print_server_types_table(types)
    return _EXIT_SUCCESS


def _cmd_test_connection(args: argparse.Namespace) -> int:
    svc = _build_service()
    try:
        result = _run_async(svc.test_connection())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        if result.get('success'):
            print(result.get('message', 'OK'))
        else:
            print(result.get('message', 'Connection failed.'), file=sys.stderr)
    return _EXIT_SUCCESS if result.get('success') else _EXIT_GENERIC_ERROR


# ---------------------------------------------------------------------------
# Top-level dispatch
# ---------------------------------------------------------------------------

def handle_hetzner_command(args: argparse.Namespace) -> int:
    """Dispatch on ``args.hetzner_command`` and return an exit code."""
    cmd = getattr(args, 'hetzner_command', None)
    try:
        if cmd == 'list':
            return _cmd_list(args)
        if cmd == 'create':
            return _cmd_create(args)
        if cmd == 'destroy':
            return _cmd_destroy(args)
        if cmd == 'ssh-keys':
            ssh_cmd = getattr(args, 'ssh_keys_command', None)
            if ssh_cmd == 'list':
                return _cmd_ssh_keys_list(args)
            if ssh_cmd == 'add':
                return _cmd_ssh_keys_add(args)
            print(f"Unknown ssh-keys subcommand: {ssh_cmd}", file=sys.stderr)
            return _EXIT_VALIDATION
        if cmd == 'server-types':
            return _cmd_server_types(args)
        if cmd == 'test-connection':
            return _cmd_test_connection(args)
    except SystemExit:
        # Propagate _build_service's intentional exits.
        raise
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return _EXIT_GENERIC_ERROR
    except Exception as exc:
        logger.exception("Unhandled error in hetzner subcommand %r", cmd)
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    print(f"Unknown hetzner subcommand: {cmd}", file=sys.stderr)
    return _EXIT_VALIDATION

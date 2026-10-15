"""``servonaut db setup`` — find an app's database settings and store them.

The keyboard companion to the ``db_setup_scan`` / ``db_setup_save`` MCP
tools. It drives the same ``ServonautTools`` engine (read-only scan on the
box → server-side staging → secret store + db_profile) through its
structured sibling :meth:`ServonautTools.db_scan_stage`, so the person sees
a numbered list and picks by number. The staging token and the password
never reach the terminal: not even the masked preview is printed.

Reusing ``ServonautTools`` keeps scan, stage and save behaviour identical
across the MCP, chat, TUI and CLI surfaces; only the presentation differs.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import re
import sys
import unicodedata
from collections.abc import Sequence
from typing import Any

from servonaut.cli.prompting import ctrl_c_interrupts

logger = logging.getLogger(__name__)

# Same exit-code convention as ``servonaut ca`` / ``servonaut vault``.
_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_USAGE = 2
_EXIT_ABORTED = 5  # refused: a non-interactive shell without --yes / --pick
_EXIT_CANCELLED = 130  # 128 + SIGINT, matching the shell convention

_ENGINE_NAMES = {
    "mysql": "MySQL", "mariadb": "MariaDB",
    "postgres": "PostgreSQL", "postgresql": "PostgreSQL",
}
_MANUAL_ENGINES = {
    "mysql": "mysql", "mariadb": "mariadb", "postgres": "postgres",
    "postgresql": "postgres", "pg": "postgres",
}
_DEFAULT_PORTS = {"mysql": 3306, "mariadb": 3306, "postgres": 5432}
_CHOICE_SPLIT = re.compile(r"[,\s]+")
# ASCII digits only: str.isdigit() and \d also accept digits int() rejects (²).
_NUMBER = re.compile(r"[0-9]+")
_RANGE = re.compile(r"([0-9]+)-([0-9]+)")

# (list number, reason) for a candidate that was not stored.
Refusal = tuple[int, str]


def add_db_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "db", help="Database tooling (credential setup for db_processlist etc.)",
    )
    sub = parser.add_subparsers(dest="db_command")
    setup = sub.add_parser(
        "setup",
        help="Find a server's database settings and store them in your secret store.",
    )
    setup.add_argument(
        "instance",
        help="Instance name or ID (<account>/<name> picks one account's server).",
    )
    setup.add_argument(
        "--search-path", default="",
        help="Directory on the box to search (or a local .env path).",
    )
    setup.add_argument(
        "--source", choices=["auto", "ssh", "local"], default="auto",
        help="Where to scan: auto/ssh read the box (default), local reads --search-path.",
    )
    choose = setup.add_mutually_exclusive_group()
    choose.add_argument(
        "--yes", action="store_true",
        help="Store everything found without asking.",
    )
    choose.add_argument(
        "--pick", metavar="N[,M]", default=None,
        help="Store these numbers from the list without asking (e.g. 1 or 1,3).",
    )
    setup.add_argument(
        "--label", metavar="NAME", default="",
        help="Store the database under this name (only when storing exactly one).",
    )
    setup.add_argument(
        "--json", action="store_true",
        help="Print JSON. Stores nothing unless --yes or --pick is given.",
    )
    setup.add_argument(
        "--manual", action="store_true",
        help="Skip the scan and type the connection details yourself.",
    )


def handle_db_command(args: argparse.Namespace) -> int:
    if getattr(args, "db_command", None) != "setup":
        print("Usage: servonaut db setup <instance> [--search-path PATH] "
              "[--source auto|ssh|local] [--yes | --pick N[,M]] [--label NAME] "
              "[--json] [--manual]")
        return _EXIT_ERROR
    try:
        return asyncio.run(_run_setup(args))
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return _EXIT_CANCELLED


def _build_tools():
    """Construct a minimal ServonautTools for the CLI (user-authorized)."""
    from dataclasses import replace

    from servonaut.config.manager import ConfigManager
    from servonaut.services.accounts.headless import build_account_registry
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.scp_service import SCPService
    from servonaut.mcp.guards import CommandGuard
    from servonaut.mcp.audit import AuditTrail
    from servonaut.mcp.tools import ServonautTools

    config_manager = ConfigManager()
    config = config_manager.get()
    # Every provider account, so any server of any account can be set up.
    accounts = build_account_registry(config_manager)
    aws_service = accounts.default_service("aws")

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
        aws_service=aws_service,
        custom_server_service=CustomServerService(config_manager),
        cache_service=aws_service.cache_service,
        ssh_service=SSHService(config_manager),
        connection_service=ConnectionService(config_manager),
        scp_service=SCPService(ssh_config=config.ssh),
        guard=guard,
        audit=AuditTrail(config.mcp.audit_path),
        secret_provider=secret_provider,
        hetzner_service=accounts.default_service("hetzner"),
        ovh_service=accounts.default_service("ovh"),
        account_registry=accounts,
    ), secret_provider


# ---------------------------------------------------------------------------
# Flow
# ---------------------------------------------------------------------------

async def _run_setup(args: argparse.Namespace) -> int:
    problem = _flag_problem(args)
    if problem:
        return _fail(args, problem, _EXIT_USAGE)
    if args.manual:
        return await _run_manual(args)

    tools, secret_provider = _build_tools()
    # Checked before the scan: finding passwords that cannot be stored helps no one.
    if secret_provider is None:
        return _fail(args, _no_secret_store_message(), _EXIT_ERROR)

    if not args.json:
        print(f"Scanning {_printable(args.instance)} for database settings (read-only)...")
    # The batch store has no count cap, so a box with many sites cannot
    # evict its own earliest results before they are stored.
    result = await tools.db_scan_stage(
        args.instance, search_path=args.search_path, source=_scan_source(args),
        staging=tools.open_db_staging_batch(),
    )
    if result.get("error"):
        return _fail(args, _scan_error_message(args, str(result["error"])), _EXIT_ERROR)
    candidates: list[dict[str, Any]] = list(result.get("candidates") or [])
    if not candidates:
        return _report_nothing_found(args)

    if args.json:
        return await _finish_json(tools, args, candidates)
    return await _finish_in_terminal(tools, args, candidates, secret_provider)


def _scan_source(args: argparse.Namespace) -> str:
    """The source to scan with: ``auto`` without a local file is ``ssh``.

    ``auto`` falls back to reading --search-path locally, and for that
    fallback it hides SSH failures. Without a local file to fall back to
    there is nothing to gain, and a refused host key or an unusable SSH key
    would read as "nothing found".
    """
    if args.source != "auto":
        return args.source
    path = os.path.expanduser(args.search_path) if args.search_path else ""
    return "auto" if path and os.path.isfile(path) else "ssh"


def _flag_problem(args: argparse.Namespace) -> str:
    """Return why the flags cannot work together, or ``""`` when they can."""
    if args.manual:
        clashing = [flag for flag, used in (
            ("--yes", args.yes), ("--pick", args.pick is not None),
            ("--json", args.json), ("--search-path", bool(args.search_path)),
            ("--source", args.source != "auto"),
        ) if used]
        if clashing:
            return f"--manual does not scan, so it cannot be combined with {', '.join(clashing)}."
        return ""
    if args.source == "local" and not args.search_path:
        return "--source local reads the file given with --search-path, so name one."
    if args.pick is not None and _parse_numbers(args.pick, None) is None:
        return f"--pick takes numbers from the list, like 1 or 1,3 (got {args.pick!r})."
    if args.source in ("auto", "ssh"):
        # db_scan_stage builds the on-box command from these roots; refuse
        # here so a bad path is a usage error, not a crash mid-scan.
        from servonaut.services.db_credential_scanner import validate_search_roots
        try:
            validate_search_roots(args.search_path)
        except ValueError:
            return "--search-path may only contain folder paths and glob patterns."
    return ""


async def _finish_in_terminal(tools, args, candidates, secret_provider) -> int:
    asking = not args.yes and args.pick is None
    _print_candidates(candidates)
    if asking and not _is_interactive():
        print("Nothing stored. Run with --yes or --pick N to store without asking.",
              file=sys.stderr)
        return _EXIT_ABORTED

    if args.yes:
        numbers = list(range(1, len(candidates) + 1))
    elif args.pick is not None:
        numbers = _parse_numbers(args.pick, len(candidates))
        if numbers is None:
            return _fail(args, _out_of_range(args.pick, len(candidates)), _EXIT_USAGE)
    elif args.label and len(candidates) > 1:
        numbers = _ask_one(candidates, args.label)
    else:
        numbers = _ask_which(candidates)
    if not numbers:
        print("Nothing stored.")
        return _EXIT_OK
    if args.label and len(numbers) > 1:
        return _fail(args, _label_needs_one(len(numbers)), _EXIT_USAGE)

    labels, skipped = _labels_for(args, candidates, numbers, ask=asking)
    for number, reason in skipped:
        print(f"Skipped #{number}: {reason}", file=sys.stderr)
    saved, failed = await _store(tools, args.instance, candidates, labels)
    _report_stored(candidates, labels, saved, failed, secret_provider)
    return _EXIT_ERROR if failed or skipped else _EXIT_OK


async def _finish_json(tools, args, candidates) -> int:
    report: dict[str, Any] = {
        "instance": args.instance, "error": None,
        "candidates": [_public_candidate(n, c) for n, c in enumerate(candidates, 1)],
        "saved": [], "failed": [],
    }
    if args.yes:
        numbers = list(range(1, len(candidates) + 1))
    elif args.pick is not None:
        numbers = _parse_numbers(args.pick, len(candidates))
        if numbers is None:
            report["error"] = _out_of_range(args.pick, len(candidates))
            _print_json(report)
            return _EXIT_USAGE
    else:
        _print_json(report)
        return _EXIT_OK
    if args.label and len(numbers) > 1:
        report["error"] = _label_needs_one(len(numbers))
        _print_json(report)
        return _EXIT_USAGE

    labels, skipped = _labels_for(args, candidates, numbers, ask=False)
    saved, failed = await _store(tools, args.instance, candidates, labels)
    report["saved"] = [{"number": n, "label": labels[n]} for n in saved]
    report["failed"] = [{"number": n, "message": reason} for n, reason in skipped + failed]
    _print_json(report)
    return _EXIT_ERROR if report["failed"] else _EXIT_OK


async def _run_manual(args: argparse.Namespace) -> int:
    """Store connection details typed at the keyboard (no scan).

    The password is read with getpass and staged in the tools' public batch
    store, then committed by :meth:`ServonautTools.db_setup_save` like a
    scanned candidate, so the secret name, the db_profile and replacing an
    earlier profile for the same site behave exactly as after a scan.
    """
    if not _is_interactive():
        print("--manual asks for the password, so run it in a terminal.", file=sys.stderr)
        return _EXIT_ABORTED
    tools, secret_provider = _build_tools()
    if secret_provider is None:
        return _fail(args, _no_secret_store_message(), _EXIT_ERROR)
    # Checked before the questions, so a mistyped name does not throw away
    # everything typed, password included.
    problem = await _unknown_instance(tools, args.instance)
    if problem:
        return _fail(args, problem, _EXIT_ERROR)

    from servonaut.services.db_credential_scanner import DBCandidate

    print(f"Database details for {_printable(args.instance)} (nothing is scanned).")
    engine = _ask_engine()
    preview: dict[str, Any] = {
        "engine": engine,
        "host": _ask_text("Host", default="127.0.0.1"),
        "port": _ask_port(_DEFAULT_PORTS[engine]),
        "user": _ask_text("User"),
        "database": _ask_text("Database", default="", default_hint="none"),
    }
    password = ""
    while not password:
        with ctrl_c_interrupts():
            password = getpass.getpass("Password (not shown): ")
    label = args.label.strip() or _ask_text("Label", default="", default_hint="none")

    token = tools.open_db_staging_batch().stage(DBCandidate(password=password, **preview))
    saved, failed = await _store(tools, args.instance, [{**preview, "token": token}], {1: label})
    _report_stored([preview], {1: label}, saved, failed, secret_provider)
    return _EXIT_ERROR if failed else _EXIT_OK


async def _unknown_instance(tools, instance: str) -> str:
    """Why *instance* cannot be saved under, or ``""`` when it can."""
    from servonaut.services.accounts.registry import UnknownAccountError
    from servonaut.utils.instance_resolver import AmbiguousInstanceError

    try:
        found = await tools.find_db_setup_instance(instance)
    except (AmbiguousInstanceError, UnknownAccountError) as exc:
        return _printable(exc)
    return "" if found else f"Instance not found: {_printable(instance)}"


# ---------------------------------------------------------------------------
# Choosing and labelling
# ---------------------------------------------------------------------------

def _is_interactive() -> bool:
    return bool(sys.stdin and sys.stdin.isatty())


def _prompt(text: str) -> str:
    """``input()`` that Ctrl+C interrupts, although asyncio.run is running."""
    with ctrl_c_interrupts():
        return input(text)


def _parse_numbers(text: str, count: int | None) -> list[int] | None:
    """Parse ``1``, ``1,3``, ``1 3``, ``1-3`` or ``all`` into list numbers.

    With *count* ``None`` only the syntax is checked (a flag read before the
    scan). Returns the numbers in list order without repeats, or ``None``
    when the text is not a selection or names a number outside the list.
    """
    words = [w for w in _CHOICE_SPLIT.split(text.strip().lower()) if w]
    if not words:
        return None
    if words == ["all"]:
        return list(range(1, count + 1)) if count is not None else []
    chosen = set()
    for word in words:
        span = _RANGE.fullmatch(word)
        if span:
            first, last = int(span.group(1)), int(span.group(2))
        elif _NUMBER.fullmatch(word):
            first = last = int(word)
        else:
            return None
        if first < 1 or last < first or (count is not None and last > count):
            return None
        chosen.update(range(first, last + 1))
    return sorted(chosen)


def _ask_which(candidates: Sequence[dict[str, Any]]) -> list[int]:
    """Ask which candidates to store; ``[]`` means store nothing."""
    count = len(candidates)
    if count == 1:
        while True:
            answer = _prompt("Store it? [Y/n]: ").strip().lower()
            if answer in ("", "y", "yes"):
                return [1]
            if answer in ("n", "no", "none"):
                return []
            print("Type y to store it or n to leave it.")
    while True:
        answer = _prompt(f"Store which? [{_shown(count)}, all, none — Enter = all]: ")
        answer = answer.strip().lower()
        if answer in ("", "all"):
            return list(range(1, count + 1))
        if answer in ("none", "n", "no"):
            return []
        numbers = _parse_numbers(answer, count)
        if numbers:
            return numbers
        print(f"Type a number from 1 to {count}, a list like 1,2, all, or none.")


def _ask_one(candidates: Sequence[dict[str, Any]], label: str) -> list[int]:
    """With --label only one database can be stored: ask for one number."""
    count = len(candidates)
    while True:
        answer = _prompt(f"Store which one as '{_printable(label)}'? "
                         f"[{_shown(count)}, none]: ").strip().lower()
        if answer in ("none", "n", "no"):
            return []
        numbers = _parse_numbers(answer, count)
        if numbers and len(numbers) == 1:
            return numbers
        print(f"--label names one database: type one number from 1 to {count}, or none.")


def _shown(count: int) -> str:
    return ", ".join(str(n) for n in range(1, count + 1)) if count <= 4 else f"1-{count}"


def _stored_as(label: str) -> str:
    """The part of the secret name db_setup_save derives from *label*.

    Labels that differ only in case, spaces or punctuation ("My Shop" and
    "my-shop") name the same secret, so they count as one label here.
    """
    from servonaut.services.db_credential_scanner import sanitize_label

    return "/" + sanitize_label(label) if label.strip() else ""


def _labels_for(args, candidates, numbers, *, ask: bool) -> tuple[dict[int, str], list[Refusal]]:
    """Pick the label each chosen candidate is stored under.

    A database is stored per (server, label), so two databases under one
    label would replace each other: when asking, the person is asked for
    another name; otherwise the later one is skipped and said so.
    """
    labels: dict[int, str] = {}
    skipped: list[Refusal] = []
    used: dict[str, int] = {}
    for number in numbers:
        derived = str(candidates[number - 1].get("label") or "").strip()
        if args.label:
            label = args.label.strip()
        elif ask:
            label = _ask_label(number, derived, used)
        else:
            label = derived
        key = _stored_as(label)
        if key in used:
            name = f"'{_printable(label)}'" if label else "no label"
            skipped.append((number, (
                f"its label ({name}) is stored under the same name as #{used[key]}, "
                f"so storing it would replace #{used[key]}. Store it on its own with "
                f"--pick {number} --label NAME."
            )))
            continue
        used[key] = number
        labels[number] = label
    return labels, skipped


def _ask_label(number: int, derived: str, used: dict[str, int]) -> str:
    """Ask for a label, pre-filled with the one derived from the config path."""
    hint = _printable(derived) if derived else "none"
    while True:
        answer = _prompt(f"Label for #{number} (Enter = {hint}): ").strip() or derived
        key = _stored_as(answer)
        if key not in used:
            return answer
        print(f"#{used[key]} is already stored under that name; choose another label "
              "so one does not replace the other.")


def _ask_text(prompt: str, *, default: str | None = None, default_hint: str = "") -> str:
    """Ask for a value; required when *default* is ``None``."""
    hint = default_hint or default
    suffix = f" (Enter = {hint})" if default is not None else ""
    while True:
        answer = _prompt(f"{prompt}{suffix}: ").strip()
        if answer:
            return answer
        if default is not None:
            return default
        print(f"{prompt} is required.")


def _ask_engine() -> str:
    while True:
        answer = _prompt("Engine [mysql, mariadb, postgres] (Enter = mysql): ").strip().lower()
        engine = _MANUAL_ENGINES.get(answer or "mysql")
        if engine:
            return engine
        print("Type mysql, mariadb or postgres.")


def _ask_port(default: int) -> int:
    while True:
        answer = _prompt(f"Port (Enter = {default}): ").strip()
        if not answer:
            return default
        if _NUMBER.fullmatch(answer) and 0 < int(answer) < 65536:
            return int(answer)
        print("Type a port number from 1 to 65535.")


# ---------------------------------------------------------------------------
# Storing
# ---------------------------------------------------------------------------

async def _store(tools, instance: str, candidates, labels: dict[int, str]):
    """Save each chosen candidate.

    Returns ``({number: save result}, [(number, reason), ...])``.
    """
    saved: dict[int, str] = {}
    failed: list[Refusal] = []
    for number, label in labels.items():
        token = candidates[number - 1]["token"]
        out = await tools.db_setup_save(token, instance_id=instance, label=label)
        if out.startswith("Saved"):
            saved[number] = out
        else:
            failed.append((number, _save_error(out)))
    return saved, failed


def _save_error(out: str) -> str:
    """Turn a db_setup_save refusal into a sentence for a person."""
    text = out.strip()
    if "staging token" in text and "dropped because too many" in text:
        return ("too many results were waiting to be stored at once. Store fewer "
                "at a time with --pick, or narrow the scan with --search-path.")
    if "staging token" in text:
        # The staged password expired while a prompt waited.
        return "the scan result expired before it was stored. Run the command again."
    text = text.removeprefix("Error: ")
    return text.splitlines()[0] if text else "unknown error"


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _printable(value: Any) -> str:
    """Replace control characters in text read off a server before printing.

    Config files on the box are not trusted: an escape sequence in a user
    name or path would otherwise be interpreted by the terminal.
    """
    return "".join(
        "?" if unicodedata.category(ch) in ("Cc", "Cf") else ch
        for ch in str(value)
    )


def _location(candidate: dict[str, Any]) -> str:
    where = (f"{candidate.get('user', '?')}@{candidate.get('host', '?')}"
             f":{candidate.get('port', '?')}")
    database = candidate.get("database")
    return _printable(f"{where}/{database}" if database else where)


def _engine_name(candidate: dict[str, Any]) -> str:
    engine = str(candidate.get("engine") or "?")
    return _ENGINE_NAMES.get(engine.lower(), _printable(engine))


def _print_candidates(candidates: Sequence[dict[str, Any]]) -> None:
    rows = [
        (str(n), _engine_name(c), _location(c), _printable(c.get("source") or ""))
        for n, c in enumerate(candidates, 1)
    ]
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    print(f"Found {len(rows)}:")
    for number, engine, location, source in rows:
        line = f"  {number:>{widths[0]}}  {engine:<{widths[1]}}  {location:<{widths[2]}}"
        print(f"{line}  from {source}" if source else line.rstrip())


def _report_stored(candidates, labels, saved, failed, secret_provider) -> None:
    from servonaut.services.secrets_status import describe_secret_store

    def name(number: int) -> str:
        label = labels.get(number, "")
        return _printable(label) if label else _location(candidates[number - 1])

    for number, reason in failed:
        print(f"Could not store {name(number)}: {_printable(reason)}", file=sys.stderr)
    if not saved:
        return
    print(f"Saved {_join([name(n) for n in saved])} to "
          f"{describe_secret_store(secret_provider)}.")
    for out in saved.values():
        for note in _save_notes(out):
            print(note)
    them = "it" if len(saved) == 1 else "them"
    print(f"Agents and the TUI can now use {them} (db_processlist, db_top_queries).")


def _save_notes(out: str) -> list[str]:
    """The note/warning lines of a save result, worded for a person."""
    notes = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        for prefix in ("note: ", "WARNING: "):
            if line.startswith(prefix):
                body = line[len(prefix):]
                notes.append("Note: " + body[:1].upper() + body[1:])
    return notes


def _join(names: list[str]) -> str:
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " and " + names[-1]


def _report_nothing_found(args: argparse.Namespace) -> int:
    from servonaut.services.db_credential_scanner import validate_search_roots

    if args.source == "local":
        places = [args.search_path] if args.search_path else []
    else:
        places = validate_search_roots(args.search_path)
    if args.json:
        _print_json({
            "instance": args.instance, "error": None, "candidates": [],
            "saved": [], "failed": [], "searched": places,
        })
        return _EXIT_OK
    instance = _printable(args.instance)
    if args.source == "local":
        print(f"No database settings found in {_printable(args.search_path)}.")
        print("--source local reads one file on this computer; name the app's "
              "settings file itself, not its folder.")
        return _EXIT_OK
    print(f"No database settings found on {instance}.")
    if places:
        shown = ["the SSH user's home folder" if p == "." else _printable(p) for p in places]
        print(f"Looked in {_join(shown)}.")
    print("If the app lives somewhere else, point the scan at its folder:\n"
          f"  servonaut db setup {instance} --search-path /path/to/app")
    return _EXIT_OK


def _scan_error_message(args: argparse.Namespace, error: str) -> str:
    kind, _, detail = error.partition(": ")
    instance = _printable(args.instance)
    if kind == "ssh_error":
        return f"Could not scan {instance} over SSH: {_printable(detail)}"
    if kind == "local_read":
        return f"Could not read {_printable(args.search_path)}: {_printable(detail)}"
    return _printable(error)


def _no_secret_store_message() -> str:
    """Explain why no secret store is active and name the command that fixes it."""
    reason = "storing database passwords needs a secret store"
    try:
        from servonaut.services.auth_service import AuthService
        signed_in = AuthService().is_authenticated
    except Exception:  # noqa: BLE001 — unsure means give the sign-in advice
        signed_in = False
    if not signed_in:
        return (f"Nothing was scanned: {reason}, and you are not signed in.\n"
                "Run `servonaut login`, then run this command again.")
    return (f"Nothing was scanned: {reason}, and your plan does not include one "
            "(Solo and Teams plans do).\n"
            "Run `servonaut secrets status` to see your plan and secret store.")


def _public_candidate(number: int, candidate: dict[str, Any]) -> dict[str, Any]:
    """A candidate for --json: connection shape only, no token, no password."""
    return {
        "number": number,
        "engine": candidate.get("engine", ""),
        "user": candidate.get("user", ""),
        "host": candidate.get("host", ""),
        "port": candidate.get("port"),
        "database": candidate.get("database", ""),
        "source": candidate.get("source", ""),
        "label": candidate.get("label", ""),
    }


def _out_of_range(pick: str, count: int) -> str:
    return f"--pick {pick} does not match the list: found {count} (numbers 1 to {count})."


def _label_needs_one(count: int) -> str:
    return (f"--label names one database, but {count} were chosen. "
            "Use --pick N --label NAME to store one.")


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2))


def _fail(args: argparse.Namespace, message: str, code: int) -> int:
    if getattr(args, "json", False):
        _print_json({"instance": args.instance, "error": message,
                     "candidates": [], "saved": [], "failed": []})
    else:
        print(message, file=sys.stderr)
    return code

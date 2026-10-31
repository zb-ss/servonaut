"""CLI subcommand handlers for ``servonaut memory``."""

from __future__ import annotations

import asyncio
import getpass
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from servonaut.utils.instance_resolver import AmbiguousInstanceError
from servonaut.services.memory.provider import instance_provider
from servonaut.services.memory.status import STOPPED_REASON, is_stopped_instance
from servonaut.services.ssh_host_keys import home_relative
from servonaut.utils.editor import editor_argv

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
_EXIT_SUCCESS = 0
_EXIT_NOT_FOUND = 1
_EXIT_OPT_OUT = 2
_EXIT_PARTIAL_FAILURE = 3
_EXIT_USAGE_ERROR = 4
_EXIT_USER_ABORT = 5
_EXIT_GENERIC_ERROR = 6


# ---------------------------------------------------------------------------
# Async wrapper
# ---------------------------------------------------------------------------

def _run_async(coro: Any) -> Any:
    """Run *coro* synchronously via ``asyncio.run``."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Headless service initialisation (mirrors mcp/server.py create_mcp_server)
# ---------------------------------------------------------------------------

def _vault_runtime() -> Any:
    """The signed-in user's vault runtime, or None (signed out, no vault)."""
    try:
        from servonaut.services.vault.command_service import VaultCommandService

        return VaultCommandService.from_local_session()
    except Exception as exc:  # noqa: BLE001 - signed out or an older service
        logger.debug("Vault runtime unavailable for memory probes: %s", type(exc).__name__)
        return None


def _connection_rows_supplier(vault_runtime: Any, fleet: Any) -> Any:
    """A rows supplier for ``MemoryService.set_connection_rows``.

    Returns ``(team_rows, fleet_rows)``: the teams' shared servers (read once
    per run, none when signed out or the read fails: a build never waits on
    or fails for the team service) and the cached fleet plus those.
    """
    teams_service = getattr(vault_runtime, "teams", None)
    state: Dict[str, Any] = {"rows": None, "lock": None}

    async def shared_rows() -> List[Dict[str, Any]]:
        if teams_service is None:
            return []
        if state["lock"] is None:
            state["lock"] = asyncio.Lock()
        async with state["lock"]:
            if state["rows"] is None:
                from servonaut.services.shared_servers import load_shared_servers  # noqa: PLC0415

                try:
                    teams = [t for t in await teams_service.list_teams() if isinstance(t, dict)]
                    state["rows"] = (await load_shared_servers(teams_service, teams)).rows
                except Exception as exc:  # noqa: BLE001 - signed out, offline, no team plan
                    logger.debug("Team shared servers not listed (%s)", type(exc).__name__)
                    state["rows"] = []
        return list(state["rows"])

    async def supply() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        shared = await shared_rows()
        return shared, [*fleet.instances(), *shared]

    return supply


def _init_headless_services() -> Tuple[Any, Any, Any]:
    """Initialise Config, MemoryService and the cached fleet.

    The fleet holds every account's cached servers of every provider (AWS,
    OVH, Hetzner) plus the custom servers.

    Returns:
        ``(config, memory_service, fleet)``
    """
    from servonaut.config.manager import ConfigManager
    from servonaut.services.accounts.headless import CachedFleet
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.log_viewer_service import LogViewerService
    from servonaut.services.memory import MemoryService
    from servonaut.services.memory.store import MemoryStore
    from servonaut.services.memory.redaction import default_redactor, noop_redactor
    from servonaut.services.memory.modules import build_default_probers

    config_manager = ConfigManager()
    config = config_manager.get()

    ssh_service = SSHService(config_manager)
    connection_service = ConnectionService(config_manager)
    log_viewer_service = LogViewerService(config_manager)
    custom_server_service = CustomServerService(config_manager)

    _memory_redactor = (
        default_redactor if config.memory.redaction_enabled else noop_redactor
    )
    memory_service = MemoryService(
        store=MemoryStore(redactor=_memory_redactor),
        config=config.memory,
        probers=build_default_probers(
            log_viewer_service=log_viewer_service,
            ssh_service=ssh_service,
            connection_service=connection_service,
        ),
        ssh_service=ssh_service,
        connection_service=connection_service,
    )
    # Back-reference for log-viewer cache lookups.
    log_viewer_service.set_memory_service(memory_service)
    # Probes use a server's Servonaut Vault key when it has one. One lease
    # cache serves the whole run, so servers behind one bastion share its
    # lease (and one lookup) instead of fetching it once each. The vault
    # runtime owns every lease; the cache never closes one, and the private
    # agents end with the process.
    vault_runtime = _vault_runtime()
    if vault_runtime is not None:
        from servonaut.services.ssh_credentials import VaultLeaseCache  # noqa: PLC0415

        vault_leases = VaultLeaseCache()
        memory_service.set_vault_runtime(vault_runtime, vault_leases)
        log_viewer_service.set_vault_runtime(vault_runtime, vault_leases)

    fleet = CachedFleet.from_config(config, custom_server_service, config_manager)
    # Team keys and a bastion's vault key need the teams' servers and the fleet.
    if vault_runtime is not None:
        memory_service.set_connection_rows(_connection_rows_supplier(vault_runtime, fleet))
    return config, memory_service, fleet


# ---------------------------------------------------------------------------
# Team copies
# ---------------------------------------------------------------------------

#: Subcommands that read or change one server's record, or probe: they merge a
#: team's copy into the user's own record first. ``clear`` and ``purge`` do not
#: (no merge right before deleting).
_MERGING_COMMANDS = frozenset({"build", "refresh", "show", "export", "annotate", "pin", "pull"})


async def _merge_team_copies(memory_service: Any) -> Any:
    from servonaut.services.memory.headless_merge import HeadlessTeamMerge  # noqa: PLC0415

    _team_rows, fleet_rows = await memory_service.connection_rows()
    if not fleet_rows:
        return None
    return await HeadlessTeamMerge(memory_service).run(fleet_rows)


def _merge_team_copies_first(memory_service: Any) -> None:
    """Fold team copies into the user's own records before the command reads them.

    Reads the rows the run already reads once (signed out, or no vault runtime,
    means no shared rows and no pass). What was merged goes to stderr so
    ``--json`` stdout is unchanged; a failed pass is logged and never fails the
    command.
    """
    try:
        report = _run_async(_merge_team_copies(memory_service))
    except Exception as exc:  # noqa: BLE001 - the command goes on without the merge
        logger.warning("Merging team copies of server memory failed (%s)", type(exc).__name__)
        return
    if report is not None and report.copies:
        print(report.message(), file=sys.stderr)


# ---------------------------------------------------------------------------
# Instance resolution
# ---------------------------------------------------------------------------

def _list_all_instances(fleet: Any) -> List[Dict[str, Any]]:
    """Return every cached server: AWS, custom, OVH and Hetzner, all accounts."""
    return fleet.instances()


def _resolve_or_exit(
    args: Any,
    fleet: Any,
    use_json: bool = False,
) -> Optional[Dict[str, Any]]:
    """Resolve instance from args.instance (if present), printing error on failure.

    Accepts an id, a name or an ``<account>/<name>`` reference (see
    :mod:`servonaut.utils.instance_resolver`). It is resolved against the
    cached rows and every account never listed on this machine, read once
    (see ``CachedFleet.checked_rows``); an account whose servers could not
    be checked gets a note on stderr.

    Raises:
        AmbiguousInstanceError: The reference names several servers; the
            caller reports it with :func:`_report_ambiguous`.
        UnknownAccountError: It is qualified with an account that cannot
            connect; reported with :func:`_report_unavailable_account`.
    """
    instance_arg = getattr(args, "instance", None)
    if not instance_arg:
        return None

    checked = _run_async(fleet.checked_rows(instance_arg))
    for note in checked.notes:
        print(note, file=sys.stderr)
    inst = fleet.resolve(instance_arg, rows=checked.rows)
    if inst is None:
        msg = f"Instance not found: {instance_arg!r}"
        if use_json:
            print(json.dumps({"error": {"code": "not_found", "message": msg}}))
        else:
            print(f"Error: {msg}", file=sys.stderr)
        return None
    return inst


def _report_ambiguous(exc: AmbiguousInstanceError, use_json: bool) -> int:
    """Print an ambiguous reference with its candidates; return the exit code."""
    if use_json:
        from servonaut.utils.instance_resolver import candidate_reference
        print(json.dumps({"error": {
            "code": "ambiguous",
            "message": str(exc),
            "candidates": [candidate_reference(row, exc.candidates) for row in exc.candidates],
        }}))
    else:
        print(f"Error: {exc}", file=sys.stderr)
    return _EXIT_USAGE_ERROR


def _report_unavailable_account(exc: Exception, use_json: bool) -> int:
    """Print why an ``<account>/...`` reference cannot be used; return the exit code."""
    if use_json:
        print(json.dumps({"error": {"code": "account_unavailable", "message": str(exc)}}))
    else:
        print(f"Error: {exc}", file=sys.stderr)
    return _EXIT_NOT_FOUND


def _check_opt_out(
    instance_id: str,
    config: Any,
    use_json: bool = False,
    instance_name: str = "",
) -> bool:
    """Return True if this instance is opted out of memory. Prints error if so."""
    memory_config = config.memory
    if not memory_config.enabled:
        msg = "Memory is disabled in configuration."
        if use_json:
            print(json.dumps({"error": {"code": "opt_out", "message": msg}}))
        else:
            print(f"Memory disabled for {instance_id}", file=sys.stderr)
        return True
    # Check by both id and name so name-based overrides fire correctly.
    if memory_config.is_instance_disabled(instance_id, instance_name):
        msg = f"Memory disabled for {instance_id}"
        if use_json:
            print(json.dumps({"error": {"code": "opt_out", "message": msg}}))
        else:
            print(msg, file=sys.stderr)
        return True
    return False


# ---------------------------------------------------------------------------
# Sub-subcommand handlers
# ---------------------------------------------------------------------------

def _report_unreached(inst: Dict[str, Any], message: str, use_json: bool = False) -> int:
    """Say why nothing was probed; the stored memory is unchanged."""
    iid = inst.get("id") or inst.get("name", "?")
    if use_json:
        print(json.dumps({"error": {"instance_id": iid, "message": message}}, indent=2))
    print(f"Memory for {iid} was not updated: {message}", file=sys.stderr)
    return _EXIT_GENERIC_ERROR


def _report_unsaved(report: Any) -> int:
    """Say which probed modules were not stored; the exit code reflects it.

    Nothing saved is a generic error, some saved is a partial failure.
    """
    message = report.unsaved_message
    if message is None:
        return _EXIT_SUCCESS
    print(message, file=sys.stderr)
    return _EXIT_PARTIAL_FAILURE if report.has_any_success else _EXIT_GENERIC_ERROR


def _cmd_build(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any]) -> int:
    """Handle ``memory build``."""
    use_json = getattr(args, "json", False)
    modules = getattr(args, "modules", None) or None

    async def _do_build() -> int:
        report = await memory_service.build_report(inst, modules)
        results = report.successes
        if report.unreached_message:
            return _report_unreached(inst, report.unreached_message, use_json)
        if use_json:
            out: Dict[str, Any] = {
                k: {
                    "module": v.module,
                    "probed_at": v.probed_at,
                    "partial": v.partial,
                    "truncated": v.truncated,
                    "observed_keys": list(v.observed.keys()),
                }
                for k, v in results.items()
            }
            # Saved modules only: the unsaved ones are named on stderr and in
            # the exit code, so every value stays a module object.
            print(json.dumps(out, indent=2))
        else:
            iid = inst.get("id") or inst.get("name", "?")
            if results:
                print(f"Built memory for {iid}: {', '.join(sorted(results))}")
            elif not report.unsaved:
                print(f"No modules probed for {iid} (check opt-out / disabled modules).")
        return _report_unsaved(report)

    return _run_async(_do_build())


async def _build_all(
    instances: List[Dict[str, Any]],
    memory_service: Any,
    modules: Optional[List[str]],
    skipped: Optional[List[str]] = None,
) -> List[Tuple[str, str]]:
    """Build memory for all *instances*, at most 5 concurrent probes.

    Returns ``(instance id, reason)`` for every server whose build failed or
    could not reach it. Servers the provider reports stopped are not
    failures: their ids are appended to *skipped* when given.
    """
    sem = asyncio.Semaphore(5)
    failures: List[Tuple[str, str]] = []
    # Stopped servers are set aside before anything is announced: "Probing"
    # and the running count cover only the servers a probe will try.
    stopped = [inst for inst in instances if is_stopped_instance(inst)]
    instances = [inst for inst in instances if not is_stopped_instance(inst)]
    if skipped is not None:
        skipped.extend(inst.get("id") or inst.get("name", "?") for inst in stopped)
    total = len(instances)
    counter = 0
    lock = asyncio.Lock()

    async def one(inst: Dict[str, Any]) -> None:
        nonlocal counter
        iid = inst.get("id") or inst.get("name", "?")
        async with lock:
            counter += 1
            n = counter
        async with sem:
            try:
                print(f"[{n}/{total}] Probing {iid}...", flush=True)
                report = await memory_service.build_report(inst, modules)
            except Exception as exc:
                failures.append((iid, str(exc)))
                return
            if report.overall_reason == STOPPED_REASON:
                if skipped is not None:
                    skipped.append(iid)
            elif report.unreached_message:
                failures.append((iid, report.unreached_message))
            elif report.unsaved_message:
                failures.append((iid, report.unsaved_message))

    await asyncio.gather(*(one(i) for i in instances))
    return failures


def _cmd_build_all(
    args: Any,
    config: Any,
    memory_service: Any,
    fleet: Any,
) -> int:
    """Handle ``memory build --all``."""
    instances = _list_all_instances(fleet)
    if not instances:
        print("No instances found.", file=sys.stderr)
        return _EXIT_NOT_FOUND

    modules = getattr(args, "modules", None) or None
    skipped: List[str] = []
    failures = _run_async(_build_all(instances, memory_service, modules, skipped))

    if skipped:
        print(f"{len(skipped)} server(s) skipped: stopped", file=sys.stderr)
    if failures:
        for iid, reason in failures:
            print(f"FAILED {iid}: {reason}", file=sys.stderr)
        return _EXIT_PARTIAL_FAILURE
    return _EXIT_SUCCESS


def _cmd_refresh(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any]) -> int:
    """Handle ``memory refresh``."""
    modules = getattr(args, "modules", None) or None

    async def _do_refresh() -> int:
        report = await memory_service.refresh_report(inst, modules)
        if report.unreached_message:
            return _report_unreached(inst, report.unreached_message)
        results = report.successes
        iid = inst.get("id") or inst.get("name", "?")
        if results or not report.unsaved:
            print(f"Refreshed memory for {iid}: {', '.join(sorted(results)) if results else '(none)'}")
        return _report_unsaved(report)

    return _run_async(_do_refresh())


def _cmd_show(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any]) -> int:
    """Handle ``memory show``.

    When ``--stale`` is set, only data for stale modules is emitted.
    """
    fmt = getattr(args, "format", "summary") or "summary"
    use_json = fmt == "json"
    module_filter = getattr(args, "module", None)
    stale_only = getattr(args, "stale", False)

    async def _do_show() -> int:
        if module_filter:
            iid = inst.get("id") or inst.get("name", "")
            provider = instance_provider(inst)
            data = memory_service.get(iid, module_filter, provider)
            if data is None:
                msg = f"Module {module_filter!r} not found for {iid!r}."
                if use_json:
                    print(json.dumps({"error": {"code": "not_found", "message": msg}}))
                else:
                    print(f"Error: {msg}", file=sys.stderr)
                return _EXIT_NOT_FOUND
            if use_json:
                print(json.dumps(data, indent=2))
            else:
                print(json.dumps(data, indent=2))
            return _EXIT_SUCCESS

        iid = inst.get("id") or inst.get("name", "")
        provider = instance_provider(inst)

        if fmt == "json":
            all_modules = memory_service.get_all_modules(iid, provider)
            if stale_only:
                stale_names = set(memory_service.stale_modules(iid, provider))
                all_modules = {k: v for k, v in all_modules.items() if k in stale_names}
            print(json.dumps(all_modules, indent=2))
        elif fmt == "markdown":
            summary = await memory_service.get_summary(inst, max_tokens=1_000_000)
            print(summary)
        else:
            # Default: summary
            summary = await memory_service.get_summary(inst, max_tokens=1500)
            print(summary)
        return _EXIT_SUCCESS

    return _run_async(_do_show())


def _cmd_export(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any]) -> int:
    """Handle ``memory export``."""
    out_path = getattr(args, "out", None)

    async def _do_export() -> int:
        if out_path:
            summary = await memory_service.get_summary(inst, max_tokens=1_000_000)
            dest = Path(out_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(summary, encoding="utf-8")
            print(f"Exported to {dest}")
        else:
            path = await memory_service.write_summary(inst)
            print(f"Exported to {path}")
        return _EXIT_SUCCESS

    return _run_async(_do_export())


def _cmd_annotate(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any], sync: Any = None) -> int:
    """Handle ``memory annotate`` — edit the notes in $VISUAL/$EDITOR/vi.

    The editor works on a private copy; the live notes file is neither created
    nor touched while it runs. On exit the text is written back only if the
    notes are still what they were when the editor opened (nothing is locked
    while it runs); otherwise the edit is kept as a draft beside the notes,
    its name is printed, and the exit status is non-zero. The private copy is
    deleted only once the text is safe in the notes or a draft; when neither
    can be written it is kept and its path printed.
    """
    import hashlib
    import tempfile

    iid = inst.get("id") or inst.get("name", "")
    provider = instance_provider(inst)
    path = memory_service.get_annotations_path(iid, provider)

    try:
        original = memory_service.read_annotations(iid, provider)
    except OSError as exc:
        print(f"Could not read the notes ({exc.strerror or exc}).", file=sys.stderr)
        return _EXIT_GENERIC_ERROR
    expected = hashlib.sha256(original.encode("utf-8")).hexdigest()

    fd, copy_name = tempfile.mkstemp(prefix="servonaut-notes-", suffix=".md")  # 0600
    copy = Path(copy_name)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(original)
    code, text_is_safe = _edit_copy(
        memory_service, sync, inst, iid, provider, path, copy, original, expected
    )
    if text_is_safe:
        copy.unlink(missing_ok=True)
    return code


def _edit_copy(
    memory_service: Any, sync: Any, inst: Dict[str, Any], iid: str, provider: str,
    path: Path, copy: Path, original: str, expected: str,
) -> "tuple[int, bool]":
    """Run the editor on *copy* and store the result; ``(exit code, copy no longer needed)``."""
    argv = editor_argv(copy)
    try:
        completed = subprocess.run(argv, check=False)
    except OSError as exc:
        print(
            f"Could not start the editor {argv[0]!r} ({exc.strerror or exc}). Set $VISUAL or "
            f"$EDITOR to an installed editor, or edit {home_relative(str(path))} directly.",
            file=sys.stderr,
        )
        return _EXIT_GENERIC_ERROR, True
    try:
        edited = copy.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        print("The editor did not leave your edit behind, so the notes are unchanged.", file=sys.stderr)
        return _EXIT_GENERIC_ERROR, True
    returncode = getattr(completed, "returncode", 0)
    if returncode != 0:
        return _keep_failed_session(
            memory_service, iid, provider, copy, original, edited, returncode
        )
    if edited == original:
        return _EXIT_SUCCESS, True
    code, saved = _save_edit(memory_service, sync, inst, iid, provider, expected, edited, copy)
    return code, saved


def _keep_failed_session(
    memory_service: Any, iid: str, provider: str, copy: Path, original: str, edited: str,
    returncode: int,
) -> "tuple[int, bool]":
    """The editor failed: leave the notes alone, keep any changed text as a draft."""
    print(f"The editor exited with status {returncode}, so the notes were not changed.", file=sys.stderr)
    if edited == original:
        return _EXIT_GENERIC_ERROR, True
    try:
        draft = memory_service.write_annotation_draft(iid, edited, provider)
    except OSError as exc:
        print(
            f"Could not keep your edit either ({exc.strerror or exc}). It is still in "
            f"{home_relative(str(copy))}.",
            file=sys.stderr,
        )
        return _EXIT_GENERIC_ERROR, False
    print(f"Your edit is kept in {home_relative(str(draft))}.", file=sys.stderr)
    return _EXIT_GENERIC_ERROR, True


def _store_edit(
    memory_service: Any, sync: Any, inst: Dict[str, Any], iid: str, provider: str,
    expected: str, edited: str,
) -> int:
    """Write *edited* if the notes are unchanged since *expected*, else keep it as a draft."""
    return _save_edit(memory_service, sync, inst, iid, provider, expected, edited, None)[0]


def _save_edit(
    memory_service: Any, sync: Any, inst: Dict[str, Any], iid: str, provider: str,
    expected: str, edited: str, copy: Optional[Path],
) -> "tuple[int, bool]":
    """Store *edited*; returns ``(exit code, whether the text is now safe elsewhere)``."""
    import hashlib
    from datetime import datetime, timezone

    from servonaut.services.memory.store import RecordLockTimeout

    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        # Text and bookkeeping are one locked step, so a pull never sees
        # the new text next to the old modified time.
        written = memory_service.write_annotations_if_unchanged(
            iid, expected, edited, provider, modified_at=now_iso
        )
        reason = "The notes changed while you were editing"
    except RecordLockTimeout:
        written, reason = False, "Another Servonaut process is saving these notes"
    except OSError as exc:
        written, reason = False, f"The notes could not be saved ({exc.strerror or exc})"
    if not written:
        try:
            draft = memory_service.write_annotation_draft(iid, edited, provider)
        except OSError as exc:
            kept = f" It is still in {home_relative(str(copy))}." if copy is not None else ""
            print(f"Could not keep your edit either ({exc.strerror or exc}).{kept}", file=sys.stderr)
            return _EXIT_GENERIC_ERROR, False
        print(
            f"{reason}, so nothing was overwritten. Your edit is kept in "
            f"{home_relative(str(draft))}.",
            file=sys.stderr,
        )
        return _EXIT_GENERIC_ERROR, True

    try:
        memory_service.update_index(
            instance_id=iid, name=inst.get("name", iid), provider=provider,
            modules=[], annotations_hash=hashlib.sha256(edited.encode("utf-8")).hexdigest(),
        )
    except OSError:
        pass
    if sync is not None and getattr(sync, "is_configured", False):
        sync.enqueue_annotations(inst, edited, probed_at=now_iso)
    return _EXIT_SUCCESS, True


def _cmd_pin(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any]) -> int:
    """Handle ``memory pin <instance> <module>.<field> <value>``."""
    from servonaut.services.memory.interfaces import MemoryModuleMissingError

    dot_expr: str = args.dot_expr
    value: str = args.value

    # Validate "<module>.<field>" syntax — exactly one dot.
    parts = dot_expr.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        print(
            f"Error: pin expression must be <module>.<field>, got {dot_expr!r}",
            file=sys.stderr,
        )
        return _EXIT_USAGE_ERROR

    module, field = parts[0], parts[1]
    iid = inst.get("id") or inst.get("name", "")
    provider = instance_provider(inst)
    pinned_by = getpass.getuser()

    async def _do_pin() -> int:
        try:
            await memory_service.pin(iid, module, field, value, pinned_by=pinned_by, provider=provider)
            print(f"Pinned {module}.{field} = {value!r} for {iid}")
            return _EXIT_SUCCESS
        except MemoryModuleMissingError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return _EXIT_NOT_FOUND
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return _EXIT_USAGE_ERROR

    return _run_async(_do_pin())


# ---------------------------------------------------------------------------
# Headless sync + retrieval service initialisation
# ---------------------------------------------------------------------------

def _init_headless_sync_services(
    config: Any,
    memory_service: Any,
    config_manager: Any,
) -> Tuple[Any, Any]:
    """Attempt to construct MemorySyncService + MemoryRetrievalService headless.

    Returns ``(sync_service, retrieval_service)`` — either or both may be
    ``None`` if the optional dependencies are unavailable or the user is not
    authenticated.

    The passphrase provider reads from stdin (non-echoing) so the CLI can
    decrypt envelopes without a TUI.
    """
    try:
        from servonaut.services.auth_service import AuthService
        from servonaut.services.api_client import APIClient

        auth = AuthService()
        if not getattr(auth, "is_authenticated", False):
            logger.debug("headless sync: not authenticated, skipping sync services")
            return None, None

        api_client = APIClient(auth)
    except Exception as exc:  # noqa: BLE001
        logger.debug("headless sync: auth/api_client unavailable: %s", exc)
        return None, None

    try:
        import servonaut.services.memory.crypto as _memory_crypto
    except Exception as exc:  # noqa: BLE001
        logger.debug("headless sync: crypto unavailable: %s", exc)
        return None, None

    sync_service = None
    retrieval_service = None

    try:
        from servonaut.services.memory.sync_service import MemorySyncService
        from servonaut.services.memory.rate_limiter import RateLimiter

        rate_limiter = RateLimiter()
        sync_service = MemorySyncService(
            api_client=api_client,
            crypto=_memory_crypto,
            memory_service=memory_service,
            config_manager=config_manager,
            auth_service=auth,
            rate_limiter=rate_limiter,
        )
        if hasattr(memory_service, "set_sync_service"):
            memory_service.set_sync_service(sync_service)
    except Exception as exc:  # noqa: BLE001
        logger.debug("headless sync: MemorySyncService init failed: %s", exc)
        return None, None

    try:
        from servonaut.services.memory.retrieval_service import MemoryRetrievalService

        async def _stdin_passphrase() -> str:  # pragma: no cover
            import getpass as _gp
            return _gp.getpass("Memory Sync passphrase: ")

        retrieval_service = MemoryRetrievalService(
            api_client=api_client,
            crypto=_memory_crypto,
            passphrase_provider=_stdin_passphrase,
            rate_limiter=rate_limiter,  # type: ignore[possibly-undefined]
        )
        sync_service.set_retrieval_service(retrieval_service)
    except Exception as exc:  # noqa: BLE001
        logger.debug("headless sync: MemoryRetrievalService init failed: %s", exc)
        # Sync service still usable for enqueue; pull won't work.

    return sync_service, retrieval_service


# ---------------------------------------------------------------------------
# Pull annotations subcommand
# ---------------------------------------------------------------------------

_PULL_RESULT_MESSAGES: Dict[str, str] = {
    "updated": "Annotations updated from sync.",
    "unchanged": "Annotations unchanged (already up to date).",
    "local_newer": "Local annotations are newer — server copy not applied.",
    "opt_out": "Memory is disabled for this instance.",
    "not_found": "No annotations found on the server for this instance.",
    "unavailable": "Memory Sync is not configured or not available.",
}

_PULL_FINDINGS_RESULT_MESSAGES: Dict[str, str] = {
    "updated": "Findings updated from sync.",
    "unchanged": "Findings unchanged (already up to date).",
    "opt_out": "Memory is disabled for this instance.",
    "not_found": "No findings found on the server for this instance.",
    "unavailable": "Memory Sync is not configured or not available.",
    "busy": "Another Servonaut process is changing this server's memory; try again.",
}


def _cmd_pull_annotations(
    args: Any,
    config: Any,
    memory_service: Any,
    inst: Dict[str, Any],
    sync: Any,
) -> int:
    """Handle ``memory pull`` — fetch and write back memory (annotations +
    findings) from the sync server for an instance."""
    if sync is None or not getattr(sync, "is_configured", False):
        print(
            "Memory Sync is not configured. Set up Memory Sync first.",
            file=sys.stderr,
        )
        return _EXIT_GENERIC_ERROR

    iid = inst.get("id") or inst.get("name", "")
    name = inst.get("name", iid)
    provider = instance_provider(inst)

    async def _do_pull() -> int:
        try:
            ann = await sync.pull_annotations(iid, name, provider)
        except Exception as exc:  # noqa: BLE001
            print(f"Error pulling annotations: {exc}", file=sys.stderr)
            return _EXIT_GENERIC_ERROR
        print(f"{iid}: annotations — "
              f"{_PULL_RESULT_MESSAGES.get(ann, f'Unexpected result: {ann!r}')}")

        try:
            fnd = await sync.pull_findings(iid, name, provider)
        except Exception as exc:  # noqa: BLE001
            print(f"Error pulling findings: {exc}", file=sys.stderr)
            return _EXIT_GENERIC_ERROR
        print(f"{iid}: findings — "
              f"{_PULL_FINDINGS_RESULT_MESSAGES.get(fnd, f'Unexpected result: {fnd!r}')}")

        # Opt-out / unavailable apply account-wide; surface them as exit codes.
        if ann in ("opt_out", "unavailable") or fnd in ("opt_out", "unavailable"):
            return _EXIT_OPT_OUT
        if ann == "not_found" and fnd == "not_found":
            return _EXIT_NOT_FOUND
        return _EXIT_SUCCESS

    return _run_async(_do_pull())


def _cmd_reset_prompts(args: Any) -> int:
    """Reset the T11 first-connect memory-build prompt counter to zero."""
    from servonaut.config.manager import ConfigManager
    cm = ConfigManager()
    config = cm.get()
    config.memory_first_connect_dismissed_count = 0
    cm.save(config)
    print("First-connect memory prompt counter reset.")
    return _EXIT_SUCCESS


def _cmd_purge(args: Any, memory_service: Any) -> int:
    """Handle ``memory purge --instance <id> | --all``.

    Differs from ``memory clear``: purge wipes module files AND the
    index entry, and ``--all`` iterates every instance currently in
    the index.  Used to satisfy a "delete every trace of locally
    probed memory" request — typically after the consent decision is
    revoked or before handing the workstation over.
    """
    purge_all = bool(getattr(args, "all", False))
    target = getattr(args, "instance", None) or ""
    skip_confirm = bool(getattr(args, "yes", False))

    instance_ids: List[str]
    if purge_all:
        try:
            instance_ids = memory_service.list_all()
        except Exception as exc:  # noqa: BLE001
            print(f"Error listing memory store: {exc}", file=sys.stderr)
            return _EXIT_GENERIC_ERROR
        instance_ids = [
            row.get("instance_id") for row in (instance_ids or [])
            if row.get("instance_id")
        ]
        if not instance_ids:
            print("Memory store is already empty.")
            return _EXIT_SUCCESS
        prompt_token = "ALL"
    else:
        if not target:
            print("Error: pass --instance <id> or --all.", file=sys.stderr)
            return _EXIT_USAGE_ERROR
        instance_ids = [target]
        prompt_token = target

    if not skip_confirm:
        print(
            f"About to PURGE locally-stored memory for "
            f"{len(instance_ids)} instance(s). This is irreversible.",
            file=sys.stderr,
        )
        try:
            answer = input(
                f"Type {prompt_token!r} to confirm (anything else aborts): ",
            ).strip()
        except EOFError:
            answer = ""
        if answer != prompt_token:
            print("Aborted.", file=sys.stderr)
            return _EXIT_USER_ABORT

    purged = 0
    for iid in instance_ids:
        # Provider lookup: index entries carry it, but for `--instance`
        # we may not have it — the store's clear() falls through to
        # provider="custom" which only matches the custom dir.  Iterate
        # over every provider sub-directory to be thorough.
        for provider in ("aws", "custom", "ovh", "gcp", "azure"):
            try:
                memory_service.clear(iid, modules=None, provider=provider)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "purge clear(%s, %s) failed: %s", iid, provider, exc,
                )
        purged += 1

    print(f"Purged memory for {purged} instance(s).")
    return _EXIT_SUCCESS


def _cmd_clear(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any]) -> int:
    """Handle ``memory clear``."""
    iid = inst.get("id") or inst.get("name", "")
    provider = instance_provider(inst)
    modules = getattr(args, "modules", None) or None
    clear_all = getattr(args, "all", False)

    if clear_all:
        modules = None  # clear everything

    memory_service.clear(iid, modules, provider)
    if modules:
        print(f"Cleared modules {', '.join(modules)} for {iid}")
    else:
        print(f"Cleared all memory for {iid}")
    return _EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_memory(args: Any) -> int:
    """Main entry point for ``servonaut memory`` subcommand.

    Called from ``main.py`` with the parsed ``argparse.Namespace``.  Returns
    an integer exit code suitable for ``sys.exit()``.
    """
    memory_command = getattr(args, "memory_command", None)
    if memory_command is None:
        print("Error: specify a memory subcommand. Use --help for usage.", file=sys.stderr)
        return _EXIT_USAGE_ERROR

    # reset-prompts doesn't need the full headless service stack — handle it
    # before we construct MemoryService so missing AWS creds / OVH tokens
    # don't make this simple config operation fail.
    if memory_command == "reset-prompts":
        return _cmd_reset_prompts(args)

    config, memory_service, fleet = _init_headless_services()

    # Attempt to wire optional sync services.  Both annotate (enqueue on
    # change) and pull need them; other subcommands ignore them silently.
    from servonaut.config.manager import ConfigManager
    _config_manager = ConfigManager()
    sync_service, _retrieval_service = _init_headless_sync_services(
        config, memory_service, _config_manager
    )

    # purge has its own resolution path: --instance accepts a free-form
    # id/name (no AWS/custom merge required) and --all skips lookup
    # entirely, so we route it before _resolve_or_exit.
    if memory_command == "purge":
        return _cmd_purge(args, memory_service)

    if memory_command in _MERGING_COMMANDS:
        _merge_team_copies_first(memory_service)

    # --all path for build
    if memory_command == "build" and getattr(args, "all", False):
        return _cmd_build_all(args, config, memory_service, fleet)

    # Most subcommands require an instance argument.
    use_json = getattr(args, "json", False)
    from servonaut.services.accounts.registry import UnknownAccountError

    try:
        inst = _resolve_or_exit(args, fleet, use_json)
    except AmbiguousInstanceError as exc:
        return _report_ambiguous(exc, use_json)
    except UnknownAccountError as exc:
        return _report_unavailable_account(exc, use_json)
    if inst is None:
        # Only fail if the subcommand actually needs an instance.
        if memory_command not in ("build",):
            return _EXIT_NOT_FOUND
        # build without --all and without instance is a usage error
        print("Error: specify an instance name/ID or use --all.", file=sys.stderr)
        return _EXIT_USAGE_ERROR

    iid = inst.get("id") or inst.get("name", "")
    iname = inst.get("name", "")
    if _check_opt_out(iid, config, use_json, instance_name=iname):
        return _EXIT_OPT_OUT

    # pull goes through the sync path; all other commands use the standard
    # dispatch table below.
    if memory_command == "pull":
        return _cmd_pull_annotations(args, config, memory_service, inst, sync_service)

    dispatch = {
        "build": _cmd_build,
        "refresh": _cmd_refresh,
        "show": _cmd_show,
        "export": _cmd_export,
        "annotate": lambda a, c, m, i: _cmd_annotate(a, c, m, i, sync=sync_service),
        "pin": _cmd_pin,
        "clear": _cmd_clear,
    }

    handler = dispatch.get(memory_command)
    if handler is None:
        print(f"Error: unknown memory subcommand {memory_command!r}", file=sys.stderr)
        return _EXIT_USAGE_ERROR

    return handler(args, config, memory_service, inst)

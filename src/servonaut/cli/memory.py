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

from servonaut.utils.instance_resolver import resolve_instance_from_lists

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

def _init_headless_services() -> Tuple[Any, Any, Any, Any, Any]:
    """Initialise Config, MemoryService, AWSService, CustomServerService, OVHService.

    Returns:
        ``(config, memory_service, aws_service, custom_server_service, ovh_service)``
    """
    from servonaut.config.manager import ConfigManager
    from servonaut.services.aws_service import AWSService
    from servonaut.services.cache_service import CacheService
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

    cache_service = CacheService(ttl_seconds=config.cache_ttl_seconds)
    aws_service = AWSService(cache_service)
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

    ovh_service = None
    try:
        ovh_config = config.ovh
        if ovh_config.enabled and (ovh_config.application_key or ovh_config.client_id):
            from servonaut.services.ovh_service import OVHService
            ovh_service = OVHService(ovh_config)
    except (ImportError, AttributeError):
        pass

    return config, memory_service, aws_service, custom_server_service, ovh_service


# ---------------------------------------------------------------------------
# Instance resolution
# ---------------------------------------------------------------------------

def _list_all_instances(
    aws_service: Any,
    custom_server_service: Any,
    ovh_service: Optional[Any],
    hetzner_service: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Return combined list of AWS + custom + OVH + Hetzner instances."""
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
    if ovh_service is not None:
        try:
            instances.extend(ovh_service.get_cached_instances())
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not load OVH cached instances: %s", exc)
    if hetzner_service is not None:
        try:
            instances.extend(hetzner_service.get_cached_instances())
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not load Hetzner cached instances: %s", exc)
    return instances


def _resolve_instance(
    id_or_name: str,
    aws_list: List[Dict[str, Any]],
    custom_list: List[Dict[str, Any]],
    ovh_list: List[Dict[str, Any]],
    hetzner_list: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Resolve *id_or_name* to an instance dict.

    Search order: AWS first, then custom, then OVH, then Hetzner —
    matching by ``id`` or ``name`` (case-insensitive). AWS takes
    precedence on name collisions.

    Delegates to the shared ``resolve_instance_from_lists`` helper so the
    resolution contract is defined once.
    """
    return resolve_instance_from_lists(
        id_or_name, aws_list, custom_list, ovh_list, hetzner_list,
    )


def _resolve_or_exit(
    args: Any,
    aws_service: Any,
    custom_server_service: Any,
    ovh_service: Optional[Any],
    use_json: bool = False,
    hetzner_service: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """Resolve instance from args.instance (if present), printing error on failure."""
    instance_arg = getattr(args, "instance", None)
    if not instance_arg:
        return None

    aws_instances: List[Dict[str, Any]] = []
    try:
        cached = aws_service._cache.load_any()
        if cached:
            aws_instances = cached
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load AWS cached instances: %s", exc)
    custom_instances: List[Dict[str, Any]] = []
    try:
        custom_instances = custom_server_service.list_as_instances()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load custom server instances: %s", exc)
    ovh_instances: List[Dict[str, Any]] = []
    if ovh_service is not None:
        try:
            ovh_instances = ovh_service.get_cached_instances()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not load OVH cached instances: %s", exc)
    hetzner_instances: List[Dict[str, Any]] = []
    if hetzner_service is not None:
        try:
            hetzner_instances = hetzner_service.get_cached_instances()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not load Hetzner cached instances: %s", exc)

    inst = _resolve_instance(
        instance_arg, aws_instances, custom_instances, ovh_instances,
        hetzner_instances,
    )
    if inst is None:
        msg = f"Instance not found: {instance_arg!r}"
        if use_json:
            print(json.dumps({"error": {"code": "not_found", "message": msg}}))
        else:
            print(f"Error: {msg}", file=sys.stderr)
        return None
    return inst


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

def _cmd_build(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any]) -> int:
    """Handle ``memory build``."""
    use_json = getattr(args, "json", False)
    modules = getattr(args, "modules", None) or None

    async def _do_build() -> int:
        results = await memory_service.build(inst, modules)
        if use_json:
            out = {
                k: {
                    "module": v.module,
                    "probed_at": v.probed_at,
                    "partial": v.partial,
                    "truncated": v.truncated,
                    "observed_keys": list(v.observed.keys()),
                }
                for k, v in results.items()
            }
            print(json.dumps(out, indent=2))
        else:
            iid = inst.get("id") or inst.get("name", "?")
            if results:
                print(f"Built memory for {iid}: {', '.join(sorted(results))}")
            else:
                print(f"No modules probed for {iid} (check opt-out / disabled modules).")
        return _EXIT_SUCCESS

    return _run_async(_do_build())


async def _build_all(
    instances: List[Dict[str, Any]],
    memory_service: Any,
    modules: Optional[List[str]],
) -> List[Tuple[str, Exception]]:
    """Build memory for all *instances*, at most 5 concurrent probes."""
    sem = asyncio.Semaphore(5)
    failures: List[Tuple[str, Exception]] = []
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
                await memory_service.build(inst, modules)
            except Exception as exc:
                failures.append((iid, exc))

    await asyncio.gather(*(one(i) for i in instances))
    return failures


def _cmd_build_all(
    args: Any,
    config: Any,
    memory_service: Any,
    aws_service: Any,
    custom_server_service: Any,
    ovh_service: Optional[Any],
) -> int:
    """Handle ``memory build --all``."""
    instances = _list_all_instances(aws_service, custom_server_service, ovh_service)
    if not instances:
        print("No instances found.", file=sys.stderr)
        return _EXIT_NOT_FOUND

    modules = getattr(args, "modules", None) or None
    failures = _run_async(_build_all(instances, memory_service, modules))

    if failures:
        for iid, exc in failures:
            print(f"FAILED {iid}: {exc}", file=sys.stderr)
        return _EXIT_PARTIAL_FAILURE
    return _EXIT_SUCCESS


def _cmd_refresh(args: Any, config: Any, memory_service: Any, inst: Dict[str, Any]) -> int:
    """Handle ``memory refresh``."""
    modules = getattr(args, "modules", None) or None

    async def _do_refresh() -> int:
        results = await memory_service.refresh(inst, modules)
        iid = inst.get("id") or inst.get("name", "?")
        print(f"Refreshed memory for {iid}: {', '.join(sorted(results)) if results else '(none)'}")
        return _EXIT_SUCCESS

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
            provider = inst.get("provider", "custom")
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
        provider = inst.get("provider", "custom")

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
    """Handle ``memory annotate`` — open annotations file in $VISUAL/$EDITOR/vi."""
    import hashlib
    from datetime import datetime, timezone

    iid = inst.get("id") or inst.get("name", "")
    provider = inst.get("provider", "custom")
    path = memory_service.get_annotations_path(iid, provider)

    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)

    # Snapshot the hash before the editor runs so we can detect changes.
    try:
        old_meta = memory_service.get_annotations_meta(iid)
        old_hash = old_meta.get("annotations_hash", "")
    except Exception:  # noqa: BLE001
        old_hash = ""

    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    subprocess.run([editor, str(path)], check=False)

    # Recompute annotations_hash and update index via the public API
    try:
        # Canonicalise to the SAME representation the screen save path and
        # pull_annotations use (decoded UTF-8 string), so the stored hash
        # describes exactly the content we enqueue and that pull recomputes
        # on its "unchanged" short-circuit. Hashing raw bytes here would drift
        # from those sites for any non-UTF-8 content and trigger spurious
        # re-pull/overwrite cycles.
        content_str = path.read_bytes().decode("utf-8", errors="replace")
        annotations_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
        memory_service.update_index(
            instance_id=iid,
            name=inst.get("name", iid),
            provider=provider,
            modules=[],
            annotations_hash=annotations_hash,
        )

        # Persist modified-at and enqueue when content actually changed.
        if annotations_hash != old_hash:
            now_iso = datetime.now(timezone.utc).isoformat()
            memory_service.set_annotations_meta(
                iid,
                annotations_hash=annotations_hash,
                annotations_modified_at=now_iso,
            )
            if sync is not None and getattr(sync, "is_configured", False):
                sync.enqueue_annotations(inst, content_str, probed_at=now_iso)
    except OSError:
        pass

    return _EXIT_SUCCESS


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
    provider = inst.get("provider", "custom")
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
    provider = inst.get("provider", "custom")

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
    provider = inst.get("provider", "custom")
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

    config, memory_service, aws_service, custom_server_service, ovh_service = (
        _init_headless_services()
    )

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

    # --all path for build
    if memory_command == "build" and getattr(args, "all", False):
        return _cmd_build_all(
            args, config, memory_service, aws_service, custom_server_service, ovh_service
        )

    # Most subcommands require an instance argument.
    use_json = getattr(args, "json", False)
    inst = _resolve_or_exit(args, aws_service, custom_server_service, ovh_service, use_json)
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

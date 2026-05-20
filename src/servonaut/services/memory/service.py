"""MemoryService — orchestrator for server memory probing.

T1 scope: skeleton + ``build`` method that dispatches probers in parallel
and persists results through ``MemoryStore``.  Prober instantiation is
wired in T2 once the concrete prober classes exist.

T3 scope: ``get_summary`` and ``write_summary`` are fully implemented using
the deterministic :mod:`summariser` module.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .interfaces import MemoryServiceInterface, MemoryModuleMissingError, ModuleProberInterface, ModuleResult
from .redaction import default_redactor, noop_redactor
from .store import MemoryStore
from .summariser import build_summary_markdown

# TYPE_CHECKING import for sync service (break circular dep at runtime)
if TYPE_CHECKING:
    from .sync_service import MemorySyncService as _MemorySyncService


# ---------------------------------------------------------------------------
# BuildReport — per-module success / failure surfaced by build_report().
# `build()` keeps returning the legacy dict so existing callers stay intact.
# MCP tools consume BuildReport to give agents actionable feedback instead of
# a silent empty dict when probes fail.
# ---------------------------------------------------------------------------


@dataclass
class ModuleBuildFailure:
    """A single module probe that did not yield a ModuleResult.

    Attributes:
        module: Prober name (``"os"``, ``"runtimes"``, …).
        reason: Machine-readable code: ``"timeout"`` | ``"exception"``.
        message: Short human-readable detail (redacted exception message).
    """

    module: str
    reason: str
    message: str = ""


@dataclass
class BuildReport:
    """Outcome of a single ``build_report()`` invocation.

    Attributes:
        successes: ``module_name → ModuleResult`` for probers that returned.
        failures: Per-module probe failures (timeouts, exceptions).
        overall_reason: Machine-readable code when ``successes`` is empty
            (``"opt_out"`` | ``"disabled"`` | ``"no_modules_matched"`` |
            ``"all_probers_failed"``); ``None`` on partial / full success.
    """

    successes: Dict[str, ModuleResult] = field(default_factory=dict)
    failures: List[ModuleBuildFailure] = field(default_factory=list)
    overall_reason: Optional[str] = None

    @property
    def count(self) -> int:
        return len(self.successes)

    @property
    def has_any_success(self) -> bool:
        return bool(self.successes)

if TYPE_CHECKING:
    from servonaut.services.interfaces import SSHServiceInterface, ConnectionServiceInterface

logger = logging.getLogger(__name__)

# Hard cap on parallel SSH sessions per ``build`` call.
_MAX_CONCURRENT_PROBES = 8

# Section header markers in drop order (least important first).
# Each entry is the Markdown heading prefix used in summariser.py output.
_DROP_ORDER = [
    "## Identity",
    "## Runtimes",
    "## Services",
    "## Web stack",
    "## Logs",
    "## Databases",
    "## Containers",
    "## Network",
    "## Git",
    "## Disk",
    "## Annotations",
    # "## Data quality" is intentionally absent — it is never dropped.
]


def _select_redactor(config: Any) -> Any:
    """Return the redactor callable appropriate for *config*.

    When ``config.redaction_enabled`` is True (the default) we return the
    production regex-based ``default_redactor``; otherwise we fall back to
    ``noop_redactor``.  A missing config object (test fixtures) also yields
    the noop so tests remain deterministic.
    """
    redaction_enabled = getattr(config, "redaction_enabled", False)
    return default_redactor if redaction_enabled else noop_redactor


def _truncate_summary(summary: str, char_cap: int) -> str:
    """Drop sections bottom-up until *summary* fits within *char_cap* chars.

    The strategy mirrors the section priority order in :mod:`summariser`:
    Identity is most informative, Data quality must always survive, everything
    in between is dropped starting from the least important (bottom) up.

    Args:
        summary: Full Markdown summary string.
        char_cap: Maximum character count for the result.

    Returns:
        Truncated summary string that is ≤ *char_cap* chars.
    """
    if len(summary) <= char_cap:
        return summary

    # Split on "\n\n" (the separator used between sections in summariser).
    # The first element is always the header line.
    parts = summary.split("\n\n")

    # Try dropping sections from the lowest-priority end first.
    for heading in reversed(_DROP_ORDER):
        # Find and remove the first part that starts with this heading.
        for i, part in enumerate(parts):
            if part.startswith(heading):
                parts.pop(i)
                break
        candidate = "\n\n".join(parts)
        if len(candidate) <= char_cap:
            return candidate

    # Last resort: hard truncate with a marker.
    joined = "\n\n".join(parts)
    return joined[:char_cap - 15] + "\n\n_(truncated)_"


class MemoryService(MemoryServiceInterface):
    """Orchestrates per-module probing and delegates persistence to MemoryStore.

    Args:
        store: ``MemoryStore`` instance for JSON I/O.  When ``None``, a default
            ``MemoryStore`` is created with ``noop_redactor`` pre-wired so the
            redaction seam is live for T9 to swap in a real implementation.
        config: ``MemoryConfig`` instance for TTL overrides and feature flags.
        probers: List of concrete ``ModuleProberInterface`` implementations.
            T2 injects these; T1 leaves the list empty by default.
        ssh_service: Optional SSH service for building remote runners.
        connection_service: Optional connection service for resolving SSH params.
    """

    def __init__(
        self,
        store: Optional[MemoryStore] = None,
        config: Any = None,  # MemoryConfig — kept as Any to avoid circular import at runtime
        probers: Optional[List[ModuleProberInterface]] = None,
        ssh_service: Optional["SSHServiceInterface"] = None,
        connection_service: Optional["ConnectionServiceInterface"] = None,
    ) -> None:
        # Default store wiring follows MemoryConfig.redaction_enabled: on by
        # default we inject the T9 regex library; when an operator flips the
        # flag off (or config is None in narrow test fixtures) we fall back to
        # ``noop_redactor`` so behaviour is deterministic. Callers supplying an
        # explicit ``store`` are respected as-is.
        self._store = (
            store if store is not None
            else MemoryStore(redactor=_select_redactor(config))
        )
        self._config = config
        self._probers: List[ModuleProberInterface] = probers or []
        self._ssh_service = ssh_service
        self._connection_service = connection_service
        # Optional sync service hook — set after construction via set_sync_service()
        # to break circular dependency (MemoryService ↔ MemorySyncService).
        self._sync_service: Optional["_MemorySyncService"] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def build(
        self,
        instance: Dict[str, Any],
        modules: Optional[List[str]] = None,
    ) -> Dict[str, ModuleResult]:
        """Probe *modules* for *instance* in parallel, persist results.

        Legacy API — returns only the successful modules.  New callers that
        need per-module failure reasons should use :meth:`build_report`.
        """
        report = await self.build_report(instance, modules)
        return report.successes

    async def build_report(
        self,
        instance: Dict[str, Any],
        modules: Optional[List[str]] = None,
    ) -> BuildReport:
        """Probe *modules* for *instance* and return successes + failures.

        Unlike :meth:`build`, this method surfaces per-module failure reasons
        (timeouts, exceptions) so callers — especially MCP agents — can tell
        a user *why* a memory build produced zero modules.

        Args:
            instance: Instance dict (``id``, ``name``, ``provider``, etc.).
            modules: Module names to probe; ``None`` or ``["*"]`` probes all
                enabled modules.

        Returns:
            ``BuildReport`` with per-module successes, failures, and an
            ``overall_reason`` code when the report produced zero successes.
        """
        instance_id = instance.get("id") or instance.get("name", "")
        provider = instance.get("provider", "custom")
        name = instance.get("name", instance_id)

        if not self._config.enabled:
            logger.info("Memory is disabled in config; skipping build for %s", instance_id)
            return BuildReport(overall_reason="disabled")

        if self._config.is_instance_disabled(instance_id, name):
            logger.info("Memory disabled for instance %s via per_server_overrides", instance_id)
            return BuildReport(overall_reason="opt_out")

        selected_probers = self._select_probers(modules)
        if not selected_probers:
            logger.debug("No probers to run for %s (modules=%s)", instance_id, modules)
            return BuildReport(overall_reason="no_modules_matched")

        # Bind instance to LogsProber (which uses a different probe path).
        for prober in selected_probers:
            if hasattr(prober, "set_instance"):
                prober.set_instance(instance)

        ssh_runner = self._make_ssh_runner(instance)

        semaphore = asyncio.Semaphore(_MAX_CONCURRENT_PROBES)

        async def run_one(
            prober: ModuleProberInterface,
        ) -> tuple[str, Optional[ModuleResult], Optional[ModuleBuildFailure]]:
            module_name = prober.name
            if module_name in self._config.disabled_modules:
                logger.debug("Module %s is disabled in config", module_name)
                # Config-disabled is not a failure to surface — user opted out.
                return (module_name, None, None)
            async with semaphore:
                try:
                    result = await prober.probe(ssh_runner)
                    return (module_name, result, None)
                except asyncio.TimeoutError:
                    logger.warning("Prober %s timed out for %s", module_name, instance_id)
                    return (
                        module_name,
                        None,
                        ModuleBuildFailure(
                            module=module_name,
                            reason="timeout",
                            message="Prober exceeded its time budget.",
                        ),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Prober %s failed for %s: %s", module_name, instance_id, exc
                    )
                    return (
                        module_name,
                        None,
                        ModuleBuildFailure(
                            module=module_name,
                            reason="exception",
                            message=str(exc)[:240],
                        ),
                    )

        tasks = [run_one(p) for p in selected_probers]
        raw_results = await asyncio.gather(*tasks)

        successes: Dict[str, ModuleResult] = {}
        failures: List[ModuleBuildFailure] = []
        probed_modules: List[str] = []

        for _module_name, result, failure in raw_results:
            if failure is not None:
                failures.append(failure)
                continue
            if result is None:
                continue
            # Stamp probed_at if the prober didn't set it.
            if not result.probed_at:
                result.probed_at = datetime.now(tz=timezone.utc).isoformat()
            self._persist_result(result, instance_id, provider, instance=instance)
            successes[result.module] = result
            probed_modules.append(result.module)

        if probed_modules:
            self._store.update_index(
                instance_id=instance_id,
                name=name,
                provider=provider,
                modules=probed_modules,
            )

        overall_reason: Optional[str] = None
        if not successes and failures:
            overall_reason = "all_probers_failed"
        return BuildReport(
            successes=successes,
            failures=failures,
            overall_reason=overall_reason,
        )

    async def refresh(
        self,
        instance: Dict[str, Any],
        modules: Optional[List[str]] = None,
    ) -> Dict[str, ModuleResult]:
        """Re-probe stale (or all requested) modules for *instance*.

        For T1 this is identical to ``build``.  T2 may add staleness checks
        to skip fresh modules.
        """
        return await self.build(instance, modules)

    async def refresh_report(
        self,
        instance: Dict[str, Any],
        modules: Optional[List[str]] = None,
    ) -> BuildReport:
        """Re-probe with full success/failure reporting (see ``build_report``)."""
        return await self.build_report(instance, modules)

    def get(
        self,
        instance_id: str,
        module: str,
        provider: str = "custom",
    ) -> Optional[Dict[str, Any]]:
        """Return stored JSON dict for *module* on *instance_id*, or ``None``."""
        return self._store.get_module(instance_id, module, provider)

    async def get_summary(
        self,
        instance_meta: Dict[str, Any],
        max_tokens: int = 1500,
    ) -> str:
        """Return a token-efficient Markdown summary for *instance_meta*.

        Delegates to the deterministic :func:`build_summary_markdown` helper
        then applies a character cap with bottom-up section truncation so that
        the most important sections (Data quality, Annotations) survive.

        Args:
            instance_meta: Instance dict with ``id``, ``name``, ``provider``.
            max_tokens: Approximate upper bound; 1 token ≈ 4 chars.

        Returns:
            Markdown summary string, never exceeding ``max_tokens * 4`` chars.
        """
        summary = build_summary_markdown(
            store=self._store,
            instance_meta=instance_meta,
            config=self._config,
        )
        char_cap = max_tokens * 4
        if len(summary) > char_cap:
            summary = _truncate_summary(summary, char_cap)
        return summary

    async def write_summary(
        self,
        instance_meta: Dict[str, Any],
    ) -> Path:
        """Write the deterministic summary to ``summary.md`` for *instance_meta*.

        Args:
            instance_meta: Instance dict with ``id``, ``name``, ``provider``.

        Returns:
            Path to the written ``summary.md`` file.
        """
        summary = await self.get_summary(instance_meta)
        instance_id = instance_meta.get("id") or instance_meta.get("name", "")
        provider = instance_meta.get("provider", "custom")
        return self._store.write_summary(instance_id, summary, provider=provider)

    def clear(
        self,
        instance_id: str,
        modules: Optional[List[str]] = None,
        provider: str = "custom",
    ) -> None:
        """Delete stored memory for *instance_id*."""
        self._store.clear(instance_id, modules, provider)

    async def pin(
        self,
        instance_id: str,
        module: str,
        field: str,
        value: Any,
        pinned_by: str,
        provider: str = "custom",
    ) -> None:
        """Pin a user-declared value for *field* in *module* for *instance_id*.

        Args:
            instance_id: Instance identifier.
            module: Module name, e.g. ``"os"``.
            field: Key to set inside ``data["declared"]``.
            value: Value to store.
            pinned_by: Username or agent identity that set the pin.
            provider: Provider slug for the storage sub-directory.

        Raises:
            MemoryModuleMissingError: If no stored data exists for *module*.
            ValueError: If *instance_id* or *module* fails safety validation.
        """
        from .store import _validate_module_name  # noqa: PLC0415
        _validate_module_name(module)
        data = self._store.get_module(instance_id, module, provider)
        if data is None:
            raise MemoryModuleMissingError(instance_id, module)
        if "declared" not in data or not isinstance(data["declared"], dict):
            data["declared"] = {}
        data["declared"][field] = {
            "value": value,
            "pinned_by": pinned_by,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        self._store.save_module(instance_id, module, data, provider)
        logger.debug("Pinned field %s.%s for %s (by %s)", module, field, instance_id, pinned_by)

    def list_all(self) -> List[Dict[str, Any]]:
        """Return index entries for all instances that have memory."""
        index_entries = []
        for instance_id in self._store.list_instances():
            entry = self._store.get_index_entry(instance_id)
            if entry:
                index_entries.append({"instance_id": instance_id, **entry})
        return index_entries

    @property
    def snapshot_stale_seconds(self) -> int:
        """Server-level staleness threshold in seconds.

        Drives the fleet/instances "Stale" badge: a server's whole snapshot
        is considered stale once its newest probe is older than this. Reads
        ``MemoryConfig.snapshot_stale_seconds`` and falls back to the schema
        default when config is absent or holds a non-positive value.
        """
        from servonaut.config.schema import DEFAULT_SNAPSHOT_STALE_SECONDS

        val = getattr(self._config, "snapshot_stale_seconds", None)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            return val
        return DEFAULT_SNAPSHOT_STALE_SECONDS

    @property
    def first_connect_reprompt_seconds(self) -> int:
        """Re-prompt threshold for the first-connect "Build memory" banner.

        A server that already has memory is only re-prompted once its
        snapshot is older than this. Reads
        ``MemoryConfig.first_connect_reprompt_seconds`` with the schema
        default as a fallback.
        """
        from servonaut.config.schema import DEFAULT_FIRST_CONNECT_REPROMPT_SECONDS

        val = getattr(self._config, "first_connect_reprompt_seconds", None)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            return val
        return DEFAULT_FIRST_CONNECT_REPROMPT_SECONDS

    def stale_modules(self, instance_id: str, provider: str = "custom") -> List[str]:
        """Return list of module names that exist on disk AND are past their TTL (missing modules are NOT included).

        Delegates to ``MemoryStore.stale_modules`` using the service's own
        ``MemoryConfig`` so callers never need to pass config directly.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.

        Returns:
            List of stale module name strings.
        """
        return self._store.stale_modules(instance_id, self._config, provider)

    def get_all_modules(
        self, instance_id: str, provider: str = "custom"
    ) -> Dict[str, Dict[str, Any]]:
        """Return all stored modules for *instance_id* as ``{module: data}``.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
        """
        return self._store.get_all_modules(instance_id, provider)

    def get_annotations_path(
        self, instance_id: str, provider: str = "custom"
    ) -> "Path":
        """Return the annotations file path for *instance_id* (may not exist yet).

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
        """
        return self._store.get_annotations_path(instance_id, provider)

    def update_index(
        self,
        instance_id: str,
        name: str,
        provider: str,
        modules: List[str],
        summary_tokens: int = 0,
        annotations_hash: str = "",
    ) -> None:
        """Upsert the index entry for *instance_id*.

        Public proxy so callers (CLI, MCP) never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
            name: Human-readable server name.
            provider: Provider label.
            modules: List of probed module names.
            summary_tokens: Approximate token count of the summary.
            annotations_hash: SHA-256 hex hash of annotations content (if any).
        """
        self._store.update_index(
            instance_id=instance_id,
            name=name,
            provider=provider,
            modules=modules,
            summary_tokens=summary_tokens,
            annotations_hash=annotations_hash,
        )

    def is_memory_disabled(self, instance_id: str, instance_name: str = "") -> bool:
        """Return True if memory is disabled for *instance_id* or *instance_name*.

        Checks both the global ``enabled`` flag and per-server overrides so
        callers (screens, CLI, MCP) never need to access ``_config`` directly.

        Args:
            instance_id: Unique instance identifier.
            instance_name: Human-readable name (optional second key to check).
        """
        if self._config is None:
            return False
        if not self._config.enabled:
            return True
        return self._config.is_instance_disabled(instance_id, instance_name)

    def set_sync_service(self, svc: Optional["_MemorySyncService"]) -> None:
        """Wire the optional sync service after construction.

        Called by app.py to avoid a circular dependency between
        MemoryService and MemorySyncService.

        Args:
            svc: A MemorySyncService instance, or None to detach.
        """
        self._sync_service = svc
        logger.debug("MemoryService: sync service %s", "attached" if svc else "detached")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _select_probers(
        self, modules: Optional[List[str]]
    ) -> List[ModuleProberInterface]:
        """Filter ``self._probers`` to only those requested."""
        if not modules or modules == ["*"]:
            return list(self._probers)
        names = set(modules)
        return [p for p in self._probers if p.name in names]

    def _persist_result(
        self,
        result: ModuleResult,
        instance_id: str,
        provider: str,
        instance: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Convert *result* to a JSON dict and write it to the store.

        After writing locally, enqueues to the sync service if wired.

        Args:
            result: The ModuleResult from a prober.
            instance_id: Instance identifier string.
            provider: Provider slug for the storage sub-directory.
            instance: Optional full instance dict (id + name + provider).
                When provided, passed to sync_service.enqueue_module so
                the cloud record includes display_name and provider.
        """
        data: Dict[str, Any] = {
            "module": result.module,
            "instance_id": instance_id,
            "probed_at": result.probed_at,
            "ttl_seconds": result.ttl_seconds,
            "sudo_used": result.sudo_used,
            "truncated": result.truncated,
            "partial": result.partial,
            "observed": result.observed,
            "declared": result.declared,
            "raw_output": result.raw_output,
        }
        self._store.save_module(instance_id, result.module, data, provider)

        # Enqueue to cloud sync if wired (best-effort — never block a probe)
        if self._sync_service is not None:
            instance_dict = instance or {
                "id": instance_id,
                "name": instance_id,
                "provider": provider,
            }
            try:
                self._sync_service.enqueue_module(instance_dict, result.module, result)
            except Exception as exc:
                logger.warning(
                    "sync enqueue_module failed for %s/%s: %s",
                    instance_id, result.module, exc
                )

    def _make_ssh_runner(self, instance: Dict[str, Any]) -> Any:
        """Return an async SSH runner callable for *instance*.

        The returned callable accepts a single shell command string and returns
        ``(stdout, stderr, returncode)`` as ``(str, str, int)``.  It uses
        ``SSHService.build_ssh_command`` + ``ConnectionService`` for SSH
        parameter resolution, then delegates execution to
        ``run_ssh_subprocess`` from :mod:`servonaut.utils.ssh_utils`.

        When ``ssh_service`` or ``connection_service`` are not wired (e.g. in
        tests that inject a stub directly), a ``NotImplementedError`` is raised
        to make the missing dependency obvious.

        Args:
            instance: Instance dict from ``app.instances``.

        Returns:
            Async callable ``(command: str) -> (stdout: str, stderr: str, returncode: int)``.
        """
        ssh_service = self._ssh_service
        connection_service = self._connection_service

        if ssh_service is None or connection_service is None:
            async def _stub_runner(command: str) -> tuple[str, str, int]:
                raise NotImplementedError(
                    "SSH runner not wired — pass ssh_service and "
                    "connection_service to MemoryService.__init__ before probing "
                    f"instance {instance.get('id')!r}"
                )
            return _stub_runner

        # Import here to avoid circular imports at module level.
        from servonaut.utils.ssh_utils import run_ssh_subprocess  # noqa: PLC0415

        # Resolve connection parameters once (not per command call).
        if instance.get("is_custom"):
            conn: Dict[str, Any] = {
                "host": instance.get("public_ip") or instance.get("private_ip", ""),
                "username": instance.get("username") or "root",
                "key_path": instance.get("ssh_key") or instance.get("key_name") or None,
                "proxy_args": [],
                "port": instance.get("port") or None,
                "extra_options": connection_service.get_extra_options(instance, None),
            }
        else:
            profile = connection_service.resolve_profile(instance)
            host = connection_service.get_target_host(instance, profile)
            proxy_args: List[str] = connection_service.get_proxy_args(profile) if profile else []
            extra_options: List[str] = connection_service.get_extra_options(instance, profile)

            instance_id_for_key = instance.get("id", "")
            key_path: Optional[str] = ssh_service.get_key_path(instance_id_for_key)
            if not key_path and instance.get("key_name"):
                key_path = ssh_service.discover_key(instance["key_name"])

            config_obj = None
            try:
                config_obj = ssh_service._config_manager.get()  # type: ignore[attr-defined]
            except AttributeError:
                pass

            username = (
                (profile.username if profile else None)
                or (config_obj.default_username if config_obj else None)
                or "ec2-user"
            )

            conn = {
                "host": host,
                "username": username,
                "key_path": key_path,
                "proxy_args": proxy_args,
                "port": None,
                "extra_options": extra_options,
            }

        async def _real_runner(command: str) -> tuple[str, str, int]:
            """Execute *command* on the remote host and return (stdout, stderr, rc)."""
            ssh_cmd = ssh_service.build_ssh_command(
                host=conn["host"],
                username=conn["username"],
                key_path=conn.get("key_path"),
                proxy_args=conn.get("proxy_args") or [],
                remote_command=command,
                port=conn.get("port"),
                extra_options=conn.get("extra_options") or [],
            )
            try:
                # timeout=5 matches the per-command cap enforced by the base
                # class caller (_CMD_TIMEOUT_SECONDS = 5.0).  Using a single
                # inner timeout (instead of a double asyncio.wait_for wrapper)
                # ensures run_ssh_subprocess calls proc.kill() on expiry, so no
                # zombie SSH processes linger past the deadline.
                stdout_bytes, stderr_bytes = await run_ssh_subprocess(ssh_cmd, timeout=5)
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                return stdout, stderr, 0
            except asyncio.TimeoutError:
                logger.warning(
                    "SSH runner timed out executing %r for instance %s",
                    command[:80],
                    instance.get("id", "?"),
                )
                raise
            except Exception as exc:
                logger.error(
                    "SSH runner error for instance %s: %s",
                    instance.get("id", "?"),
                    exc,
                )
                return "", str(exc), 1

        return _real_runner

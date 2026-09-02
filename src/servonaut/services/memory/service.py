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
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from .interfaces import MemoryServiceInterface, MemoryModuleMissingError, ModuleProberInterface, ModuleResult
from .redaction import default_redactor, noop_redactor, scan_for_secrets
from .store import MemoryStore, _validate_finding_id
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
    "## Findings",
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
        # Demo mode resolvers (identity until the app wires them): every
        # instance dict / id entering the public surface is mapped back to
        # the real record before probes, storage keys or the sync queue.
        self._resolve_instance: Callable[[Dict[str, Any]], Dict[str, Any]] = lambda inst: inst
        self._resolve_id: Callable[[str], str] = lambda instance_id: instance_id
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
        instance = self._resolve_instance(instance)
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
        instance = self._resolve_instance(instance)
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
        instance = self._resolve_instance(instance)
        return await self.build(instance, modules)

    async def refresh_report(
        self,
        instance: Dict[str, Any],
        modules: Optional[List[str]] = None,
    ) -> BuildReport:
        """Re-probe with full success/failure reporting (see ``build_report``)."""
        instance = self._resolve_instance(instance)
        return await self.build_report(instance, modules)

    def get(
        self,
        instance_id: str,
        module: str,
        provider: str = "custom",
    ) -> Optional[Dict[str, Any]]:
        """Return stored JSON dict for *module* on *instance_id*, or ``None``."""
        instance_id = self._resolve_id(instance_id)
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
        instance_meta = self._resolve_instance(instance_meta)
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
        instance_meta = self._resolve_instance(instance_meta)
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
        instance_id = self._resolve_id(instance_id)
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
        instance_id = self._resolve_id(instance_id)
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
        instance_id = self._resolve_id(instance_id)
        return self._store.stale_modules(instance_id, self._config, provider)

    def get_all_modules(
        self, instance_id: str, provider: str = "custom"
    ) -> Dict[str, Dict[str, Any]]:
        """Return all stored modules for *instance_id* as ``{module: data}``.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
        """
        instance_id = self._resolve_id(instance_id)
        return self._store.get_all_modules(instance_id, provider)

    def get_annotations_path(
        self, instance_id: str, provider: str = "custom"
    ) -> "Path":
        """Return the annotations file path for *instance_id* (may not exist yet).

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
        """
        instance_id = self._resolve_id(instance_id)
        return self._store.get_annotations_path(instance_id, provider)

    def read_annotations(self, instance_id: str, provider: str = "custom") -> str:
        """Return the annotations content for *instance_id*, or empty string if none.

        Public proxy so callers (screens, CLI, MCP) never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
        """
        instance_id = self._resolve_id(instance_id)
        return self._store.read_annotations(instance_id, provider)

    def write_annotations(
        self, instance_id: str, content: str, provider: str = "custom"
    ) -> Path:
        """Persist *content* as the annotations for *instance_id* and return the path.

        Public proxy so callers (screens, CLI, MCP) never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
            content: Raw annotation text to write.
            provider: Provider slug.
        """
        instance_id = self._resolve_id(instance_id)
        return self._store.write_annotations(instance_id, content, provider)

    def get_annotations_meta(self, instance_id: str) -> Dict[str, Any]:
        """Return the annotations metadata dict for *instance_id*.

        Public proxy so callers (screens, CLI, MCP) never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
        """
        instance_id = self._resolve_id(instance_id)
        return self._store.get_annotations_meta(instance_id)

    def set_annotations_meta(
        self,
        instance_id: str,
        *,
        annotations_hash: Optional[str] = None,
        annotations_synced_at: Optional[str] = None,
        annotations_modified_at: Optional[str] = None,
    ) -> None:
        """Update annotations metadata fields for *instance_id*.

        Public proxy so callers (screens, CLI, MCP) never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
            annotations_hash: SHA-256 hex hash of annotations content (if any).
            annotations_synced_at: ISO-8601 timestamp of last successful sync.
            annotations_modified_at: ISO-8601 timestamp of last local modification.
        """
        instance_id = self._resolve_id(instance_id)
        self._store.set_annotations_meta(
            instance_id,
            annotations_hash=annotations_hash,
            annotations_synced_at=annotations_synced_at,
            annotations_modified_at=annotations_modified_at,
        )

    # ------------------------------------------------------------------
    # Findings: class-level constants
    # ------------------------------------------------------------------

    #: Soft cap on total findings (active + superseded) per instance before pruning.
    _FINDINGS_SOFT_CAP: int = 200

    #: Word-tokeniser for lexical scoring in recall_findings.
    _FINDING_WORD_RE: "re.Pattern[str]" = re.compile(r"[a-z0-9_]+")

    #: Valid source values for remember_finding.
    _VALID_SOURCES = frozenset({"ai_chat", "agent", "user"})

    # ------------------------------------------------------------------
    # Findings public proxies (Wave 2a delegations)
    # ------------------------------------------------------------------

    def list_findings(
        self,
        instance_id: str,
        provider: str = "custom",
        *,
        include_superseded: bool = False,
    ) -> List[Dict[str, Any]]:
        """Return all stored findings for *instance_id*.

        Public proxy so callers never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
            include_superseded: When ``False`` (default), superseded findings
                are excluded.
        """
        instance_id = self._resolve_id(instance_id)
        return self._store.list_findings(
            instance_id, provider, include_superseded=include_superseded
        )

    def get_finding(
        self,
        instance_id: str,
        finding_id: str,
        provider: str = "custom",
    ) -> Optional[Dict[str, Any]]:
        """Return a single finding dict by ID, or ``None``.

        Public proxy so callers never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
            finding_id: Finding identifier.
            provider: Provider slug.
        """
        instance_id = self._resolve_id(instance_id)
        return self._store.get_finding(instance_id, finding_id, provider)

    def get_findings_meta(self, instance_id: str) -> Dict[str, Any]:
        """Return findings bookkeeping keys from the index for *instance_id*.

        Public proxy so callers never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
        """
        instance_id = self._resolve_id(instance_id)
        return self._store.get_findings_meta(instance_id)

    def set_findings_meta(self, instance_id: str, **kw: Any) -> None:
        """Update findings bookkeeping keys in the index for *instance_id*.

        Public proxy so callers never reach into ``_store`` directly.

        Args:
            instance_id: Instance identifier.
            **kw: Forwarded to ``MemoryStore.set_findings_meta``
                (``findings_count``, ``findings_synced_at``).
        """
        instance_id = self._resolve_id(instance_id)
        self._store.set_findings_meta(instance_id, **kw)

    # ------------------------------------------------------------------
    # Findings higher-level operations
    # ------------------------------------------------------------------

    def remember_finding(
        self,
        instance: Dict[str, Any],
        *,
        title: str,
        body: str,
        tags: Optional[List[str]] = None,
        confidence: float = 0.6,
        source: str = "ai_chat",
        supersede_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a new agent finding for *instance*.

        Args:
            instance: Instance dict (must contain ``id`` or ``name``).
            title: Short title string (required, non-empty after strip).
            body: Full finding text.
            tags: Optional list of tag strings; deduped, lowercased, max 12.
            confidence: Float in [0.0, 1.0]; clamped to that range.
            source: One of ``{"ai_chat", "agent", "user"}``; falls back to
                ``"ai_chat"`` when an invalid value is supplied.
            supersede_id: Optional ID of an existing finding to supersede.
                The referenced finding's ``superseded_by`` field is set to the
                new ID when the record exists; otherwise silently ignored.

        Returns:
            Dict with keys ``finding_id``, ``instance_id``, ``title``,
            ``auto_inject``, ``superseded``, ``secret_warning``, ``pruned``.
            When memory is disabled for the instance, returns
            ``{"refused": True, "reason": "memory_disabled"}``.

        Raises:
            ValueError: If *title* is empty after stripping.
        """
        instance = self._resolve_instance(instance)
        instance_id = instance.get("id") or instance.get("name", "")
        provider = instance.get("provider", "custom")
        instance_name = instance.get("name", "")

        # Opt-out gate.
        if self.is_memory_disabled(instance_id, instance_name):
            return {"refused": True, "reason": "memory_disabled"}

        # --- Validate / normalise inputs ---
        confidence = max(0.0, min(1.0, float(confidence)))
        title = str(title).strip()
        if not title:
            raise ValueError("title must not be empty after stripping whitespace")
        body = str(body)
        if source not in self._VALID_SOURCES:
            source = "ai_chat"

        # Normalise tags: lowercase, strip, dedupe, max 12.
        if tags:
            seen: set = set()
            clean_tags: List[str] = []
            for t in tags:
                t_norm = str(t).strip().lower()
                if t_norm and t_norm not in seen:
                    seen.add(t_norm)
                    clean_tags.append(t_norm)
            tags = clean_tags[:12]
        else:
            tags = []

        # Generate finding ID: "f_" + first 26 chars of a UUID4 hex.
        fid = "f_" + uuid.uuid4().hex[:26]
        now_iso = datetime.now(timezone.utc).isoformat()

        # Handle supersede: if the referenced finding exists, mark it.
        effective_supersede: Optional[str] = None
        if supersede_id:
            try:
                _validate_finding_id(supersede_id)
                old_record = self._store.get_finding(instance_id, supersede_id, provider)
                if old_record is not None:
                    old_record["superseded_by"] = fid
                    old_record["updated_at"] = now_iso
                    self._store.save_finding(instance_id, old_record, provider)
                    effective_supersede = supersede_id
            except ValueError:
                pass  # invalid supersede_id — ignore silently

        # Secret scan (warn, never block — findings convention mirrors annotations).
        warnings = scan_for_secrets(body)

        # Build and persist record.
        record: Dict[str, Any] = {
            "id": fid,
            "instance_id": instance_id,
            "title": title,
            "body": body,
            "tags": tags,
            "confidence": confidence,
            "source": source,
            "created_at": now_iso,
            "updated_at": now_iso,
            "superseded_by": None,
        }
        self._store.save_finding(instance_id, record, provider)

        # Prune over-cap findings (never prunes the record just saved).
        pruned_ids = self._prune_findings(instance_id, provider, fid)

        # Update meta with fresh active count.
        active_count = len(
            self._store.list_findings(instance_id, provider, include_superseded=False)
        )
        try:
            self._store.set_findings_meta(instance_id, findings_count=active_count)
        except Exception as exc:
            logger.warning("set_findings_meta failed for %s: %s", instance_id, exc)

        # Enqueue for sync (best-effort — never blocks).
        if self._sync_service is not None:
            try:
                all_findings = self._store.list_findings(
                    instance_id, provider, include_superseded=True
                )
                self._sync_service.enqueue_findings(instance, all_findings)
            except Exception as exc:
                logger.warning(
                    "sync enqueue_findings failed for %s: %s", instance_id, exc
                )

        auto_inject = confidence >= getattr(
            self._config, "findings_confidence_threshold", 0.6
        )

        return {
            "finding_id": fid,
            "instance_id": instance_id,
            "title": title,
            "auto_inject": auto_inject,
            "superseded": effective_supersede,
            "secret_warning": warnings,
            "pruned": pruned_ids,
        }

    def recall_findings(
        self,
        instance_id: str,
        *,
        instance_name: str = "",
        query: str = "",
        tags: Optional[List[str]] = None,
        limit: int = 10,
        include_superseded: bool = False,
        provider: str = "custom",
    ) -> List[Dict[str, Any]]:
        """Retrieve findings for *instance_id*, optionally filtered by query/tags.

        Args:
            instance_id: Instance identifier.
            instance_name: Instance name — required so the opt-out check covers
                name-keyed overrides (per the id-AND-name convention); an
                id-only check would leak findings for a server opted out by name.
            query: Free-text lexical search.  Tokens matched against title
                (weight 3), tags (weight 2), body (weight 1).
            tags: AND-filter: only findings whose tag set is a superset of the
                requested tags are returned.
            limit: Maximum findings returned; clamped to [1, 50].
            include_superseded: When ``True``, superseded findings are included.
            provider: Provider slug.

        Returns:
            Matching finding dicts.  When no query: newest-first.  When query:
            score-desc then newest-first.  Body text is set to ``""`` with
            ``_body_truncated=True`` once cumulative body chars exceed 12000.
            Returns ``[]`` when memory is disabled (by id OR name).
        """
        instance_id = self._resolve_id(instance_id)
        if self.is_memory_disabled(instance_id, instance_name):
            return []

        records = self._store.list_findings(
            instance_id, provider, include_superseded=include_superseded
        )

        # Tags AND-filter.
        if tags:
            required = {str(t).strip().lower() for t in tags}
            records = [r for r in records if required.issubset(set(r.get("tags") or []))]

        # Lexical scoring.
        if query:
            q_tokens = set(self._FINDING_WORD_RE.findall(query.lower()))
            if q_tokens:
                def _score(r: Dict[str, Any]) -> int:
                    title_tokens = set(
                        self._FINDING_WORD_RE.findall((r.get("title") or "").lower())
                    )
                    tag_tokens = set(r.get("tags") or [])
                    body_tokens = set(
                        self._FINDING_WORD_RE.findall((r.get("body") or "").lower())
                    )
                    return (
                        len(q_tokens & title_tokens) * 3
                        + len(q_tokens & tag_tokens) * 2
                        + len(q_tokens & body_tokens) * 1
                    )

                scored = [(r, _score(r)) for r in records]
                scored = [(r, s) for r, s in scored if s > 0]
                # Sort: score descending, then created_at descending (reverse
                # string comparison — ISO-8601 sorts lexicographically).
                scored.sort(
                    key=lambda x: (-x[1], x[0].get("created_at") or ""),
                    reverse=False,
                )
                scored.sort(key=lambda x: x[1], reverse=True)
                records = [r for r, _s in scored]

        limit = max(1, min(50, limit))
        records = records[:limit]

        # Per-response body cap: 12 000 chars total.
        _BODY_CAP = 12000
        total_chars = 0
        result: List[Dict[str, Any]] = []
        for rec in records:
            out = dict(rec)
            body_text = out.get("body") or ""
            if total_chars >= _BODY_CAP:
                out["body"] = ""
                out["_body_truncated"] = True
            else:
                total_chars += len(body_text)
                if total_chars > _BODY_CAP:
                    out["body"] = ""
                    out["_body_truncated"] = True
            result.append(out)

        return result

    def merge_findings(
        self,
        instance_id: str,
        incoming: List[Dict[str, Any]],
        provider: str = "custom",
    ) -> Dict[str, int]:
        """Merge *incoming* finding records into the local store.

        Last-writer-wins based on ``max(created_at, updated_at)``.  Ties keep
        the local record.  ``superseded_by`` is monotonic: once set on either
        side it is never unset on the merged record.

        Args:
            instance_id: Instance identifier.
            incoming: List of finding dicts (typically from cloud sync).
            provider: Provider slug.

        Returns:
            Dict with ``created``, ``updated``, ``skipped``,
            ``active_after`` (count of non-superseded findings after merge).
        """
        instance_id = self._resolve_id(instance_id)
        created = 0
        updated = 0
        skipped = 0

        for record in incoming:
            fid = record.get("id", "")
            try:
                _validate_finding_id(fid)
            except (ValueError, TypeError):
                skipped += 1
                continue

            local = self._store.get_finding(instance_id, fid, provider)
            if local is None:
                try:
                    self._store.save_finding(instance_id, dict(record), provider)
                    created += 1
                except Exception as exc:
                    logger.warning(
                        "merge_findings: could not save %s for %s: %s",
                        fid, instance_id, exc,
                    )
                    skipped += 1
                continue

            # Effective timestamp: max(created_at, updated_at).
            def _eff_ts(r: Dict[str, Any]) -> str:
                return max(
                    r.get("created_at") or "",
                    r.get("updated_at") or "",
                )

            local_ts = _eff_ts(local)
            incoming_ts = _eff_ts(record)

            if incoming_ts > local_ts:
                # Incoming wins — but apply monotonic superseded_by from local.
                merged = dict(record)
                local_sup = local.get("superseded_by")
                inc_sup = merged.get("superseded_by")
                if local_sup and not inc_sup:
                    merged["superseded_by"] = local_sup
                try:
                    self._store.save_finding(instance_id, merged, provider)
                    updated += 1
                except Exception as exc:
                    logger.warning(
                        "merge_findings: could not save %s for %s: %s",
                        fid, instance_id, exc,
                    )
                    skipped += 1
            else:
                # Local wins — still apply monotonic superseded_by from incoming.
                inc_sup = record.get("superseded_by")
                if inc_sup and not local.get("superseded_by"):
                    local["superseded_by"] = inc_sup
                    try:
                        self._store.save_finding(instance_id, local, provider)
                    except Exception as exc:
                        logger.warning(
                            "merge_findings: could not update superseded_by for %s: %s",
                            fid, exc,
                        )
                skipped += 1

        active_after = len(
            self._store.list_findings(instance_id, provider, include_superseded=False)
        )
        return {
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "active_after": active_after,
        }

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
        instance_id = self._resolve_id(instance_id)
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
        # Per-server overrides are keyed by the REAL id / name.
        resolved = self._resolve_instance({"id": instance_id, "name": instance_name})
        return self._config.is_instance_disabled(
            str(resolved.get("id") or instance_id),
            str(resolved.get("name") or instance_name),
        )

    def set_instance_resolver(
        self,
        instance_resolver: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]],
        instance_id_resolver: Optional[Callable[[str], str]],
    ) -> None:
        """Install the demo-mode resolvers (dict → pristine dict, id → real id).

        The TUI redacts its instance list in place for display; anything that
        reaches this service from a screen may therefore carry a fake id and
        fake connection fields. Both resolvers are identity outside demo mode.
        """
        def _dict(inst: Dict[str, Any]) -> Dict[str, Any]:
            if not instance_resolver or not isinstance(inst, dict):
                return inst
            out = instance_resolver(inst)
            return out if isinstance(out, dict) else inst

        def _id(instance_id: str) -> str:
            if not instance_id_resolver or not instance_id:
                return instance_id
            out = instance_id_resolver(instance_id)
            return out if isinstance(out, str) else instance_id

        self._resolve_instance = _dict
        self._resolve_id = _id
        self._store.set_instance_id_resolver(_id)

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

    def _prune_findings(
        self, instance_id: str, provider: str, just_saved_id: str
    ) -> List[str]:
        """Delete lowest-priority findings until count <= _FINDINGS_SOFT_CAP.

        Deletion priority (most expendable first):
        1. Superseded findings, oldest-first by ``created_at``.
        2. Active findings below ``findings_confidence_threshold``, oldest-first.
        3. Remaining active findings, oldest-first (last resort).

        The finding identified by *just_saved_id* is never deleted.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
            just_saved_id: ID of the finding just written; exempt from pruning.

        Returns:
            List of deleted finding IDs.
        """
        all_findings = self._store.list_findings(
            instance_id, provider, include_superseded=True
        )
        if len(all_findings) <= self._FINDINGS_SOFT_CAP:
            return []

        threshold = getattr(self._config, "findings_confidence_threshold", 0.6)

        superseded = sorted(
            [f for f in all_findings if f.get("superseded_by")],
            key=lambda r: r.get("created_at") or "",
        )
        low_conf = sorted(
            [
                f for f in all_findings
                if not f.get("superseded_by")
                and (f.get("confidence") or 0.0) < threshold
            ],
            key=lambda r: r.get("created_at") or "",
        )
        active_rest = sorted(
            [
                f for f in all_findings
                if not f.get("superseded_by")
                and (f.get("confidence") or 0.0) >= threshold
            ],
            key=lambda r: r.get("created_at") or "",
        )

        candidates = superseded + low_conf + active_rest
        pruned: List[str] = []
        remaining = len(all_findings)

        for candidate in candidates:
            if remaining <= self._FINDINGS_SOFT_CAP:
                break
            cid = candidate.get("id", "")
            if cid == just_saved_id:
                continue
            if self._store.delete_finding(instance_id, cid, provider):
                pruned.append(cid)
                remaining -= 1

        return pruned

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

    def make_ssh_runner(self, instance: Dict[str, Any]) -> Any:
        """Public factory for a one-shot async SSH runner bound to *instance*.

        Returns the same ``(command) -> (stdout, stderr, returncode)`` callable
        used internally for probing, so consumers outside ``services/memory/``
        (e.g. the live-stats panel on ``ServerActionsScreen``) get the exact
        same provider-aware connection resolution — host, username, key path,
        proxy args, port — without duplicating it.

        The runner is read-only by nature of how callers use it; it imposes no
        write-guard (that is the prober base class's responsibility), so callers
        MUST only pass read-only commands.

        Args:
            instance: Instance dict (same format as ``app.instances``).

        Returns:
            Async callable ``(command: str) -> (stdout, stderr, returncode)``.
        """
        instance = self._resolve_instance(instance)
        return self._make_ssh_runner(instance)

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
            # Attach instance so LogsProber can read it from the runner directly,
            # eliminating the shared _instance field race in concurrent build_report calls.
            _stub_runner.instance = instance  # type: ignore[attr-defined]
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

        # Attach instance so LogsProber can read it from the runner directly,
        # eliminating the shared _instance field race in concurrent build_report calls.
        _real_runner.instance = instance  # type: ignore[attr-defined]
        return _real_runner

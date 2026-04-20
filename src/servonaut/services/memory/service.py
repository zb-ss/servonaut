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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .interfaces import MemoryServiceInterface, ModuleProberInterface, ModuleResult
from .redaction import noop_redactor
from .store import MemoryStore
from .summariser import build_summary_markdown

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
        # Default-construct MemoryStore with noop_redactor so T9 can swap it in
        # without refactoring any call sites — just replace noop_redactor.
        self._store = store if store is not None else MemoryStore(redactor=noop_redactor)
        self._config = config
        self._probers: List[ModuleProberInterface] = probers or []
        self._ssh_service = ssh_service
        self._connection_service = connection_service

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def build(
        self,
        instance: Dict[str, Any],
        modules: Optional[List[str]] = None,
    ) -> Dict[str, ModuleResult]:
        """Probe *modules* for *instance* in parallel, persist results.

        Args:
            instance: Instance dict (``id``, ``name``, ``provider``, etc.).
            modules: Module names to probe; ``None`` or ``["*"]`` probes all
                enabled modules.

        Returns:
            Mapping of ``module_name → ModuleResult`` for completed probes.
        """
        instance_id = instance.get("id") or instance.get("name", "")
        provider = instance.get("provider", "custom")
        name = instance.get("name", instance_id)

        if not self._config.enabled:
            logger.info("Memory is disabled in config; skipping build for %s", instance_id)
            return {}

        if self._config.is_module_disabled_for(instance_id):
            logger.info("Memory disabled for instance %s via per_server_overrides", instance_id)
            return {}

        selected_probers = self._select_probers(modules)
        if not selected_probers:
            logger.debug("No probers to run for %s (modules=%s)", instance_id, modules)
            return {}

        # Bind instance to LogsProber (which uses a different probe path).
        for prober in selected_probers:
            if hasattr(prober, "set_instance"):
                prober.set_instance(instance)

        ssh_runner = self._make_ssh_runner(instance)

        semaphore = asyncio.Semaphore(_MAX_CONCURRENT_PROBES)

        async def run_one(prober: ModuleProberInterface) -> Optional[ModuleResult]:
            module_name = prober.name
            if module_name in self._config.disabled_modules:
                logger.debug("Module %s is disabled in config", module_name)
                return None
            async with semaphore:
                try:
                    result = await prober.probe(ssh_runner)
                    return result
                except asyncio.TimeoutError:
                    logger.warning("Prober %s timed out for %s", module_name, instance_id)
                    return None
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Prober %s failed for %s: %s", module_name, instance_id, exc
                    )
                    return None

        tasks = [run_one(p) for p in selected_probers]
        raw_results: List[Optional[ModuleResult]] = await asyncio.gather(*tasks)

        results: Dict[str, ModuleResult] = {}
        probed_modules: List[str] = []

        for result in raw_results:
            if result is None:
                continue
            # Stamp probed_at if the prober didn't set it.
            if not result.probed_at:
                result.probed_at = datetime.now(tz=timezone.utc).isoformat()
            self._persist_result(result, instance_id, provider)
            results[result.module] = result
            probed_modules.append(result.module)

        if probed_modules:
            self._store.update_index(
                instance_id=instance_id,
                name=name,
                provider=provider,
                modules=probed_modules,
            )

        return results

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

    def list_all(self) -> List[Dict[str, Any]]:
        """Return index entries for all instances that have memory."""
        index_entries = []
        for instance_id in self._store.list_instances():
            entry = self._store.get_index_entry(instance_id)
            if entry:
                index_entries.append({"instance_id": instance_id, **entry})
        return index_entries

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
    ) -> None:
        """Convert *result* to a JSON dict and write it to the store."""
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

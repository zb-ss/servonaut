"""Abstract interfaces for the server memory subsystem."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------

class MemoryModuleMissingError(LookupError):
    """Raised when a pin operation targets a module that has no stored data.

    The module must be probed at least once before a field can be pinned.

    Args:
        instance_id: Instance the operation was targeting.
        module: Module name that was not found.
    """

    def __init__(self, instance_id: str, module: str) -> None:
        self.instance_id = instance_id
        self.module = module
        super().__init__(
            f"Memory module {module!r} not found for instance {instance_id!r}. "
            "Run 'memory build' first to create the module before pinning."
        )


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------

@dataclass
class ModuleResult:
    """Result emitted by a single module prober after a successful (or partial) probe.

    Attributes:
        module: Module name, e.g. ``"runtimes"``.
        instance_id: Target instance identifier.
        observed: Dict of key → observed value (raw data, post-redaction).
        declared: Dict of key → user override / pin.
        sudo_used: Whether the probe required sudo escalation.
        truncated: True if output was cut at the 16 KB probe cap.
        partial: True when sudo was unavailable and a fallback was used.
        probed_at: ISO-8601 timestamp of when the probe completed (UTC).
        ttl_seconds: Module-default TTL in seconds (may be overridden by MemoryConfig).
        raw_output: Concatenated raw command output (already redacted).
    """

    module: str
    instance_id: str
    observed: Dict[str, Any] = field(default_factory=dict)
    declared: Dict[str, Any] = field(default_factory=dict)
    sudo_used: bool = False
    truncated: bool = False
    partial: bool = False
    probed_at: str = ""
    ttl_seconds: int = 86400
    raw_output: str = ""


# ---------------------------------------------------------------------------
# Abstract service interface
# ---------------------------------------------------------------------------

class MemoryServiceInterface(ABC):
    """Top-level API for the server memory subsystem.

    Consumers (chat, MCP, CLI) use this interface; the concrete
    ``MemoryService`` implementation is wired in ``app.py``.
    """

    @abstractmethod
    async def build(
        self,
        instance: Dict[str, Any],
        modules: Optional[List[str]] = None,
    ) -> Dict[str, ModuleResult]:
        """Probe the specified modules for *instance* and persist results.

        Args:
            instance: Instance dict (same format as ``app.instances``).
            modules: Module names to probe; ``None`` / ``["*"]`` → all enabled.

        Returns:
            Mapping of module name → ``ModuleResult`` for every module that
            completed (successfully or partially).
        """

    @abstractmethod
    async def refresh(
        self,
        instance: Dict[str, Any],
        modules: Optional[List[str]] = None,
    ) -> Dict[str, ModuleResult]:
        """Re-probe stale (or forced) modules and update the store.

        Functionally identical to ``build`` but intended for incremental
        refresh rather than a first-time full scan.
        """

    @abstractmethod
    def get(
        self,
        instance_id: str,
        module: str,
    ) -> Optional[Dict[str, Any]]:
        """Return the stored JSON dict for a single module, or ``None``.

        Args:
            instance_id: Instance identifier.
            module: Module name (e.g. ``"os"``).
        """

    @abstractmethod
    async def get_summary(
        self,
        instance_meta: Dict[str, Any],
        max_tokens: int = 1500,
    ) -> str:
        """Return a token-efficient Markdown summary for *instance_meta*.

        Suitable for injection into an AI system prompt inside a
        ``<server_memory>`` tag.

        Args:
            instance_meta: Instance dict with ``id``, ``name``, ``provider``
                keys (mirrors ``app.instances`` entries).
            max_tokens: Approximate upper bound on summary length
                (1 token ≈ 4 chars).

        Returns:
            Markdown-formatted summary string (may be empty if no memory exists).
        """

    @abstractmethod
    async def write_summary(
        self,
        instance_meta: Dict[str, Any],
    ) -> "Path":
        """Write the deterministic summary to ``summary.md`` for *instance_meta*.

        Args:
            instance_meta: Instance dict with ``id``, ``name``, ``provider``.

        Returns:
            Path to the written ``summary.md`` file.
        """

    @abstractmethod
    def clear(
        self,
        instance_id: str,
        modules: Optional[List[str]] = None,
    ) -> None:
        """Delete stored memory for *instance_id*.

        Args:
            instance_id: Instance identifier.
            modules: Module names to clear; ``None`` → clear all modules.
        """

    @abstractmethod
    def list_all(self) -> List[Dict[str, Any]]:
        """Return a list of index entries for every instance that has memory."""

    def stale_modules(self, instance_id: str, provider: str = "custom") -> List[str]:
        """Return module names whose stored data has exceeded its TTL.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.

        Returns:
            List of stale module name strings.
        """
        return []

    def get_all_modules(
        self, instance_id: str, provider: str = "custom"
    ) -> "Dict[str, Dict[str, Any]]":
        """Return all stored modules for *instance_id* as ``{module: data}``.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
        """
        return {}

    def get_annotations_path(
        self, instance_id: str, provider: str = "custom"
    ) -> "Path":
        """Return the annotations file path for *instance_id* (may not exist).

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.
        """
        raise NotImplementedError

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

        Public proxy so CLI/MCP callers never reach into ``_store`` directly.
        """

    def is_memory_disabled(self, instance_id: str, instance_name: str = "") -> bool:
        """Return True if memory is disabled for *instance_id* or *instance_name*.

        Checks both the per-server override by ID and by name so callers never
        need to access ``_config`` directly.
        """
        return False

    @abstractmethod
    async def pin(
        self,
        instance_id: str,
        module: str,
        field: str,
        value: Any,
        pinned_by: str,
        provider: str = "custom",
    ) -> None:
        """Pin a user-declared value for a specific field in a module.

        Requires the module to have been probed at least once (i.e. a JSON
        file must exist on disk).  Raises :exc:`MemoryModuleMissingError` if
        the module file is absent.

        Args:
            instance_id: Instance identifier.
            module: Module name, e.g. ``"os"``.
            field: Key to set inside ``data["declared"]``.
            value: Value to store (persisted as a string).
            pinned_by: Username or agent identity that set the pin.
            provider: Provider slug for the storage sub-directory.

        Raises:
            MemoryModuleMissingError: If no stored data exists for *module*.
            ValueError: If *instance_id* or *module* fails safety validation.
        """


# ---------------------------------------------------------------------------
# Abstract prober interface (contract for T2 module implementations)
# ---------------------------------------------------------------------------

class ModuleProberInterface(ABC):
    """Contract for individual module probers.

    Each concrete prober implements exactly one module (``name``) and is
    responsible for running its allowlisted commands via ``ssh_runner``,
    parsing the output, and returning a ``ModuleResult``.

    T2 implements the concrete subclasses; T1 only defines this seam.
    """

    #: Module identifier, e.g. ``"runtimes"``. Must be unique across all probers.
    name: str

    #: Default TTL for this module in seconds.
    ttl_seconds: int

    @abstractmethod
    async def probe(self, ssh_runner: Any) -> ModuleResult:
        """Run allowlisted SSH commands and return a ``ModuleResult``.

        Args:
            ssh_runner: A callable (or async callable) that accepts a shell
                command string and returns ``(stdout, stderr, returncode)``.
                Concrete type is defined by T2 when the SSH plumbing is wired.

        Returns:
            A ``ModuleResult`` populated from the probe output.

        Raises:
            asyncio.TimeoutError: If the probe exceeds its wall-clock cap.
        """

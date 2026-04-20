"""Abstract interfaces for the server memory subsystem."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


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

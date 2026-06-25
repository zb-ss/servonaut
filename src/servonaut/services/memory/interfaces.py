"""Abstract interfaces for the server memory subsystem."""

from __future__ import annotations

import re
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

    def read_annotations(self, instance_id: str, provider: str = "custom") -> str:
        """Return the current annotations markdown content for *instance_id*.

        Args:
            instance_id: Instance identifier.
            provider: Provider slug for the storage sub-directory.

        Returns:
            Markdown string, or ``""`` if no annotations file exists.
        """
        return ""

    def write_annotations(
        self, instance_id: str, content: str, provider: str = "custom"
    ) -> "Path":
        """Persist *content* as the annotations file for *instance_id*.

        Writes atomically (tmp-file + os.replace) and sets permissions to
        0o600.  Returns the path of the written file.

        Args:
            instance_id: Instance identifier.
            content: Markdown string to persist.
            provider: Provider slug for the storage sub-directory.

        Returns:
            :class:`~pathlib.Path` of the written annotations file.
        """
        raise NotImplementedError

    def get_annotations_meta(self, instance_id: str) -> Dict[str, Any]:
        """Return annotations bookkeeping keys from the instance index entry.

        Returns the three bookkeeping keys ``annotations_hash``,
        ``annotations_modified_at`` and ``annotations_synced_at``. The concrete
        implementation always returns all three, defaulting absent ones to
        ``""``; callers should still use ``.get`` for safety. This default
        stub returns ``{}`` (treated as all-empty by ``.get``).

        Args:
            instance_id: Instance identifier.

        Returns:
            Dict of the three bookkeeping keys (``""`` when unset).
        """
        return {}

    def set_annotations_meta(
        self,
        instance_id: str,
        *,
        annotations_hash: Optional[str] = None,
        annotations_synced_at: Optional[str] = None,
        annotations_modified_at: Optional[str] = None,
    ) -> None:
        """Upsert annotations bookkeeping keys in the instance index entry.

        Only the keyword arguments that are not ``None`` are written; existing
        keys are left untouched.

        Args:
            instance_id: Instance identifier.
            annotations_hash: SHA-256 hex of the current annotations content.
            annotations_synced_at: ISO-8601 UTC timestamp of the last
                enqueued or pulled envelope.
            annotations_modified_at: ISO-8601 UTC timestamp of the last
                local save or successful pull write-back.
        """
        return None

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


# ---------------------------------------------------------------------------
# Memory sync API — domain constants
# ---------------------------------------------------------------------------

#: Instance IDs that the server routes to dedicated handlers; never valid as a
#: user-chosen instance_id.  Validated in upsert + retrieval before hitting wire.
RESERVED_INSTANCE_IDS: frozenset = frozenset({
    "drift",
    "anomalies",
    "fleet",
    "export",
    "export-signing-key",
    "summary",
    "sync",
    "instances",
    "keys",
    "ai-provider-info",
    "settings",
})

#: Valid pattern for user-chosen instance IDs per spec §3.2.
INSTANCE_ID_RE: re.Pattern = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


# ---------------------------------------------------------------------------
# Memory sync API — shared data transfer objects
# ---------------------------------------------------------------------------

@dataclass
class QuotaInfo:
    """Envelope quota summary returned in every sync response.

    Attributes:
        envelopes_used: Number of envelopes currently stored.
        envelopes_soft_cap: Soft warning threshold for the plan tier.
        envelopes_hard_cap: Hard limit; writes rejected above this value.
        retention_days: How long old snapshots are retained.
    """

    envelopes_used: int
    envelopes_soft_cap: int
    envelopes_hard_cap: int
    retention_days: int


@dataclass
class MemorySyncStatus:
    """Observable state of the background sync loop.

    Attributes:
        state: One of ``idle | running | halted | error | disabled``.
        last_sync_at: ISO-8601 timestamp of the last successful drain, or None.
        last_error: Human-readable last error message, or None.
        pending_envelopes: Number of envelopes waiting to be synced.
        quota: Latest quota snapshot from the server, or None if unavailable.
        halted_reason: Machine code for why the loop is halted, or None.
            Known values: ``"quota_exceeded"`` | ``"no_active_keypair"``.
    """

    state: str
    last_sync_at: Optional[str]
    last_error: Optional[str]
    pending_envelopes: int
    quota: Optional[QuotaInfo]
    halted_reason: Optional[str]


@dataclass
class SyncEnvelope:
    """Pre-encryption envelope payload queued for sync to the server.

    Attributes:
        instance_id: User-chosen instance identifier (≤ 128 chars, alphanumeric + _-).
        module: Module name (e.g. ``"os"``, ``"runtimes"``).
        probed_at: ISO-8601 timestamp of when the probe completed (UTC).
        ttl_seconds: Lifetime hint for the server-side snapshot.
        truncated: True if raw output was cut at the probe cap.
        partial: True when sudo was unavailable and a fallback was used.
        sudo_used: True if the probe required sudo escalation.
        memory_disabled: True if the instance is flagged opt-out.
        safe_metrics: Optional string→number metrics dict (allowlisted keys only).
        plaintext_payload: Dict to be JSON-serialised and encrypted.
    """

    instance_id: str
    module: str
    probed_at: str
    ttl_seconds: int
    truncated: bool
    partial: bool
    sudo_used: bool
    memory_disabled: bool
    safe_metrics: Optional[Dict[str, Any]]
    plaintext_payload: Dict[str, Any]


@dataclass
class SyncRejection:
    """A rejected envelope from a sync batch response.

    Attributes:
        index: Zero-based position of the envelope in the submitted batch.
        reason: Machine code (e.g. ``"duplicate_hash"``, ``"bad_crypto"``).
        message: Human-readable rejection explanation from the server.
    """

    index: int
    reason: str
    message: str


@dataclass
class SyncBatchResult:
    """Result of a POST /memory/sync batch operation.

    Attributes:
        accepted: List of accepted-envelope dicts (id, instance_id, module, etc.).
        rejected: List of per-envelope rejection details.
        quota: Updated quota snapshot, or None if not returned.
    """

    accepted: List[Dict[str, Any]]
    rejected: List[SyncRejection]
    quota: Optional[QuotaInfo]


@dataclass
class DecryptedEnvelope:
    """A server envelope that has been successfully decrypted by the caller.

    Attributes:
        id: Server-assigned envelope UUID.
        instance_id: User-chosen instance identifier.
        module: Module name.
        snapshot_version: Monotonically increasing snapshot counter.
        probed_at: ISO-8601 timestamp when the probe ran.
        ttl_seconds: Lifetime hint.
        truncated: True if raw output was cut at the probe cap.
        partial: True if sudo was unavailable.
        sudo_used: True if sudo was used.
        safe_metrics: Optional string→number dict.
        plaintext: Decrypted JSON payload dict.
        created_at: ISO-8601 timestamp when the server stored the envelope.
        grant_id: Team grant UUID (Teams read path only), or None.
        required_role: Minimum team role required to read (Teams path only), or None.
    """

    id: str
    instance_id: str
    module: str
    snapshot_version: int
    probed_at: str
    ttl_seconds: int
    truncated: bool
    partial: bool
    sudo_used: bool
    safe_metrics: Optional[Dict[str, Any]]
    plaintext: Dict[str, Any]
    created_at: str
    grant_id: Optional[str] = None
    required_role: Optional[str] = None


@dataclass
class DriftEvent:
    """A server-detected configuration drift event.

    Attributes:
        id: Server-assigned drift event UUID.
        instance_id: The instance where drift was detected.
        module: The module that changed (e.g. ``"os"``).
        old_hash: SHA-256 hex of the previous snapshot, or None if first probe.
        new_hash: SHA-256 hex of the new snapshot.
        probed_at: ISO-8601 timestamp of the probe that detected the drift.
        detected_at: ISO-8601 timestamp when the server computed the diff.
        severity: ``"low"`` | ``"medium"`` | ``"high"``.
        acknowledged_at: ISO-8601 acknowledgement timestamp, or None.
        old_envelope_id: UUID of the previous envelope, or None.
        new_envelope_id: UUID of the new (drifted) envelope.
    """

    id: str
    instance_id: str
    module: str
    old_hash: Optional[str]
    new_hash: str
    probed_at: str
    detected_at: str
    severity: str
    acknowledged_at: Optional[str]
    old_envelope_id: Optional[str]
    new_envelope_id: str


@dataclass
class AnomalyEvent:
    """A rule-triggered anomaly detected by the server.

    Attributes:
        id: Server-assigned anomaly event UUID.
        instance_id: The instance where the anomaly was detected.
        module: The module the rule matched against.
        rule_key: Identifier of the anomaly rule (e.g. ``"drift.os_kernel"``).
        severity: ``"low"`` | ``"medium"`` | ``"high"``.
        summary: Human-readable anomaly description.
        detected_at: ISO-8601 timestamp of detection.
        acknowledged_at: ISO-8601 acknowledgement timestamp, or None.
    """

    id: str
    instance_id: str
    module: str
    rule_key: str
    severity: str
    summary: str
    detected_at: str
    acknowledged_at: Optional[str]


@dataclass
class RemoteFleetItem:
    """A single instance entry from GET /memory/fleet.

    Attributes:
        instance: Raw instance dict from the server.
        drift_count_7d: Number of drift events in the last 7 days.
        memory_age: Age bucket: ``"green"`` < 24 h, ``"amber"`` 24–168 h,
            ``"red"`` ≥ 168 h, ``"unknown"`` if never probed.
    """

    instance: Dict[str, Any]
    drift_count_7d: int
    memory_age: str


@dataclass
class RemoteFleet:
    """Aggregated fleet overview from GET /memory/fleet.

    Attributes:
        total: Total number of instances tracked server-side.
        by_provider: Count of instances per provider slug.
        oldest_last_probe_at: ISO-8601 timestamp of the least recently probed
            instance, or None if no instances have been probed.
        items: Per-instance detail list.
    """

    total: int
    by_provider: Dict[str, int]
    oldest_last_probe_at: Optional[str]
    items: List[RemoteFleetItem]


@dataclass
class AnomalyRule:
    """An anomaly detection rule returned from GET /memory/settings.

    Attributes:
        key: Machine identifier (e.g. ``"drift.os_kernel"``).
        label: Human-readable rule name.
        severity: Default severity: ``"low"`` | ``"medium"`` | ``"high"``.
        default_enabled: Whether the rule is on by default.
        enabled: Current enabled state for this user.
    """

    key: str
    label: str
    severity: str
    default_enabled: bool
    enabled: bool


@dataclass
class MemorySettings:
    """User memory settings from GET /memory/settings.

    Attributes:
        digest_frequency: Email digest cadence: ``"weekly"`` | ``"monthly"`` | ``"off"``.
        mercure_push_enabled: Whether Mercure server-sent-event push is active.
        ai_consent_mode: AI summary mode: ``"server_60s"`` | ``"client"`` | ``"off"``.
        anomaly_rules: Mapping of rule_key → AnomalyRule for all configured rules.
        raw: Unprocessed settings dict from the server (for forward-compatibility).
    """

    digest_frequency: str
    mercure_push_enabled: bool
    anomaly_rules: Dict[str, AnomalyRule]
    raw: Dict[str, Any]
    ai_consent_mode: str = "off"
    auto_sync_enabled: bool = False


@dataclass(frozen=True)
class KeyMaterial:
    """Active memory keypair material plus the resolved server-side user id.

    Lives in :mod:`memory.interfaces` so every service (sync, retrieval, team,
    AI summary) can consume the same dataclass without poking private
    attributes on each other.

    Attributes:
        user_id: Numeric user id resolved from ``/keys/me`` or auth bootstrap.
        public_key: Raw 32-byte X25519 public key.
        private_key: Raw 32-byte X25519 private key (kept in process memory).
    """

    user_id: int
    public_key: bytes
    private_key: bytes


# ---------------------------------------------------------------------------
# Memory sync API — domain exceptions
# ---------------------------------------------------------------------------

class MemoryBackendError(Exception):
    """Base class for errors raised by memory backend services."""


class BackendMaintenance(MemoryBackendError):
    """Server returned 503 feature_disabled (kill-switch active)."""


class BetaWaitlist(MemoryBackendError):
    """Server returned 403 feature_not_available (user not on beta allowlist)."""


class UpsellRequired(MemoryBackendError):
    """Server returned 403 forbidden_entitlement — feature requires a paid plan.

    Attributes:
        plan: Minimum plan slug required (e.g. ``"solo"`` or ``"teams"``).
    """

    def __init__(self, plan: str = "solo") -> None:
        self.plan = plan
        super().__init__(plan)


class QuotaExceeded(MemoryBackendError):
    """Hard envelope quota cap was reached — further writes are rejected."""


class ReservedInstanceIdError(ValueError):
    """The chosen instance_id collides with a reserved server path segment."""


class NoActiveKeypair(MemoryBackendError):
    """The caller has no active keypair on the server — key enrolment required."""


class MissingSelfWrap(MemoryBackendError):
    """An envelope in a sync batch had no DEK wrap for the calling user.

    This indicates a local crypto bug (not a server error) because the client
    is responsible for generating its own self-wrap before upload.
    """


class ValidationFailed(MemoryBackendError):
    """Server returned 422 validation_failed with per-field error details.

    Attributes:
        errors: List of ``{key, error}`` dicts from ``details.errors``.
    """

    def __init__(self, errors: List[Dict[str, str]]) -> None:
        self.errors = errors
        super().__init__()


class RateLimited(MemoryBackendError):
    """Server returned 429 rate_limited.

    Attributes:
        endpoint: API path that was rate-limited.
        retry_after_s: Suggested retry delay in seconds (from Retry-After header).
    """

    def __init__(self, endpoint: str, retry_after_s: float) -> None:
        self.endpoint = endpoint
        self.retry_after_s = retry_after_s
        super().__init__()

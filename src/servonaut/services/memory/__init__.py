"""Server memory package — per-instance knowledge base stored locally.

Public re-exports for consumers (chat, MCP, CLI):

    from servonaut.services.memory import MemoryService, MemoryStore, ModuleResult
"""

from .interfaces import (
    MemoryServiceInterface,
    ModuleProberInterface,
    ModuleResult,
    # Domain exceptions (Stream 1B)
    MemoryModuleMissingError,
    MemoryBackendError,
    BackendMaintenance,
    BetaWaitlist,
    UpsellRequired,
    QuotaExceeded,
    MissingSelfWrap,
    ValidationFailed,
    RateLimited,
    ReservedInstanceIdError,
    NoActiveKeypair,
    # Data-transfer objects (Stream 1B)
    QuotaInfo,
    MemorySyncStatus,
    SyncEnvelope,
    SyncRejection,
    SyncBatchResult,
    DecryptedEnvelope,
    DriftEvent,
    AnomalyEvent,
    RemoteFleetItem,
    RemoteFleet,
    AnomalyRule,
    MemorySettings,
    KeyMaterial,
    RESERVED_INSTANCE_IDS,
    INSTANCE_ID_RE,
)
from .service import MemoryService
from .store import MemoryStore

# Stream 2 services — import with graceful fallback if not yet delivered.
try:
    from .sync_service import MemorySyncService
except ImportError:  # pragma: no cover — Stream 2 TODO
    MemorySyncService = None  # type: ignore[assignment,misc]

try:
    from .retrieval_service import MemoryRetrievalService  # type: ignore[attr-defined]  # Stream 2 TODO
except ImportError:  # pragma: no cover — Stream 2 TODO
    MemoryRetrievalService = None  # type: ignore[assignment,misc]

try:
    from .drift_service import DriftService, AnomalyService  # type: ignore[attr-defined]  # Stream 2 TODO
except ImportError:  # pragma: no cover — Stream 2 TODO
    DriftService = None  # type: ignore[assignment,misc]
    AnomalyService = None  # type: ignore[assignment,misc]

try:
    from .fleet_service import FleetService  # type: ignore[attr-defined]  # Stream 2 TODO
except ImportError:  # pragma: no cover — Stream 2 TODO
    FleetService = None  # type: ignore[assignment,misc]

try:
    from .settings_service import MemorySettingsService  # type: ignore[attr-defined]  # Stream 2 TODO
except ImportError:  # pragma: no cover — Stream 2 TODO
    MemorySettingsService = None  # type: ignore[assignment,misc]

# Stream 3 services — import with graceful fallback if not yet delivered.
try:
    from .ai_summary_service import (
        AISummaryService,
        ProviderInfo,
        ConsentToken,
    )
except ImportError:  # pragma: no cover — Stream 3 TODO
    AISummaryService = None  # type: ignore[assignment,misc]
    ProviderInfo = None  # type: ignore[assignment,misc]
    ConsentToken = None  # type: ignore[assignment,misc]

try:
    from .export_service import MemoryExportService, SigningKey  # type: ignore[attr-defined]  # Stream 3 TODO
except ImportError:  # pragma: no cover — Stream 3 TODO
    MemoryExportService = None  # type: ignore[assignment,misc]
    SigningKey = None  # type: ignore[assignment,misc]

try:
    from .team_service import (  # type: ignore[attr-defined]  # Stream 3 TODO
        TeamMemoryService,
        TeamMemberKey,
        Grant,
        SharedInstance,
        MissingWrap,
        WrapEntry,
    )
except ImportError:  # pragma: no cover — Stream 3 TODO
    TeamMemoryService = None  # type: ignore[assignment,misc]
    TeamMemberKey = None  # type: ignore[assignment,misc]
    Grant = None  # type: ignore[assignment,misc]
    SharedInstance = None  # type: ignore[assignment,misc]
    MissingWrap = None  # type: ignore[assignment,misc]
    WrapEntry = None  # type: ignore[assignment,misc]

__all__ = [
    # Core
    "MemoryService",
    "MemoryServiceInterface",
    "MemoryStore",
    "ModuleProberInterface",
    "ModuleResult",
    # Exceptions
    "MemoryModuleMissingError",
    "MemoryBackendError",
    "BackendMaintenance",
    "BetaWaitlist",
    "UpsellRequired",
    "QuotaExceeded",
    "MissingSelfWrap",
    "ValidationFailed",
    "RateLimited",
    "ReservedInstanceIdError",
    "NoActiveKeypair",
    # DTOs
    "QuotaInfo",
    "MemorySyncStatus",
    "SyncEnvelope",
    "SyncRejection",
    "SyncBatchResult",
    "DecryptedEnvelope",
    "DriftEvent",
    "AnomalyEvent",
    "RemoteFleetItem",
    "RemoteFleet",
    "AnomalyRule",
    "MemorySettings",
    "KeyMaterial",
    "RESERVED_INSTANCE_IDS",
    "INSTANCE_ID_RE",
    # Stream 2
    "MemorySyncService",
    "MemoryRetrievalService",
    "DriftService",
    "AnomalyService",
    "FleetService",
    "MemorySettingsService",
    # Stream 3
    "AISummaryService",
    "ProviderInfo",
    "ConsentToken",
    "MemoryExportService",
    "SigningKey",
    "TeamMemoryService",
    "TeamMemberKey",
    "Grant",
    "SharedInstance",
    "MissingWrap",
    "WrapEntry",
]

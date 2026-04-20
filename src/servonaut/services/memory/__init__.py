"""Server memory package — per-instance knowledge base stored locally.

Public re-exports for consumers (chat, MCP, CLI):

    from servonaut.services.memory import MemoryService, MemoryStore, ModuleResult
"""

from .interfaces import MemoryServiceInterface, ModuleProberInterface, ModuleResult
from .service import MemoryService
from .store import MemoryStore

__all__ = [
    "MemoryService",
    "MemoryServiceInterface",
    "MemoryStore",
    "ModuleProberInterface",
    "ModuleResult",
]

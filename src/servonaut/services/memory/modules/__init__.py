"""Module probers package — one file per memory module.

Public factory function:

    from servonaut.services.memory.modules import build_default_probers

This returns the five MVP probers ready to be injected into ``MemoryService``.
"""

from __future__ import annotations

from typing import List, Optional, TYPE_CHECKING

from servonaut.services.memory.interfaces import ModuleProberInterface

if TYPE_CHECKING:
    from servonaut.services.log_viewer_service import LogViewerService
    from servonaut.services.interfaces import SSHServiceInterface, ConnectionServiceInterface


def build_default_probers(
    log_viewer_service: Optional["LogViewerService"] = None,
    ssh_service: Optional["SSHServiceInterface"] = None,
    connection_service: Optional["ConnectionServiceInterface"] = None,
) -> List[ModuleProberInterface]:
    """Instantiate and return all five MVP module probers.

    The ``os``, ``runtimes``, ``services``, and ``web_stack`` probers require
    no constructor arguments.  The ``logs`` prober needs the service
    dependencies provided here.

    Args:
        log_viewer_service: Required for the ``logs`` prober.  When ``None``
            the logs prober is omitted from the returned list.
        ssh_service: Required for the ``logs`` prober.
        connection_service: Required for the ``logs`` prober.

    Returns:
        List of ``ModuleProberInterface`` instances in probing order.
    """
    from .os import OSProber
    from .runtimes import RuntimesProber
    from .services import ServicesProber
    from .web_stack import WebStackProber
    from .logs import LogsProber

    probers: List[ModuleProberInterface] = [
        OSProber(),
        RuntimesProber(),
        ServicesProber(),
        WebStackProber(),
    ]

    if log_viewer_service is not None and ssh_service is not None and connection_service is not None:
        logs_prober = LogsProber(log_viewer_service, ssh_service, connection_service)
        probers.append(logs_prober)

    return probers


__all__ = [
    "build_default_probers",
]

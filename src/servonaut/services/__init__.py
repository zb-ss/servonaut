"""Services package for Servonaut v2.0.

The public names below resolve lazily (PEP 562): importing any service
submodule — for example the voice engine registry the voice worker needs —
must not pull in the whole service layer and its heavy dependencies
(boto3 and friends). Each name is imported on first attribute access and
cached on the module afterwards.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from servonaut.services.aws_service import AWSService
    from servonaut.services.cache_service import CacheService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.interfaces import (
        ConnectionServiceInterface,
        InstanceServiceInterface,
        KeywordStoreInterface,
        SCPServiceInterface,
        ScanServiceInterface,
        SSHServiceInterface,
        TerminalServiceInterface,
    )
    from servonaut.services.keyword_store import KeywordStore
    from servonaut.services.scan_service import ScanService
    from servonaut.services.scp_service import SCPService
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.terminal_service import TerminalService

# Public name -> submodule that defines it.
_LAZY_EXPORTS: Dict[str, str] = {
    'InstanceServiceInterface': 'servonaut.services.interfaces',
    'SSHServiceInterface': 'servonaut.services.interfaces',
    'SCPServiceInterface': 'servonaut.services.interfaces',
    'ConnectionServiceInterface': 'servonaut.services.interfaces',
    'ScanServiceInterface': 'servonaut.services.interfaces',
    'KeywordStoreInterface': 'servonaut.services.interfaces',
    'TerminalServiceInterface': 'servonaut.services.interfaces',
    'CacheService': 'servonaut.services.cache_service',
    'AWSService': 'servonaut.services.aws_service',
    'SSHService': 'servonaut.services.ssh_service',
    'ConnectionService': 'servonaut.services.connection_service',
    'ScanService': 'servonaut.services.scan_service',
    'KeywordStore': 'servonaut.services.keyword_store',
    'SCPService': 'servonaut.services.scp_service',
    'TerminalService': 'servonaut.services.terminal_service',
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    """Resolve a public service name on first access.

    Unknown names raise ``AttributeError`` so ``from servonaut.services
    import <submodule>`` still falls through to a normal submodule import.
    """
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))

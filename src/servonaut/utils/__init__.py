"""Utilities package for Servonaut v2.0.

The public names below resolve lazily (PEP 562): importing one utility
submodule — for example the archive-safety helper the voice worker needs —
must not import every other utility and its dependencies (``rich`` via
the formatting helpers). Each name is imported on first attribute access
and cached on the module afterwards.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from servonaut.utils.formatting import (
        format_file_size,
        format_timedelta,
        truncate_string,
    )
    from servonaut.utils.platform_utils import (
        command_exists,
        get_home_dir,
        get_os,
        get_ssh_dir,
    )

# Public name -> submodule that defines it.
_LAZY_EXPORTS: Dict[str, str] = {
    'format_timedelta': 'servonaut.utils.formatting',
    'truncate_string': 'servonaut.utils.formatting',
    'format_file_size': 'servonaut.utils.formatting',
    'get_os': 'servonaut.utils.platform_utils',
    'command_exists': 'servonaut.utils.platform_utils',
    'get_home_dir': 'servonaut.utils.platform_utils',
    'get_ssh_dir': 'servonaut.utils.platform_utils',
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    """Resolve a public utility name on first access.

    Unknown names raise ``AttributeError`` so ``from servonaut.utils import
    <submodule>`` still falls through to a normal submodule import.
    """
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))

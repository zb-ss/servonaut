"""Shared instance-resolution logic: match by id or name, AWS first on collision.

Used by both ``ServonautApp.resolve_instance`` and ``cli/memory.py::_resolve_instance``
so the resolution contract is defined once and tested once.
"""

from __future__ import annotations

from typing import Iterable, Optional


def resolve_instance_from_lists(
    id_or_name: str,
    aws: Iterable[dict],
    custom: Iterable[dict],
    ovh: Optional[Iterable[dict]] = None,
) -> Optional[dict]:
    """Return the first instance matching *id_or_name* across all provider lists.

    Search order: AWS first, then custom, then OVH.  Matching is
    case-insensitive on both ``id`` and ``name`` fields.  The first match
    wins, so AWS instances take precedence on name collisions.

    Args:
        id_or_name: Instance ID or display name to search for.
        aws: AWS instance dicts.
        custom: Custom-server instance dicts.
        ovh: OVH instance dicts (optional).

    Returns:
        The first matching instance dict, or ``None`` if not found.
    """
    needle = (id_or_name or "").lower()
    if not needle:
        return None
    for inst in list(aws) + list(custom) + list(ovh or []):
        if (inst.get("id") or "").lower() == needle or (inst.get("name") or "").lower() == needle:
            return inst
    return None

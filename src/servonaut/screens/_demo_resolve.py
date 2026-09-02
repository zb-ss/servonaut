"""Demo-mode resolution helpers for screens and widgets.

Demo mode redacts the instance list in place, so a screen's row may carry a
fake id and fake connection fields. ``ServonautApp.connection_instance`` /
``real_instance_id`` map them back to the pristine record; these wrappers
call them tolerantly so a screen keeps working against any app stand-in
(tests, previews) that does not implement them.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


def connection_instance(app: Any, instance: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The real record behind *instance*, or *instance* itself."""
    if not isinstance(instance, dict):
        return instance
    resolver = getattr(app, "connection_instance", None)
    if not callable(resolver):
        return instance
    try:
        resolved = resolver(instance)
    except Exception:  # noqa: BLE001 — a stand-in app must never break a screen
        return instance
    return resolved if isinstance(resolved, dict) else instance


def real_instance_id(app: Any, instance_id: Optional[str]) -> Optional[str]:
    """The real id behind a demo-mode fake, or *instance_id* itself."""
    if not instance_id:
        return instance_id
    resolver = getattr(app, "real_instance_id", None)
    if not callable(resolver):
        return instance_id
    try:
        resolved = resolver(instance_id)
    except Exception:  # noqa: BLE001
        return instance_id
    return resolved if isinstance(resolved, str) else instance_id

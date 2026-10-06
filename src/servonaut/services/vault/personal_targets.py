"""Route keys for a personal instance's credential binding.

The service stores no inventory for personal servers: a binding is addressed
by ``/api/v1/me/instances/{provider}/{instance_id}`` and signed for the target
``instance:{provider}:{instance_id}``. Cloud instances use their provider and
id; a custom server (any other host) uses the provider ``custom`` and an id
derived from its name, because names may contain characters an id may not.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from servonaut.utils.validation import validate_instance_id, validate_provider

CUSTOM_PROVIDER = "custom"

_SLUG_SEPARATORS = re.compile(r"[^a-z0-9_-]+")
_SLUG_MAX = 40


def custom_binding_id(name: Any) -> str:
    """A stable route id for a custom server: a readable slug plus a short hash.

    The hash covers the exact name, so two names that slug alike stay
    distinct; the result always fits the service's ``[A-Za-z0-9_-]{1,64}``.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("a custom server needs a name to bind a vault key")
    slug = _SLUG_SEPARATORS.sub("-", name.strip().lower()).strip("-")[:_SLUG_MAX].strip("-") or "server"
    return f"{slug}-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:8]}"


def personal_target(provider: str, instance_id: str) -> tuple[str, str]:
    """``(provider, route id)`` for explicit input; a custom server is given by its name."""
    if isinstance(provider, str) and provider.strip().lower() == CUSTOM_PROVIDER:
        return CUSTOM_PROVIDER, custom_binding_id(instance_id)
    return validate_provider(provider), validate_instance_id(instance_id)


def instance_target(instance: Mapping[str, Any]) -> tuple[str, str]:
    """``(provider, route id)`` for an inventory row."""
    if instance.get("is_custom") is True:
        return CUSTOM_PROVIDER, custom_binding_id(instance.get("name"))
    return validate_provider(instance.get("provider")), validate_instance_id(instance.get("id"))

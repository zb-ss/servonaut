"""Client-side validators for wire-format fields shared with servonaut.dev.

These mirror server-side route requirements so that obviously-malformed input
fails locally with a friendly message instead of round-tripping to the API
and coming back as a 404 (provider whitelist) or 400 (instance id regex).

Server-side regexes (locked contract — do not loosen without coordinating):
- provider: ``aws|ovh|hetzner``
- instance_id: ``[A-Za-z0-9_\\-]{1,64}``
"""

from __future__ import annotations

import re

ALLOWED_PROVIDERS: frozenset[str] = frozenset({"aws", "ovh", "hetzner"})

_INSTANCE_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


class ValidationError(ValueError):
    """Raised when a wire-format field fails client-side validation."""


def validate_provider(provider: str) -> str:
    if not isinstance(provider, str):
        raise ValidationError(
            f"Provider must be a string, got {type(provider).__name__}."
        )
    normalized = provider.strip().lower()
    if normalized not in ALLOWED_PROVIDERS:
        allowed = ", ".join(sorted(ALLOWED_PROVIDERS))
        raise ValidationError(
            f"Unknown provider {provider!r}. Allowed: {allowed}."
        )
    return normalized


def validate_instance_id(instance_id: str) -> str:
    if not isinstance(instance_id, str):
        raise ValidationError(
            f"Instance id must be a string, got {type(instance_id).__name__}."
        )
    if not _INSTANCE_ID_RE.match(instance_id):
        raise ValidationError(
            f"Instance id {instance_id!r} must match "
            "[A-Za-z0-9_-] (1-64 chars)."
        )
    return instance_id

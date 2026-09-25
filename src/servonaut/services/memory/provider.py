"""Provider slug for server memory records.

Memory is filed on disk under ``~/.servonaut/memory/<provider>/<id>/`` and
registered with the sync server under the same provider slug. Every surface
that turns an instance dict into a memory provider goes through
:func:`instance_provider`, so AWS, OVH, Hetzner and custom servers are
filed consistently whichever screen, CLI command or MCP tool touched them.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

# Instance-dict ``provider`` value (lower-cased) → canonical slug.
_PROVIDER_SLUGS: Dict[str, str] = {
    "aws": "aws",
    "ec2": "aws",
    "amazon": "aws",
    "custom": "custom",
    "ovh": "ovh",
    "ovhcloud": "ovh",
    "hetzner": "hetzner",
}


def provider_slug(provider: str) -> str:
    """Normalise a provider label to its canonical slug.

    Unknown providers are lower-cased and used as-is (safe fallback); an
    empty label maps to ``"custom"``.
    """
    lowered = (provider or "").strip().lower()
    return _PROVIDER_SLUGS.get(lowered, lowered or "custom")


def instance_provider(instance: Mapping[str, Any]) -> str:
    """Return the memory provider slug for an instance dict.

    AWS instance dicts carry no ``provider`` key (the rest of the app reads
    a missing provider as AWS); OVH, Hetzner and custom servers always set
    one. A dict flagged ``is_custom`` without a provider stays ``"custom"``.
    """
    raw = str(instance.get("provider") or "").strip()
    if raw:
        return provider_slug(raw)
    return "custom" if instance.get("is_custom") else "aws"

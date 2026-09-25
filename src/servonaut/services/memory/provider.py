"""Provider slug for server memory records.

Memory is filed on disk under ``~/.servonaut/memory/<provider>/<id>/`` and
registered with the sync server under the same provider slug. Every surface
that turns an instance dict into a memory provider goes through
:func:`instance_provider`, so AWS, OVH, Hetzner and custom servers are
filed consistently whichever screen, CLI command or MCP tool touched them.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping

# EC2 instance id shape. Custom servers are always "custom-<name>", so an id
# like this under a "custom" label can only be a legacy AWS index row.
_AWS_INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8}(?:[0-9a-f]{9})?$")

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


def index_entry_provider(entry: Mapping[str, Any]) -> str:
    """Return the provider slug for a memory index row.

    Rows written before AWS memory had its own provider say ``"custom"``
    for AWS instances. An EC2-shaped id identifies those rows (custom
    servers use ``custom-<name>`` ids), so they report ``"aws"`` exactly
    like rows written since — which keeps the provider the sync server
    stores from flipping between the two. The on-disk data is unaffected:
    the store still serves a legacy ``custom/`` directory for ``"aws"``.
    """
    provider = instance_provider(entry)
    instance_id = str(entry.get("instance_id") or entry.get("id") or "")
    if provider == "custom" and _AWS_INSTANCE_ID_RE.match(instance_id):
        return "aws"
    return provider

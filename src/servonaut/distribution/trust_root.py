"""Pinned trust anchors for verifying Servonaut release manifests.

This module is the single source of truth for the Ed25519 public keys that may
sign a release manifest and for the origins that release artifacts may be
downloaded from. Both are security invariants that ship with a release rather
than runtime configuration: changing either requires a new build.

Packaged builds only check for updates once at least one release key is
pinned here; until then they report that updates are not configured.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

# Manifest signing keys: key id -> raw 32-byte Ed25519 public key encoded as
# hex or base64.
PINNED_RELEASE_KEYS: Final[Mapping[str, str]] = MappingProxyType({})

# Artifact download URL prefixes. Each is an HTTPS origin plus a path that
# ends in "/", so a match is always on a whole path segment.
ALLOWED_ARTIFACT_ORIGINS: Final[tuple[str, ...]] = (
    "https://github.com/zb-ss/servonaut/releases/download/",
    "https://releases.servonaut.dev/",
)

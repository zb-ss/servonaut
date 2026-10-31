"""Pinned trust anchors for verifying Servonaut release manifests.

This module is the single source of truth for the Ed25519 public keys that may
sign a release manifest, for the origins that release artifacts may be
downloaded from, and for the manifest URL each release channel publishes. All
three are security invariants that ship with a release rather than runtime
configuration: changing any of them requires a new build.

A packaged build checks the manifest of the release channel its build marker
names. ``SERVONAUT_RELEASE_MANIFEST_URL`` can point it at another manifest (a
mirror or a local fake), which must still be signed by a key pinned here.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

# Manifest signing keys: key id -> raw 32-byte Ed25519 public key encoded as
# hex or base64. "release-2026a" signs the published manifests; the standby
# "release-2026b" takes over when the active key is retired. To rotate, ship a
# build that pins a new standby before a key is retired, so every supported
# build already trusts the key that signs next.
PINNED_RELEASE_KEYS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "release-2026a": "55870200b4e4afedd56a86598a276386371f7d9d278dfd4c98754aac43a69a1e",
        "release-2026b": "2df8f2d500c9b5e2f759b318ccc5a9ba966b13435677a615a8d208eaf270025f",
    }
)

# Artifact download URL prefixes. Each is an HTTPS origin plus a path that
# ends in "/", so a match is always on a whole path segment.
ALLOWED_ARTIFACT_ORIGINS: Final[tuple[str, ...]] = (
    "https://github.com/zb-ss/servonaut/releases/download/",
    "https://releases.servonaut.dev/",
)

# Signed release manifest a packaged build checks for updates, keyed by the
# release channel its build marker names. A channel without an entry here has
# no default manifest.
DEFAULT_MANIFEST_URLS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "stable": "https://releases.servonaut.dev/manifest/stable.json",
        "preview": "https://releases.servonaut.dev/manifest/preview.json",
    }
)

"""The public keys that sign team agent rules, per Servonaut API origin.

A team's agent rules (see ``team_policy``) are signed by the Servonaut API
with a dedicated Ed25519 key. This release trusts only the keys listed here,
and each key only for the API origin it belongs to: rules fetched from any
other API base (a staging server, a mirror) do not verify with it.

The keys ship with the release on purpose. Nothing a member can change
(environment, config, a file) adds a key, because a key they control would
let them sign any rules for themselves. A key is rotated by shipping the next
one here before the API starts signing with it; signatures by keys this
release does not know are ignored. A key's id is derived from the key itself
(:func:`key_id_for`); an entry whose id does not match its key is ignored.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from types import MappingProxyType
from typing import Any, Dict, Mapping
from urllib.parse import urlsplit

# The production API origin (the default API base without a path).
PRODUCTION_ORIGIN = "https://api.servonaut.dev"

# API origin -> key id -> the raw 32-byte Ed25519 public key in standard
# base64 (the form a key is published in).
TEAM_POLICY_KEYS: Mapping[str, Mapping[str, str]] = MappingProxyType({
    PRODUCTION_ORIGIN: MappingProxyType({
        "ddab938be92e4573": "jzEqA4TczRbiz31ITQ6J2VuvNMP3lQhtWigGnliwEjk=",
    }),
})

_DEFAULT_PORTS = {"https": 443, "http": 80}
_KEY_ID_HEX_DIGITS = 16
_PUBLIC_KEY_BYTES = 32


def key_id_for(public_key: bytes) -> str:
    """The id of a raw Ed25519 public key: the first 16 hex digits of its SHA-256."""
    return hashlib.sha256(public_key).hexdigest()[:_KEY_ID_HEX_DIGITS]


def decode_public_key(text: Any) -> bytes:
    """The raw Ed25519 public key in standard base64 *text*.

    Raises:
        ValueError: *text* is not base64 of exactly 32 bytes.
    """
    if not isinstance(text, str):
        raise ValueError("a public key is base64 text")
    try:
        raw = base64.b64decode(text, validate=True)
    except binascii.Error as exc:
        raise ValueError("a public key is base64 text") from exc
    if len(raw) != _PUBLIC_KEY_BYTES:
        raise ValueError("an Ed25519 public key has 32 bytes")
    return raw


def api_origin(base_url: str) -> str:
    """The origin of *base_url*: ``scheme://host[:port]``, lower case.

    The path, a trailing slash and the scheme's default port are left out,
    so every spelling of one API base binds to the same keys.

    Raises:
        ValueError: *base_url* has no scheme or host, or a malformed port.
    """
    parts = urlsplit(str(base_url).strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        raise ValueError("an API base needs a scheme and a host")
    port = parts.port
    if ":" in host:
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def knows_origin(origin: str) -> bool:
    """Whether this release lists API *origin* at all.

    Rules from a listed origin verify once a release bundles their key (the
    production origin is listed before its first key is); rules from any
    other origin never do, whichever release runs.
    """
    return origin in TEAM_POLICY_KEYS


def keys_for_origin(origin: str) -> Dict[str, bytes]:
    """The trusted keys (key id -> raw public key) for API *origin*.

    Read at call time, so the table can be replaced as a whole. An entry
    that is not a 32-byte key, or whose id is not :func:`key_id_for` its
    key, is left out: it trusts nothing.
    """
    trusted: Dict[str, bytes] = {}
    for key_id, text in (TEAM_POLICY_KEYS.get(origin) or {}).items():
        try:
            raw = decode_public_key(text)
        except ValueError:
            continue
        if key_id == key_id_for(raw):
            trusted[key_id] = raw
    return trusted

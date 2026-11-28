"""Doubles for the Bitwarden key provider that resolve_with_vault consults.

The provider is duck-typed: an object with ``async apply(conn, instance)``
that returns a conn carrying the Bitwarden key, a conn naming why the key was
not usable, or None when the server has no Bitwarden ref.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock


def no_ref_provider() -> SimpleNamespace:
    """A provider that finds no Bitwarden ref for any server."""
    return SimpleNamespace(apply=AsyncMock(return_value=None))


def key_provider(key_path: str = "/tmp/bw-test", source: str = "personal") -> SimpleNamespace:
    """A provider that finds a readable Bitwarden key (*source*: 'personal' or 'team')."""

    async def apply(conn, instance):
        return {**conn, "key_path": key_path, "key_source": f"bw_{source}"}

    return SimpleNamespace(apply=AsyncMock(side_effect=apply))


def unavailable_provider(reason: str = "BwSessionMissingError") -> SimpleNamespace:
    """A provider whose ref cannot be read: the conn comes back with the reason code."""

    async def apply(conn, instance):
        return {**conn, "bw_key_unavailable": reason}

    return SimpleNamespace(apply=AsyncMock(side_effect=apply))

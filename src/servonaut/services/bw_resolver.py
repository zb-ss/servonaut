"""Bitwarden CLI resolver for SSH private keys stored as native BW SSH items.

Wire contract (locked 2026-05-24):
- Requires Bitwarden CLI 2023.10+ which introduced native SSH item type.
- ``bw get item <uuid>`` returns JSON with path ``.sshKey.privateKey`` containing
  the OpenSSH private key body.
- The server does NOT store a ``key_field`` pointer — we default to
  ``sshKey.privateKey`` and surface a clear error if absent.

No fallback shapes (no notes blob, no attachment lookup) — this is intentional.
The single-path contract keeps the implementation auditable and the error messages
actionable. A ``key_field`` parameter can be added if a real user reports a
non-default vault item shape.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Callable, Optional

from servonaut.services.bw_errors import (
    BwCliMissingError,
    BwItemNotFoundError,
    BwItemShapeError,
    BwResolverError,
    BwSessionMissingError,
)
from servonaut.utils.validation import validate_instance_id

logger = logging.getLogger(__name__)

# Re-exported for backward compatibility: callers historically imported the BW
# error taxonomy from this module. The canonical definitions now live in
# ``servonaut.services.bw_errors`` so the session service can share them.
__all__ = [
    "BwResolver",
    "BwResolverError",
    "BwCliMissingError",
    "BwSessionMissingError",
    "BwItemNotFoundError",
    "BwItemShapeError",
]

_BW_TIMEOUT_SECONDS: int = 15
_LOCKED_STDERR_PHRASES: tuple[str, ...] = (
    "You are not logged in",
    "Vault is locked",
    "Mac failed",
)
_NOT_FOUND_PHRASE: str = "Not found."


class BwResolver:
    """Resolve a Bitwarden Password Manager item id to an OpenSSH private key.

    Uses the ``bw`` CLI via subprocess. Requires an active BW session. The
    session key is sourced, in priority order, from:

    1. ``session_getter`` — an injected callable returning the TUI-managed
       in-memory session (set after the user unlocks via :class:`BwUnlockModal`).
       Passed to ``bw`` through ``env=``, never argv, and never logged.
    2. the ambient ``BW_SESSION`` environment variable (back-compat: a user who
       ran ``bw unlock`` and exported it by hand).
    """

    def __init__(
        self,
        bw_binary: str = "bw",
        session_getter: Optional[Callable[[], Optional[str]]] = None,
    ) -> None:
        self._bw_binary = bw_binary
        self._session_getter = session_getter

    def _build_env(self) -> dict:
        """Return the subprocess environment with the managed session injected.

        Copies the current environment and overlays ``BW_SESSION`` from the
        injected getter when one is available. Falls back to the ambient
        ``BW_SESSION`` already present in ``os.environ`` when no getter is wired
        or it yields nothing. The session key is never placed on argv.
        """
        env = dict(os.environ)
        if self._session_getter is not None:
            try:
                session = self._session_getter()
            except Exception:  # noqa: BLE001 — a broken getter must never block resolution
                session = None
            if session:
                env["BW_SESSION"] = session
        return env

    def resolve_ssh_key(self, item_id: str) -> str:
        """Resolve a BW item id to its OpenSSH private key body.

        Returns the raw key text (suitable for writing to a 0600 tmpfile).
        Raises specific BwResolverError subclasses for each failure mode.
        """
        validate_instance_id(item_id)  # rejects path traversal and non-UUID-ish ids

        if shutil.which(self._bw_binary) is None:
            raise BwCliMissingError(
                f"Bitwarden CLI ({self._bw_binary!r}) not found on PATH. "
                "Install it from https://bitwarden.com/help/cli/ and ensure it is on your PATH."
            )

        logger.debug(
            "Resolving BW item %s via sshKey.privateKey (BW 2023.10+ native shape)",
            item_id,
        )

        result = subprocess.run(
            [self._bw_binary, "get", "item", item_id],
            capture_output=True,
            text=True,
            timeout=_BW_TIMEOUT_SECONDS,
            env=self._build_env(),
        )

        stderr = result.stderr or ""

        if any(phrase in stderr for phrase in _LOCKED_STDERR_PHRASES):
            raise BwSessionMissingError(
                "Bitwarden vault is locked or you are not logged in. "
                "Run `bw unlock` and export BW_SESSION, then retry."
            )

        if _NOT_FOUND_PHRASE in stderr:
            raise BwItemNotFoundError(
                f"Bitwarden item {item_id!r} was not found. "
                "Verify the item UUID in your Bitwarden vault."
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise BwItemShapeError(
                f"BW item {item_id} returned non-JSON output. "
                "Expected a BW 2023.10+ native SSH item. "
                f"Raw error: {exc}"
            ) from exc

        try:
            private_key = data["sshKey"]["privateKey"]
        except (KeyError, TypeError):
            raise BwItemShapeError(
                f"BW item {item_id} has no SSH key field "
                "(expected BW 2023.10+ native SSH item with .sshKey.privateKey)."
            )

        if not isinstance(private_key, str) or not private_key:
            raise BwItemShapeError(
                f"BW item {item_id} has no SSH key field "
                "(expected BW 2023.10+ native SSH item with .sshKey.privateKey)."
            )

        return private_key

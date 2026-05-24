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
import shutil
import subprocess

from servonaut.utils.validation import validate_instance_id

logger = logging.getLogger(__name__)

_BW_TIMEOUT_SECONDS: int = 15
_LOCKED_STDERR_PHRASES: tuple[str, ...] = (
    "You are not logged in",
    "Vault is locked",
    "Mac failed",
)
_NOT_FOUND_PHRASE: str = "Not found."


class BwResolverError(Exception):
    """Base for all BW resolution failures — friendly user-facing message in .message."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class BwCliMissingError(BwResolverError):
    """bw command not found on PATH."""


class BwSessionMissingError(BwResolverError):
    """bw exists but BW_SESSION env var not set or vault locked — user must run ``bw unlock``."""


class BwItemNotFoundError(BwResolverError):
    """bw get item returned 404 / item does not exist."""


class BwItemShapeError(BwResolverError):
    """Item exists but has no .sshKey.privateKey field — likely a non-native SSH item."""


class BwResolver:
    """Resolve a Bitwarden Password Manager item id to an OpenSSH private key.

    Uses the ``bw`` CLI via subprocess. Requires an active BW session
    (``BW_SESSION`` env var set via ``bw unlock``).
    """

    def __init__(self, bw_binary: str = "bw") -> None:
        self._bw_binary = bw_binary

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

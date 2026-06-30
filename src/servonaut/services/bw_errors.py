"""Shared Bitwarden CLI error taxonomy.

Both :mod:`servonaut.services.bw_resolver` (item -> private-key resolution) and
:mod:`servonaut.services.bw_session_service` (auth-state + vault discovery) raise
these exceptions, so callers can handle Bitwarden failures uniformly regardless of
which half produced them.

``bw_resolver`` re-exports the four original names
(:class:`BwCliMissingError`, :class:`BwSessionMissingError`,
:class:`BwItemNotFoundError`, :class:`BwItemShapeError`) for backward
compatibility — existing imports from ``servonaut.services.bw_resolver`` keep
working.
"""

from __future__ import annotations


class BwError(Exception):
    """Base for all Bitwarden CLI failures.

    A friendly, user-facing message is always available on ``.message`` so the
    TUI can surface it directly (with ``markup=False`` — the text may echo vault
    or CLI output).
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# Back-compat alias: the resolver historically named the base ``BwResolverError``.
# Subclasses inherit from :class:`BwError`, so ``isinstance(e, BwResolverError)``
# stays true and ``except BwResolverError`` keeps catching every subclass.
BwResolverError = BwError


class BwCliMissingError(BwError):
    """``bw`` command not found on PATH."""


class BwSessionMissingError(BwError):
    """``bw`` exists but the vault is locked / no session — user must ``bw unlock``."""


class BwItemNotFoundError(BwError):
    """``bw get item`` returned 404 / the item does not exist."""


class BwItemShapeError(BwError):
    """Item exists but has no ``.sshKey.privateKey`` field (not a native SSH item)."""


class BwUnauthenticatedError(BwError):
    """``bw`` is installed but the user is logged out — they must run ``bw login``."""


class BwUnlockFailedError(BwError):
    """``bw unlock`` failed — typically a wrong master password."""


class BwListError(BwError):
    """A ``bw list`` / folder-create operation failed unexpectedly."""

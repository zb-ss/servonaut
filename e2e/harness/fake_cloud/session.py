"""The account's OAuth session as FakeCloud sees it: one token pair at a time.

Refresh tokens are single-use, as on the real service: a refresh issues a new
pair and retires the one presented, so a client that forgets to persist the
rotated pair is refused on its next refresh. Tests expire the access token
(the next API call answers 401 and the client has to refresh) or revoke the
whole session (refresh is refused with ``invalid_grant``).

Tokens are fabricated placeholders, ``at-fake-<nonce>-<n>`` and
``rt-fake-<nonce>-<n>``. The nonce changes on every reset, so a process left
over from an earlier journey cannot authenticate into the next one.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from typing import Optional

# Prefixes of the fabricated tokens.
ACCESS_TOKEN = "at-fake"
REFRESH_TOKEN = "rt-fake"


@dataclass(frozen=True)
class SessionView:
    """A snapshot of the server-side session."""

    generation: int
    access_token: str
    refresh_token: str
    access_valid: bool
    refresh_valid: bool


class TokenSession:
    """Thread-safe server-side token state for the one fake account."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._nonce = secrets.token_hex(4)
            self._generation = 1
            self._access_valid = True
            self._refresh_valid = True

    def _pair(self) -> tuple[str, str]:
        suffix = f"{self._nonce}-{self._generation}"
        return f"{ACCESS_TOKEN}-{suffix}", f"{REFRESH_TOKEN}-{suffix}"

    def view(self) -> SessionView:
        with self._lock:
            access, refresh = self._pair()
            return SessionView(
                self._generation, access, refresh, self._access_valid, self._refresh_valid
            )

    def tokens(self) -> tuple[str, str]:
        """The current (access, refresh) pair."""
        with self._lock:
            return self._pair()

    def bearer_valid(self, authorization: Optional[str]) -> bool:
        """True when *authorization* carries the current, unexpired access token."""
        with self._lock:
            access, _ = self._pair()
            return self._access_valid and authorization == f"Bearer {access}"

    def issue_login(self) -> tuple[str, str]:
        """The pair a completed device-flow sign-in receives.

        The current pair while it is still usable; otherwise a new one.
        """
        with self._lock:
            if not (self._access_valid and self._refresh_valid):
                self._generation += 1
                self._access_valid = self._refresh_valid = True
            return self._pair()

    def rotate(self, presented: object) -> Optional[tuple[str, str]]:
        """Exchange *presented* for a new pair; None means ``invalid_grant``."""
        with self._lock:
            _, refresh = self._pair()
            if not self._refresh_valid or presented != refresh:
                return None
            self._generation += 1
            self._access_valid = self._refresh_valid = True
            return self._pair()

    def expire_access(self) -> None:
        """The access token stops working; the refresh token still does."""
        with self._lock:
            self._access_valid = False

    def revoke(self) -> None:
        """Neither token works any more (revoked server-side, or signed out)."""
        with self._lock:
            self._access_valid = False
            self._refresh_valid = False

    def revoke_token(self, token: object) -> bool:
        """Sign-out: revoke the session if *token* is one of the current pair."""
        with self._lock:
            if token not in self._pair():
                return False
            self._access_valid = False
            self._refresh_valid = False
            return True

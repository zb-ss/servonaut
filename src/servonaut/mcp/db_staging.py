"""Server-side staging for discovered DB credentials.

``db_setup_scan`` stages each discovered credential here under an opaque
token so ``db_setup_save`` can commit it to the secret store without the
plaintext password ever entering a tool result or a model's context.

Staged passwords are plaintext in process memory, so staging is bounded in
two ways: every token expires (the entry, and with it the store's reference
to the password, is dropped on expiry), and the number of live tokens is
capped (the oldest is evicted first). Python cannot zero a ``str``, so
dropping the reference is the strongest guarantee available.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections import OrderedDict
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

# Long enough to review candidates with the user before saving, short enough
# that a forgotten scan does not keep a plaintext password around.
DEFAULT_TTL_SECONDS = 900
# One scan stages one token per discovered site; this comfortably covers a
# multi-site box or a fleet scan while bounding memory held in plaintext.
DEFAULT_MAX_TOKENS = 50

_TOKEN_PREFIX = "dbstg_"


@dataclass
class StagedCredential:
    """One staged candidate and the instance whose config it came from."""

    candidate: Any  # DBCandidate
    instance_id: str = ""
    instance_name: str = ""
    expires_at: float = 0.0
    _timer: Optional[asyncio.TimerHandle] = field(default=None, repr=False)


class DBCredentialStaging(MutableMapping):
    """``token -> DBCandidate`` with per-token expiry and a size cap.

    The mapping interface exposes the candidates themselves; :meth:`stage`
    also records which instance was scanned, read back via :meth:`entry`.
    Expired entries are purged on every access and, when a running event
    loop is available, by a timer at the moment they expire.

    Args:
        ttl_seconds: Lifetime of a staged token.
        max_tokens: Maximum live tokens; staging beyond it evicts the oldest.
        clock: Monotonic clock, injectable for tests.
    """

    def __init__(
        self,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds if ttl_seconds > 0 else DEFAULT_TTL_SECONDS
        self._max = max_tokens if max_tokens > 0 else DEFAULT_MAX_TOKENS
        self._clock = clock
        self._entries: "OrderedDict[str, StagedCredential]" = OrderedDict()

    # ------------------------------------------------------------------
    # Staging API
    # ------------------------------------------------------------------

    def stage(
        self, candidate: Any, instance_id: str = "", instance_name: str = "",
    ) -> str:
        """Stage *candidate* for the scanned instance; return its new token."""
        token = _TOKEN_PREFIX + secrets.token_urlsafe(6)
        self._put(token, StagedCredential(
            candidate=candidate,
            instance_id=instance_id,
            instance_name=instance_name,
        ))
        return token

    def entry(self, token: str) -> Optional[StagedCredential]:
        """Return the live staged entry for *token*, or ``None``."""
        self.purge_expired()
        return self._entries.get(token)

    def purge_expired(self) -> None:
        """Drop every entry whose expiry has passed."""
        now = self._clock()
        for token in [t for t, e in self._entries.items() if e.expires_at <= now]:
            self._drop(token)

    # ------------------------------------------------------------------
    # MutableMapping
    # ------------------------------------------------------------------

    def __getitem__(self, token: str) -> Any:
        found = self.entry(token)
        if found is None:
            raise KeyError(token)
        return found.candidate

    def __setitem__(self, token: str, candidate: Any) -> None:
        self._put(token, StagedCredential(candidate=candidate))

    def __delitem__(self, token: str) -> None:
        if token not in self._entries:
            raise KeyError(token)
        self._drop(token)

    def __iter__(self) -> Iterator[str]:
        self.purge_expired()
        return iter(list(self._entries))

    def __len__(self) -> int:
        self.purge_expired()
        return len(self._entries)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _put(self, token: str, staged: StagedCredential) -> None:
        self.purge_expired()
        if token in self._entries:
            self._drop(token)
        while len(self._entries) >= self._max:
            oldest = next(iter(self._entries))
            self._drop(oldest)
        staged.expires_at = self._clock() + self._ttl
        staged._timer = self._schedule_expiry(token)
        self._entries[token] = staged

    def _schedule_expiry(self, token: str) -> Optional[asyncio.TimerHandle]:
        """Drop *token* at expiry even if nothing touches the store again.

        Replacing or removing a token cancels its timer, so a firing timer
        always belongs to the entry currently stored under that token.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None  # no loop: the purge-on-access path still applies
        return loop.call_later(self._ttl, self._drop, token)

    def _drop(self, token: str) -> None:
        staged = self._entries.pop(token, None)
        if staged is not None and staged._timer is not None:
            staged._timer.cancel()

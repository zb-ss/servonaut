"""Reads of the vault key bindings of the user's own servers, shared by one process.

Some views read every own server's binding in one go (Auto-bind's review,
the check before a vault key is deleted) and do it again on each re-plan.
The service rate-limits those reads, so each answer is reused for a short
while. Once the service refuses one (429, or 401 for the sign-in), no read
is sent until the pause ends: a loop over the fleet then stops at its first
refusal instead of sending one more refused request per server.
"""
from __future__ import annotations

import copy
import hashlib
import time
from typing import Any, Awaitable, Callable, Hashable, Mapping, Optional

from servonaut.services.api_client import APIError
from servonaut.services.retry_after import retry_after_seconds, wait_text

from .errors import VaultUserError

Binding = Optional[Mapping[str, Any]]

_RATE_LIMITED = "rate_limited"
_SIGNED_OUT = "signed_out"


class BindingReadsPaused(VaultUserError):
    """The service refused a binding read, so reads are paused for a while."""


class PersonalBindingReads:
    """Remembers personal binding reads for *ttl_seconds* and pauses them after a refusal.

    *session* names the current sign-in (any value; it is hashed, never
    kept): a 401 pause ends early once it changes, for example after
    ``servonaut login``. A 429 pause lasts as long as its ``Retry-After``
    asks, *backoff_seconds* without one.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float,
        backoff_seconds: float,
        session: Callable[[], Any] = lambda: None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._backoff = backoff_seconds
        self._session = session
        self._clock = clock
        # key -> (expiry, binding or None)
        self._entries: dict[Hashable, tuple[float, Binding]] = {}
        self._paused_until = 0.0
        self._pause_kind = ""
        self._paused_session: bytes | None = None

    async def read(
        self, key: Hashable | None, fetch: Callable[[], Awaitable[Binding]], *, fresh: bool = False,
    ) -> Binding:
        """The binding for *key*: remembered, or ``await fetch()``.

        *fresh* skips the remembered answer (and remembers the new one).
        A *key* of None is never remembered. A remembered answer is still
        given while reads are paused: it sends nothing either way.

        Raises:
            BindingReadsPaused: reads are paused, or this one was refused
                with 429 or 401; nothing more is sent until the pause ends.
        """
        if key is not None and not fresh:
            hit = self._entries.get(key)
            if hit is not None and hit[0] > self._clock():
                return copy.deepcopy(hit[1])
        self._raise_if_paused()
        try:
            binding = await fetch()
        except APIError as exc:
            if exc.status == 429:
                self._pause(_RATE_LIMITED, retry_after_seconds(exc))
                raise self._paused_error() from exc
            if exc.status == 401:
                self._pause(_SIGNED_OUT, None)
                raise self._paused_error() from exc
            raise
        if key is not None and self._ttl > 0:
            self._entries[key] = (self._clock() + self._ttl, copy.deepcopy(binding))
        return binding

    def forget(self, key: Hashable) -> None:
        """Drop the answer for *key* (this process just changed that binding)."""
        self._entries.pop(key, None)

    def clear(self) -> None:
        """Drop every answer and any pause."""
        self._entries.clear()
        self._paused_until = 0.0
        self._pause_kind = ""
        self._paused_session = None

    def _pause(self, kind: str, seconds: float | None) -> None:
        until = self._clock() + (seconds if seconds is not None else self._backoff)
        if kind == self._pause_kind:
            # Reads refused together keep the longest wait any of them was asked for.
            until = max(until, self._paused_until)
        self._paused_until, self._pause_kind = until, kind
        self._paused_session = self._session_digest() if kind == _SIGNED_OUT else None

    def _raise_if_paused(self) -> None:
        if not self._pause_kind:
            return
        ended = self._clock() >= self._paused_until
        if self._pause_kind == _SIGNED_OUT and self._session_digest() != self._paused_session:
            ended = True
        if ended:
            self._paused_until, self._pause_kind, self._paused_session = 0.0, "", None
            return
        raise self._paused_error()

    def _paused_error(self) -> BindingReadsPaused:
        if self._pause_kind == _SIGNED_OUT:
            return BindingReadsPaused(
                "the Servonaut service did not accept your sign-in; run `servonaut login` and try again"
            )
        remaining = max(0.0, self._paused_until - self._clock())
        return BindingReadsPaused(
            "the Servonaut service is limiting requests from this computer; "
            f"nothing is wrong with your setup, so {wait_text(remaining)}"
        )

    def _session_digest(self) -> bytes | None:
        session = self._session()
        if session is None:
            return None
        return hashlib.sha256(repr(session).encode("utf-8")).digest()

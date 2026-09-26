"""The relay side of FakeCloud: a Mercure hub and what listeners report back.

A relay listener (``servonaut connect``, or the TUI's in-process listener)
fetches a subscriber token, subscribes to its account's topics over SSE,
heartbeats, and posts command results. :class:`RelayHub` holds that state.
Tests publish events into it from any thread and read back what the listener
did; the aiohttp handlers in ``routes_relay`` feed it from the server's own
event loop.

Mercure behaviour kept here:

* the hub accepts only subscriber tokens it minted and has not revoked, and
  a subscription receives only the topics its token's ``mercure.subscribe``
  claim covers, whatever else it asks for;
* an event goes to every live subscription whose topics include the event's
  topic; two publishes of the same payload are two events with different
  ids (how the service dual-publishes);
* a subscription that sends ``Last-Event-ID`` first receives the events
  published after that id (recorded as *replayed*), then live ones (*sent*).

Subscriber tokens carry a nonce that changes on every reset, so a token
cached by a process from an earlier journey is never accepted again.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import itertools
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from e2e.harness.fake_cloud import sse

TOPIC_SUFFIXES = ("commands", "ai-tool-calls")
# The real service keeps a listener "connected" this long after its last
# heartbeat; ``servonaut connect --status`` explains the lag to users.
DEFAULT_STATUS_TTL_SECONDS = 90.0
# A subscription stream checks for new events and for a closed client at
# this interval, writing an SSE comment so a vanished client is noticed.
KEEPALIVE_SECONDS = 0.25


def topic_for(user_id: object, suffix: str) -> str:
    return f"/cli/{user_id}/{suffix}"


def _b64(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _iso(timestamp: float) -> str:
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat()


@dataclass(frozen=True)
class Event:
    """One published update."""

    event_id: str
    topic: str
    data: str

    def frame(self) -> bytes:
        return sse.frame(self.data, event_id=self.event_id)


@dataclass(frozen=True)
class Grant:
    """What an accepted subscriber token allows."""

    number: int
    topics: tuple[str, ...]


@dataclass
class Subscription:
    """One SSE connection to the hub."""

    number: int
    requested: tuple[str, ...]
    topics: tuple[str, ...]  # the requested topics the token covers
    last_event_id: Optional[str]
    token_number: int
    opened_at: float
    queue: Any = None  # asyncio.Queue owned by the server loop
    loop: Any = None
    closed_at: Optional[float] = None
    replayed: list[str] = field(default_factory=list)  # ids resent after Last-Event-ID
    sent: list[str] = field(default_factory=list)  # ids delivered live

    def summary(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "requested": list(self.requested),
            "topics": list(self.topics),
            "last_event_id": self.last_event_id,
            "token_number": self.token_number,
            "open": self.closed_at is None,
            "replayed": list(self.replayed),
            "sent": list(self.sent),
        }


_CLOSE = object()


class RelayHub:
    """Thread-safe state behind the relay and Mercure routes."""

    def __init__(self, account_user_id: Callable[[], object]) -> None:
        self._account_user_id = account_user_id
        self._lock = threading.Lock()
        self._clear()

    def _clear(self) -> None:
        self._nonce = secrets.token_hex(4)
        self._event_numbers = itertools.count(1)
        self._subscription_numbers = itertools.count(1)
        self._events: list[Event] = []
        self._subscriptions: list[Subscription] = []
        self._grants: dict[str, Grant] = {}
        self._revoked_tokens: set[int] = set()
        self._heartbeats: list[dict[str, Any]] = []
        self._command_results: list[dict[str, Any]] = []
        self._status_ttl = DEFAULT_STATUS_TTL_SECONDS
        self._hub_failures: list[int] = []

    # ------------------------------------------------------------------
    # Test API
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Forget everything and end every open subscription."""
        self.drop_streams()
        with self._lock:
            self._clear()

    def configure(
        self,
        *,
        status_ttl: Optional[float] = None,
        hub_failures: Optional[Iterable[int]] = None,
    ) -> None:
        """Change how the relay routes answer.

        *status_ttl*: seconds a heartbeat keeps ``/api/cli/status``
        connected (0: the service stops seeing every listener).
        *hub_failures*: HTTP statuses the hub answers to the next
        subscription attempts, one each, before accepting again.
        """
        with self._lock:
            if status_ttl is not None:
                self._status_ttl = float(status_ttl)
            if hub_failures is not None:
                self._hub_failures = [int(code) for code in hub_failures]

    def publish(
        self,
        payload: dict[str, Any],
        *,
        topic: str = "commands",
        user_id: Optional[object] = None,
        event_id: Optional[str] = None,
    ) -> str:
        """Publish *payload* as one event on one topic; return the event id.

        *topic* is a suffix of ``/cli/{user_id}/``; *user_id* defaults to the
        account's (whatever ``user_id`` the payload itself carries). The
        service's dual-publish is two calls, one per topic.
        """
        owner = self._account_user_id() if user_id is None else user_id
        event = Event(
            event_id=event_id or f"evt-{next(self._event_numbers)}",
            topic=topic_for(owner, topic),
            data=json.dumps(payload),
        )
        with self._lock:
            self._events.append(event)
            targets = [
                s for s in self._subscriptions if s.closed_at is None and event.topic in s.topics
            ]
        for subscription in targets:
            _deliver(subscription, event)
        return event.event_id

    def drop_streams(self) -> None:
        """End every open subscription, as a network drop would."""
        with self._lock:
            live = [s for s in self._subscriptions if s.closed_at is None]
        for subscription in live:
            _deliver(subscription, _CLOSE)

    def revoke_subscriber_tokens(self) -> None:
        """The hub stops accepting every subscriber token minted so far."""
        with self._lock:
            self._revoked_tokens.update(grant.number for grant in self._grants.values())

    def subscriptions(self, *, live: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            return [
                s.summary() for s in self._subscriptions if not live or s.closed_at is None
            ]

    def heartbeats(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(h) for h in self._heartbeats]

    def command_results(self, request_id: Optional[str] = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(r) for r in self._command_results]
        return [r for r in rows if request_id is None or r["request_id"] == request_id]

    def tokens_minted(self) -> int:
        with self._lock:
            return len(self._grants)

    # ------------------------------------------------------------------
    # Route API (server loop)
    # ------------------------------------------------------------------

    def mint_token(self, user_id: object) -> str:
        """A subscriber token scoped to the account's topics (JWT-shaped)."""
        with self._lock:
            number = len(self._grants) + 1
            topics = tuple(topic_for(user_id, s) for s in TOPIC_SUFFIXES)
            claims = {"mercure": {"subscribe": list(topics)}, "n": number, "nonce": self._nonce}
            token = ".".join([_b64({"alg": "none", "typ": "JWT"}), _b64(claims), "e2e"])
            self._grants[token] = Grant(number, topics)
            return token

    def next_hub_failure(self) -> Optional[int]:
        with self._lock:
            return self._hub_failures.pop(0) if self._hub_failures else None

    def grant_for(self, token: Optional[str]) -> Optional[Grant]:
        """What *token* allows, or None when the hub does not accept it."""
        with self._lock:
            grant = self._grants.get(token or "")
            if grant is None or grant.number in self._revoked_tokens:
                return None
            return grant

    def open_subscription(
        self,
        requested: tuple[str, ...],
        last_event_id: Optional[str],
        grant: Grant,
        loop: asyncio.AbstractEventLoop,
    ) -> tuple[Subscription, list[Event]]:
        """Register a live subscription; return it and the events to replay."""
        subscription = Subscription(
            number=next(self._subscription_numbers),
            requested=requested,
            topics=tuple(topic for topic in requested if topic in grant.topics),
            last_event_id=last_event_id,
            token_number=grant.number,
            opened_at=time.time(),
            queue=asyncio.Queue(),
            loop=loop,
        )
        with self._lock:
            replay: list[Event] = []
            if last_event_id:
                ids = [event.event_id for event in self._events]
                if last_event_id in ids:
                    later = self._events[ids.index(last_event_id) + 1 :]
                    replay = [event for event in later if event.topic in subscription.topics]
            self._subscriptions.append(subscription)
        return subscription, replay

    def close_subscription(self, subscription: Subscription) -> None:
        with self._lock:
            subscription.closed_at = time.time()

    def record_sent(self, subscription: Subscription, event: Event, *, replayed: bool) -> None:
        with self._lock:
            (subscription.replayed if replayed else subscription.sent).append(event.event_id)

    def record_heartbeat(self, body: dict[str, Any], generation: int) -> None:
        with self._lock:
            self._heartbeats.append({**body, "at": time.time(), "token_generation": generation})

    def record_command_result(self, request_id: str, body: dict[str, Any]) -> None:
        with self._lock:
            self._command_results.append({**body, "request_id": request_id, "at": time.time()})

    def status_payload(self) -> dict[str, Any]:
        """``/api/cli/status``: connected while heartbeats are recent."""
        with self._lock:
            now = time.time()
            recent = [h for h in self._heartbeats if now - h["at"] <= self._status_ttl]
            last = self._heartbeats[-1]["at"] if self._heartbeats else None
        return {
            "connected": bool(recent),
            "last_heartbeat_at": _iso(last) if last is not None else None,
            "client_ids": sorted({h.get("client_id") for h in recent if h.get("client_id")}),
        }


def _deliver(subscription: Subscription, item: object) -> None:
    try:
        subscription.loop.call_soon_threadsafe(subscription.queue.put_nowait, item)
    except RuntimeError:
        pass  # the server loop has already stopped


def close_marker() -> object:
    return _CLOSE

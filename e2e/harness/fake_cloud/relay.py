"""The relay side of FakeCloud: a Mercure hub and what listeners report back.

A relay listener (``servonaut connect``, or the TUI's in-process listener)
fetches a subscriber token, subscribes to its account's topics over SSE,
heartbeats, and posts command and tool results. :class:`RelayHub` holds that
state. Tests publish events into it from any thread and read back what the
listener did; the aiohttp handlers in ``routes_relay`` feed it from the
server's own event loop.

Mercure behaviour kept here:

* an event goes to every live subscription whose topics include one of the
  event's topics; two publishes of the same payload are two events with
  different ids (how the service dual-publishes);
* a subscription that sends ``Last-Event-ID`` first receives the events
  published after that id, then live ones;
* the hub accepts only subscriber tokens it minted and has not revoked.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import itertools
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

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
    topics: tuple[str, ...]
    data: str

    def frame(self) -> bytes:
        lines = [f"id: {self.event_id}"]
        lines += [f"data: {line}" for line in self.data.splitlines() or [""]]
        return ("\n".join(lines) + "\n\n").encode()


@dataclass
class Subscription:
    """One SSE connection to the hub."""

    number: int
    topics: tuple[str, ...]
    last_event_id: Optional[str]
    token_number: int
    opened_at: float
    queue: Any = None  # asyncio.Queue owned by the server loop
    loop: Any = None
    closed_at: Optional[float] = None
    sent: list[str] = field(default_factory=list)  # event ids written to the stream

    def summary(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "topics": list(self.topics),
            "last_event_id": self.last_event_id,
            "token_number": self.token_number,
            "open": self.closed_at is None,
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
        self._event_numbers = itertools.count(1)
        self._subscription_numbers = itertools.count(1)
        self._events: list[Event] = []
        self._subscriptions: list[Subscription] = []
        self._tokens: dict[str, int] = {}
        self._revoked_tokens: set[int] = set()
        self._heartbeats: list[dict[str, Any]] = []
        self._command_results: list[dict[str, Any]] = []
        self._tool_results: list[dict[str, Any]] = []
        self._hosted_calls: list[dict[str, Any]] = []
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
        event_id: Optional[str] = None,
    ) -> str:
        """Publish *payload* as one event on one topic; return the event id.

        *topic* is a suffix of the account's ``/cli/{user_id}/`` topics,
        whatever ``user_id`` the payload itself carries. The service's
        dual-publish is two calls, one per topic.
        """
        event = Event(
            event_id=event_id or f"evt-{next(self._event_numbers)}",
            topics=(topic_for(self._account_user_id(), topic),),
            data=json.dumps(payload),
        )
        with self._lock:
            self._events.append(event)
            targets = [s for s in self._subscriptions if s.closed_at is None and _wants(s, event)]
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
            self._revoked_tokens.update(self._tokens.values())

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

    def tool_results(self, tool_call_id: Optional[str] = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(r) for r in self._tool_results]
        return [r for r in rows if tool_call_id is None or r.get("tool_call_id") == tool_call_id]

    def hosted_calls(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(c) for c in self._hosted_calls]

    def tokens_minted(self) -> int:
        with self._lock:
            return len(self._tokens)

    # ------------------------------------------------------------------
    # Route API (server loop)
    # ------------------------------------------------------------------

    def mint_token(self, user_id: object) -> str:
        """A subscriber token scoped to the account's topics (JWT-shaped)."""
        with self._lock:
            number = len(self._tokens) + 1
            claims = {
                "mercure": {"subscribe": [topic_for(user_id, s) for s in TOPIC_SUFFIXES]},
                "n": number,
            }
            token = ".".join([_b64({"alg": "none", "typ": "JWT"}), _b64(claims), "e2e"])
            self._tokens[token] = number
            return token

    def next_hub_failure(self) -> Optional[int]:
        with self._lock:
            return self._hub_failures.pop(0) if self._hub_failures else None

    def token_number(self, token: Optional[str]) -> Optional[int]:
        """The minted token's number if the hub accepts it, else None."""
        with self._lock:
            number = self._tokens.get(token or "")
            if number is None or number in self._revoked_tokens:
                return None
            return number

    def open_subscription(
        self,
        topics: tuple[str, ...],
        last_event_id: Optional[str],
        token_number: int,
        loop: asyncio.AbstractEventLoop,
    ) -> tuple[Subscription, list[Event]]:
        """Register a live subscription; return it and the events to replay."""
        subscription = Subscription(
            number=next(self._subscription_numbers),
            topics=topics,
            last_event_id=last_event_id,
            token_number=token_number,
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
                    replay = [event for event in later if _wants(subscription, event)]
            self._subscriptions.append(subscription)
        return subscription, replay

    def close_subscription(self, subscription: Subscription) -> None:
        with self._lock:
            subscription.closed_at = time.time()

    def record_sent(self, subscription: Subscription, event: Event) -> None:
        with self._lock:
            subscription.sent.append(event.event_id)

    def record_heartbeat(self, body: dict[str, Any], generation: int) -> None:
        with self._lock:
            self._heartbeats.append({**body, "at": time.time(), "token_generation": generation})

    def record_command_result(self, request_id: str, body: dict[str, Any]) -> None:
        with self._lock:
            self._command_results.append({**body, "request_id": request_id, "at": time.time()})

    def record_tool_result(self, body: dict[str, Any]) -> None:
        with self._lock:
            self._tool_results.append({**body, "at": time.time()})

    def record_hosted_call(self, body: dict[str, Any]) -> None:
        with self._lock:
            self._hosted_calls.append(dict(body))

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


def _wants(subscription: Subscription, event: Event) -> bool:
    return any(topic in subscription.topics for topic in event.topics)


def _deliver(subscription: Subscription, item: object) -> None:
    try:
        subscription.loop.call_soon_threadsafe(subscription.queue.put_nowait, item)
    except RuntimeError:
        pass  # the server loop has already stopped


def close_marker() -> object:
    return _CLOSE

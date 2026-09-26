"""In-memory relay backend for RelayListener tests.

:class:`FakeRelayServer` answers the three routes a relay listener uses —
the subscriber-token endpoint, the heartbeat and the Mercure hub — plus,
when scripted, the OAuth refresh endpoint, through
an ``httpx.MockTransport``, so tests drive the real listener, the real
httpx client and the real ``httpx_sse`` parsing without any network.

A hub subscription that the fake accepts stays open and idle by default, as
a quiet hub does in production: nothing ends it except the client going
away.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Iterable, Union

import httpx

BASE_URL = "https://api.example.test"
MERCURE_URL = "https://hub.example.test/.well-known/mercure"

_TOKEN_PATH = "/api/cli/mercure-token"
_HEARTBEAT_PATH = "/api/cli/heartbeat"
_REFRESH_PATH = "/api/oauth/refresh"
_HUB_PATH = "/.well-known/mercure"
_EVENT_STREAM = "text/event-stream"


@dataclass(frozen=True)
class HubReply:
    """One scripted hub answer; a bare int in a script means ``HubReply(status)``."""

    status: int = 200
    content_type: str = _EVENT_STREAM
    stays_open: bool = True


@dataclass(frozen=True)
class RefreshReply:
    """One scripted answer of the OAuth refresh endpoint."""

    status: int
    body: str = ""
    content_type: str = "application/json"


class FakeRelayServer:
    """Scriptable stand-in for the API and the Mercure hub.

    Args:
        hub_replies: hub answers, in order; the last one repeats once the
            script is exhausted.
        heartbeat_statuses: heartbeat response statuses, scripted the same way.
        heartbeat_waits_for_subscription: hold each heartbeat response until
            the hub has accepted a subscription, so a rejected heartbeat
            reaches a listener that is already parked on an idle stream.
        refresh_replies: OAuth refresh answers, scripted the same way; with
            none scripted the route answers 404.

    ``timeline`` records ``("hub", status, token)`` for every subscribe
    request; tests may append their own entries to interleave other events.
    """

    def __init__(
        self,
        *,
        hub_replies: Iterable[Union[int, HubReply]] = (200,),
        heartbeat_statuses: Iterable[int] = (200,),
        heartbeat_waits_for_subscription: bool = False,
        refresh_replies: Iterable[RefreshReply] = (),
    ) -> None:
        self._hub_replies = [
            reply if isinstance(reply, HubReply) else HubReply(reply)
            for reply in hub_replies
        ]
        self._heartbeat_statuses = list(heartbeat_statuses)
        self._heartbeat_waits = heartbeat_waits_for_subscription
        self._refresh_replies = list(refresh_replies)
        self.refresh_requests = 0
        self.tokens_issued: list[str] = []
        self.hub_tokens: list[str | None] = []
        self.heartbeat_replies: list[int] = []
        self.heartbeat_types: list[str | None] = []  # payload "type" per heartbeat
        self.timeline: list[tuple] = []
        self.subscribed = asyncio.Event()
        self.transport = httpx.MockTransport(self._handle)

    @property
    def heartbeats(self) -> int:
        return len(self.heartbeat_replies)

    def install(self, monkeypatch) -> None:
        """Route every ``httpx.AsyncClient`` created during the test here."""
        real_client = httpx.AsyncClient

        def client_factory(*args, **kwargs):
            kwargs["transport"] = self.transport
            return real_client(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", client_factory)

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == _TOKEN_PATH:
            token = f"jwt-{len(self.tokens_issued) + 1}"
            self.tokens_issued.append(token)
            return httpx.Response(200, json={"token": token})
        if path == _HEARTBEAT_PATH:
            if self._heartbeat_waits:
                await self.subscribed.wait()
            status = _next(self._heartbeat_statuses)
            self.heartbeat_types.append(json.loads(request.content).get("type"))
            self.heartbeat_replies.append(status)
            return httpx.Response(status, text="")
        if path == _HUB_PATH:
            return self._subscribe(request)
        if path == _REFRESH_PATH and self._refresh_replies:
            self.refresh_requests += 1
            reply = _next(self._refresh_replies)
            return httpx.Response(
                reply.status,
                headers={"content-type": reply.content_type},
                text=reply.body,
            )
        return httpx.Response(404)

    def _subscribe(self, request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("authorization")
        reply = _next(self._hub_replies)
        self.hub_tokens.append(token)
        self.timeline.append(("hub", reply.status, token))
        if reply.status != 200:
            return httpx.Response(reply.status, text="subscription rejected")
        if reply.content_type == _EVENT_STREAM:
            self.subscribed.set()
        return httpx.Response(
            200,
            headers={"content-type": reply.content_type},
            content=_event_stream(stays_open=reply.stays_open),
        )


def _next(script: list):
    """Pop the next scripted item, repeating the last one forever."""
    return script.pop(0) if len(script) > 1 else script[0]


async def _event_stream(*, stays_open: bool):
    yield b": subscribed\n\n"
    if stays_open:
        # Park until the client disconnects (cancellation ends the wait).
        await asyncio.Event().wait()


async def finishes_within(awaitable, bound: float = 5.0) -> bool:
    """Return whether ``awaitable`` completes within ``bound`` seconds.

    Returns as soon as it completes. On overrun it is cancelled and False is
    returned. ``asyncio.wait_for`` cannot serve here: it cannot tell a
    listener that stopped from one that absorbed the timeout's cancellation.
    """
    task = asyncio.ensure_future(awaitable)
    done, _ = await asyncio.wait({task}, timeout=bound)
    if not done:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return False
    task.result()
    return True

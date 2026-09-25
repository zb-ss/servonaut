"""In-memory relay backend for RelayListener tests.

:class:`FakeRelayServer` answers the three routes a relay listener uses —
the subscriber-token endpoint, the heartbeat and the Mercure hub — through
an ``httpx.MockTransport``, so tests drive the real listener, the real
httpx client and the real ``httpx_sse`` parsing without any network.

A hub subscription that the fake accepts stays open and idle, as a quiet
hub does in production: nothing ends it except the client going away.
"""
from __future__ import annotations

import asyncio
from typing import Iterable

import httpx

BASE_URL = "https://api.example.test"
MERCURE_URL = "https://hub.example.test/.well-known/mercure"

_TOKEN_PATH = "/api/cli/mercure-token"
_HEARTBEAT_PATH = "/api/cli/heartbeat"
_HUB_PATH = "/.well-known/mercure"


class FakeRelayServer:
    """Scriptable stand-in for the API and the Mercure hub.

    Args:
        hub_statuses: statuses the hub answers with, in order; the last one
            repeats once the list is exhausted. 200 opens an idle stream.
        heartbeat_status: status of every heartbeat response.
        heartbeat_waits_for_subscription: hold each heartbeat response until
            the hub has accepted a subscription, so a rejected heartbeat
            reaches a listener that is already parked on an idle stream.
    """

    def __init__(
        self,
        *,
        hub_statuses: Iterable[int] = (200,),
        heartbeat_status: int = 200,
        heartbeat_waits_for_subscription: bool = False,
    ) -> None:
        self._hub_statuses = list(hub_statuses)
        self._heartbeat_status = heartbeat_status
        self._heartbeat_waits = heartbeat_waits_for_subscription
        self.tokens_issued: list[str] = []
        self.hub_tokens: list[str | None] = []
        self.heartbeats = 0
        self.subscribed = asyncio.Event()
        self.transport = httpx.MockTransport(self._handle)

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
            self.heartbeats += 1
            if self._heartbeat_waits:
                await self.subscribed.wait()
            return httpx.Response(self._heartbeat_status, text="")
        if path == _HUB_PATH:
            return self._subscribe(request)
        return httpx.Response(404)

    def _subscribe(self, request: httpx.Request) -> httpx.Response:
        self.hub_tokens.append(request.url.params.get("authorization"))
        if len(self._hub_statuses) > 1:
            status = self._hub_statuses.pop(0)
        else:
            status = self._hub_statuses[0]
        if status != 200:
            return httpx.Response(status, text="subscription rejected")
        self.subscribed.set()
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=_idle_event_stream(),
        )


async def _idle_event_stream():
    yield b": subscribed\n\n"
    # Park until the client disconnects (cancellation ends the wait).
    await asyncio.Event().wait()


async def finishes_within(awaitable, bound: float = 5.0) -> bool:
    """Return whether ``awaitable`` completes within ``bound`` seconds.

    Returns as soon as it completes. On overrun it is cancelled and False is
    returned. ``asyncio.wait_for`` cannot serve here: ``RelayListener.run``
    absorbs cancellation, so a timed-out ``wait_for`` would return normally
    and hide the overrun.
    """
    task = asyncio.ensure_future(awaitable)
    done, _ = await asyncio.wait({task}, timeout=bound)
    if not done:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return False
    task.result()
    return True

"""The hosted chat stream: replays one scripted turn as server-sent events.

:func:`replay` serves a :class:`~e2e.harness.fake_cloud.chat_script.ChatTurn`
the way the service streams a chat turn: the ``conversation`` frame first,
then the turn's events, spaced by its ``gap``. After a ``tool_call`` frame it
waits for the client's answer on the tool-result route (sending ``ping``
frames meanwhile when the turn asks for them); ``stall_after`` goes silent
and ``hold_open`` stays open after the last frame, both until the client
leaves. How the stream ended is written to the chat record
(:meth:`AiState.chats`), and a reset of the AI state ends every stream.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any, Callable, Optional

from aiohttp import web

from e2e.harness.fake_cloud.chat_script import PING, ChatTurn, SseEvent, conversation

if TYPE_CHECKING:
    from e2e.harness.fake_cloud.routes_ai import AiState

# How long a chat stream waits for the client's tool result before it gives up.
TOOL_RESULT_WAIT_SECONDS = 30.0
_POLL_SECONDS = 0.02


async def replay(
    request: web.Request, state: AiState, turn: ChatTurn, record: dict[str, Any]
) -> web.StreamResponse:
    """Serve *turn* as an SSE stream until it ends or the client leaves."""
    generation = state.stream_generation()
    response = web.StreamResponse(
        headers={"Content-Type": "text/event-stream", "Cache-Control": "no-store"}
    )

    def gone() -> bool:
        transport = request.transport
        return (
            transport is None
            or transport.is_closing()
            or state.stream_generation() != generation
        )

    keepalive = _Keepalive(response, state, record, turn.ping_every)
    events = list(turn.events)
    stall_after = turn.stall_after
    if turn.announce:
        events.insert(0, conversation(record["conversation_id"]))
        stall_after = None if stall_after is None else stall_after + 1
    ended = "completed"
    try:
        await response.prepare(request)
        for sent, event in enumerate(events):
            if stall_after is not None and sent >= stall_after:
                ended = await _hold(gone, "stalled")
                break
            if sent and turn.gap:
                await asyncio.sleep(turn.gap)
            if gone():
                ended = "client_left"
                break
            await response.write(event.frame())
            state.update_chat(record, frames=sent + 1)
            if event.name == "tool_call":
                waited = await _wait_for_tool_result(state, event, gone, keepalive)
                if waited is not None:
                    ended = waited
                    break
        else:
            if turn.hold_open:
                ended = await _hold(gone, "held", keepalive)
    except ConnectionError:
        ended = "client_left"
    except asyncio.CancelledError:
        ended = "client_left"
        raise
    finally:
        state.update_chat(record, ended=ended)
    with contextlib.suppress(ConnectionError, RuntimeError):
        await response.write_eof()
    return response


class _Keepalive:
    """Sends the service's ``ping`` frame every *every* seconds while a stream waits."""

    def __init__(
        self,
        response: web.StreamResponse,
        state: AiState,
        record: dict[str, Any],
        every: Optional[float],
    ) -> None:
        self._response = response
        self._state = state
        self._record = record
        self._every = every
        self._last = asyncio.get_running_loop().time()
        self._sent = 0

    async def tick(self) -> None:
        now = asyncio.get_running_loop().time()
        if self._every is None or now - self._last < self._every:
            return
        await self._response.write(PING.frame())
        self._last = now
        self._sent += 1
        self._state.update_chat(self._record, pings=self._sent)


async def _hold(
    gone: Callable[[], bool], label: str, keepalive: Optional[_Keepalive] = None
) -> str:
    """Keep the stream open until the client leaves (pinging, if asked)."""
    while not gone():
        if keepalive is not None:
            await keepalive.tick()
        await asyncio.sleep(_POLL_SECONDS)
    return f"{label}:client_left"


async def _wait_for_tool_result(
    state: AiState, event: SseEvent, gone: Callable[[], bool], keepalive: _Keepalive
) -> Optional[str]:
    """Wait for the client's answer to a tool call; a reason string if it never came."""
    tool_call_id = event.payload().get("tool_call_id")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + TOOL_RESULT_WAIT_SECONDS
    while not state.tool_results(tool_call_id):
        if gone():
            return "client_left"
        if loop.time() >= deadline:
            return "tool_result_timeout"
        await keepalive.tick()
        await asyncio.sleep(_POLL_SECONDS)
    return None

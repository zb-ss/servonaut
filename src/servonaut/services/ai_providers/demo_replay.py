"""Scripted chat replay for demo mode.

Demo mode redacts what the TUI shows, but the chat panel's answers and
tool rows come from the hosted gateway and the fleet's real tools, which
the stream scrubber only partly covers. For recordings, screenshots and
offline demos the panel can instead replay a script: a plain SSE fixture
served through an :mod:`httpx` transport, so the very same stream parser,
tool bridge, confirm modal and rendering run as with the real gateway.

Activation needs BOTH demo mode and ``SERVONAUT_DEMO_CHAT_REPLAY`` set to a
readable script; every other request the client makes still goes to the
real API through the wrapped transport.

Script format — a standard ``text/event-stream`` body plus SSE comment
lines the replay understands::

    : delay 1.5            pause 1.5 s before the next event
    : wait tool-result     hold the stream until the CLI has POSTed a tool result
    event: token
    data: {"text": "Checking "}

    event: tool_call
    data: {"tool_call_id": "tc_1", "tool": "run_command", "args": {...}, "guard_level": "standard"}

    : wait tool-result
    event: tool_result
    data: {"tool_call_id": "tc_1", "status": "ok", "result_summary": "{{tool_result}}"}

``{{tool_result}}`` inside an event is replaced with the (JSON-escaped,
truncated) result the CLI posted, so the row shows what really ran.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional

import httpx

logger = logging.getLogger(__name__)

ENV_VAR = "SERVONAUT_DEMO_CHAT_REPLAY"
CHAT_PATH = "/api/ai/chat"
TOOL_RESULT_PATH = "/api/ai/chat/tool-result"
RESULT_PLACEHOLDER = "{{tool_result}}"
_RESULT_MAX_CHARS = 600
# Comment heartbeat while a ``wait`` step holds the stream, so the
# panel's dead-stream watchdog (35 s) never fires during a long approval.
_WAIT_PING_SECONDS = 5.0


@dataclass(frozen=True)
class ScriptStep:
    """One replay step: an SSE event block, a pause, or a hold point."""

    kind: str  # "event" | "delay" | "wait"
    event: bytes = b""
    seconds: float = 0.0


def parse_script(text: str) -> List[ScriptStep]:
    """Turn a script into steps.

    Comment lines (``:`` prefix) are directives when they read
    ``: delay <seconds>`` or ``: wait tool-result``; any other comment is
    dropped. Event blocks end at a blank line and are kept verbatim.
    """
    steps: List[ScriptStep] = []
    block: List[str] = []

    def flush() -> None:
        body = "".join(block).strip()
        if body:
            steps.append(ScriptStep("event", event=(body + "\n\n").encode("utf-8")))
        block.clear()

    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(":"):
            words = stripped[1:].split()
            if len(words) == 2 and words[0] == "delay":
                try:
                    seconds = float(words[1])
                except ValueError:
                    continue  # not a directive, just a comment
                flush()
                steps.append(ScriptStep("delay", seconds=max(0.0, seconds)))
            elif words[:2] == ["wait", "tool-result"]:
                flush()
                steps.append(ScriptStep("wait"))
            continue
        if stripped == "":
            flush()
            continue
        block.append(line)
    flush()
    return steps


def _escape_for_json_string(value: str) -> str:
    return json.dumps(value)[1:-1]


class DemoChatReplayTransport(httpx.AsyncBaseTransport):
    """Serve the chat stream from a script; pass everything else through."""

    def __init__(
        self,
        steps: List[ScriptStep],
        inner: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self._steps = steps
        self._inner = inner
        self._tool_result_received: Optional[asyncio.Event] = None
        self.last_tool_result: Optional[Dict[str, Any]] = None
        self.stream_requests = 0

    def _event(self) -> asyncio.Event:
        if self._tool_result_received is None:
            self._tool_result_received = asyncio.Event()
        return self._tool_result_received

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith(TOOL_RESULT_PATH):
            try:
                self.last_tool_result = json.loads(request.content or b"{}")
            except ValueError:
                self.last_tool_result = {"result": request.content.decode("utf-8", "replace")}
            self._event().set()
            return httpx.Response(202, json={}, request=request)
        if request.method == "POST" and path.endswith(CHAT_PATH):
            self.stream_requests += 1
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream", "cache-control": "no-cache"},
                stream=_ReplayStream(self),
                request=request,
            )
        if self._inner is not None:
            return await self._inner.handle_async_request(request)
        return httpx.Response(
            404, json={"error": "demo chat replay: no route"}, request=request,
        )

    async def aclose(self) -> None:
        if self._inner is not None:
            await self._inner.aclose()

    def _render(self, event: bytes) -> bytes:
        if RESULT_PLACEHOLDER.encode() not in event:
            return event
        posted = self.last_tool_result or {}
        raw = str(posted.get("result") or posted.get("error") or "").strip()
        if len(raw) > _RESULT_MAX_CHARS:
            raw = raw[:_RESULT_MAX_CHARS] + "…"
        return event.replace(
            RESULT_PLACEHOLDER.encode(), _escape_for_json_string(raw).encode("utf-8")
        )

    async def iter_script(self) -> AsyncIterator[bytes]:
        for step in self._steps:
            if step.kind == "delay":
                await asyncio.sleep(step.seconds)
            elif step.kind == "wait":
                event = self._event()
                while not event.is_set():
                    try:
                        await asyncio.wait_for(event.wait(), timeout=_WAIT_PING_SECONDS)
                    except asyncio.TimeoutError:
                        yield b": ping\n\n"
                event.clear()
            else:
                yield self._render(step.event)


class _ReplayStream(httpx.AsyncByteStream):
    def __init__(self, transport: DemoChatReplayTransport) -> None:
        self._transport = transport

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._transport.iter_script():
            yield chunk

    async def aclose(self) -> None:
        return None


def replay_script_path(
    demo_mode: bool, environ: Optional[Mapping[str, str]] = None,
) -> Optional[Path]:
    """Return the script to replay, or None when replay must stay off.

    Off unless demo mode is active AND the variable names a readable file;
    a variable that points nowhere is logged and ignored rather than
    silently switching the chat back to the real gateway.
    """
    env = os.environ if environ is None else environ
    raw = (env.get(ENV_VAR) or "").strip()
    if not demo_mode or not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_file():
        logger.warning("%s points at a missing script; chat replay stays off", ENV_VAR)
        return None
    return path


def install_demo_chat_replay(api_client: Any, path: Path) -> DemoChatReplayTransport:
    """Wrap the client's HTTP in a replay transport built from ``path``."""
    steps = parse_script(path.read_text(encoding="utf-8"))
    inner = api_client.transport or httpx.AsyncHTTPTransport()
    transport = DemoChatReplayTransport(steps, inner=inner)
    api_client.transport = transport
    logger.info("Demo chat replay active: %s (%d steps)", path.name, len(steps))
    return transport


def maybe_install_demo_chat_replay(
    api_client: Any, demo_mode: bool, environ: Optional[Mapping[str, str]] = None,
) -> Optional[DemoChatReplayTransport]:
    """Install the replay when demo mode and the environment ask for it."""
    path = replay_script_path(demo_mode, environ)
    if path is None or api_client is None:
        return None
    return install_demo_chat_replay(api_client, path)

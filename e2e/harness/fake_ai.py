"""Local stand-ins for the AI providers a user brings their own key for.

:class:`FakeAi` serves the three wire formats Servonaut speaks on one
loopback HTTP port, in its own thread:

* OpenAI ``POST /v1/chat/completions``;
* Anthropic ``POST /v1/messages``;
* Ollama ``POST /api/chat``.

The product reaches it through its own ``ai_provider.base_url`` setting,
so no product code is patched. Each provider answers from a queue of
scripted turns (:func:`reply`, :func:`tool_call`, :func:`failure`); a
request with nothing scripted gets a 500, so a journey can never pass on
an answer it did not ask for. Every request is recorded (credentials
reduced to a yes/no ``auth_ok``) so journeys can check what the product
sent, including the tool results it fed back to the model.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from aiohttp import web

PROVIDERS = ("openai", "anthropic", "ollama")
# A fabricated key: the fake accepts only this one.
API_KEY = "sk-e2e-fake-0000"
_START_TIMEOUT_SECONDS = 15
_PATHS = {
    "openai": "/v1/chat/completions",
    "anthropic": "/v1/messages",
    "ollama": "/api/chat",
}


@dataclass(frozen=True)
class Turn:
    """One scripted answer: a text reply, a tool call, or an HTTP error."""

    kind: str
    text: str = ""
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    status: int = 200


def reply(text: str) -> Turn:
    """The model answers with *text* and ends its turn."""
    return Turn("reply", text=text)


def tool_call(tool: str, **args: Any) -> Turn:
    """The model asks the client to run *tool* with *args*."""
    return Turn("tool_call", tool=tool, args=dict(args))


def failure(status: int, message: str) -> Turn:
    """The provider refuses the request with *status*."""
    return Turn("error", text=message, status=status)


class FakeAi:
    """Scripted OpenAI, Anthropic and Ollama endpoints on one loopback port."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._turns: dict[str, deque[Turn]] = {name: deque() for name in PROVIDERS}
        self._requests: list[dict[str, Any]] = []
        self._counter = 0
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None
        self._port = 0

    # ------------------------------------------------------------------
    # Test API
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        """The base URL to put in ``ai_provider.base_url``."""
        return f"http://127.0.0.1:{self._port}"

    def script(self, provider: str, *turns: Turn) -> None:
        """Queue *turns*; each request to *provider* consumes the next one."""
        if provider not in PROVIDERS:
            raise ValueError(f"provider must be one of {PROVIDERS}")
        with self._lock:
            self._turns[provider].extend(turns)

    def requests(self, provider: Optional[str] = None) -> list[dict[str, Any]]:
        """Requests received so far, oldest first."""
        with self._lock:
            rows = [dict(r) for r in self._requests]
        return [r for r in rows if provider is None or r["provider"] == provider]

    def pending(self, provider: str) -> int:
        """Scripted turns not consumed yet."""
        with self._lock:
            return len(self._turns[provider])

    def reset(self) -> None:
        with self._lock:
            for queue in self._turns.values():
                queue.clear()
            self._requests.clear()
            self._counter = 0

    def start(self) -> "FakeAi":
        self._thread = threading.Thread(target=self._serve, name="fake-ai", daemon=True)
        self._thread.start()
        if not self._ready.wait(_START_TIMEOUT_SECONDS):
            raise RuntimeError("FakeAi did not start in time")
        if self._error is not None:
            raise RuntimeError(f"FakeAi failed to start: {self._error}") from self._error
        return self

    def stop(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=10)

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def _next(self, provider: str, record: dict[str, Any]) -> tuple[Optional[Turn], int]:
        with self._lock:
            self._requests.append(record)
            self._counter += 1
            queue = self._turns[provider]
            return (queue.popleft() if queue else None), self._counter

    def _handler(self, provider: str) -> Any:
        async def handle(request: web.Request) -> web.Response:
            try:
                body = await request.json()
            except ValueError:
                body = {}
            auth_ok = _auth_ok(provider, request.headers)
            record = {"provider": provider, "path": request.path, "body": body, "auth_ok": auth_ok}
            if not auth_ok:
                with self._lock:
                    self._requests.append(record)
                return _error(provider, 401, "invalid API key")
            turn, number = self._next(provider, record)
            if turn is None:
                return _error(provider, 500, f"no scripted {provider} turn for this request")
            if turn.kind == "error":
                return _error(provider, turn.status, turn.text)
            return web.json_response(_answer(provider, turn, number, body.get("model", "")))

        return handle

    def _serve(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        app = web.Application()
        for provider, path in _PATHS.items():
            app.router.add_post(path, self._handler(provider))
        runner = web.AppRunner(app, access_log=None)
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            self._port = listener.getsockname()[1]
            loop.run_until_complete(runner.setup())
            loop.run_until_complete(web.SockSite(runner, listener).start())
        except BaseException as exc:  # noqa: BLE001 - reported to the starting thread
            self._error = exc
            self._ready.set()
            loop.close()
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(runner.cleanup())
            loop.close()


def _auth_ok(provider: str, headers: Any) -> bool:
    """True when the request carries the key the way the real provider expects."""
    if provider == "openai":
        return headers.get("Authorization") == f"Bearer {API_KEY}"
    if provider == "anthropic":
        return headers.get("x-api-key") == API_KEY and bool(headers.get("anthropic-version"))
    # A local Ollama needs no key; one that is configured must be sent.
    authorization = headers.get("Authorization")
    return authorization in (None, f"Bearer {API_KEY}")


def _error(provider: str, status: int, message: str) -> web.Response:
    if provider == "openai":
        body: dict[str, Any] = {"error": {"message": message, "type": "e2e_error"}}
    elif provider == "anthropic":
        body = {"type": "error", "error": {"type": "e2e_error", "message": message}}
    else:
        body = {"error": message}
    return web.json_response(body, status=status)


def _answer(provider: str, turn: Turn, number: int, model: str) -> dict[str, Any]:
    """The provider's JSON answer for *turn* (non-streaming, as the product asks)."""
    call_id = f"call-e2e-{number}"
    usage_in, usage_out = 40 + number, 10 + number
    if provider == "openai":
        if turn.kind == "tool_call":
            message: dict[str, Any] = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {"name": turn.tool, "arguments": json.dumps(turn.args)},
                    }
                ],
            }
            finish = "tool_calls"
        else:
            message, finish = {"role": "assistant", "content": turn.text}, "stop"
        return {
            "id": f"chatcmpl-e2e-{number}",
            "object": "chat.completion",
            "model": model or "gpt-e2e",
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {
                "prompt_tokens": usage_in,
                "completion_tokens": usage_out,
                "total_tokens": usage_in + usage_out,
            },
        }
    if provider == "anthropic":
        if turn.kind == "tool_call":
            content = [{"type": "tool_use", "id": call_id, "name": turn.tool, "input": turn.args}]
            stop = "tool_use"
        else:
            content, stop = [{"type": "text", "text": turn.text}], "end_turn"
        return {
            "id": f"msg-e2e-{number}",
            "type": "message",
            "role": "assistant",
            "model": model or "claude-e2e",
            "content": content,
            "stop_reason": stop,
            "usage": {"input_tokens": usage_in, "output_tokens": usage_out},
        }
    message = {"role": "assistant", "content": "" if turn.kind == "tool_call" else turn.text}
    if turn.kind == "tool_call":
        message["tool_calls"] = [{"function": {"name": turn.tool, "arguments": turn.args}}]
    return {
        "model": model or "llama-e2e",
        "created_at": "2030-01-01T00:00:00Z",
        "message": message,
        "done": True,
        "prompt_eval_count": usage_in,
        "eval_count": usage_out,
    }

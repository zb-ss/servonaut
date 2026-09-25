"""Local stand-ins for the AI providers a user brings their own key for.

:class:`FakeAi` serves the three wire formats Servonaut speaks on one
loopback HTTP port:

* OpenAI ``POST /v1/chat/completions``;
* Anthropic ``POST /v1/messages``;
* Ollama ``POST /api/chat``.

The product reaches it through its own ``ai_provider.base_url`` setting,
so no product code is patched. Each provider has its own fabricated key
(:data:`KEYS`) and accepts it only the way the real API expects it: OpenAI
and Ollama as ``Authorization: Bearer``, Anthropic as ``x-api-key`` with an
``anthropic-version``. A local Ollama needs no key at all.

Requests are checked against the minimum each real API enforces, and a
request the real API would refuse gets that provider's own 400 error
envelope instead of an answer (see :func:`request_problem`). Only then
does the provider answer from its queue of scripted turns (:func:`reply`,
:func:`tool_call`, :func:`failure`); a valid request with nothing scripted
gets a 500, so a journey can never pass on an answer it did not ask for.

Every request is recorded with its body, which auth headers it carried
(names only), whether its key was right, and the problem found, if any.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from aiohttp import web

from e2e.harness.loopback import LoopbackServer

PROVIDERS = ("openai", "anthropic", "ollama")
# Fabricated keys, one per provider; each fake accepts only its own.
KEYS = {
    "openai": "sk-e2e-openai-0001",
    "anthropic": "sk-e2e-anthropic-0002",
    "ollama": "e2e-ollama-cloud-0003",
}
# The auth header names the fake reports back (never their values).
AUTH_HEADERS = ("authorization", "x-api-key")
_PATHS = {
    "openai": "/v1/chat/completions",
    "anthropic": "/v1/messages",
    "ollama": "/api/chat",
}
_OPENAI_ROLES = frozenset({"system", "developer", "user", "assistant", "tool"})
_OLLAMA_ROLES = frozenset({"system", "user", "assistant", "tool"})


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


class FakeAi(LoopbackServer):
    """Scripted OpenAI, Anthropic and Ollama endpoints on one loopback port."""

    NAME = "FakeAi"

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._turns: dict[str, deque[Turn]] = {name: deque() for name in PROVIDERS}
        self._requests: list[dict[str, Any]] = []
        self._issued: set[str] = set()
        self._counter = 0

    # ------------------------------------------------------------------
    # Test API
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        """The base URL to put in ``ai_provider.base_url``."""
        return f"http://127.0.0.1:{self.port}"

    def script(self, provider: str, *turns: Turn) -> None:
        """Queue *turns*; each valid request to *provider* consumes the next one."""
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
            self._issued.clear()
            self._counter = 0

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def build_app(self) -> web.Application:
        app = web.Application()
        for provider, path in _PATHS.items():
            app.router.add_post(path, self._handler(provider))
        return app

    def _record(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._requests.append(record)

    def _next(self, provider: str) -> tuple[Optional[Turn], int]:
        with self._lock:
            self._counter += 1
            queue = self._turns[provider]
            return (queue.popleft() if queue else None), self._counter

    def _issue(self, call_id: str) -> None:
        with self._lock:
            self._issued.add(call_id)

    def _issued_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._issued)

    def _handler(self, provider: str) -> Any:
        async def handle(request: web.Request) -> web.Response:
            try:
                body = await request.json()
            except ValueError:
                body = None
            record: dict[str, Any] = {
                "provider": provider,
                "path": request.path,
                "body": body,
                "auth_headers": [h for h in AUTH_HEADERS if h in request.headers],
                "auth_ok": _auth_ok(provider, request.headers),
                "problem": None,
            }
            if not record["auth_ok"]:
                self._record(record)
                return _error(provider, 401, "invalid API key")
            record["problem"] = request_problem(provider, body, self._issued_ids())
            self._record(record)
            if record["problem"]:
                return _error(provider, 400, record["problem"])
            turn, number = self._next(provider)
            if turn is None:
                return _error(provider, 500, f"no scripted {provider} turn for this request")
            if turn.kind == "error":
                return _error(provider, turn.status, turn.text)
            call_id = f"call-e2e-{number}"
            if turn.kind == "tool_call" and provider != "ollama":
                self._issue(call_id)
            return web.json_response(_answer(provider, turn, number, call_id, body["model"]))

        return handle


# ---------------------------------------------------------------------------
# What each real API checks
# ---------------------------------------------------------------------------


def _auth_ok(provider: str, headers: Any) -> bool:
    """True when the request carries this provider's key the way its API expects."""
    key = KEYS[provider]
    if provider == "openai":
        return headers.get("Authorization") == f"Bearer {key}"
    if provider == "anthropic":
        return headers.get("x-api-key") == key and bool(headers.get("anthropic-version"))
    # A local Ollama needs no key; a configured one (Ollama Cloud) must be right.
    authorization = headers.get("Authorization")
    return authorization is None or authorization == f"Bearer {key}"


def request_problem(provider: str, body: Any, issued: frozenset[str]) -> Optional[str]:
    """Why the real *provider* API would refuse *body* with a 400, or None."""
    if not isinstance(body, dict):
        return "We could not parse the JSON body of your request."
    checks = {"openai": _openai_problem, "anthropic": _anthropic_problem, "ollama": _ollama_problem}
    return checks[provider](body, issued)


def _openai_problem(body: dict[str, Any], issued: frozenset[str]) -> Optional[str]:
    if not body.get("model"):
        return "you must provide a model parameter"
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        return "Missing required parameter: 'messages'."
    announced: set[str] = set()
    for index, message in enumerate(messages):
        role = message.get("role") if isinstance(message, dict) else None
        if role not in _OPENAI_ROLES:
            return f"Invalid value: '{role}'. Supported values are: {sorted(_OPENAI_ROLES)}."
        if role == "assistant":
            announced |= {c.get("id") for c in message.get("tool_calls") or []}
        if role == "tool":
            call_id = message.get("tool_call_id")
            if call_id not in issued or call_id not in announced:
                return (
                    f"Invalid parameter: messages.[{index}]: messages with role 'tool' must "
                    "be a response to a preceding message with 'tool_calls'."
                )
    return None


def _anthropic_problem(body: dict[str, Any], issued: frozenset[str]) -> Optional[str]:
    if not body.get("model"):
        return "model: Field required"
    if not isinstance(body.get("max_tokens"), int) or isinstance(body.get("max_tokens"), bool):
        return "max_tokens: Field required"
    if "system" in body and not isinstance(body["system"], (str, list)):
        return "system: Input should be a valid string or list"
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        return "messages: Field required"
    previous_uses: set[str] = set()
    for index, message in enumerate(messages):
        role = message.get("role") if isinstance(message, dict) else None
        if role not in ("user", "assistant"):
            return (
                f'messages.{index}.role: Unexpected role "{role}". The Messages API accepts '
                'a top-level `system` parameter, not "system" as an input message role.'
            )
        blocks = message["content"] if isinstance(message.get("content"), list) else []
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                use_id = block.get("tool_use_id")
                if use_id not in issued or use_id not in previous_uses:
                    return (
                        f"messages.{index}.content: unexpected `tool_use_id` found in "
                        f"`tool_result` blocks: {use_id}. Each `tool_result` block must have "
                        "a corresponding `tool_use` block in the previous message."
                    )
        previous_uses = {
            b.get("id") for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"
        }
    return None


def _ollama_problem(body: dict[str, Any], issued: frozenset[str]) -> Optional[str]:
    if not body.get("model"):
        return "model is required"
    if body.get("stream") is not False:
        # The product parses one JSON object; a streamed answer would be NDJSON.
        return "this stand-in answers non-streaming requests only (stream must be false)"
    messages = body.get("messages")
    if not isinstance(messages, list):
        return "messages is required"
    for message in messages:
        role = message.get("role") if isinstance(message, dict) else None
        if role not in _OLLAMA_ROLES:
            return f"invalid role: {role}"
    return None


def _error(provider: str, status: int, message: str) -> web.Response:
    """*message* in *provider*'s own error envelope."""
    kind = "invalid_request_error" if status == 400 else "e2e_error"
    if provider == "openai":
        body: dict[str, Any] = {
            "error": {"message": message, "type": kind, "param": None, "code": None}
        }
    elif provider == "anthropic":
        body = {"type": "error", "error": {"type": kind, "message": message}}
    else:
        body = {"error": message}
    return web.json_response(body, status=status)


def _answer(provider: str, turn: Turn, number: int, call_id: str, model: str) -> dict[str, Any]:
    """The provider's JSON answer for *turn* (non-streaming, as the product asks)."""
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
            "model": model,
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
            "model": model,
            "content": content,
            "stop_reason": stop,
            "usage": {"input_tokens": usage_in, "output_tokens": usage_out},
        }
    message = {"role": "assistant", "content": "" if turn.kind == "tool_call" else turn.text}
    if turn.kind == "tool_call":
        message["tool_calls"] = [{"function": {"name": turn.tool, "arguments": turn.args}}]
    return {
        "model": model,
        "created_at": "2030-01-01T00:00:00Z",
        "message": message,
        "done": True,
        "prompt_eval_count": usage_in,
        "eval_count": usage_out,
    }

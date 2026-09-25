"""What the fake hosted AI answers: scripted chat streams and stored threads.

A journey scripts what ``POST /api/ai/chat`` answers with :class:`ChatTurn`
objects, one per request (``FakeCloud.ai.script``; the routes live in
``routes_ai``). A turn replays one of the recorded SSE scenarios in
``tests/fixtures/sse`` (:meth:`ChatTurn.fixture`, the same files the unit
tests use) or events built with the helpers below, and says how to deliver
them: a gap between frames, a stall that leaves the stream open and silent,
a stream that stays open after its last frame until the client leaves, and
keep-alive pings while it waits. After a ``tool_call`` frame the stream
waits for the client's answer on the tool-result route, as the service
does. Everything here is neutral, fabricated data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from e2e.harness.bootstrap import REPO_ROOT

SSE_FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "sse"


@dataclass(frozen=True)
class SseEvent:
    """One server-sent event: a name and its raw data line."""

    name: str
    data: str = ""

    def frame(self) -> bytes:
        return f"event: {self.name}\ndata: {self.data}\n\n".encode("utf-8")

    def payload(self) -> dict[str, Any]:
        try:
            value = json.loads(self.data) if self.data.strip() else {}
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}


def fixture_events(name: str) -> list[SseEvent]:
    """The events of ``tests/fixtures/sse/<name>.sse``, in order."""
    path = SSE_FIXTURES_DIR / f"{name.removesuffix('.sse')}.sse"
    events: list[SseEvent] = []
    event_name, data_lines = "message", []
    for line in [*path.read_text(encoding="utf-8").splitlines(), ""]:
        if not line.strip():
            if data_lines or event_name != "message":
                events.append(SseEvent(event_name, "\n".join(data_lines)))
            event_name, data_lines = "message", []
        elif line.startswith("event:"):
            event_name = line.partition(":")[2].strip()
        elif line.startswith("data:"):
            data_lines.append(line.partition(":")[2].strip())
    return events


def fixture_names() -> list[str]:
    return sorted(path.stem for path in SSE_FIXTURES_DIR.glob("*.sse"))


def _event(name: str, **data: Any) -> SseEvent:
    return SseEvent(name, json.dumps(data))


# The keep-alive frame the service sends while a turn is quiet.
PING = SseEvent("ping")


def conversation(conversation_id: str) -> SseEvent:
    """The frame the service opens every chat stream with."""
    return _event("conversation", conversation_id=conversation_id)


def token(text: str) -> SseEvent:
    return _event("token", text=text)


def tool_call(
    tool_call_id: str, tool: str, args: dict[str, Any], *, guard_level: str
) -> SseEvent:
    return _event(
        "tool_call", tool_call_id=tool_call_id, tool=tool, args=args, guard_level=guard_level
    )


def tool_result(tool_call_id: str, summary: str, *, status: str = "ok") -> SseEvent:
    return _event(
        "tool_result",
        tool_call_id=tool_call_id,
        status=status,
        result_summary=summary,
        bytes=len(summary),
    )


def usage(model: str = "hosted-e2e-model", **quota: Any) -> SseEvent:
    block = {
        "tokens_used": 120,
        "tokens_limit": 500000,
        "tokens_topup_remaining": 0,
        "resets_at": "2030-01-01T00:00:00+00:00",
        "soft_capped": False,
        "hard_capped": False,
        **quota,
    }
    return _event(
        "usage",
        model=model,
        vendor="e2e",
        input_tokens=100,
        output_tokens=20,
        fallback_used=False,
        quota=block,
    )


def error(code: str, message: str, **extra: Any) -> SseEvent:
    return _event("error", code=code, message=message, **extra)


@dataclass
class ChatTurn:
    """What one ``POST /api/ai/chat`` answers.

    ``status`` other than 200 answers with the JSON error envelope
    ``error_body`` before any stream opens. ``gap`` spaces the frames out;
    ``stall_after`` stops after that many frames and keeps the stream open
    and silent; ``hold_open`` keeps it open after the last frame. Either
    way the stream ends when the client leaves. ``ping_every`` sends the
    service's keep-alive while the stream waits for a tool result or is
    held open (a stall stays silent). ``announce`` sends the
    ``conversation`` frame the service opens every stream with.
    """

    events: list[SseEvent] = field(default_factory=list)
    status: int = 200
    error_body: Optional[dict[str, Any]] = None
    gap: float = 0.0
    stall_after: Optional[int] = None
    hold_open: bool = False
    ping_every: Optional[float] = None
    announce: bool = True

    @classmethod
    def fixture(cls, name: str, **options: Any) -> "ChatTurn":
        return cls(events=fixture_events(name), **options)

    @classmethod
    def of(cls, *events: SseEvent, **options: Any) -> "ChatTurn":
        return cls(events=list(events), **options)

    @classmethod
    def refused(cls, status: int, code: str, message: str, **details: Any) -> "ChatTurn":
        body = {"error": {"code": code, "message": message, "details": details}}
        return cls(status=status, error_body=body)


def conversation_row(
    conversation_id: str,
    title: str,
    *,
    status: str = "active",
    messages: Optional[list[dict[str, str]]] = None,
) -> dict[str, Any]:
    """A stored conversation: its summary fields plus its messages."""
    messages = list(messages or [])
    return {
        "id": conversation_id,
        "title": title,
        "status": status,
        "created_at": "2030-01-01T09:00:00+00:00",
        "updated_at": "2030-01-01T09:05:00+00:00",
        "message_count": len(messages),
        "last_model": "",
        "messages": messages,
    }

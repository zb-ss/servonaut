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
does, unless the turn pauses: a turn with a :func:`turn_suspended` frame
sends its tool calls, then the pause, and closes, and the next scripted turn
answers ``POST /api/ai/chat/continue``. Everything here is neutral,
fabricated data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from e2e.harness.bootstrap import REPO_ROOT
from e2e.harness.fake_cloud import sse

SSE_FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "sse"


@dataclass(frozen=True)
class SseEvent:
    """One server-sent event: a name and its data (possibly several lines).

    ``expires_in`` stamps the data's ``expires_at`` that many seconds after
    the frame is sent, so a scripted deadline counts from when it is sent.
    """

    name: str
    data: str = ""
    expires_in: Optional[float] = None

    def frame(self) -> bytes:
        data = self.data
        if self.expires_in is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.expires_in)
            data = json.dumps({**self.payload(), "expires_at": expires_at.isoformat()})
        return sse.frame(data, event=self.name)

    def payload(self) -> dict[str, Any]:
        try:
            value = json.loads(self.data) if self.data.strip() else {}
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}


def fixture_events(name: str) -> list[SseEvent]:
    """The events of ``tests/fixtures/sse/<name>.sse``, in order."""
    path = SSE_FIXTURES_DIR / f"{name.removesuffix('.sse')}.sse"
    return [SseEvent(e.event, e.data) for e in sse.parse(path.read_text(encoding="utf-8"))]


def fixture_names() -> list[str]:
    return sorted(path.stem for path in SSE_FIXTURES_DIR.glob("*.sse"))


def _event(name: str, **data: Any) -> SseEvent:
    return SseEvent(name, json.dumps(data))


# The keep-alive frame the service sends while a turn is quiet.
PING = SseEvent("ping")


def conversation(conversation_id: str, *, split_turns: bool = False) -> SseEvent:
    """The frame the service opens every chat stream with.

    ``split_turns`` says the service will pause this turn for its tools.
    """
    extra = {"split_turns": True} if split_turns else {}
    return _event("conversation", conversation_id=conversation_id, **extra)


def token(text: str) -> SseEvent:
    return _event("token", text=text)


def tool_call(
    tool_call_id: str, tool: str, args: dict[str, Any], *, guard_level: Optional[str]
) -> SseEvent:
    """A tool call; ``guard_level=None`` leaves the label out, as some services do."""
    label = {} if guard_level is None else {"guard_level": guard_level}
    return _event("tool_call", tool_call_id=tool_call_id, tool=tool, args=args, **label)


def turn_suspended(
    continuation_id: str, tool_call_ids: list[str], *, expires_in: float = 300.0
) -> SseEvent:
    """The pause that ends a round waiting on *tool_call_ids*, open for
    *expires_in* s from when it is sent."""
    data = json.dumps({"continuation_id": continuation_id, "tool_call_ids": list(tool_call_ids)})
    return SseEvent("turn_suspended", data, expires_in=expires_in)


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


def error_then_usage(
    code: str,
    message: str,
    *,
    balance: Optional[dict[str, Any]] = None,
    debit_micros: int = 0,
) -> "ChatTurn":
    """A refusal followed by final accounting, as the live stream permits."""
    usage_data: dict[str, Any] = {
        "model": "hosted-e2e-model",
        "input_tokens": 100,
        "output_tokens": 20,
        "fallback_used": False,
        "quota": {},
        "debit_micros": debit_micros,
    }
    if balance is not None:
        usage_data["balance"] = balance
    return ChatTurn.of(error(code, message), _event("usage", **usage_data))


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
    ``conversation`` frame the service opens every stream with;
    ``says_it_pauses`` marks it as pausing the turn when the request asked
    for ``split_turns``. ``retry_after`` sends that header with a refusal.
    """

    events: list[SseEvent] = field(default_factory=list)
    status: int = 200
    error_body: Optional[dict[str, Any]] = None
    gap: float = 0.0
    stall_after: Optional[int] = None
    hold_open: bool = False
    ping_every: Optional[float] = None
    announce: bool = True
    says_it_pauses: bool = False
    retry_after: Optional[int] = None

    @property
    def pauses(self) -> bool:
        """Whether this turn pauses for its tools instead of waiting on them."""
        return any(event.name == "turn_suspended" for event in self.events)

    @classmethod
    def fixture(cls, name: str, **options: Any) -> "ChatTurn":
        return cls(events=fixture_events(name), **options)

    @classmethod
    def of(cls, *events: SseEvent, **options: Any) -> "ChatTurn":
        return cls(events=list(events), **options)

    @classmethod
    def refused(
        cls,
        status: int,
        code: str,
        message: str,
        *,
        retry_after: Optional[int] = None,
        **details: Any,
    ) -> "ChatTurn":
        body = {"error": {"code": code, "message": message, "details": details}}
        return cls(status=status, error_body=body, retry_after=retry_after)


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

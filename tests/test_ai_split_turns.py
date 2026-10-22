"""Split hosted chat turns: pausing for tools and continuing the turn."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AIProviderConfig
from servonaut.services import ai_split_turns
from servonaut.services.ai_error_handler import UserFacingAction, map_error_to_action
from servonaut.services.ai_providers import ServonautProvider
from servonaut.services.ai_split_turns import (
    CONTINUATION_LOST_CODE,
    CONTINUE_PATH,
    Suspension,
    prompt_deadline,
    stream_continuation,
    window_seconds,
)
from servonaut.services.ai_sse import SSEStreamError
from servonaut.services.api_client import APIClient, APIError, NotFoundError


def run(coro):
    return asyncio.run(coro)


def _iso_in(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _suspended(call_ids: List[str], *, cid: str = "cont-1", expires_in: float = 300.0) -> Dict[str, Any]:
    return {
        "event": "turn_suspended",
        "data": {
            "continuation_id": cid,
            "tool_call_ids": call_ids,
            "expires_at": _iso_in(expires_in),
        },
    }


def _tool_call(call_id: str, *, tool: str = "run_command", guard: str = "standard") -> Dict[str, Any]:
    return {
        "event": "tool_call",
        "data": {"tool_call_id": call_id, "tool": tool, "args": {}, "guard_level": guard},
    }


def _refusal(status: int, code: str, *, retry_after: str | None = None) -> APIError:
    headers = {"retry-after": retry_after} if retry_after is not None else {}
    cls = NotFoundError if status == 404 else APIError
    return cls(code=code, message=code, status=status, response_headers=headers)


class _Server:
    """Scripted ``stream_sse``: one entry per request, in order.

    An entry is a list of events to stream, or an :class:`APIError` raised
    before the stream opens. Records every request's path and body, and the
    events the consumer had handled when each request was made.
    """

    def __init__(self, *responses: Any) -> None:
        self._responses = list(responses)
        self.requests: List[Dict[str, Any]] = []
        self.handled: List[str] = []

    def stream_sse(self, path: str, body: Dict[str, Any], **kwargs: Any):
        self.requests.append({"path": path, "body": body, "kwargs": kwargs,
                              "handled_before": list(self.handled)})
        response = self._responses.pop(0)

        async def _gen():
            if isinstance(response, Exception):
                raise response
            for event in response:
                yield event

        return _gen()


def _provider(server: _Server) -> ServonautProvider:
    api = MagicMock(spec=APIClient)
    api.stream_sse = MagicMock(side_effect=server.stream_sse)
    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)
    return ServonautProvider(api_client=api, auth_service=auth)


def _drain(provider: ServonautProvider, server: _Server, **kwargs: Any) -> List[Dict[str, Any]]:
    """Consume a turn the way the chat panel does: handle each event before the next."""
    async def _run():
        out = []
        async for event in provider.stream_chat(
            [{"role": "user", "content": "hi"}], "",
            AIProviderConfig(provider="servonaut"),
            **kwargs,
        ):
            out.append(event)
            if event["event"] == "tool_call":
                server.handled.append(event["data"]["tool_call_id"])
        return out
    return run(_run())


@pytest.fixture
def no_sleep(monkeypatch):
    """Record /continue retry waits instead of sleeping through them."""
    waits: List[float] = []

    async def _sleep(seconds):
        waits.append(seconds)

    monkeypatch.setattr(ai_split_turns.asyncio, "sleep", _sleep)
    return waits


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------


def test_window_is_measured_from_an_iso_timestamp():
    now = time.time()
    moment = datetime.fromtimestamp(now + 300, tz=timezone.utc)
    assert window_seconds(moment.isoformat(), now=now) == pytest.approx(300, abs=0.01)
    zulu = moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    assert window_seconds(zulu, now=now) == pytest.approx(300, abs=0.01)


@pytest.mark.parametrize("value", [None, "", "soon", 300, "2026-13-40T00:00:00Z"])
def test_unreadable_expiry_gives_no_window(value):
    assert window_seconds(value) is None


@pytest.mark.parametrize("offset", [-5, 0, 901, 4000])
def test_expiry_outside_the_service_range_is_not_believed(offset):
    # Already past, or further away than the service ever waits: the
    # clocks disagree, so the window cannot be measured from here.
    assert window_seconds(_iso_in(offset)) is None


def test_suspension_turns_the_window_into_a_monotonic_deadline():
    before = time.monotonic()
    suspension = Suspension.from_event(_suspended(["a", "b"], expires_in=300)["data"])

    assert suspension.continuation_id == "cont-1"
    assert suspension.tool_call_ids == ("a", "b")
    assert suspension.respond_by == pytest.approx(before + 300, abs=2)
    assert suspension.retry_until() == suspension.respond_by


def test_suspension_with_an_unbelievable_window_retries_for_the_shortest_one():
    suspension = Suspension.from_event(_suspended(["a"], expires_in=-10)["data"])

    assert suspension.respond_by is None
    assert suspension.retry_until() == pytest.approx(
        suspension.received_at + ai_split_turns.FALLBACK_WINDOW_SECONDS,
    )


@pytest.mark.parametrize("data", [None, [], {}, {"continuation_id": ""}, {"continuation_id": 7}])
def test_suspension_needs_a_continuation_id(data):
    assert Suspension.from_event(data) is None


def test_prompt_leaves_time_to_run_the_tool_and_continue():
    assert prompt_deadline(None, run_seconds=60) is None
    # 300 s window: up to a minute to run, 5 s to post and continue.
    assert prompt_deadline(1300.0, run_seconds=60, now=1000.0) == 235.0
    assert prompt_deadline(1300.0, run_seconds=300, now=1000.0) == 235.0
    assert prompt_deadline(1300.0, run_seconds=10, now=1000.0) == 285.0
    # No time left to answer.
    assert prompt_deadline(1030.0, run_seconds=60, now=1000.0) == 0.0


# ---------------------------------------------------------------------------
# /continue
# ---------------------------------------------------------------------------


def _collect_continuation(server: _Server, suspension: Suspension) -> List[Dict[str, Any]]:
    async def _run():
        api = MagicMock()
        api.stream_sse = MagicMock(side_effect=server.stream_sse)
        return [event async for event in stream_continuation(api, suspension)]
    return run(_run())


def _suspension(expires_in: float = 300.0) -> Suspension:
    return Suspension.from_event(_suspended(["a"], expires_in=expires_in)["data"])


def test_continue_posts_the_continuation_id_and_streams_the_rest():
    server = _Server([{"event": "tool_result", "data": {"tool_call_id": "a"}}])

    events = _collect_continuation(server, _suspension())

    assert events == [{"event": "tool_result", "data": {"tool_call_id": "a"}}]
    assert server.requests[0]["path"] == CONTINUE_PATH
    assert server.requests[0]["body"] == {"continuation_id": "cont-1"}
    assert server.requests[0]["kwargs"]["drain_terminal_error"] is True


@pytest.mark.parametrize("status,code,retry_after,wait", [
    (409, "tool_results_pending", None, 1.0),
    (409, "tool_results_pending", "2", 2.0),
    (503, "server_busy", "3", 3.0),
    (429, "rate_limited", "1", 1.0),
])
def test_refusals_that_keep_the_continuation_are_retried(no_sleep, status, code, retry_after, wait):
    server = _Server(
        _refusal(status, code, retry_after=retry_after),
        [{"event": "token", "data": {"text": "done"}}],
    )

    events = _collect_continuation(server, _suspension())

    assert events == [{"event": "token", "data": {"text": "done"}}]
    assert len(server.requests) == 2
    assert no_sleep == [wait]


def test_a_lost_continuation_is_not_reported_as_a_stale_conversation():
    # A bare 404 would make the chat panel resend the whole turn.
    server = _Server(_refusal(404, "continuation_not_found"))

    with pytest.raises(SSEStreamError) as raised:
        _collect_continuation(server, _suspension())

    assert raised.value.code == CONTINUATION_LOST_CODE
    assert not isinstance(raised.value, APIError)


def test_results_still_pending_when_the_window_closes_lose_the_turn(no_sleep):
    server = _Server(_refusal(409, "tool_results_pending", retry_after="30"))

    with pytest.raises(SSEStreamError) as raised:
        _collect_continuation(server, _suspension(expires_in=20))

    assert raised.value.code == CONTINUATION_LOST_CODE
    assert no_sleep == []


def test_a_busy_server_past_the_window_surfaces_as_busy(no_sleep):
    server = _Server(_refusal(503, "server_busy", retry_after="30"))

    with pytest.raises(APIError) as raised:
        _collect_continuation(server, _suspension(expires_in=20))

    assert raised.value.code == "server_busy"


def test_payment_refusal_is_not_retried(no_sleep):
    server = _Server(_refusal(402, "balance_exhausted"))

    with pytest.raises(APIError) as raised:
        _collect_continuation(server, _suspension())

    assert raised.value.status == 402
    assert len(server.requests) == 1
    assert no_sleep == []


def test_a_lost_turn_gets_its_own_message():
    payload = map_error_to_action(ai_split_turns.continuation_lost("refused"))

    assert payload.code == CONTINUATION_LOST_CODE
    assert payload.action == UserFacingAction.TOAST_WARNING
    assert "Send your message again" in payload.user_message


# ---------------------------------------------------------------------------
# stream_chat with split_turns
# ---------------------------------------------------------------------------


def test_split_turns_is_requested_only_when_asked():
    server = _Server([], [])
    provider = _provider(server)

    _drain(provider, server, split_turns=True)
    _drain(provider, server)

    assert server.requests[0]["body"]["split_turns"] is True
    assert "split_turns" not in server.requests[1]["body"]


def test_a_paused_turn_is_continued_after_its_tool_calls_were_handled():
    server = _Server(
        [
            {"event": "conversation", "data": {"conversation_id": "conv-1"}},
            {"event": "token", "data": {"text": "Checking."}},
            _tool_call("a"),
            _suspended(["a"]),
        ],
        [
            {"event": "tool_result", "data": {"tool_call_id": "a", "status": "ok"}},
            {"event": "token", "data": {"text": " All good."}},
            {"event": "usage", "data": {"input_tokens": 1}},
        ],
    )
    provider = _provider(server)

    events = _drain(provider, server, split_turns=True)

    names = [e["event"] for e in events]
    assert names == ["conversation", "token", "tool_call", "tool_result", "token", "usage", "done"]
    assert server.requests[1]["path"] == CONTINUE_PATH
    assert server.requests[1]["body"] == {"continuation_id": "cont-1"}
    # Pull-based: the call was run and posted before the turn continued.
    assert server.requests[1]["handled_before"] == ["a"]
    # Without the service saying it pauses, the call was handed on at once,
    # so it carries no deadline (the prompt keeps its configured limit).
    assert "respond_by" not in events[2]["data"]


def test_when_the_service_says_it_pauses_calls_wait_for_the_deadline():
    server = _Server(
        [
            {"event": "conversation", "data": {"conversation_id": "conv-1", "split_turns": True}},
            _tool_call("refused"),
            {"event": "tool_result", "data": {"tool_call_id": "refused", "status": "denied"}},
            _tool_call("a"),
            _tool_call("b", guard="readonly"),
            _suspended(["a", "b"]),
        ],
        [{"event": "usage", "data": {}}],
    )
    provider = _provider(server)
    before = time.monotonic()

    events = _drain(provider, server, split_turns=True)

    calls = [e["data"] for e in events if e["event"] == "tool_call"]
    # The refused call already has its result, so it is not run here.
    assert [c["tool_call_id"] for c in calls] == ["a", "b"]
    for call in calls:
        assert call["respond_by"] == pytest.approx(before + 300, abs=2)
    names = [e["event"] for e in events]
    assert names.index("tool_result") < names.index("tool_call")
    assert server.requests[1]["handled_before"] == ["a", "b"]


def test_continued_segments_hold_calls_until_the_next_pause():
    server = _Server(
        [_tool_call("a"), _suspended(["a"], cid="first")],
        [
            {"event": "tool_result", "data": {"tool_call_id": "a"}},
            _tool_call("b"),
            _suspended(["b"], cid="second", expires_in=60),
        ],
        [
            {"event": "tool_result", "data": {"tool_call_id": "b"}},
            {"event": "token", "data": {"text": "Done."}},
            {"event": "usage", "data": {}},
        ],
    )
    provider = _provider(server)

    events = _drain(provider, server, split_turns=True)

    assert [r["body"].get("continuation_id") for r in server.requests[1:]] == ["first", "second"]
    second_call = [e for e in events if e["event"] == "tool_call"][1]
    assert second_call["data"]["respond_by"] == pytest.approx(time.monotonic() + 60, abs=3)
    assert [e["event"] for e in events].count("done") == 1


def test_a_pause_without_a_continuation_loses_the_turn():
    server = _Server([_tool_call("a"), {"event": "turn_suspended", "data": {"tool_call_ids": ["a"]}}])
    provider = _provider(server)

    with pytest.raises(SSEStreamError) as raised:
        _drain(provider, server, split_turns=True)

    assert raised.value.code == CONTINUATION_LOST_CODE
    assert len(server.requests) == 1


def test_without_split_turns_a_turn_is_never_continued():
    server = _Server([_tool_call("a"), {"event": "usage", "data": {}}])
    provider = _provider(server)

    events = _drain(provider, server)

    assert [e["event"] for e in events] == ["tool_call", "usage", "done"]
    assert len(server.requests) == 1

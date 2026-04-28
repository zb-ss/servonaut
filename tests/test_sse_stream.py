"""Tests for the SSE stream consumer (T2).

Covers the architect plan §T2 minimum-test list:

- pure-tokens stream → 5 token events + terminal usage
- mid-stream tool round → token, tool_call, tool_result, usage
- ``wall_clock_cap_exceeded`` surfaces as info, not error
- terminal ``error`` event raises :class:`SSEStreamError`
- ``rate_limited`` carries ``retry_after``
- ``ping`` events absorbed (never yielded)
- heartbeat watchdog (>35s silence) raises :class:`SSEStreamDead`
- caller cancellation unwinds the connection cleanly
- ``fallback_used`` surfaces in usage
- soft-cap model swap visible in usage event

For heartbeat tests we monkeypatch ``SSE_HEARTBEAT_DEAD_S`` to a tiny
value (0.5s) and pair it with a 1.0s injected delay between events
via ``build_mock_transport_with_delay`` — this exercises the watchdog
without burning real wall-clock. The same trick keeps
``test_ping_absorbed_never_yielded`` fast.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services import ai_sse
from servonaut.services.ai_sse import (
    SSEStreamDead,
    SSEStreamError,
    stream_sse,
)
from servonaut.services.api_client import APIClient

from .sse_replay import (
    build_cancellable_transport,
    build_mock_transport,
    build_mock_transport_with_delay,
    fixture_for,
)


def run(coro):
    """asyncio.run wrapper — matches project test convention (no pytest-asyncio)."""
    return asyncio.run(coro)


def _make_api_client() -> APIClient:
    """Build an APIClient with a mocked AuthService — enough for ``_get_headers``."""
    auth = MagicMock()
    auth.access_token = "test-token"
    auth.refresh_token = AsyncMock(return_value=True)
    return APIClient(auth)


async def _drain(generator):
    """Collect every yielded event from an async generator into a list."""
    out = []
    async for event in generator:
        out.append(event)
    return out


# ---------------------------------------------------------------------------
# 1. Pure tokens → 5 tokens + 1 usage
# ---------------------------------------------------------------------------

def test_pure_tokens_stream_yields_5_token_events_and_usage(monkeypatch):
    transport = build_mock_transport(fixture_for("tokens_only"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()
    events = run(_drain(stream_sse(api, "/api/ai/chat", {"task": "chat"})))

    token_events = [e for e in events if e["event"] == "token"]
    usage_events = [e for e in events if e["event"] == "usage"]

    assert len(token_events) == 5
    assert [e["data"]["text"] for e in token_events] == [
        "Hello", " world", ", how", " are", " you?",
    ]
    assert len(usage_events) == 1
    assert usage_events[0]["data"]["model"] == "gemini-2-flash-002"
    assert usage_events[0]["data"]["input_tokens"] == 100


# ---------------------------------------------------------------------------
# 2. Tool round → token, tool_call, tool_result, token, usage
# ---------------------------------------------------------------------------

def test_tool_round_yields_correct_event_sequence(monkeypatch):
    transport = build_mock_transport(fixture_for("tool_round_one"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()
    events = run(_drain(stream_sse(api, "/api/ai/chat", {"task": "chat"})))

    event_names = [e["event"] for e in events]
    assert event_names == ["token", "tool_call", "tool_result", "token", "usage"]

    tool_call = events[1]
    assert tool_call["data"]["tool_call_id"] == "tc_abc123"
    assert tool_call["data"]["tool"] == "tail_log"
    assert tool_call["data"]["guard_level"] == "readonly"

    tool_result = events[2]
    assert tool_result["data"]["status"] == "ok"
    assert tool_result["data"]["bytes"] == 4823

    usage = events[4]
    assert usage["data"]["tool_calls_count"] == 1


# ---------------------------------------------------------------------------
# 3a. tool_round_limit → emitted as info, not error (D1)
# ---------------------------------------------------------------------------

def test_tool_round_limit_emits_info_event(monkeypatch):
    """Plan §T2: ``tool_round_limit`` is informational, not an error.

    The server emits it as an SSE ``event: error`` with the canonical
    ``code: "tool_round_limit"`` per the SSE format, but the consumer
    must reroute it to ``event="info"`` (already in
    :data:`_INFO_ERROR_CODES`) so the UI renders softly rather than
    raising :class:`SSEStreamError`.
    """
    transport = build_mock_transport(fixture_for("tool_round_limit_5"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()
    events = run(_drain(stream_sse(api, "/api/ai/chat", {"task": "chat"})))

    # Five tool_call + tool_result rounds, then one info event for the cap.
    tool_calls = [e for e in events if e["event"] == "tool_call"]
    assert len(tool_calls) == 5

    info_events = [e for e in events if e["event"] == "info"]
    assert len(info_events) == 1
    assert info_events[0]["data"]["code"] == "tool_round_limit"
    assert "MAX_TOOL_ROUNDS" in info_events[0]["data"]["message"]


# ---------------------------------------------------------------------------
# 3. wall_clock_cap_exceeded → emitted as info, not error
# ---------------------------------------------------------------------------

def test_wall_clock_emits_info_event(monkeypatch):
    transport = build_mock_transport(fixture_for("wall_clock_120s"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()
    events = run(_drain(stream_sse(api, "/api/ai/chat", {"task": "chat"})))

    info_events = [e for e in events if e["event"] == "info"]
    assert len(info_events) == 1
    assert info_events[0]["data"]["code"] == "wall_clock_cap_exceeded"
    assert "120s" in info_events[0]["data"]["message"]
    # Critical: no SSEStreamError raised.
    # If we got here, the stream completed without raising.


# ---------------------------------------------------------------------------
# 4. quota_exhausted → SSEStreamError with details
# ---------------------------------------------------------------------------

def test_error_terminal_raises_sse_stream_error(monkeypatch):
    transport = build_mock_transport(fixture_for("error_quota_exhausted"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()

    async def _consume():
        out = []
        async for event in stream_sse(api, "/api/ai/chat", {"task": "chat"}):
            out.append(event)
        return out

    with pytest.raises(SSEStreamError) as exc_info:
        run(_consume())

    err = exc_info.value
    assert err.code == "quota_exhausted"
    assert err.details.get("topup_url", "").startswith("https://")
    assert err.details.get("tokens_used") == 15_000_000
    assert err.details.get("tokens_limit") == 15_000_000


# ---------------------------------------------------------------------------
# 5. rate_limited → retry_after preserved
# ---------------------------------------------------------------------------

def test_rate_limited_includes_retry_after(monkeypatch):
    transport = build_mock_transport(fixture_for("error_rate_limited"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()

    async def _consume():
        async for _ in stream_sse(api, "/api/ai/chat", {"task": "chat"}):
            pass

    with pytest.raises(SSEStreamError) as exc_info:
        run(_consume())

    assert exc_info.value.code == "rate_limited"
    assert exc_info.value.retry_after == 12


# ---------------------------------------------------------------------------
# 6. ping events absorbed (never yielded)
# ---------------------------------------------------------------------------

def test_ping_absorbed_never_yielded(monkeypatch):
    """Six pings + a usage → consumer sees only the usage event.

    Use a small heartbeat threshold so the test verifies that pings
    actively reset the watchdog (otherwise the test is flaky when run on
    a slow machine that processes 7 events in >35s).
    """
    transport = build_mock_transport(fixture_for("ping_only_90s"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)
    monkeypatch.setattr(ai_sse, "SSE_HEARTBEAT_DEAD_S", 5.0)

    api = _make_api_client()
    events = run(_drain(stream_sse(api, "/api/ai/chat", {"task": "chat"})))

    # No ping events leaked through — only the usage event.
    ping_events = [e for e in events if e["event"] == "ping"]
    assert ping_events == []
    assert len(events) == 1
    assert events[0]["event"] == "usage"


# ---------------------------------------------------------------------------
# 7. heartbeat watchdog → SSEStreamDead after timeout
# ---------------------------------------------------------------------------

def test_heartbeat_watchdog_dead_after_timeout(monkeypatch):
    """Inject a 1.0s gap between events with the watchdog at 0.5s.

    Decision: rather than monkey with ``time.monotonic`` we simply scale
    both knobs down (0.5s threshold + 1.0s injected delay) — same logic,
    real time, ~1s test runtime.
    """
    monkeypatch.setattr(ai_sse, "SSE_HEARTBEAT_DEAD_S", 0.5)

    transport = build_mock_transport_with_delay(
        fixture_for("mid_stream_silence"),
        delay_at_event=4,  # silence after the 5th token (0-indexed)
        delay_seconds=1.0,
    )
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()

    async def _consume():
        out = []
        async for event in stream_sse(api, "/api/ai/chat", {"task": "chat"}):
            out.append(event)
        return out

    with pytest.raises(SSEStreamDead):
        run(_consume())


# ---------------------------------------------------------------------------
# 8. cancellation unwinds cleanly
# ---------------------------------------------------------------------------

def test_cancellation_unwinds_cleanly(monkeypatch):
    """Cancel after 3 events; assert the body generator's ``finally`` ran.

    The cancellable transport parks forever after emitting all fixture
    events; we ``aclose()`` the consuming generator and verify the body
    coroutine's ``finally`` block recorded the close — proves the
    ``async with httpx.AsyncClient`` in :func:`stream_sse` unwound.
    """
    close_recorded: list = []
    transport = build_cancellable_transport(
        fixture_for("cancelled_mid_stream"),
        on_close_recorder=close_recorded,
    )
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)
    # Keep watchdog generous so the test doesn't race the heartbeat.
    monkeypatch.setattr(ai_sse, "SSE_HEARTBEAT_DEAD_S", 30.0)

    api = _make_api_client()

    async def _partial_consume():
        gen = stream_sse(api, "/api/ai/chat", {"task": "chat"})
        seen = 0
        async for _ in gen:
            seen += 1
            if seen >= 3:
                await gen.aclose()
                break
        return seen

    seen = run(_partial_consume())
    assert seen == 3
    # The body generator's ``finally`` block ran → MockTransport stream
    # was unwound, which means the AsyncClient closed cleanly.
    assert close_recorded == [True], (
        "Expected body generator finally to run on cancellation"
    )


# ---------------------------------------------------------------------------
# 9. fallback_used surfaces in usage
# ---------------------------------------------------------------------------

def test_fallback_used_surfaces_in_usage(monkeypatch):
    transport = build_mock_transport(fixture_for("fallback_used"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()
    events = run(_drain(stream_sse(api, "/api/ai/chat", {"task": "chat"})))

    usage = next(e for e in events if e["event"] == "usage")
    assert usage["data"]["fallback_used"] is True
    assert usage["data"]["vendor"] == "openai"


# ---------------------------------------------------------------------------
# 10. soft-cap model swap visible
# ---------------------------------------------------------------------------

def test_soft_cap_model_swap_visible(monkeypatch):
    transport = build_mock_transport(fixture_for("soft_cap"))
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", transport)

    api = _make_api_client()
    events = run(_drain(stream_sse(api, "/api/ai/chat", {"task": "chat"})))

    usage = next(e for e in events if e["event"] == "usage")
    # Server force-downgraded — model field reflects the swap.
    assert usage["data"]["model"] == "gemini-2-flash-002"
    assert usage["data"]["quota"]["soft_capped"] is True

"""Demo-mode chat replay: scripted SSE through the real stream pipeline."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from servonaut.services import ai_sse
from servonaut.services.ai_providers import demo_replay
from servonaut.services.ai_providers.demo_replay import (
    DemoChatReplayTransport,
    ScriptStep,
    install_demo_chat_replay,
    maybe_install_demo_chat_replay,
    parse_script,
    replay_script_path,
)
from servonaut.services.ai_sse import stream_sse
from servonaut.services.api_client import APIClient

SCRIPT = """\
: a comment the replay ignores
event: conversation
data: {"conversation_id": "conv_demo"}

: delay 0.01
event: token
data: {"text": "Checking "}

event: tool_call
data: {"tool_call_id": "tc_1", "tool": "run_command", "args": {"instance_id": "custom-abc", "command": "uptime"}, "guard_level": "standard"}

: wait tool-result
event: tool_result
data: {"tool_call_id": "tc_1", "status": "ok", "result_summary": "{{tool_result}}"}

event: token
data: {"text": "Load is low."}

event: usage
data: {"model": "demo", "vendor": "demo", "input_tokens": 1, "output_tokens": 1, "cached_tokens": 0, "tool_calls_count": 1, "fallback_used": false}
"""


def _api_client() -> APIClient:
    # Same mocked AuthService the SSE tests use — enough for ``_get_headers``.
    from tests.test_sse_stream import _make_api_client

    return _make_api_client()


def run(coro):
    return asyncio.run(coro)


# --- parsing ---------------------------------------------------------------

def test_parse_script_keeps_events_and_reads_directives():
    steps = parse_script(SCRIPT)
    kinds = [s.kind for s in steps]
    assert kinds == ["event", "delay", "event", "event", "wait", "event", "event", "event"]
    assert steps[1].seconds == pytest.approx(0.01)
    assert steps[0].event.startswith(b"event: conversation\n")
    assert steps[0].event.endswith(b"\n\n")


def test_parse_script_ignores_unknown_comments_and_blank_runs():
    steps = parse_script(": hello\n\n\n: delay nope\nevent: token\ndata: {}\n")
    assert [s.kind for s in steps] == ["event"]


# --- replay through the real stream pipeline --------------------------------

def test_replay_streams_events_and_waits_for_the_tool_result(monkeypatch):
    monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", None)
    api = _api_client()
    transport = DemoChatReplayTransport(parse_script(SCRIPT))
    api.transport = transport

    async def scenario():
        seen = []
        posted = asyncio.Event()

        async def consume():
            async for event in stream_sse(api, "/api/ai/chat", {"task": "chat"}):
                seen.append(event)
                if event["event"] == "tool_call":
                    # The CLI executes the tool and posts the result; the
                    # stream must hold until then.
                    await asyncio.sleep(0.05)
                    assert seen[-1]["event"] == "tool_call"
                    await api.post(
                        "/api/ai/chat/tool-result",
                        json={"tool_call_id": "tc_1", "status": "ok", "result": " 12:00 up 5 days, load 0.10\n"},
                    )
                    posted.set()

        await asyncio.wait_for(consume(), timeout=5)
        return seen, posted.is_set()

    events, posted = run(scenario())
    names = [e["event"] for e in events]
    assert names == ["conversation", "token", "tool_call", "tool_result", "token", "usage"]
    assert posted
    assert events[3]["data"]["result_summary"] == "12:00 up 5 days, load 0.10"
    assert transport.last_tool_result["tool_call_id"] == "tc_1"
    assert transport.stream_requests == 1


def test_wait_step_emits_ping_comments_while_holding(monkeypatch):
    monkeypatch.setattr(demo_replay, "_WAIT_PING_SECONDS", 0.01)
    transport = DemoChatReplayTransport([ScriptStep("wait"), ScriptStep("event", event=b"event: token\ndata: {}\n\n")])

    async def scenario():
        chunks = []
        gen = transport.iter_script()
        chunks.append(await gen.__anext__())  # first ping while waiting
        chunks.append(await gen.__anext__())
        # release the hold
        await transport.handle_async_request(
            httpx.Request("POST", "https://api.example.com/api/ai/chat/tool-result", content=b"{}")
        )
        async for chunk in gen:
            chunks.append(chunk)
        return chunks

    chunks = run(scenario())
    assert chunks[0] == b": ping\n\n"
    assert chunks[-1].startswith(b"event: token")


def test_other_requests_pass_through_to_the_inner_transport():
    inner = httpx.MockTransport(lambda request: httpx.Response(200, json={"me": "real"}))
    transport = DemoChatReplayTransport([], inner=inner)
    api = _api_client()
    api.transport = transport

    assert run(api.get("/api/v1/me")) == {"me": "real"}


def test_without_inner_transport_unknown_routes_are_404():
    transport = DemoChatReplayTransport([])
    api = _api_client()
    api.transport = transport
    with pytest.raises(Exception):
        run(api.get("/api/v1/me"))


# --- gating ----------------------------------------------------------------

def test_replay_script_path_requires_demo_mode_and_a_readable_file(tmp_path):
    script = tmp_path / "chat.sse"
    script.write_text(SCRIPT)
    assert replay_script_path(False, {"SERVONAUT_DEMO_CHAT_REPLAY": str(script)}) is None
    assert replay_script_path(True, {}) is None
    assert replay_script_path(True, {"SERVONAUT_DEMO_CHAT_REPLAY": str(tmp_path / "missing.sse")}) is None
    assert replay_script_path(True, {"SERVONAUT_DEMO_CHAT_REPLAY": str(script)}) == script


def test_install_wraps_the_client_and_maybe_install_is_a_no_op_without_env(tmp_path):
    script = tmp_path / "chat.sse"
    script.write_text(SCRIPT)
    api = _api_client()
    assert maybe_install_demo_chat_replay(api, True, {}) is None
    assert api.transport is None

    transport = maybe_install_demo_chat_replay(api, True, {"SERVONAUT_DEMO_CHAT_REPLAY": str(script)})
    assert isinstance(transport, DemoChatReplayTransport)
    assert api.transport is transport
    assert len(transport._steps) == len(parse_script(SCRIPT))


def test_install_keeps_an_existing_transport_as_the_inner_one(tmp_path):
    script = tmp_path / "chat.sse"
    script.write_text(SCRIPT)
    api = _api_client()
    inner = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    api.transport = inner
    transport = install_demo_chat_replay(api, script)
    assert transport._inner is inner
    assert run(api.get("/api/anything")) == {"ok": True}

"""The AI stand-ins hold the product to the real wire rules.

The provider stand-in must refuse, in each provider's own error envelope,
the requests its real API refuses; otherwise a journey could pass on a
request the real service would reject. The SSE helpers shared by the
FakeCloud streams must keep data exactly as sent.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
import pytest

from e2e.harness.fake_ai import KEYS, reply, tool_call
from e2e.harness.fake_cloud import sse

pytestmark = [pytest.mark.e2e_pr]

PATHS = {"openai": "/v1/chat/completions", "anthropic": "/v1/messages", "ollama": "/api/chat"}
USER = {"role": "user", "content": "Hello"}


def _headers(provider: str, key: Optional[str] = None) -> dict[str, str]:
    key = key or KEYS[provider]
    if provider == "anthropic":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    return {"Authorization": f"Bearer {key}"}


def _post(fake_ai: Any, provider: str, body: Any, headers: Optional[dict] = None) -> httpx.Response:
    with httpx.Client(trust_env=False, timeout=10) as client:
        return client.post(
            fake_ai.url + PATHS[provider],
            json=body,
            headers=_headers(provider) if headers is None else headers,
        )


def _refusal(response: httpx.Response, provider: str) -> str:
    """The 400 message, read from *provider*'s own envelope."""
    assert response.status_code == 400, response.text
    body = response.json()
    if provider == "openai":
        assert body["error"]["type"] == "invalid_request_error"
        return body["error"]["message"]
    if provider == "anthropic":
        assert body["type"] == "error" and body["error"]["type"] == "invalid_request_error"
        return body["error"]["message"]
    return body["error"]


@pytest.mark.parametrize(
    ("provider", "body", "says"),
    [
        ("openai", {"messages": [USER]}, "model"),
        ("openai", {"model": "m"}, "messages"),
        (
            "openai",
            {"model": "m", "messages": [USER, {"role": "tool", "tool_call_id": "x"}]},
            "role 'tool'",
        ),
        ("anthropic", {"model": "m", "messages": [USER]}, "max_tokens"),
        (
            "anthropic",
            {"model": "m", "max_tokens": 5, "messages": [{"role": "system", "content": "s"}, USER]},
            "top-level `system`",
        ),
        (
            "anthropic",
            {
                "model": "m",
                "max_tokens": 5,
                "messages": [
                    USER,
                    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x"}]},
                ],
            },
            "tool_use_id",
        ),
        ("ollama", {"model": "m", "messages": [USER]}, "stream"),
        ("ollama", {"messages": [USER], "stream": False}, "model"),
    ],
)
def test_requests_the_real_api_refuses_are_refused(fake_ai, provider, body, says):
    fake_ai.script(provider, reply("never sent"))
    assert says in _refusal(_post(fake_ai, provider, body), provider)
    assert fake_ai.pending(provider) == 1  # the scripted answer was not used
    assert fake_ai.requests(provider)[-1]["problem"]


@pytest.mark.parametrize(
    ("provider", "headers"),
    [
        ("openai", {"x-api-key": KEYS["openai"]}),
        ("openai", {"Authorization": f"Bearer {KEYS['anthropic']}"}),
        ("anthropic", {"Authorization": f"Bearer {KEYS['anthropic']}"}),
        ("anthropic", {"x-api-key": KEYS["anthropic"]}),  # no anthropic-version
        ("ollama", {"Authorization": f"Bearer {KEYS['openai']}"}),
    ],
    ids=["openai-wrong-header", "openai-wrong-key", "anthropic-bearer", "anthropic-no-version",
         "ollama-wrong-key"],
)
def test_keys_are_accepted_only_where_the_real_api_expects_them(fake_ai, provider, headers):
    assert _post(fake_ai, provider, {"model": "m"}, headers=headers).status_code == 401


def test_a_tool_round_the_real_api_accepts(fake_ai):
    fake_ai.script("openai", tool_call("list_instances"), reply("Done."))
    first = _post(fake_ai, "openai", {"model": "m", "messages": [USER]})
    assistant = first.json()["choices"][0]["message"]
    call_id = assistant["tool_calls"][0]["id"]
    answer = {"role": "tool", "tool_call_id": call_id, "content": "3 servers"}
    second = _post(fake_ai, "openai", {"model": "m", "messages": [USER, assistant, answer]})
    assert second.status_code == 200, second.text
    assert second.json()["choices"][0]["message"]["content"] == "Done."
    assert [r["auth_headers"] for r in fake_ai.requests()] == [["authorization"]] * 2


def test_sse_frames_keep_data_exactly():
    data = " leading space\nsecond line  \n\nafter a blank line"
    stream = sse.comment("keepalive") + sse.frame(data, event="token", event_id="7")
    [event] = sse.parse(stream.decode("utf-8"))
    assert event == sse.ParsedEvent("token", data, "7")
    # A field with no space after the colon, and a bare data line.
    assert sse.parse("event:ping\ndata:\n\n") == [sse.ParsedEvent("ping", "")]


def test_a_pause_deadline_counts_from_when_it_is_sent():
    import json
    import time
    from datetime import datetime

    from e2e.harness.fake_cloud.chat_script import turn_suspended

    event = turn_suspended("cont-1", ["tc-1"], expires_in=300)
    [parsed] = sse.parse(event.frame().decode("utf-8"))
    data = json.loads(parsed.data)
    assert (data["continuation_id"], data["tool_call_ids"]) == ("cont-1", ["tc-1"])
    left = datetime.fromisoformat(data["expires_at"]).timestamp() - time.time()
    assert 295 < left <= 300


def _scripted(spec: dict) -> list:
    from unittest.mock import MagicMock

    from e2e.sandbox import ai_script

    fake_cloud = MagicMock()
    fake_cloud.entitlements.return_value = {"quota": {}}
    ai_script.apply(fake_cloud, ai_script.load_spec(spec))
    return [turn for call in fake_cloud.ai.script.call_args_list for turn in call.args]


NOTE_CALL = {"tool": "remember_server_finding", "args": {"instance_id": "web-1"}, "result": "Saved."}


def test_a_sandbox_tool_turn_pauses_like_the_service():
    first, rest = _scripted({"turns": [{"reply": "On it.", "after": " Done.", "tool_call": NOTE_CALL}]})
    assert [e.name for e in first.events] == ["token", "token", "tool_call", "turn_suspended"]
    assert [e.name for e in rest.events] == ["tool_result", "token", "token", "usage"]
    assert first.pauses and first.says_it_pauses and rest.says_it_pauses


def test_a_sandbox_tool_turn_can_keep_the_stream_open():
    [turn] = _scripted({"turns": [{"reply": "On it.", "pause": False, "tool_call": NOTE_CALL}]})
    assert [e.name for e in turn.events] == ["token", "token", "tool_call", "tool_result", "usage"]
    assert not turn.pauses and not turn.says_it_pauses


@pytest.mark.parametrize("turn,says", [
    ({"reply": "x", "tool_call": "run it"}, 'with a "tool" name'),
    ({"reply": "x", "tool_call": {"tool": "t", "args": ["a"]}}, "args must be an object"),
    ({"reply": "x", "tool_call": {"tool": "t", "result": 3}}, "result must be a string"),
    ({"reply": "x", "pause": "yes", "tool_call": {"tool": "t"}}, "pause true or false"),
])
def test_a_malformed_sandbox_tool_turn_is_refused(turn, says):
    from e2e.sandbox import ai_script

    with pytest.raises(ai_script.ScriptError, match=says):
        ai_script.load_spec({"turns": [turn]})

"""Tests for ServonautProvider — buffered path (T1).

Covers the unit-test minimum from the architect plan §T1:
- Buffered chat unmarshals all 11 fields.
- ``is_available()`` is offline (no network call).
- ``AIAnalysisService`` skips the api-key check for ``provider == "servonaut"``.
- Request body matches the plan §"Request — POST /api/ai/chat" shape.
- ``APIError`` subclasses propagate without being wrapped.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AIProviderConfig, AppConfig
from servonaut.services.ai_analysis_service import AIAnalysisService
from servonaut.services.ai_providers import ServonautProvider
from servonaut.services.api_client import APIClient, RateLimitedError


def run(coro):
    """Synchronous asyncio wrapper — matches the project test convention."""
    return asyncio.run(coro)


# Canonical 11-field buffered response from the plan
# §"Buffered (stream: false) JSON response".
_CANONICAL_RESPONSE = {
    "conversation_id": "conv-uuid-123",
    "content": "Why nginx is 502ing on web-prod-1: upstream timeout.",
    "model": "gemini-2-flash-002",
    "vendor": "gemini",
    "input_tokens": 4230,
    "output_tokens": 812,
    "cached_tokens": 3800,
    "tool_calls_count": 2,
    "fallback_used": False,
    "quota": {
        "tokens_used": 123_456,
        "tokens_limit": 15_000_000,
        "tokens_topup_remaining": 500_000,
        "resets_at": "2026-05-01T00:00:00+00:00",
        "soft_capped": False,
        "hard_capped": False,
        "rpm_limit": 30,
        "tokens_per_minute_limit": 600_000,
    },
    "usage_persisted": True,
    "warning": "context truncated",
}


def _make_provider(*, authenticated: bool = True, premium: bool = True):
    """Build a ServonautProvider with mocked APIClient + AuthService."""
    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value=dict(_CANONICAL_RESPONSE))
    api.get = AsyncMock()
    api.patch = AsyncMock()
    api.delete = AsyncMock()
    api.get_bytes = AsyncMock()

    auth = MagicMock()
    auth.is_authenticated = authenticated
    auth.has_feature = MagicMock(return_value=premium)

    provider = ServonautProvider(api_client=api, auth_service=auth)
    return provider, api, auth


def _ai_config() -> AIProviderConfig:
    return AIProviderConfig(provider="servonaut", api_key="", model="")


# ---------------------------------------------------------------------------
# 1. Buffered chat unmarshals all 11 fields
# ---------------------------------------------------------------------------

def test_buffered_chat_unmarshals_all_11_fields():
    """All 11 fields from the canonical response land in the result dict.

    The unmarshalled dict also includes the unified provider-result keys
    so downstream consumers (chat-panel stats bar, error handler) work
    without special-casing the Servonaut provider.
    """
    provider, api, _auth = _make_provider()
    config = _ai_config()
    messages = [{"role": "user", "content": "why is nginx 502ing?"}]

    result = run(provider.chat(messages, "system", config))

    # Standard provider-result contract.
    assert result["content"] == _CANONICAL_RESPONSE["content"]
    assert result["model"] == _CANONICAL_RESPONSE["model"]
    assert result["input_tokens"] == _CANONICAL_RESPONSE["input_tokens"]
    assert result["output_tokens"] == _CANONICAL_RESPONSE["output_tokens"]
    assert result["tokens_used"] == (
        _CANONICAL_RESPONSE["input_tokens"]
        + _CANONICAL_RESPONSE["output_tokens"]
    )
    assert result["tool_calls"] == []  # buffered: server already executed
    assert result["raw_message"] == _CANONICAL_RESPONSE
    # tool_calls_count > 0 → stop_reason is tool_use.
    assert result["stop_reason"] == "tool_use"

    # Servonaut-specific extras (downstream T3/T5/T7/T10 consumers).
    assert result["conversation_id"] == _CANONICAL_RESPONSE["conversation_id"]
    assert result["fallback_used"] is False
    assert result["quota"] == _CANONICAL_RESPONSE["quota"]
    assert result["cached_tokens"] == _CANONICAL_RESPONSE["cached_tokens"]
    assert result["tool_calls_count"] == _CANONICAL_RESPONSE["tool_calls_count"]
    assert result["vendor"] == _CANONICAL_RESPONSE["vendor"]
    assert result["warning"] == _CANONICAL_RESPONSE["warning"]


def test_buffered_chat_handles_missing_fields_gracefully():
    """Missing fields fall back to safe defaults (free user, etc.)."""
    provider, api, _auth = _make_provider()
    api.post = AsyncMock(return_value={
        "content": "hi",
        "model": "gemini-flash",
        "input_tokens": 10,
        "output_tokens": 5,
        # quota: null (free user)
        # other fields absent
    })

    result = run(provider.chat(
        [{"role": "user", "content": "ping"}], "", _ai_config(),
    ))

    assert result["content"] == "hi"
    assert result["tool_calls_count"] == 0
    assert result["stop_reason"] == "end_turn"
    assert result["fallback_used"] is False
    assert result["cached_tokens"] == 0
    assert result["vendor"] == ""
    assert result["warning"] == ""
    assert result["conversation_id"] == ""
    assert result["quota"] is None


# ---------------------------------------------------------------------------
# 2. is_available is offline (no network)
# ---------------------------------------------------------------------------

def test_is_available_offline_no_network():
    """``is_available()`` must NOT touch the network — only cached state."""
    provider, api, auth = _make_provider(authenticated=True, premium=True)

    assert provider.is_available() is True

    # Critical contract: no API method invoked.
    api.get.assert_not_called()
    api.post.assert_not_called()
    api.patch.assert_not_called()
    api.delete.assert_not_called()
    api.get_bytes.assert_not_called()

    # And it consults the auth service.
    auth.has_feature.assert_called_once_with("premium_ai")


def test_is_available_false_when_unauthenticated():
    provider, api, auth = _make_provider(authenticated=False, premium=True)

    assert provider.is_available() is False
    api.post.assert_not_called()


def test_is_available_false_when_no_premium_ai():
    provider, api, auth = _make_provider(authenticated=True, premium=False)

    assert provider.is_available() is False
    api.post.assert_not_called()


# ---------------------------------------------------------------------------
# 3. AIAnalysisService skips api-key check for servonaut
# ---------------------------------------------------------------------------

def test_servonaut_skips_api_key_check():
    """``AIAnalysisService.chat`` must NOT short-circuit on empty api_key
    when ``provider == "servonaut"``.
    """
    ai_config = AIProviderConfig(provider="servonaut", api_key="", model="")
    config = AppConfig(ai_provider=ai_config, ai_system_prompt="sys")
    cfg_mgr = MagicMock()
    cfg_mgr.get.return_value = config

    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value=dict(_CANONICAL_RESPONSE))

    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)

    service = AIAnalysisService(cfg_mgr, api_client=api, auth_service=auth)

    result = run(service.chat([{"role": "user", "content": "hi"}]))

    # api_key is empty BUT we still got a real response — gate skipped.
    assert result["content"] == _CANONICAL_RESPONSE["content"]
    assert "API key is not configured" not in result["content"]
    api.post.assert_awaited_once()


def test_servonaut_skips_api_key_check_in_analyze_text():
    """The api-key gate in ``analyze_text`` must also be skipped."""
    ai_config = AIProviderConfig(provider="servonaut", api_key="", model="")
    config = AppConfig(
        ai_provider=ai_config,
        ai_system_prompt="sys",
        ai_chunk_size=4000,
    )
    cfg_mgr = MagicMock()
    cfg_mgr.get.return_value = config

    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value=dict(_CANONICAL_RESPONSE))

    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)

    service = AIAnalysisService(cfg_mgr, api_client=api, auth_service=auth)

    result = run(service.analyze_text("some logs to analyze"))

    assert "API key is not configured" not in result["content"]
    api.post.assert_awaited()


# ---------------------------------------------------------------------------
# 4. Request body matches the plan's POST /api/ai/chat shape
# ---------------------------------------------------------------------------

def test_chat_sends_correct_request_body():
    """Verify the request shape exactly matches the plan's contract:

      {
        "task": "chat",
        "messages": [...],
        "allow_tools": true,
        "stream": false
      }
    """
    provider, api, _auth = _make_provider()
    messages = [{"role": "user", "content": "why is nginx 502ing on web-prod-1?"}]

    run(provider.chat(messages, "you are a sysadmin", _ai_config()))

    api.post.assert_awaited_once()
    args, kwargs = api.post.call_args

    # Path is positional in APIClient.post(path, *, json=...).
    assert args[0] == "/api/ai/chat"
    # json= is keyword-only — never positional.
    assert "json" in kwargs, "Request body must be passed as json= kwarg"
    body = kwargs["json"]

    assert body["task"] == "chat"
    assert body["allow_tools"] is True
    assert body["stream"] is False

    # The gateway owns its system prompt and rejects client system roles.
    assert body["messages"] == messages
    assert all(message["role"] != "system" for message in body["messages"])


def test_analyze_uses_analyze_logs_task():
    """``analyze()`` must use the ``analyze_logs`` task enum, not ``chat``."""
    provider, api, _auth = _make_provider()

    run(provider.analyze("some log lines", "system", _ai_config()))

    api.post.assert_awaited_once()
    _args, kwargs = api.post.call_args
    assert kwargs["json"]["task"] == "analyze_logs"


def test_chat_omits_optional_fields_when_unset():
    """``conversation_id``, ``context``, ``tools`` must NOT appear when not set."""
    provider, api, _auth = _make_provider()

    run(provider.chat(
        [{"role": "user", "content": "hi"}], "", _ai_config(),
    ))

    body = api.post.call_args.kwargs["json"]
    assert "conversation_id" not in body
    assert "context" not in body
    assert "tools" not in body


def test_invalid_task_raises_value_error():
    """Client-side validation rejects unknown task names before round-trip."""
    provider, api, _auth = _make_provider()
    messages = [{"role": "user", "content": "hi"}]

    with pytest.raises(ValueError, match="Invalid task"):
        run(provider._chat_internal(  # noqa: SLF001 — direct internal exercise
            messages=messages,
            system_prompt="",
            config=_ai_config(),
            tools=None,
            task="not_a_real_task",
        ))

    # Critical: no network call was made.
    api.post.assert_not_called()


# ---------------------------------------------------------------------------
# 5. APIError subclasses propagate (no wrapping)
# ---------------------------------------------------------------------------

def test_chat_propagates_api_errors():
    """``RateLimitedError`` (and any APIError subclass) propagates verbatim.

    The T5 error-handler service owns the UX mapping; the provider must
    not catch and convert errors here.
    """
    provider, api, _auth = _make_provider()
    api.post = AsyncMock(side_effect=RateLimitedError(
        code="rate_limited",
        message="Rate limit exceeded.",
        status=429,
        details={"retry_after": 12},
    ))

    with pytest.raises(RateLimitedError) as exc_info:
        run(provider.chat(
            [{"role": "user", "content": "hi"}], "", _ai_config(),
        ))

    assert exc_info.value.code == "rate_limited"
    assert exc_info.value.status == 429


# ---------------------------------------------------------------------------
# 6. Streaming (T2): stream_chat over SSE
# ---------------------------------------------------------------------------
#
# We mock APIClient.stream_sse directly — the SSE consumer itself is
# exercised end-to-end in test_sse_stream.py. Here we verify only the
# provider-level contract: body construction, decorator behaviour, and
# the synthetic ``done`` terminator.


def _async_iter(items):
    """Wrap a list as an async iterator returned by ``stream_sse``."""
    async def _gen():
        for item in items:
            yield item
    return _gen()


def _drain_stream(provider, **kwargs):
    """Run an async-generator method to completion and collect events."""
    async def _run():
        out = []
        async for event in provider.stream_chat(
            kwargs.pop("messages", [{"role": "user", "content": "hi"}]),
            kwargs.pop("system_prompt", ""),
            kwargs.pop("config", _ai_config()),
            **kwargs,
        ):
            out.append(event)
        return out
    return run(_run())


def test_stream_chat_yields_token_then_usage():
    """Happy path: tokens + terminal usage + synthesised ``done``."""
    provider, api, _auth = _make_provider()
    server_events = [
        {"event": "token", "data": {"text": "Hello"}},
        {"event": "token", "data": {"text": " world"}},
        {
            "event": "usage",
            "data": {
                "model": "gemini-2-flash-002",
                "input_tokens": 10,
                "output_tokens": 2,
                "fallback_used": False,
            },
        },
    ]
    api.stream_sse = MagicMock(return_value=_async_iter(server_events))

    events = _drain_stream(provider)

    # Provider must pass through the server events untouched and append ``done``.
    assert len(events) == len(server_events) + 1
    assert events[:-1] == server_events
    assert events[-1] == {"event": "done", "data": {}}


def test_stream_chat_passes_conversation_id_in_body():
    """``conversation_id`` (when set) must reach the request body verbatim."""
    provider, api, _auth = _make_provider()
    api.stream_sse = MagicMock(return_value=_async_iter([]))

    _drain_stream(provider, conversation_id="conv-uuid-xyz")

    api.stream_sse.assert_called_once()
    args, kwargs = api.stream_sse.call_args
    assert args[0] == "/api/ai/chat"
    body = args[1]
    assert body["conversation_id"] == "conv-uuid-xyz"


def test_stream_chat_uses_stream_true_in_body():
    """``stream: true`` must be set on the streaming path (vs buffered)."""
    provider, api, _auth = _make_provider()
    api.stream_sse = MagicMock(return_value=_async_iter([]))

    _drain_stream(provider)

    body = api.stream_sse.call_args.args[1]
    assert body["stream"] is True
    assert body["task"] == "chat"
    assert body["allow_tools"] is True


def test_stream_chat_propagates_sse_stream_error():
    """``SSEStreamError`` from the SSE layer must surface to the caller.

    The provider does NOT catch / wrap stream errors — the T5 error
    handler downstream owns the UX mapping.
    """
    from servonaut.services.ai_sse import SSEStreamError

    provider, api, _auth = _make_provider()

    async def _failing_stream(*args, **kwargs):
        yield {"event": "token", "data": {"text": "Working"}}
        raise SSEStreamError(
            code="quota_exhausted",
            message="Out of tokens",
            details={"topup_url": "https://servonaut.dev/topup"},
        )

    api.stream_sse = MagicMock(side_effect=_failing_stream)

    async def _consume():
        out = []
        async for event in provider.stream_chat(
            [{"role": "user", "content": "hi"}], "", _ai_config(),
        ):
            out.append(event)
        return out

    with pytest.raises(SSEStreamError) as exc_info:
        run(_consume())

    assert exc_info.value.code == "quota_exhausted"
    assert exc_info.value.details["topup_url"].startswith("https://")


def test_stream_chat_synthesises_done_event_at_end():
    """After a clean stream-close, ``stream_chat`` yields ``{"event":"done"}``.

    This terminator lets the chat panel distinguish graceful end-of-turn
    from an exception-raising terminal event.
    """
    provider, api, _auth = _make_provider()
    api.stream_sse = MagicMock(return_value=_async_iter([
        {"event": "token", "data": {"text": "ok"}},
    ]))

    events = _drain_stream(provider)

    assert events[-1] == {"event": "done", "data": {}}
    # Exactly one ``done`` event — never duplicated.
    done_events = [e for e in events if e["event"] == "done"]
    assert len(done_events) == 1


# ---------------------------------------------------------------------------
# max_tool_rounds wiring (hosted agentic-loop cap).
# ---------------------------------------------------------------------------


def _make_provider_with_config(chat_max_tool_rounds):
    """Provider with a mocked config_manager exposing chat_max_tool_rounds."""
    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value=dict(_CANONICAL_RESPONSE))
    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)
    cfg = MagicMock()
    cfg.get.return_value = MagicMock(chat_max_tool_rounds=chat_max_tool_rounds)
    return ServonautProvider(api_client=api, auth_service=auth, config_manager=cfg), api


def test_chat_body_includes_max_tool_rounds_when_configured():
    provider, api = _make_provider_with_config(150)
    run(provider.chat([{"role": "user", "content": "hi"}], "system", _ai_config()))
    body = api.post.call_args.kwargs["json"]
    assert body["max_tool_rounds"] == 150


def test_chat_body_omits_max_tool_rounds_when_unset():
    provider, api = _make_provider_with_config(None)
    run(provider.chat([{"role": "user", "content": "hi"}], "system", _ai_config()))
    body = api.post.call_args.kwargs["json"]
    assert "max_tool_rounds" not in body


def test_chat_body_omits_max_tool_rounds_without_config_manager():
    """Construction sites that don't inject config keep the old wire shape."""
    provider, api, _ = _make_provider()
    run(provider.chat([{"role": "user", "content": "hi"}], "system", _ai_config()))
    body = api.post.call_args.kwargs["json"]
    assert "max_tool_rounds" not in body

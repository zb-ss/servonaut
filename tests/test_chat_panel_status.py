"""Chat panel status surfaces: the stats-bar tool note and error toasts.

- A bring-your-own provider chat runs tools at the chat guard level, so
  the stats bar must say which level (not that tools need Servonaut AI).
- A rate-limited turn is not retried, so the toast must say when to try
  again rather than promise a retry.

Same construction pattern as ``test_ai_provider_chain.py``: the panel is
built via ``__new__`` with a mocked ``app``; no Textual app is mounted.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.services.ai_sse import SSEStreamDead
from servonaut.services.api_client import RateLimitedError
from servonaut.services.chat_service import ChatService


def _make_panel(app: MagicMock, captured: list):
    """Minimal unmounted ChatPanel whose stats bar writes into *captured*."""
    from servonaut.widgets.chat_panel import ChatPanel

    # A per-call subclass carries the mocked ``app`` so the real class is
    # left untouched for other tests.
    class _Panel(ChatPanel):
        app = property(lambda _self: app)

    panel = _Panel.__new__(_Panel)
    panel._upstream_failures = []
    panel._session_provider_override = None
    panel._last_fallback_used = False
    panel._last_soft_capped = False
    panel._last_hard_capped = False
    panel._total_tokens = 0
    panel._total_cost = 0.0
    panel._model = "gpt-4o-mini"
    panel._session = None
    panel._recording = False
    panel._transcribing = False
    panel._speaking = False
    panel._conversation_state = "off"
    panel._spinner_frame = 0
    panel.query_one = lambda *a, **kw: SimpleNamespace(update=captured.append)
    panel._update_quota_footer = lambda: None
    panel._update_provider_indicator = lambda: None
    return panel


def _stats_text(*, provider: str, guard_level) -> str:
    app = MagicMock()
    app.chat_service = SimpleNamespace(tool_guard_level=guard_level)
    captured: list = []
    panel = _make_panel(app, captured)
    panel._session_provider_override = provider
    panel._update_stats()
    assert captured, "stats bar was not updated"
    return captured[-1]


# ---------------------------------------------------------------------------
# Stats-bar tool note
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "guard_level, label",
    [("readonly", "read-only"), ("standard", "standard"), ("dangerous", "dangerous")],
)
def test_byo_stats_bar_names_the_tool_guard_level(guard_level, label):
    text = _stats_text(provider="openai", guard_level=guard_level)
    assert "requires Servonaut AI" not in text
    assert f"[dim]Tools:[/dim] {label}" in text


def test_byo_stats_bar_says_tools_off_without_a_tool_executor():
    text = _stats_text(provider="anthropic", guard_level=None)
    assert "Tools off" in text
    assert "requires Servonaut AI" not in text


def test_servonaut_stats_bar_has_no_byo_tool_note():
    text = _stats_text(provider="servonaut", guard_level="readonly")
    assert "Tools:" not in text
    assert "Tools off" not in text


def _chat_service(*, ai_service, tool_executor) -> ChatService:
    service = ChatService.__new__(ChatService)
    service._ai_service = ai_service
    service._tool_executor = tool_executor
    return service


def test_chat_service_reports_its_tool_executor_guard_level():
    executor = SimpleNamespace(guard_level="readonly")
    service = _chat_service(ai_service=object(), tool_executor=executor)
    assert service.tool_guard_level == "readonly"


@pytest.mark.parametrize(
    "ai_service, tool_executor",
    [(object(), None), (None, SimpleNamespace(guard_level="standard"))],
)
def test_chat_service_reports_no_guard_level_when_tools_cannot_run(
    ai_service, tool_executor,
):
    service = _chat_service(ai_service=ai_service, tool_executor=tool_executor)
    assert service.tool_guard_level is None


def test_chat_tool_executor_exposes_its_guard_level():
    from servonaut.services.chat_tools import ChatToolExecutor

    tools = MagicMock()
    tools.config_manager.get.return_value.mcp.command_blocklist = []
    tools.config_manager.get.return_value.mcp.command_allowlist = []
    executor = ChatToolExecutor(tools=tools, guard_level="readonly")
    assert executor.guard_level == "readonly"


# ---------------------------------------------------------------------------
# Error toasts do not promise retries
# ---------------------------------------------------------------------------


def _error_panel():
    app = MagicMock()
    panel = _make_panel(app, [])
    panel._record_upstream_failure = MagicMock()
    panel._maybe_offer_fallback = MagicMock()
    panel._set_banner = MagicMock()
    return panel, app


def test_rate_limited_turn_says_when_to_try_again():
    panel, app = _error_panel()
    exc = RateLimitedError(
        code="rate_limited",
        message="Too many requests",
        status=429,
        response_headers={"retry-after": "12"},
    )

    panel._handle_stream_error(exc, accumulated="")

    app.notify.assert_called_once_with(
        "Rate limited — try again in 12 s.", severity="warning", markup=False,
    )


def test_lost_connection_banner_asks_the_user_to_resend():
    panel, _app = _error_panel()

    panel._handle_stream_error(SSEStreamDead("silence"), accumulated="")

    banner = panel._set_banner.call_args.args[0]
    assert "Retrying" not in banner
    assert "send your message again" in banner


def test_malformed_retry_after_cannot_crash_the_error_handler():
    panel, app = _error_panel()
    exc = RateLimitedError(
        code="rate_limited", message="slow down", status=429,
        details={"retry_after": float("inf")},
    )

    panel._handle_stream_error(exc, accumulated="")

    app.notify.assert_called_once_with(
        "Rate limited — wait a moment, then try again.",
        severity="warning", markup=False,
    )


# ---------------------------------------------------------------------------
# The tool call keeps the service's guard label as sent
# ---------------------------------------------------------------------------


def _tool_call_panel():
    from unittest.mock import AsyncMock

    app = MagicMock()
    bridge = MagicMock()
    bridge.handle_tool_call = AsyncMock(return_value=SimpleNamespace(skipped=False))
    bridge.post_tool_result = AsyncMock()
    app.ai_tool_bridge = bridge
    panel = _make_panel(app, [])
    panel._turn_tool_calls = 0
    panel._remote_conversation_id = "conv-1"
    return panel, bridge


@pytest.mark.parametrize("sent, expected", [(None, ""), ("ReadOnly", "ReadOnly")])
def test_streamed_tool_call_records_guard_label_as_sent(sent, expected):
    import asyncio

    panel, bridge = _tool_call_panel()
    data = {"tool_call_id": "tc-1", "tool": "list_instances", "args": {}}
    if sent is not None:
        data["guard_level"] = sent

    asyncio.run(panel._handle_streamed_tool_call(data))

    call = bridge.handle_tool_call.call_args.args[0]
    assert call.server_guard_level == expected

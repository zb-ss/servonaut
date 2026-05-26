"""Tests for PR5' tool_catalog SSE event handler in ServonautProvider.

Verifies that:
1. A ``tool_catalog`` SSE event is consumed (not forwarded to the caller).
2. An audit row is written (when _audit is wired) with reason
   ``tool_catalog_received`` and the correct fields.
3. Subsequent non-catalog events still yield to the caller.
4. _LOCAL_TOOL_HANDLERS dispatch state is NOT mutated (audit-only).
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator, Dict, Any
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from servonaut.services.ai_providers.servonaut_provider import ServonautProvider
from servonaut.services.ai_tool_bridge import _LOCAL_TOOL_HANDLERS


def run(coro):
    return asyncio.run(coro)


async def _fake_sse_stream(events: list) -> AsyncIterator[Dict[str, Any]]:
    """Async generator that yields the given event dicts."""
    for event in events:
        yield event


def _make_provider(audit=None) -> ServonautProvider:
    """Return a ServonautProvider with all external deps mocked."""
    api = MagicMock()
    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)
    provider = ServonautProvider(api_client=api, auth_service=auth)
    if audit is not None:
        provider._audit = audit
    return provider


# ---------------------------------------------------------------------------
# _handle_tool_catalog_event unit tests
# ---------------------------------------------------------------------------


class TestHandleToolCatalogEvent:
    def test_audit_log_written_with_correct_reason(self):
        """_handle_tool_catalog_event writes audit row with reason=tool_catalog_received."""
        audit = MagicMock()
        audit.log = MagicMock()
        provider = _make_provider(audit=audit)

        provider._handle_tool_catalog_event({
            "catalog_version": "2026-05-26.2",
            "surface": "chat",
            "tools": [
                {"name": "aws_list_regions"},
                {"name": "s3_list_buckets"},
            ],
        })

        audit.log.assert_called_once()
        call_args = audit.log.call_args
        # Positional arg[4] is the reason
        if len(call_args.args) > 4:
            reason = call_args.args[4]
        else:
            reason = call_args.kwargs.get("reason", "")
        assert reason == "tool_catalog_received"

    def test_audit_log_includes_catalog_version_and_count(self):
        """Audit row carries catalog_version and tool_count kwargs."""
        audit = MagicMock()
        audit.log = MagicMock()
        provider = _make_provider(audit=audit)

        provider._handle_tool_catalog_event({
            "catalog_version": "2026-05-26.2",
            "surface": "chat",
            "tools": [{"name": f"tool_{i}"} for i in range(10)],
        })

        call_kwargs = audit.log.call_args.kwargs
        assert call_kwargs.get("catalog_version") == "2026-05-26.2"
        assert call_kwargs.get("tool_count") == 10

    def test_tool_names_sample_limited_to_5(self):
        """tool_names_sample carries at most 5 names."""
        audit = MagicMock()
        audit.log = MagicMock()
        provider = _make_provider(audit=audit)

        provider._handle_tool_catalog_event({
            "catalog_version": "v-test",
            "surface": "chat",
            "tools": [{"name": f"tool_{i}"} for i in range(20)],
        })

        sample = audit.log.call_args.kwargs.get("tool_names_sample", [])
        assert len(sample) <= 5

    def test_no_audit_degrades_to_logger_info(self):
        """When _audit is absent, the handler logs via standard logger and does not raise."""
        provider = _make_provider(audit=None)
        # Remove _audit if somehow present
        if hasattr(provider, "_audit"):
            del provider._audit

        # Should not raise
        provider._handle_tool_catalog_event({
            "catalog_version": "v-test",
            "surface": "chat",
            "tools": [{"name": "aws_list_regions"}],
        })


# ---------------------------------------------------------------------------
# stream_chat integration: tool_catalog event consumed, not forwarded
# ---------------------------------------------------------------------------


class TestStreamChatToolCatalogConsumption:
    def test_tool_catalog_event_not_yielded_to_caller(self):
        """stream_chat absorbs tool_catalog events; they don't reach the caller."""
        provider = _make_provider()

        # Mock api_client.stream_sse to yield a tool_catalog then a token event
        sse_events = [
            {
                "event": "tool_catalog",
                "data": {
                    "catalog_version": "2026-05-26.2",
                    "surface": "chat",
                    "tools": [{"name": "aws_list_regions"}],
                },
            },
            {"event": "token", "data": {"text": "Hello"}},
        ]

        async def fake_stream(*args, **kwargs):
            for ev in sse_events:
                yield ev

        provider._api_client.stream_sse = fake_stream

        async def collect():
            events = []
            async for ev in provider.stream_chat(
                messages=[{"role": "user", "content": "hi"}],
                system_prompt="",
                config=MagicMock(),
            ):
                events.append(ev)
            return events

        yielded = run(collect())

        # tool_catalog must NOT be in yielded events
        yielded_types = [e.get("event") for e in yielded]
        assert "tool_catalog" not in yielded_types
        # token must be yielded
        assert "token" in yielded_types
        # done sentinel must be yielded
        assert "done" in yielded_types

    def test_dispatch_state_not_mutated(self):
        """tool_catalog SSE event does not modify _LOCAL_TOOL_HANDLERS."""
        provider = _make_provider()
        handler_before = dict(_LOCAL_TOOL_HANDLERS)

        sse_events = [
            {
                "event": "tool_catalog",
                "data": {
                    "catalog_version": "2026-05-26.2",
                    "surface": "chat",
                    "tools": [
                        {"name": "aws_list_regions"},
                        {"name": "new_future_tool"},
                    ],
                },
            },
        ]

        async def fake_stream(*args, **kwargs):
            for ev in sse_events:
                yield ev

        provider._api_client.stream_sse = fake_stream

        async def collect():
            async for _ in provider.stream_chat(
                messages=[{"role": "user", "content": "hi"}],
                system_prompt="",
                config=MagicMock(),
            ):
                pass

        run(collect())

        # _LOCAL_TOOL_HANDLERS must be identical to before
        assert dict(_LOCAL_TOOL_HANDLERS) == handler_before, (
            "tool_catalog SSE event must not mutate _LOCAL_TOOL_HANDLERS in PR5'"
        )

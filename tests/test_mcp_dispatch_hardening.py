"""The MCP tool dispatch must never let a handler crash the server loop.

Regression guard: an unhandled exception raised inside a tool handler used to
propagate out of the ``call_tool`` callback and tear down the stdio transport,
dropping the whole session (observed live: a transient failure in
``relay_status`` disconnected the server). ``_dispatch_tool`` now converts any
handler failure into a bounded error result while letting cooperative
cancellation propagate.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("mcp")

from servonaut.mcp.server import _dispatch_tool


def _run(coro):
    return asyncio.run(coro)


class TestDispatchHardening:
    def test_throwing_handler_returns_error_not_raised(self):
        # A handler that raises (e.g. a network blip in relay_status) must be
        # caught — the server loop, and every other in-flight call, survive.
        tools = SimpleNamespace(
            whoami=AsyncMock(side_effect=RuntimeError("backend unreachable")),
        )
        out = _run(_dispatch_tool(tools, "whoami", {}))
        assert len(out) == 1
        assert out[0].text.startswith("tool 'whoami' failed:")
        assert "backend unreachable" in out[0].text

    def test_error_text_is_bounded(self):
        tools = SimpleNamespace(whoami=AsyncMock(side_effect=RuntimeError("x" * 5000)))
        out = _run(_dispatch_tool(tools, "whoami", {}))
        # Message is truncated so a huge exception can't flood the transport.
        assert len(out[0].text) < 600

    def test_success_path_unchanged(self):
        tools = SimpleNamespace(whoami=AsyncMock(return_value="session ok"))
        out = _run(_dispatch_tool(tools, "whoami", {}))
        assert out[0].text == "session ok"

    def test_unknown_tool_reported(self):
        out = _run(_dispatch_tool(SimpleNamespace(), "not_a_real_tool_xyz", {}))
        assert out[0].text.startswith("Unknown tool:")

    def test_missing_handler_reported(self):
        # Name is in the schema registry but the tools object lacks the method.
        out = _run(_dispatch_tool(SimpleNamespace(), "whoami", {}))
        assert out[0].text.startswith("Tool handler not available:")

    def test_cancellation_propagates(self):
        # CancelledError is a BaseException, not Exception — cooperative
        # cancellation must NOT be swallowed by the crash guard.
        tools = SimpleNamespace(whoami=AsyncMock(side_effect=asyncio.CancelledError()))
        with pytest.raises(asyncio.CancelledError):
            _run(_dispatch_tool(tools, "whoami", {}))

    def test_arguments_forwarded(self):
        handler = AsyncMock(return_value="ok")
        tools = SimpleNamespace(whoami=handler)
        _run(_dispatch_tool(tools, "whoami", {"foo": 1, "bar": "x"}))
        handler.assert_awaited_once_with(foo=1, bar="x")

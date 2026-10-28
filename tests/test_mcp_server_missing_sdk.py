"""The MCP server must explain a missing SDK where the client can see it.

Regression: with the ``mcp`` package absent, ``servonaut --mcp`` wrote the
reason only to its log file and exited, so MCP clients showed nothing but
"connection closed". The message now goes to stderr as well.
"""
from __future__ import annotations

import asyncio
import sys

import pytest

from servonaut.mcp import server


@pytest.mark.parametrize(
    ("blocked_module", "start"),
    [
        ("mcp.server.stdio", lambda: asyncio.run(server.run_server())),
        ("mcp.server", server.create_mcp_server),
    ],
    ids=["run_server", "create_mcp_server"],
)
def test_missing_sdk_is_reported_on_stderr(monkeypatch, capsys, blocked_module, start):
    # A None entry in sys.modules makes the import raise ImportError,
    # whether or not the SDK is installed in the test environment.
    monkeypatch.setitem(sys.modules, blocked_module, None)

    with pytest.raises(SystemExit) as exit_info:
        start()

    assert exit_info.value.code == 1
    captured = capsys.readouterr()
    assert "MCP SDK not installed" in captured.err
    assert "servonaut[mcp]" in captured.err
    # stdout carries the protocol; nothing else may be written there.
    assert captured.out == ""

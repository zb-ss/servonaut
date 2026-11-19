"""The MCP transport leaves process streams available to its executable host."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

import anyio
import pytest

pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import LATEST_PROTOCOL_VERSION

from scripts.standalone_cli.smoke_artifact import isolated_child_environment

_SERVER_SCRIPT = """
import sys
from servonaut.main import main
main()
sys.stdout.flush()
sys.stderr.flush()
"""
_FIXED_INPUT_SCRIPT = """
import sys
class FixedInput:
    def __getattr__(self, name):
        if name == "reconfigure":
            raise AttributeError(name)
        return getattr(sys.__stdin__, name)
sys.stdin = FixedInput()
"""
_REFUSING_INPUT_SCRIPT = """
import io, sys
class FixedInput:
    def reconfigure(self, **kwargs):
        raise ERROR_TYPE("input cannot be reconfigured")
    def __getattr__(self, name):
        return getattr(sys.__stdin__, name)
sys.stdin = FixedInput()
"""


def _environment(tmp_path: Path) -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    environment = isolated_child_environment(tmp_path)
    environment.update(PYTHONPATH=str(root / "src"), PYTHONIOENCODING="utf-8:strict")
    return environment


@pytest.mark.asyncio
async def test_normal_mcp_shutdown_leaves_standard_streams_flushable(tmp_path: Path) -> None:
    # The frozen executable's bootloader flushes process streams after main
    # returns. Exercise that lifecycle without building an artifact per test.
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", _SERVER_SCRIPT, "--mcp"],
        cwd=str(tmp_path),
        env=_environment(tmp_path),
    )
    error_path = tmp_path / "mcp-stderr.log"
    with error_path.open("w", encoding="utf-8") as errors:
        # Bound a broken handshake/shutdown while retaining the real EOF path.
        with anyio.fail_after(15):
            async with stdio_client(parameters, errlog=errors) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()

    assert tools.tools
    assert error_path.read_text(encoding="utf-8") == ""


async def _response(process: asyncio.subprocess.Process, request_id: int) -> dict:
    while True:
        line = await process.stdout.readline()
        assert line, (await process.stderr.read()).decode("utf-8")
        message = json.loads(line)
        if message.get("id") == request_id:
            return message


async def _start_server(
    tmp_path: Path, reconfigurable: bool, refusal: str | None = None,
) -> asyncio.subprocess.Process:
    script = _SERVER_SCRIPT
    if refusal is not None:
        script = _REFUSING_INPUT_SCRIPT.replace("ERROR_TYPE", refusal) + script
    elif not reconfigurable:
        script = _FIXED_INPUT_SCRIPT + script
    return await asyncio.create_subprocess_exec(
        sys.executable, "-c", script, "--mcp", cwd=tmp_path, env=_environment(tmp_path),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        # The tools catalogue is larger than asyncio's default line buffer.
        limit=1024 * 1024,
    )


async def _exchange_bad_line(process: asyncio.subprocess.Process) -> dict:
    initialize = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {},
                   "clientInfo": {"name": "test-client", "version": "1"}},
    }
    process.stdin.write(json.dumps(initialize).encode() + b"\n")
    await process.stdin.drain()
    assert "result" in await _response(process, 1)
    process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    process.stdin.write(b"\xff\n")
    process.stdin.write(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    await process.stdin.drain()
    return await _response(process, 2)


async def _check_malformed_session(process: asyncio.subprocess.Process) -> None:
    try:
        with anyio.fail_after(15):
            response = await _exchange_bad_line(process)
            assert response["result"]["tools"]
            process.stdin.close()
            await process.wait()
            errors = (await process.stderr.read()).decode("utf-8")
            assert process.returncode == 0, errors
            assert "UnicodeDecodeError" not in errors
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


@pytest.mark.asyncio
@pytest.mark.parametrize("reconfigurable", [True, False])
async def test_invalid_utf8_does_not_end_the_mcp_session(
    tmp_path: Path, reconfigurable: bool,
) -> None:
    await _check_malformed_session(await _start_server(tmp_path, reconfigurable))


@pytest.mark.asyncio
@pytest.mark.parametrize("refusal", ["io.UnsupportedOperation", "ValueError", "OSError"])
async def test_stdin_reconfiguration_refusal_keeps_the_session_usable(
    tmp_path: Path, refusal: str,
) -> None:
    await _check_malformed_session(await _start_server(tmp_path, True, refusal))

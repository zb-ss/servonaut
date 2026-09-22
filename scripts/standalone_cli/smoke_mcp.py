"""Bounded MCP stdio checks for an extracted standalone executable."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import BinaryIO, NoReturn


class MCPSmokeError(RuntimeError):
    """Raised when the packaged MCP endpoint violates the smoke contract."""


@dataclass(frozen=True)
class MCPTimeouts:
    """Policy-owned limits for one MCP stdio session."""

    initialize_seconds: float
    request_seconds: float
    shutdown_seconds: float
    frame_max_bytes: int
    stderr_max_bytes: int


@dataclass(frozen=True)
class MCPCheck:
    """Public-safe summary of a successful MCP protocol check."""

    tool_count: int
    whoami_logged_out: bool
    stderr_bytes: int
    stderr_sha256: str


@dataclass
class _CaptureState:
    byte_count: int = 0
    exceeded: bool = False
    failure: BaseException | None = None


class _BoundedPipeCapture:
    """Drain child stderr without retaining its potentially sensitive content."""

    def __init__(self, limit: int) -> None:
        if type(limit) is not int or limit < 1:
            raise MCPSmokeError("MCP stderr limit is invalid")
        self._limit = limit
        self._digest = hashlib.sha256()
        self._state = _CaptureState()
        read_fd, write_fd = os.pipe()
        self._reader = os.fdopen(read_fd, "rb", buffering=0)
        self.writer: BinaryIO = os.fdopen(write_fd, "wb", buffering=0)
        self._thread = threading.Thread(target=self._drain, daemon=True)

    def __enter__(self) -> _BoundedPipeCapture:  # noqa: PYI034 - Python 3.10
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.writer.close()
        self._thread.join(timeout=5)
        self._reader.close()
        if self._thread.is_alive():
            raise MCPSmokeError("MCP stderr drain did not finish")
        if self._state.failure is not None:
            raise MCPSmokeError("MCP stderr could not be captured") from self._state.failure

    def _drain(self) -> None:
        try:
            while True:
                chunk = self._reader.read(65536)
                if not chunk:
                    return
                self._state.byte_count += len(chunk)
                self._digest.update(chunk)
                if self._state.byte_count > self._limit:
                    self._state.exceeded = True
        except OSError as error:  # pragma: no cover - OS pipe failure
            self._state.failure = error

    @property
    def byte_count(self) -> int:
        return self._state.byte_count

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()

    @property
    def exceeded(self) -> bool:
        return self._state.exceeded


def _fail(message: str) -> NoReturn:
    raise MCPSmokeError(message)


def _validate_command(
    command: Path,
    args: Sequence[str],
    environment: Mapping[str, str],
    working_directory: Path,
    expected_args: Sequence[str],
) -> None:
    if not command.is_absolute() or command.is_symlink() or not command.is_file():
        _fail("MCP command is not an absolute regular file")
    if not working_directory.is_absolute() or not working_directory.is_dir():
        _fail("MCP working directory is invalid")
    if not args or len(args) > 4 or any(
        not isinstance(value, str) or not value or "\x00" in value or len(value) > 256
        for value in args
    ):
        _fail("MCP arguments are invalid")
    if list(args) != list(expected_args):
        _fail("MCP arguments do not select the packaged server")
    if len(environment) > 64:
        _fail("MCP environment has too many entries")
    if len({name.casefold() for name in environment}) != len(environment):
        _fail("MCP environment has case-insensitive duplicate names")
    for name, value in environment.items():
        if (
            not isinstance(name, str)
            or not name
            or "=" in name
            or "\x00" in name
            or not isinstance(value, str)
            or "\x00" in value
            or len(name) > 128
            or len(value) > 4096
        ):
            _fail("MCP environment is invalid")


def _sdk_isolated_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Neutralize every environment name the pinned SDK implicitly inherits."""
    try:
        from mcp.client.stdio import get_default_environment
    except ImportError as error:  # pragma: no cover - packaging setup failure
        raise MCPSmokeError("MCP SDK is unavailable") from error

    defaults = get_default_environment()
    if not isinstance(defaults, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in defaults.items()
    ):
        _fail("MCP SDK default environment is invalid")
    explicit_by_case = {name.casefold(): (name, value) for name, value in environment.items()}
    isolated = {
        name: explicit_by_case.get(name.casefold(), (name, ""))[1] for name in defaults
    }
    default_cases = {name.casefold() for name in defaults}
    isolated.update(
        {
            name: value
            for name, value in environment.items()
            if name.casefold() not in default_cases
        }
    )
    return isolated


def _bounded_model_json(value: object, limit: int, label: str) -> bytes:
    try:
        if hasattr(value, "model_dump"):
            data = value.model_dump(mode="json")  # type: ignore[union-attr]
        else:
            data = value
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise MCPSmokeError(f"{label} could not be encoded") from error
    if len(encoded) > limit:
        _fail(f"{label} exceeds the response limit")
    return encoded


def _text_content(result: object) -> str:
    if getattr(result, "isError", False):
        _fail("MCP whoami returned an error")
    content = getattr(result, "content", None)
    if not isinstance(content, list) or len(content) != 1:
        _fail("MCP whoami returned an invalid content list")
    text = getattr(content[0], "text", None)
    if not isinstance(text, str):
        _fail("MCP whoami did not return text")
    return text


async def _run_session(
    command: Path,
    args: Sequence[str],
    environment: Mapping[str, str],
    working_directory: Path,
    timeouts: MCPTimeouts,
    errlog: BinaryIO,
) -> tuple[int, bool]:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as error:  # pragma: no cover - packaging setup failure
        raise MCPSmokeError("MCP SDK is unavailable") from error

    parameters = StdioServerParameters(
        command=str(command),
        args=list(args),
        env=_sdk_isolated_environment(environment),
        cwd=working_directory,
        encoding="utf-8",
        encoding_error_handler="strict",
    )
    request_timeout: timedelta | float
    try:
        import mcp

        mcp_version = getattr(mcp, "__version__", "")
        if mcp_version.startswith(("2.", "3.")):
            request_timeout = float(timeouts.request_seconds)
        else:
            request_timeout = timedelta(seconds=timeouts.request_seconds)
    except Exception:
        request_timeout = timedelta(seconds=timeouts.request_seconds)

    try:
        async with (
            stdio_client(parameters, errlog=errlog) as (reader, writer),
            ClientSession(
                reader,
                writer,
                read_timeout_seconds=request_timeout,
            ) as session,
        ):
            initialized = await asyncio.wait_for(
                session.initialize(), timeouts.initialize_seconds
            )
            _bounded_model_json(initialized, timeouts.frame_max_bytes, "MCP initialize")
            tools = await asyncio.wait_for(session.list_tools(), timeouts.request_seconds)
            _bounded_model_json(tools, timeouts.frame_max_bytes, "MCP tool list")
            names = [getattr(tool, "name", None) for tool in tools.tools]
            if not names or any(not isinstance(name, str) for name in names):
                _fail("MCP tool list is invalid")
            if len(names) != len(set(names)) or "whoami" not in names:
                _fail("MCP tool list is missing the unique whoami tool")
            whoami = await asyncio.wait_for(
                session.call_tool("whoami", {}), timeouts.request_seconds
            )
            _bounded_model_json(whoami, timeouts.frame_max_bytes, "MCP whoami")
            try:
                payload = json.loads(_text_content(whoami))
            except (json.JSONDecodeError, RecursionError) as error:
                raise MCPSmokeError("MCP whoami returned invalid JSON") from error
            if payload != {"logged_in": False}:
                _fail("MCP whoami did not report the isolated logged-out state")
            return len(names), True
    except (asyncio.TimeoutError, TimeoutError) as error:
        raise MCPSmokeError("MCP protocol timed out") from error
    except MCPSmokeError:
        raise
    except Exception as error:
        raise MCPSmokeError(f"MCP protocol failed: {type(error).__name__}: {error}") from error


def run_mcp_smoke(
    *,
    command: Path,
    args: Sequence[str],
    environment: Mapping[str, str],
    working_directory: Path,
    timeouts: MCPTimeouts,
    expected_args: Sequence[str] = ("--mcp",),
) -> MCPCheck:
    """Initialize the real MCP server and exercise its logged-out identity tool."""
    _validate_command(command, args, environment, working_directory, expected_args)
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
        for value in (
            timeouts.initialize_seconds,
            timeouts.request_seconds,
            timeouts.shutdown_seconds,
        )
    ):
        _fail("MCP timeout policy is invalid")
    if type(timeouts.frame_max_bytes) is not int or timeouts.frame_max_bytes < 1024:
        _fail("MCP frame limit is invalid")
    total_timeout = (
        timeouts.initialize_seconds
        + (2 * timeouts.request_seconds)
        + timeouts.shutdown_seconds
    )
    with _BoundedPipeCapture(timeouts.stderr_max_bytes) as capture:
        try:
            tool_count, logged_out = asyncio.run(
                asyncio.wait_for(
                    _run_session(
                        command,
                        args,
                        environment,
                        working_directory,
                        timeouts,
                        capture.writer,
                    ),
                    total_timeout,
                )
            )
        except (asyncio.TimeoutError, TimeoutError) as error:
            raise MCPSmokeError("MCP session did not shut down in time") from error
    if capture.exceeded:
        _fail("MCP stderr exceeds the output limit")
    return MCPCheck(tool_count, logged_out, capture.byte_count, capture.sha256)

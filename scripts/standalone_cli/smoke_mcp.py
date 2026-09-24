"""Bounded MCP stdio checks for an extracted standalone executable.

The smoke owns the server process and speaks newline-delimited JSON-RPC
itself, so every stdout line is validated, the frame limit applies before a
line is buffered, and the server's real exit status is part of the result.
"""

from __future__ import annotations

import hashlib
import json
import queue
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, NoReturn

from scripts.standalone_cli.bounded_command import (
    reap_process_tree,
    start_process_tree,
)

_JSONRPC_VERSION = "2.0"
_CLIENT_INFO = {"name": "servonaut-artifact-smoke", "version": "1"}
_READ_CHUNK_BYTES = 64 * 1024


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
    exit_code: int
    elapsed_ms: int
    stdout_bytes: int
    stdout_sha256: str


@dataclass(frozen=True)
class _ProtocolVersions:
    requested: str
    supported: frozenset[str]


@dataclass(frozen=True)
class _OutputEnd:
    failure: str | None


class _FrameError(Exception):
    """A server output line that is not one bounded JSON-RPC message."""


def _fail(message: str) -> NoReturn:
    raise MCPSmokeError(message)


class _StderrDigest:
    """Drain server stderr without retaining its potentially sensitive content."""

    def __init__(self, stream: IO[bytes], limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._digest = hashlib.sha256()
        self.byte_count = 0
        self.failed = False
        self.thread = threading.Thread(target=self._drain, daemon=True)

    def _drain(self) -> None:
        try:
            while chunk := self._stream.read(_READ_CHUNK_BYTES):
                self.byte_count += len(chunk)
                self._digest.update(chunk)
        except (OSError, ValueError):
            self.failed = True
        finally:
            _close_quietly(self._stream)

    @property
    def exceeded(self) -> bool:
        return self.byte_count > self._limit

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()


class _FrameReader:
    """Split server stdout into bounded JSON-RPC messages on a daemon thread."""

    def __init__(self, stream: IO[bytes], frame_limit: int) -> None:
        self._stream = stream
        self._frame_limit = frame_limit
        self._items: queue.Queue[dict[str, object] | _OutputEnd] = queue.Queue()
        self._digest = hashlib.sha256()
        self._end: _OutputEnd | None = None
        self.byte_count = 0
        self.thread = threading.Thread(target=self._read, daemon=True)

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()

    def next_message(self, deadline: float) -> dict[str, object]:
        """Return the next validated message or fail on timeout or bad output."""
        item = self._next_item(deadline, "MCP protocol timed out")
        if isinstance(item, _OutputEnd):
            _fail(item.failure or "MCP server closed its output early")
        return item

    def wait_for_end(self, deadline: float) -> None:
        """Accept only notifications until the server closes its output."""
        while True:
            item = self._next_item(deadline, "MCP server output did not close")
            if isinstance(item, _OutputEnd):
                if item.failure is not None:
                    _fail(item.failure)
                return
            if not _is_notification(item):
                _fail("MCP server sent an unexpected message")

    def _next_item(
        self, deadline: float, timeout_message: str
    ) -> dict[str, object] | _OutputEnd:
        if self._end is not None:
            return self._end
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail(timeout_message)
        try:
            item = self._items.get(timeout=remaining)
        except queue.Empty:
            _fail(timeout_message)
        if isinstance(item, _OutputEnd):
            self._end = item
        return item

    def _read(self) -> None:
        failure: str | None = None
        buffer = bytearray()
        try:
            while chunk := self._stream.read1(_READ_CHUNK_BYTES):
                self.byte_count += len(chunk)
                self._digest.update(chunk)
                buffer.extend(chunk)
                self._emit_complete_frames(buffer)
            if buffer:
                raise _FrameError("MCP server output ended inside a frame")
        except _FrameError as error:
            failure = str(error)
        except (OSError, ValueError):
            failure = "MCP server output could not be read"
        finally:
            _close_quietly(self._stream)
            self._items.put(_OutputEnd(failure))

    def _emit_complete_frames(self, buffer: bytearray) -> None:
        while (newline := buffer.find(b"\n")) >= 0:
            frame = bytes(buffer[:newline])
            del buffer[: newline + 1]
            self._items.put(_parse_frame(frame, self._frame_limit))
        if len(buffer) > self._frame_limit:
            raise _FrameError("MCP frame exceeds the frame limit")


class _Session:
    """Minimal JSON-RPC client over the owned process's stdio pipes."""

    def __init__(
        self, stdin: IO[bytes], reader: _FrameReader, deadline: float
    ) -> None:
        self._stdin = stdin
        self._reader = reader
        self._deadline = deadline

    def request(
        self,
        request_id: int,
        method: str,
        params: Mapping[str, object],
        timeout_seconds: float,
        label: str,
    ) -> dict[str, object]:
        self._send(
            {
                "jsonrpc": _JSONRPC_VERSION,
                "id": request_id,
                "method": method,
                "params": dict(params),
            }
        )
        deadline = min(self._deadline, time.monotonic() + timeout_seconds)
        while True:
            message = self._reader.next_message(deadline)
            if _is_notification(message):
                continue
            if "method" in message:
                _fail("MCP server sent an unexpected request")
            response_id = message.get("id")
            if type(response_id) is not int or response_id != request_id:
                _fail("MCP server answered an unknown request")
            if "error" in message:
                _fail(f"{label} returned an error")
            result = message.get("result")
            if not isinstance(result, dict):
                _fail(f"{label} returned an invalid result")
            return result

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": _JSONRPC_VERSION, "method": method})

    def _send(self, message: Mapping[str, object]) -> None:
        data = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self._stdin.write(data)
            self._stdin.flush()
        except (OSError, ValueError) as error:
            raise MCPSmokeError("MCP server stopped reading its input") from error


def _close_quietly(stream: IO[bytes] | None) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except (OSError, ValueError):
        return


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _FrameError("MCP server wrote a non-JSON-RPC line")
        result[key] = value
    return result


def _parse_frame(frame: bytes, limit: int) -> dict[str, object]:
    if len(frame) > limit:
        raise _FrameError("MCP frame exceeds the frame limit")
    try:
        message = json.loads(frame.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise _FrameError("MCP server wrote a non-JSON-RPC line") from error
    if not _is_jsonrpc_message(message):
        raise _FrameError("MCP server wrote a non-JSON-RPC line")
    return message


def _is_jsonrpc_message(message: object) -> bool:
    if not isinstance(message, dict) or message.get("jsonrpc") != _JSONRPC_VERSION:
        return False
    if "method" in message:
        return isinstance(message["method"], str) and (
            "id" not in message or _valid_request_id(message["id"])
        )
    return (
        "id" in message
        and _valid_request_id(message["id"])
        and ("result" in message) != ("error" in message)
    )


def _valid_request_id(value: object) -> bool:
    return type(value) in {int, str}


def _is_notification(message: Mapping[str, object]) -> bool:
    return "method" in message and "id" not in message


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


def _validate_timeouts(timeouts: MCPTimeouts) -> None:
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
    if type(timeouts.stderr_max_bytes) is not int or timeouts.stderr_max_bytes < 1:
        _fail("MCP stderr limit is invalid")


def _protocol_versions() -> _ProtocolVersions:
    """Negotiate with the protocol revisions of the pinned harness SDK."""
    try:
        from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
        from mcp.types import LATEST_PROTOCOL_VERSION
    except ImportError as error:  # pragma: no cover - packaging setup failure
        raise MCPSmokeError("MCP SDK is unavailable") from error
    return _ProtocolVersions(
        LATEST_PROTOCOL_VERSION, frozenset(SUPPORTED_PROTOCOL_VERSIONS)
    )


def _tool_names(result: Mapping[str, object]) -> list[str]:
    tools = result.get("tools")
    if not isinstance(tools, list) or not tools:
        _fail("MCP tool list is invalid")
    names = [tool.get("name") if isinstance(tool, dict) else None for tool in tools]
    if any(not isinstance(name, str) for name in names):
        _fail("MCP tool list is invalid")
    if len(names) != len(set(names)) or "whoami" not in names:
        _fail("MCP tool list is missing the unique whoami tool")
    return names  # type: ignore[return-value]


def _require_logged_out(result: Mapping[str, object]) -> None:
    if result.get("isError", False) is not False:
        _fail("MCP whoami returned an error")
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1:
        _fail("MCP whoami returned an invalid content list")
    item = content[0]
    if (
        not isinstance(item, dict)
        or item.get("type") != "text"
        or not isinstance(item.get("text"), str)
    ):
        _fail("MCP whoami did not return text")
    try:
        payload = json.loads(item["text"])
    except (json.JSONDecodeError, RecursionError) as error:
        raise MCPSmokeError("MCP whoami returned invalid JSON") from error
    if payload != {"logged_in": False}:
        _fail("MCP whoami did not report the isolated logged-out state")


def _exercise_server(
    session: _Session, timeouts: MCPTimeouts, versions: _ProtocolVersions
) -> int:
    initialized = session.request(
        1,
        "initialize",
        {
            "protocolVersion": versions.requested,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        },
        timeouts.initialize_seconds,
        "MCP initialize",
    )
    if initialized.get("protocolVersion") not in versions.supported:
        _fail("MCP server negotiated an unsupported protocol version")
    session.notify("notifications/initialized")
    tools = session.request(
        2, "tools/list", {}, timeouts.request_seconds, "MCP tool list"
    )
    tool_count = len(_tool_names(tools))
    whoami = session.request(
        3,
        "tools/call",
        {"name": "whoami", "arguments": {}},
        timeouts.request_seconds,
        "MCP whoami",
    )
    _require_logged_out(whoami)
    return tool_count


def _shut_down(
    process: subprocess.Popen, reader: _FrameReader, shutdown_seconds: float
) -> int:
    """Close stdin like a finished client, then require a clean, prompt exit."""
    deadline = time.monotonic() + shutdown_seconds
    _close_quietly(process.stdin)
    try:
        exit_code = process.wait(timeout=shutdown_seconds)
    except subprocess.TimeoutExpired as error:
        raise MCPSmokeError("MCP server did not shut down in time") from error
    reader.wait_for_end(deadline)
    return exit_code


def _join_threads(threads: Sequence[threading.Thread], deadline: float) -> bool:
    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        thread.join(remaining)
    return not any(thread.is_alive() for thread in threads)


def run_mcp_smoke(
    *,
    command: Path,
    args: Sequence[str],
    environment: Mapping[str, str],
    working_directory: Path,
    timeouts: MCPTimeouts,
    expected_args: Sequence[str] = ("--mcp",),
) -> MCPCheck:
    """Initialize the real MCP server and exercise its logged-out identity tool.

    The child receives exactly ``environment``. A stdout line that is not one
    bounded JSON-RPC message, stderr over its limit, or a non-zero exit after
    stdin closes fails the check.
    """
    _validate_command(command, args, environment, working_directory, expected_args)
    _validate_timeouts(timeouts)
    versions = _protocol_versions()
    started = time.monotonic()
    deadline = started + (
        timeouts.initialize_seconds
        + (2 * timeouts.request_seconds)
        + timeouts.shutdown_seconds
    )
    try:
        process = start_process_tree(
            [str(command), *args],
            environment=environment,
            working_directory=working_directory,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise MCPSmokeError("MCP server could not be started") from error
    reader = _FrameReader(process.stdout, timeouts.frame_max_bytes)
    stderr = _StderrDigest(process.stderr, timeouts.stderr_max_bytes)
    try:
        reader.thread.start()
        stderr.thread.start()
        session = _Session(process.stdin, reader, deadline)
        tool_count = _exercise_server(session, timeouts, versions)
        exit_code = _shut_down(process, reader, timeouts.shutdown_seconds)
    finally:
        reaped = reap_process_tree(process)
        settled = _join_threads(
            (reader.thread, stderr.thread),
            time.monotonic() + timeouts.shutdown_seconds,
        )
    if not reaped or not settled:
        _fail("MCP server cleanup did not complete")
    if stderr.failed:
        _fail("MCP stderr could not be captured")
    if stderr.exceeded:
        _fail("MCP stderr exceeds the output limit")
    if exit_code != 0:
        _fail("MCP server exited with a non-zero status")
    return MCPCheck(
        tool_count=tool_count,
        whoami_logged_out=True,
        stderr_bytes=stderr.byte_count,
        stderr_sha256=stderr.sha256,
        exit_code=exit_code,
        elapsed_ms=round((time.monotonic() - started) * 1000),
        stdout_bytes=reader.byte_count,
        stdout_sha256=reader.sha256,
    )

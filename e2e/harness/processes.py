"""Run Servonaut as real child processes: CLI commands and the MCP server.

Every child gets an explicit environment from ``bootstrap.build_env`` (never
the test process's own) and a bounded timeout, and must report its guard as
armed (see ``child_site/sitecustomize.py``); a child that never armed is a
failure, because it ran unguarded. Output is kept for the failure artifacts.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Mapping, Optional, Sequence

from e2e.harness.bootstrap import load_guard

DEFAULT_TIMEOUT_SECONDS = 60.0


class UnguardedChildError(AssertionError):
    """A Python child finished without arming the e2e guard."""


@dataclass(frozen=True)
class CliResult:
    """Outcome of one CLI invocation."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float

    def describe(self) -> str:
        return (
            f"$ {' '.join(self.argv)}\n[exit {self.returncode} after {self.duration:.1f}s]\n"
            f"--- stdout ---\n{self.stdout}\n--- stderr ---\n{self.stderr}\n"
        )


class ChildLog:
    """Collects the output of every child a journey runs (for artifacts)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, text: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")


def armed_records(armed_log: Path) -> list[dict]:
    """Children that reported an armed guard."""
    return load_guard().read_log(armed_log)


def require_armed(armed_log: Path, *, pid: Optional[int] = None, marker: str = "") -> None:
    """Fail unless a child with *pid* (or with *marker* in its command) armed."""
    for record in armed_records(armed_log):
        if pid is not None and record.get("pid") == pid:
            return
        if marker and marker in record.get("cmdline", []):
            return
    raise UnguardedChildError(
        f"a child process (pid={pid}, marker={marker!r}) never armed the e2e guard"
    )


def run_cli(
    command: Sequence[str],
    *args: str,
    env: Mapping[str, str],
    cwd: Path,
    armed_log: Path,
    stdin: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    log: Optional[ChildLog] = None,
) -> CliResult:
    """Run ``servonaut <args>`` to completion and capture its output."""
    argv = [*command, *args]
    started = time.monotonic()
    with subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(env),
        cwd=str(cwd),
    ) as process:
        try:
            stdout, stderr = process.communicate(input=stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            raise
    result = CliResult(
        argv=argv,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration=time.monotonic() - started,
    )
    if log is not None:
        log.append(result.describe())
    require_armed(armed_log, pid=process.pid)
    return result


class McpSession:
    """A live MCP client session with a ``servonaut --mcp`` child."""

    def __init__(self, session: Any, initialize_result: Any, stderr_path: Path) -> None:
        self.session = session
        self.initialize_result = initialize_result
        self.stderr_path = stderr_path

    async def tool_names(self) -> list[str]:
        result = await self.session.list_tools()
        return [tool.name for tool in result.tools]

    async def tools(self) -> list[Any]:
        return list((await self.session.list_tools()).tools)

    async def call(
        self, name: str, arguments: Optional[dict] = None, *, timeout: float = 30.0
    ) -> str:
        """Call a tool and return its text content."""
        result = await self.session.call_tool(
            name, arguments or {}, read_timeout_seconds=timedelta(seconds=timeout)
        )
        parts = [getattr(item, "text", "") for item in result.content]
        return "\n".join(parts)


@asynccontextmanager
async def mcp_session(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    stderr_path: Path,
    armed_log: Path,
) -> AsyncIterator[McpSession]:
    """Start ``servonaut --mcp`` over stdio and complete the MCP handshake."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=command[0],
        args=[*command[1:], "--mcp"],
        env=dict(env),
        cwd=str(cwd),
    )
    before = len(armed_records(armed_log))
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with stderr_path.open("w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                initialize_result = await session.initialize()
                yield McpSession(session, initialize_result, stderr_path)
    started = [r for r in armed_records(armed_log)[before:] if "--mcp" in r.get("cmdline", [])]
    if not started:
        raise UnguardedChildError("the MCP server process never armed the e2e guard")


def _belongs_to_sandbox(pid: int, sandbox_root: Path) -> bool:
    """True when the process's environment points into *sandbox_root*."""
    try:
        environ = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return False
    return os.fsencode(str(sandbox_root)) in environ


def stop_pid_file(path: Path, *, sandbox_root: Path, timeout: float = 5.0) -> str:
    """Stop the process recorded in *path* if it is one of the sandbox's own.

    A PID file can outlive its process, and the number can be reused by an
    unrelated program, so nothing is signalled unless the process's
    environment points into *sandbox_root*. Returns what happened.
    """
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return "no pid file"
    if not _belongs_to_sandbox(pid, sandbox_root):
        return f"skipped pid {pid}: not running, or not a sandbox process"
    deadline = time.monotonic() + timeout
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            return f"pid {pid} already gone"
        while time.monotonic() < deadline:
            if not _belongs_to_sandbox(pid, sandbox_root):
                return f"stopped pid {pid}"
            time.sleep(0.05)
        deadline = time.monotonic() + timeout
    return f"pid {pid} did not stop"

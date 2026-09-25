"""Run Servonaut as real child processes: CLI commands, the MCP server and
the relay listener.

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
    """A live MCP client session with a ``servonaut --mcp`` child.

    ``protocol_errors`` collects every line the server wrote to stdout that
    was not a valid JSON-RPC message: stdout is the protocol channel, so any
    stray output there corrupts it.
    """

    def __init__(
        self,
        session: Any,
        initialize_result: Any,
        stderr_path: Path,
        protocol_errors: Optional[list[Exception]] = None,
    ) -> None:
        self.session = session
        self.initialize_result = initialize_result
        self.stderr_path = stderr_path
        self.protocol_errors: list[Exception] = (
            protocol_errors if protocol_errors is not None else []
        )

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
    protocol_errors: list[Exception] = []

    async def on_message(message: Any) -> None:
        # The stdio client hands over unparseable stdout lines as exceptions.
        if isinstance(message, Exception):
            protocol_errors.append(message)

    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with stderr_path.open("w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
            async with ClientSession(
                read_stream, write_stream, message_handler=on_message
            ) as session:
                initialize_result = await session.initialize()
                yield McpSession(session, initialize_result, stderr_path, protocol_errors)
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
    return stop_sandbox_pid(pid, sandbox_root=sandbox_root, timeout=timeout)


def stop_sandbox_pid(pid: int, *, sandbox_root: Path, timeout: float = 5.0) -> str:
    """SIGTERM, then SIGKILL, *pid*, but only if it is a sandbox process.

    Never signals this process or its parent, whatever their environment.
    """
    if pid in (os.getpid(), os.getppid()) or pid <= 1:
        return f"skipped pid {pid}: the test process itself"
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


# ---------------------------------------------------------------------------
# Relay listener
# ---------------------------------------------------------------------------


class RelayProcess:
    """``servonaut connect`` in one sandbox home.

    :meth:`start` runs the listener in the foreground as a child this object
    owns; :meth:`run` runs a one-shot form (``--bg``, ``--status``,
    ``--stop``, ``--reconnect``, ``--force-bg``) to completion. :meth:`close`
    (also the context-manager exit) guarantees cleanup: the foreground child,
    then any background listener the home recorded in its PID file or relay
    lock. Every PID is checked to belong to the sandbox before it is
    signalled, and the test process itself is never signalled.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        home: Path,
        env: Mapping[str, str],
        cwd: Path,
        sandbox_root: Path,
        armed_log: Path,
        output_path: Path,
        log: Optional[ChildLog] = None,
    ) -> None:
        self.command = list(command)
        self.home = home
        self.env = {**env, "PYTHONUNBUFFERED": "1"}  # output reaches the file at once
        self.cwd = cwd
        self.sandbox_root = sandbox_root
        self.armed_log = armed_log
        self.output_path = output_path
        self.log = log
        self._process: Optional[subprocess.Popen[bytes]] = None
        self._argv: list[str] = []

    # -- where the listener keeps its state ------------------------------

    @property
    def data_dir(self) -> Path:
        return self.home / ".servonaut"

    @property
    def pid_file(self) -> Path:
        return self.data_dir / "relay.pid"

    @property
    def lock_file(self) -> Path:
        return self.data_dir / "relay.lock"

    def background_pid(self) -> Optional[int]:
        """The PID ``connect --bg`` recorded, if any."""
        try:
            return int(self.pid_file.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None

    def lock_owner(self) -> Optional[dict]:
        """``{"pid", "mode"}`` of the listener holding the relay lock, or None.

        Uses the application's own probe, which trusts the recorded owner
        only while the operating-system lock is actually held.
        """
        from servonaut.services.relay_lock import active_owner

        owner = active_owner(self.lock_file)
        if owner is None:
            return None
        return {"pid": owner.pid, "mode": owner.mode}

    def armed(self, pid: Optional[int]) -> bool:
        """True once the process *pid* reported its guard as armed."""
        return pid is not None and any(r.get("pid") == pid for r in armed_records(self.armed_log))

    # -- foreground listener ---------------------------------------------

    @property
    def pid(self) -> Optional[int]:
        return self._process.pid if self._process is not None else None

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def returncode(self) -> Optional[int]:
        return self._process.poll() if self._process is not None else None

    def start(self, *args: str, timeout: float = 15.0) -> "RelayProcess":
        """Start ``connect`` in the foreground and wait until its guard is armed."""
        if self._process is not None:
            raise RuntimeError("this relay process was already started")
        self._argv = [*self.command, "connect", *args]
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("wb") as output:
            self._process = subprocess.Popen(
                self._argv,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                env=self.env,
                cwd=str(self.cwd),
                start_new_session=True,
            )
        deadline = time.monotonic() + timeout
        while not self.armed(self._process.pid):
            if self._process.poll() is not None or time.monotonic() >= deadline:
                self.close()
                raise UnguardedChildError(
                    f"the relay listener never armed the e2e guard:\n{self.output()}"
                )
            time.sleep(0.02)
        return self

    def output(self) -> str:
        try:
            return self.output_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def interrupt(self, timeout: float = 10.0) -> Optional[int]:
        """Press Ctrl+C on the foreground listener; return its exit code."""
        return self._stop_foreground(signal.SIGINT, timeout)

    def _stop_foreground(self, first: int, timeout: float) -> Optional[int]:
        process = self._process
        if process is None or process.poll() is not None:
            return process.poll() if process is not None else None
        # The child is ours and not yet reaped, so its PID cannot have been
        # reused; the sandbox check keeps this path identical to the others.
        if not _belongs_to_sandbox(process.pid, self.sandbox_root):
            return None
        for sig in (first, signal.SIGTERM, signal.SIGKILL):
            try:
                process.send_signal(sig)
            except ProcessLookupError:
                break
            try:
                return process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                continue
        return process.poll()

    # -- one-shot forms ----------------------------------------------------

    def run(self, *args: str, timeout: float = 30.0) -> CliResult:
        """Run ``connect <args>`` to completion (``--bg``, ``--status`` ...)."""
        return run_cli(
            self.command,
            "connect",
            *args,
            env=self.env,
            cwd=self.cwd,
            armed_log=self.armed_log,
            timeout=timeout,
            log=self.log,
        )

    # -- cleanup -------------------------------------------------------------

    def close(self) -> list[str]:
        """Stop everything this home's relay may have left running."""
        notes = []
        if self._process is not None:
            code = self._stop_foreground(signal.SIGINT, 5.0)
            notes.append(f"foreground pid {self._process.pid}: exit {code}")
            if self.log is not None:
                self.log.append(
                    f"$ {' '.join(self._argv)}\n[exit {code}]\n--- output ---\n{self.output()}"
                )
        notes.append(stop_pid_file(self.pid_file, sandbox_root=self.sandbox_root))
        owner = self.lock_owner() or {}
        if isinstance(owner.get("pid"), int) and owner.get("mode") == "bg":
            notes.append(stop_sandbox_pid(owner["pid"], sandbox_root=self.sandbox_root))
        return notes

    def __enter__(self) -> "RelayProcess":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

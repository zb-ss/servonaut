"""``servonaut connect`` as a child process, with guaranteed cleanup.

:class:`RelayProcess` runs the relay listener in one sandbox home, in the
foreground or through its one-shot forms, and stops everything that home's
relay may have left running. :func:`stop_journey_listeners` is the backstop
a journey's teardown runs: it stops every relay listener the journey's
children reported, whoever started it.
"""

from __future__ import annotations

import signal
import subprocess
import time
from pathlib import Path
from typing import Mapping, Optional, Sequence

from e2e.harness.processes import (
    ChildLog,
    CliResult,
    UnguardedChildError,
    belongs_to_sandbox,
    armed_records,
    run_cli,
    stop_pid_file,
    stop_sandbox_pid,
)


def _is_listener(cmdline: Sequence[str]) -> bool:
    """True for a ``servonaut connect`` process (the one-shot forms included)."""
    return "servonaut.main" in cmdline and "connect" in cmdline


def stop_journey_listeners(armed_log: Path, sandbox_root: Path) -> list[str]:
    """Stop every relay listener in *armed_log* that is still a sandbox process.

    Catches listeners no fixture knows about: one that ``--reconnect`` or
    ``--force-bg`` started and failed to stop, or one an MCP tool started.
    Each PID is checked to belong to *sandbox_root* before it is signalled.
    """
    notes = []
    for record in armed_records(armed_log):
        pid = record.get("pid")
        if isinstance(pid, int) and _is_listener(record.get("cmdline", [])):
            if belongs_to_sandbox(pid, sandbox_root):
                notes.append(stop_sandbox_pid(pid, sandbox_root=sandbox_root))
    return notes


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
        if not belongs_to_sandbox(process.pid, self.sandbox_root):
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

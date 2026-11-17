"""Own the real OpenSSH agents launched by the guarded test tools.

Setgid ssh-agent hides /proc/<pid>/exe and environ on Linux. Record each
launch instead, and validate its uid, start time and exact command before
shutdown. A PID from a different run, or a reused PID, is never signalled.
This module is also imported directly by the standalone agent shim.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

LEDGER_NAME = "ssh-agents.jsonl"
STOP_TIMEOUT_SECONDS = 5.0
POLL_SECONDS = 0.02
_PS_DIRS = "/usr/bin:/bin:/usr/sbin:/sbin"


def _ps(pid: int, *fields: str) -> str:
    program = shutil.which("ps", path=_PS_DIRS)
    if program is None:
        return ""
    guard = sys.modules.get("_servonaut_e2e_netguard")
    with guard.suspended() if guard is not None else contextlib.nullcontext():
        result = subprocess.run(
            [program, *(f"-o{field}=" for field in fields), "-p", str(pid)],
            env={"PATH": _PS_DIRS, "LC_ALL": "C"}, capture_output=True,
            text=True, timeout=10, check=False,
        )
    return result.stdout.strip() if result.returncode == 0 else ""


def process_identity(pid: int, executable: str, socket: str) -> str | None:
    """Return the birth identity of this exact owned agent, including setgid ones."""
    if pid <= 1 or pid in (os.getpid(), os.getppid()):
        return None
    expected = [executable, "-a", socket, "-s"]
    try:
        if Path("/proc/self").exists():
            proc = Path(f"/proc/{pid}")
            fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
            argv = [os.fsdecode(arg) for arg in (proc / "cmdline").read_bytes().split(b"\0") if arg]
            if proc.stat().st_uid != os.getuid() or fields[0] in ("Z", "X") or argv != expected:
                return None
            return fields[19]
        details = _ps(pid, "uid", "stat", "lstart").split(None, 2)
        if len(details) != 3 or int(details[0]) != os.getuid() or details[1][0] in ("Z", "X"):
            return None
        return details[2] if _ps(pid, "command") == " ".join(expected) else None
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None


def records(root: Path, *, shim_dir: Path | None = None) -> list[dict[str, Any]]:
    try:
        lines = (root / LEDGER_NAME).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    found = []
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue  # A truncated last write cannot grant ownership.
        if isinstance(record, dict) and (shim_dir is None or record.get("shim_dir") == str(shim_dir)):
            found.append(record)
    return found


def record_agent(root: Path, shim_dir: Path, pid: int, executable: str, socket: str) -> None:
    started = process_identity(pid, executable, socket)
    if started is None:
        raise RuntimeError("could not establish the launched SSH agent's ownership")
    record = {"pid": pid, "executable": executable, "socket": socket,
              "started": started, "shim_dir": str(shim_dir)}
    with (root / LEDGER_NAME).open("a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.write(json.dumps(record) + "\n")
        handle.flush()


def owns_agent(root: Path, pid: int, executable: str, socket: str) -> bool:
    identity = process_identity(pid, executable, socket)
    return identity is not None and any(
        record.get("pid") == pid and record.get("executable") == executable
        and record.get("socket") == socket and record.get("started") == identity
        for record in records(root)
    )


def _stop_record(record: dict[str, Any]) -> None:
    pid, executable, socket = (record.get(key) for key in ("pid", "executable", "socket"))
    if not isinstance(pid, int) or pid <= 1 or not isinstance(executable, str) or not isinstance(socket, str):
        return
    descriptor = None
    try:
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            descriptor = os.pidfd_open(pid)
        for signum in (signal.SIGTERM, signal.SIGKILL):
            if process_identity(pid, executable, socket) != record.get("started") or not record.get("started"):
                return
            if descriptor is None:
                os.kill(pid, signum)
            else:
                signal.pidfd_send_signal(descriptor, signum)
            deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if process_identity(pid, executable, socket) != record["started"]:
                    return
                time.sleep(POLL_SECONDS)
        raise RuntimeError("the owned SSH agent did not stop")
    except ProcessLookupError:
        return
    finally:
        if descriptor is not None:
            os.close(descriptor)


def stop_owned_agents(root: Path, *, shim_dir: Path | None = None) -> None:
    """Stop only agents whose launch and current process identity agree."""
    for record in records(root, shim_dir=shim_dir):
        _stop_record(record)

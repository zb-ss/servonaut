"""Scripted fake tools for the suite's PATH.

A :class:`ShimSet` is a directory holding one small script per tool. The
directory is the *only* entry on ``PATH`` in the test process and in every
child, so the application can never find the host's real ``ssh``, ``scp``,
``ssh-agent`` or terminal emulator. Every call is recorded; answers come from
rules a test adds with :meth:`ShimSet.when`::

    shims.when("ssh", r"uptime", stdout=" 10:00:00 up 3 days\\n")
    ...
    assert "uptime" in shims.calls("ssh")[-1].joined
"""

from __future__ import annotations

import fcntl
import json
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from e2e.harness.bootstrap import HARNESS_DIR

TERMINAL = "xterm"
TOOLS = ("ssh", "scp", "ssh-add", "ssh-agent", "ssh-keygen", TERMINAL, "browser", "editor")

# Answers used when no test rule matches. ``ssh`` and ``scp`` have none: they
# exit 255, as if the host refused the connection, so an unscripted call looks
# like an unreachable server rather than a silent success.
_DEFAULT_RULES: tuple[dict[str, Any], ...] = (
    {
        "name": "terminal-runs-command",
        "tool": TERMINAL,
        "match": "",
        "action": "run_terminal_command",
    },
    {
        "name": "agent-not-running",
        "tool": "ssh-add",
        "match": "",
        "stderr": "Could not open a connection to your authentication agent.\n",
        "rc": 2,
    },
    {
        "name": "agent-start-refused",
        "tool": "ssh-agent",
        "match": "",
        "stderr": "e2e: starting an agent is disabled in tests\n",
        "rc": 1,
    },
    {"name": "browser-records-url", "tool": "browser", "match": "", "rc": 0},
    {"name": "editor-noop", "tool": "editor", "match": "", "rc": 0},
)


@dataclass(frozen=True)
class ShimCall:
    """One recorded invocation of a fake tool."""

    tool: str
    argv: list[str]
    cwd: str
    rule: Optional[str]
    stdin: Optional[str] = None

    @property
    def joined(self) -> str:
        return " ".join(self.argv)


@dataclass
class ShimSet:
    """A directory of fake tools plus the rules that script their answers."""

    directory: Path
    _rules: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        runner = HARNESS_DIR / "shim_runner.py"
        python = shlex.quote(sys.executable)
        for tool in TOOLS:
            # -B: isolated mode ignores PYTHONDONTWRITEBYTECODE, and the runner
            # is unguarded, so it would compile the standard library into the
            # toolchain unnoticed.
            self._write_script(
                tool,
                f"exec {python} -I -B {shlex.quote(str(runner))} "
                f"{shlex.quote(str(self.directory))} {shlex.quote(tool)} \"$@\"\n",
            )
        # Python itself is the one real program reachable by name.
        for name in ("python", "python3"):
            self._write_script(name, f"exec {python} \"$@\"\n")
        self._save()

    def _write_script(self, name: str, body: str) -> None:
        path = self.directory / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)

    @property
    def log_path(self) -> Path:
        return self.directory / "argv.jsonl"

    def path_of(self, tool: str) -> Path:
        return self.directory / tool

    def when(
        self,
        tool: str,
        match: str = "",
        *,
        stdout: str = "",
        stderr: str = "",
        rc: int = 0,
        delay: float = 0.0,
        capture_stdin: bool = False,
        name: Optional[str] = None,
    ) -> None:
        """Answer calls to *tool* whose joined argv matches *match* (a regex).

        Rules are tried in the order they were added; the first match wins,
        and the built-in defaults come last.
        """
        self._rules.append(
            {
                "name": name or f"{tool}:{match}",
                "tool": tool,
                "match": match,
                "stdout": stdout,
                "stderr": stderr,
                "rc": rc,
                "delay": delay,
                "capture_stdin": capture_stdin,
            }
        )
        self._save()

    def _save(self) -> None:
        payload = {"rules": [*self._rules, *_DEFAULT_RULES]}
        tmp = self.directory / ".scenario.json.tmp"
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.directory / "scenario.json")

    def _read_log(self) -> list[str]:
        """The log's lines, read under the lock the fake tools write with."""
        try:
            with self.log_path.open(encoding="utf-8") as handle:
                fcntl.flock(handle, fcntl.LOCK_SH)
                try:
                    return handle.read().splitlines()
                finally:
                    fcntl.flock(handle, fcntl.LOCK_UN)
        except FileNotFoundError:
            return []

    def calls(self, tool: Optional[str] = None) -> list[ShimCall]:
        """Return the recorded calls, oldest first, optionally for one tool."""
        records = []
        for line in self._read_log():
            try:
                data = json.loads(line)
            except ValueError:
                continue  # blank or partial line
            records.append((data.get("sequence", 0), data))
        records.sort(key=lambda item: item[0])
        out = [
            ShimCall(
                tool=data["tool"],
                argv=list(data["argv"]),
                cwd=data.get("cwd", ""),
                rule=data.get("rule"),
                stdin=data.get("stdin"),
            )
            for _, data in records
        ]
        return [call for call in out if tool is None or call.tool == tool]

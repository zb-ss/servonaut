"""Converse with an interactive CLI command: read its prompts, type answers.

``run_cli`` hands a child all of its standard input up front, which cannot
answer a prompt whose right answer is only printed at run time (a staging
token, say). :class:`InteractiveCli` keeps the pipes open instead::

    with InteractiveCli.start(cmd, "db", "setup", "edge-1", env=..., ...) as child:
        token = child.expect(r"token=(\\S+)").group(1)
        child.expect(r"Token to save")
        child.send(token)
    result = child.result  # a CliResult, like run_cli's

Waits are bounded and condition-based: :meth:`expect` returns as soon as the
output matches, and fails with everything read so far when it does not. The
child must arm the e2e guard like every other one.
"""

from __future__ import annotations

import codecs
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Mapping, Optional, Sequence

from e2e.harness.processes import ChildLog, CliResult, require_armed

DEFAULT_EXPECT_TIMEOUT = 10.0


class _Stream:
    """Everything one pipe has produced so far, filled by a reader thread."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._changed = threading.Condition()
        self.text = ""
        self.closed = False
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        while True:
            try:
                chunk = os.read(self._fd, 4096)
            except OSError:
                chunk = b""
            with self._changed:
                if chunk:
                    self.text += self._decoder.decode(chunk)
                else:
                    self.text += self._decoder.decode(b"", final=True)
                    self.closed = True
                self._changed.notify_all()
            if not chunk:
                return

    def wait(self, predicate, timeout: float) -> bool:
        with self._changed:
            return self._changed.wait_for(lambda: predicate() or self.closed, timeout)

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)


class InteractiveCli:
    """A running ``servonaut`` command with its standard streams kept open."""

    def __init__(
        self,
        process: subprocess.Popen,
        argv: list[str],
        *,
        armed_log: Path,
        log: Optional[ChildLog],
    ) -> None:
        self._process = process
        self._argv = argv
        self._armed_log = armed_log
        self._log = log
        self._started = time.monotonic()
        assert process.stdout is not None and process.stderr is not None
        self._stdout = _Stream(process.stdout.fileno())
        self._stderr = _Stream(process.stderr.fileno())
        self._position = 0
        self.result: Optional[CliResult] = None

    @classmethod
    def start(
        cls,
        command: Sequence[str],
        *args: str,
        env: Mapping[str, str],
        cwd: Path,
        armed_log: Path,
        log: Optional[ChildLog] = None,
    ) -> "InteractiveCli":
        argv = [*command, *args]
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            cwd=str(cwd),
        )
        return cls(process, argv, armed_log=armed_log, log=log)

    def __enter__(self) -> "InteractiveCli":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def output(self) -> str:
        """Standard output read so far."""
        return self._stdout.text

    def expect(self, pattern: str, *, timeout: float = DEFAULT_EXPECT_TIMEOUT) -> re.Match:
        """Wait for *pattern* in output not yet consumed; consume through it."""
        regex = re.compile(pattern)
        found: list[re.Match] = []

        def matched() -> bool:
            match = regex.search(self._stdout.text, self._position)
            if match:
                found.append(match)
            return bool(match)

        self._stdout.wait(matched, timeout)
        if not found:
            raise AssertionError(
                f"timed out after {timeout:.0f}s waiting for /{pattern}/ from "
                f"{' '.join(self._argv[-3:])}; stdout so far:\n{self._stdout.text}\n"
                f"stderr so far:\n{self._stderr.text}"
            )
        self._position = found[0].end()
        return found[0]

    def send(self, line: str) -> None:
        """Type *line* and press Enter."""
        assert self._process.stdin is not None
        self._process.stdin.write(line.encode() + b"\n")
        self._process.stdin.flush()

    def close(self, *, timeout: float = 30.0) -> CliResult:
        """Close standard input, wait for the exit and collect the result."""
        if self.result is not None:
            return self.result
        if self._process.stdin is not None and not self._process.stdin.closed:
            self._process.stdin.close()
        try:
            self._process.wait(timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
            raise
        finally:
            self._stdout.join(5)
            self._stderr.join(5)
        self.result = CliResult(
            argv=self._argv,
            returncode=self._process.returncode,
            stdout=self._stdout.text,
            stderr=self._stderr.text,
            duration=time.monotonic() - self._started,
        )
        if self._log is not None:
            self._log.append(self.result.describe())
        require_armed(self._armed_log, pid=self._process.pid)
        return self.result

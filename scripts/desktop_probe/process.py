"""Bounded pipe transport for a directly executed Textual child."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Awaitable, Callable, Sequence

from .config import ProbeConfig
from .diagnostics import parse_record


class TextualChild:
    def __init__(self, command: Sequence[str], config: ProbeConfig) -> None:
        self.command = tuple(command)
        self.config = config
        self.process: asyncio.subprocess.Process | None = None
        self.forced_stop = False
        self.errors: list[dict[str, object]] = []
        self._stderr_task: asyncio.Task[None] | None = None

    async def start(self, width: int, height: int) -> None:
        # The fixture needs interpreter/OS plumbing, never provider credentials,
        # Textual devtools flags or logging overrides from the operator's shell.
        names = (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "TMPDIR",
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "LANG",
            "LC_ALL",
            "PYTHONPATH",
            "PYTHONIOENCODING",
        )
        environment = {name: os.environ[name] for name in names if name in os.environ}
        environment.update(
            COLUMNS=str(width),
            ROWS=str(height),
            TEXTUAL_COLOR_SYSTEM="truecolor",
            TERM_PROGRAM="textual",
            TERM_PROGRAM_VERSION=self.config.textual_serve_version,
        )
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        self._stderr_task = asyncio.create_task(self._read_diagnostics())
        assert self.process.stdout is not None
        prelude = await asyncio.wait_for(
            self.process.stdout.readline(), self.config.startup_seconds
        )
        if prelude != b"__GANGLION__\n":
            raise RuntimeError("Textual child did not become ready")

    async def _read_diagnostics(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        pending = b""
        limit = self.config.max_message_bytes
        while chunk := await self.process.stderr.read(limit):
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()[-limit:]
            for line in lines:
                record = parse_record(line) if len(line) <= limit else None
                if (
                    record is not None
                    and len(self.errors) < self.config.max_diagnostic_entries
                ):
                    self.errors.append(record)

    async def send(self, kind: bytes, payload: bytes) -> None:
        assert self.process is not None and self.process.stdin is not None
        self.process.stdin.write(kind + len(payload).to_bytes(4, "big") + payload)
        await self.process.stdin.drain()

    async def meta(self, value: dict[str, object]) -> None:
        await self.send(b"M", json.dumps(value).encode())

    async def forward(self, send: Callable[[bytes], Awaitable[None]]) -> None:
        assert self.process is not None and self.process.stdout is not None
        stream = self.process.stdout
        try:
            while True:
                header = await stream.readexactly(5)
                size = int.from_bytes(header[1:], "big")
                if size > self.config.max_packet_bytes:
                    raise ValueError("Textual packet exceeds size limit")
                payload = await stream.readexactly(size)
                if header[:1] == b"D":
                    await send(payload)
                elif header[:1] == b"M" and json.loads(payload).get("type") == "exit":
                    return
                # File downloads and navigation are intentionally not forwarded.
        except asyncio.IncompleteReadError:
            return

    async def stop(self) -> None:
        process = self.process
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), self.config.shutdown_seconds)
        except asyncio.TimeoutError:
            if process.returncode is None:
                self.forced_stop = True
                process.kill()
            await process.wait()
        if self._stderr_task is not None:
            await self._stderr_task

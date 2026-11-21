"""Detect when a fresh stdio MCP connection would launch a newer pipx generation."""

from __future__ import annotations

import asyncio
import logging
import os
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING

from servonaut.utils.package_version import PackageVersion

if TYPE_CHECKING:
    from servonaut.updates.state import InstallState

PIPX_GENERATION_CURRENT = "pipx_generation_current"
_MAX_STATE_BYTES = 1024 * 1024
logger = logging.getLogger(__name__)


class MCPDisplayText(str):
    """A successful, human-readable result that can carry a reconnect hint."""


@dataclass(frozen=True, order=True)
class ReconnectBuild:
    version: PackageVersion
    revision: int = 0

    def display(self) -> str:
        return f"{self.version.text} (revision {self.revision})" if self.revision else self.version.text


class PipxReconnectHint:
    def __init__(self, store: InstallState, running: PackageVersion, poll_seconds: float) -> None:
        self._store = store
        self._running = ReconnectBuild(running)
        self._poll_seconds = poll_seconds
        self._state_path = store.directory / "state.json"
        self._stamp: tuple[int, int, int, int] | None = None
        self._target: ReconnectBuild | None = None
        self._announced: set[ReconnectBuild] = set()
        self._next_poll = 0.0
        self._probe: asyncio.Task[None] | None = None

    @classmethod
    def detect(cls, running_version: str) -> PipxReconnectHint | None:
        if os.environ.get("SERVONAUT_SKIP_AUTO_APPLY") == "1":
            return None

        from servonaut.updates.layout import UpdateLayout
        from servonaut.updates.status import public_version

        running = public_version(running_version)
        if running is None:
            return None
        try:
            layout = UpdateLayout.detect()
            if layout is not None:
                return cls(layout.store, running, layout.store.preferences().status_poll_seconds)
        except (OSError, RuntimeError, ValueError):
            pass
        return None

    def refresh_if_due(self) -> None:
        loop = asyncio.get_running_loop()
        now = loop.time()
        if now < self._next_poll or (self._probe is not None and not self._probe.done()):
            return
        self._next_poll = now + self._poll_seconds
        self._probe = loop.create_task(self._refresh())

    async def _refresh(self) -> None:
        self._target = await asyncio.to_thread(self._read_current_target)

    def _read_current_target(self) -> ReconnectBuild | None:
        from servonaut.updates.launch import installed_generation_version

        try:
            entry = self._state_path.lstat()
            if not stat.S_ISREG(entry.st_mode) or entry.st_size > _MAX_STATE_BYTES:
                self._stamp = None
                return None
            stamp = (entry.st_dev, entry.st_ino, entry.st_mtime_ns, entry.st_size)
            # Publication and rollback update this stamp. Removing a generation
            # by hand is detected the next time the updater publishes its state.
            if stamp == self._stamp:
                return self._target
            state = self._store.load_state(maximum_bytes=_MAX_STATE_BYTES)
            version = installed_generation_version(self._store, state)
        except (OSError, RuntimeError, ValueError):
            self._stamp = None
            return None
        self._stamp = stamp
        target = ReconnectBuild(version) if version is not None else None
        return target if target is not None and target > self._running else None

    def message(self, *, diagnostic: bool) -> str | None:
        """Read or claim the hint in the dispatch loop without yielding."""
        target = self._target
        if target is None or (not diagnostic and target in self._announced):
            return None
        if not diagnostic:
            self._announced.add(target)
        return (
            f"Servonaut is running {self._running.display()}. {target.display()} is installed. "
            "Reconnect this MCP server to use it."
        )

    async def close(self) -> None:
        if self._probe is None:
            return
        self._probe.cancel()
        try:
            await self._probe
        except asyncio.CancelledError:
            pass
        except Exception as error:
            logger.debug("MCP reconnect probe failed during shutdown (%s).", type(error).__name__)

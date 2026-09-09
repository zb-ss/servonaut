"""Read-only host monitoring, independent of cloud-provider metrics APIs."""

from __future__ import annotations

import asyncio
import math
from collections.abc import AsyncIterator, Awaitable, Callable

from servonaut.config.schema import SSHConfig
from servonaut.utils.live_stats import LIVE_STATS_COMMAND, LiveStats, parse_live_stats

SSHRunner = Callable[[str], Awaitable[tuple[str, str, int]]]
RunnerFactory = Callable[[dict], SSHRunner]


def _positive_seconds(value: object) -> bool:
    return (
        isinstance(value, (int, float)) and not isinstance(value, bool)
        and math.isfinite(value) and value > 0
    )


class LiveStatsError(Exception):
    """A monitoring failure with a safe, actionable message for the user."""


def _ssh_error_message(stderr: str) -> str:
    """Classify diagnostics without exposing hosts, usernames, or key paths."""
    diagnostic = stderr.lower()
    if "host key verification failed" in diagnostic or "host identification has changed" in diagnostic:
        return "SSH host verification failed. Verify the server's host key before retrying."
    if any(value in diagnostic for value in (
        "permission denied", "authentication fail", "too many authentication failures",
        "sign_and_send_pubkey", "load key",
    )):
        return "SSH authentication failed. Check the SSH username, key, and agent; for OVH, check OVH SSH settings."
    if "connection refused" in diagnostic:
        return "SSH connection refused. Check that SSH is running and reachable on the configured port."
    if "timed out" in diagnostic:
        return "SSH timed out. Check server reachability and the SSH monitoring timeout."
    return "SSH could not collect metrics. Check SSH connectivity and access to Linux host metrics."


class LiveStatsService:
    """Collect Linux snapshots through an injected, provider-aware SSH runner."""

    def __init__(self, runner_factory: RunnerFactory, config: SSHConfig) -> None:
        self._runner_factory = runner_factory
        self._config = config

    async def collect(self, instance: dict) -> LiveStats:
        """Return real metrics or raise an actionable error; never fabricate data."""
        try:
            runner = self._runner_factory(instance)
            stdout, stderr, return_code = await runner(LIVE_STATS_COMMAND)
        except asyncio.TimeoutError as exc:
            raise LiveStatsError(_ssh_error_message("timed out")) from exc
        except (OSError, ValueError, NotImplementedError) as exc:
            raise LiveStatsError("SSH is unavailable. Check the server's SSH settings.") from exc
        if return_code != 0:
            raise LiveStatsError(_ssh_error_message(stderr))
        stats = parse_live_stats(stdout)
        if not stats.has_data:
            raise LiveStatsError("SSH connected, but no Linux host metrics were available.")
        return stats

    async def watch(self, instance: dict) -> AsyncIterator[LiveStats]:
        """Poll until cancelled; failures stop polling so credentials can be fixed."""
        interval = self._config.live_stats_interval_seconds
        if not _positive_seconds(interval):
            raise LiveStatsError("SSH monitoring interval must be a positive number of seconds.")
        timeout = self._config.live_stats_timeout_seconds
        if not _positive_seconds(timeout):
            raise LiveStatsError("SSH monitoring timeout must be a positive number of seconds.")
        while True:
            yield await self.collect(instance)
            await asyncio.sleep(interval)

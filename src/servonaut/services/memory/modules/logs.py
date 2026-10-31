"""Logs module prober — discovers readable log paths via LogViewerService.

This module is a thin wrapper around ``LogViewerService.probe_log_paths``.
Rather than running its own SSH commands, it delegates to the existing
log-viewer infrastructure, which already handles SSH plumbing and path testing.

TTL: 1 day.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from servonaut.services.memory.interfaces import ModuleProberInterface, ModuleResult

if TYPE_CHECKING:
    from servonaut.services.log_viewer_service import LogViewerService
    from servonaut.services.interfaces import SSHServiceInterface, ConnectionServiceInterface

logger = logging.getLogger(__name__)

_TTL_1_DAY = 86400


class LogsProber(ModuleProberInterface):
    """Discover readable log paths on the remote server.

    Delegates entirely to ``LogViewerService.probe_log_paths``.  Because this
    prober doesn't follow the ``_commands`` / ``_parse`` pattern it overrides
    ``probe()`` directly.

    Args:
        log_viewer_service: The ``LogViewerService`` instance to delegate to.
        ssh_service: ``SSHService`` for building SSH commands.
        connection_service: ``ConnectionService`` for bastion resolution.
    """

    name = "logs"
    ttl_seconds = _TTL_1_DAY

    def __init__(
        self,
        log_viewer_service: "LogViewerService",
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface",
    ) -> None:
        self._log_viewer_service = log_viewer_service
        self._ssh_service = ssh_service
        self._connection_service = connection_service
        # Store the instance so probe() can pass it to probe_log_paths.
        self._instance: Optional[Dict[str, Any]] = None
        # The rows a team key and a bastion's vault key are looked up in.
        self._team_rows: List[Dict[str, Any]] = []
        self._fleet_rows: Optional[List[Dict[str, Any]]] = None

    def set_connection_rows(
        self, team_rows: List[Dict[str, Any]], fleet_rows: Optional[List[Dict[str, Any]]],
    ) -> None:
        """Rows for this build's connection (``MemoryService`` sets them per build)."""
        self._team_rows = list(team_rows)
        self._fleet_rows = list(fleet_rows) if fleet_rows is not None else None

    def set_instance(self, instance: Dict[str, Any]) -> None:
        """Bind a server instance dict before calling ``probe()``.

        ``MemoryService`` calls this (or passes it via ssh_runner) before
        dispatching the prober.  Here we adopt the simplest approach: the
        instance is stored on the prober before it is dispatched.

        Args:
            instance: Instance dict from ``app.instances``.
        """
        self._instance = instance

    async def probe(self, ssh_runner: Any) -> ModuleResult:
        """Probe readable log paths and return a ``ModuleResult``.

        The compound ``test -r`` command runs through *ssh_runner*, so it
        shares the build's connection and limits; a cached ``logs`` module is
        still served without connecting.

        Returns:
            A ``ModuleResult`` with ``observed={"probed_paths": [...]}`` and
            a human-readable ``raw_output`` listing what was found.
        """
        # Prefer the instance attached to the per-call runner (set by
        # MemoryService._make_ssh_runner) over the shared _instance field, so
        # concurrent build_report calls for different instances don't race.
        instance = getattr(ssh_runner, "instance", None) or self._instance
        if instance is None:
            logger.error("LogsProber.probe() called without setting instance first")
            return ModuleResult(
                module=self.name,
                instance_id="",
                observed={"probed_paths": []},
                partial=True,
                probed_at=datetime.now(tz=timezone.utc).isoformat(),
                ttl_seconds=self.ttl_seconds,
                raw_output="[ERROR] No instance bound — call set_instance() first.",
            )

        instance_id = instance.get("id") or instance.get("name", "")
        partial = False
        probed_paths: List[str] = []
        raw_output = ""

        # The build's own rows ride on its runner, like the instance: the
        # prober is shared, so concurrent builds would overwrite its fields.
        carried = getattr(ssh_runner, "connection_rows", None)
        team_rows, fleet_rows = carried if isinstance(carried, tuple) else (self._team_rows, self._fleet_rows)

        try:
            probed_paths = await self._log_viewer_service.probe_log_paths(
                instance,
                self._ssh_service,
                self._connection_service,
                team_rows=team_rows,
                rows=fleet_rows,
                runner=ssh_runner if callable(ssh_runner) else None,
            )
            if probed_paths:
                raw_output = "Readable log paths found:\n" + "\n".join(
                    f"  {p}" for p in probed_paths
                )
            else:
                raw_output = "No readable log paths found."
        except Exception as exc:  # noqa: BLE001 — never propagate
            logger.error(
                "LogsProber failed for %s: %s", instance_id, exc, exc_info=True
            )
            raw_output = f"[ERROR] {type(exc).__name__}: {exc}"
            partial = True

        return ModuleResult(
            module=self.name,
            instance_id="",
            observed={"probed_paths": probed_paths},
            partial=partial,
            probed_at=datetime.now(tz=timezone.utc).isoformat(),
            ttl_seconds=self.ttl_seconds,
            raw_output=raw_output,
        )

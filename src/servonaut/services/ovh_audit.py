"""Append-only JSON-lines audit logger for destructive OVH operations."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class OVHAuditLogger:
    """Append-only JSON-lines audit log for destructive OVH operations."""

    def __init__(self, audit_path: str = "~/.servonaut/ovh_audit.json") -> None:
        self._path = Path(audit_path).expanduser()

    def log_action(
        self,
        action: str,
        target: str,
        details: dict,
        confirmed: bool,
    ) -> None:
        """Append a JSON line: {ts, action, target, details, confirmed}.

        Args:
            action: Operation performed, e.g. "vps_reinstall", "cloud_delete".
            target: Resource identifier, e.g. "vps-abc123.ovh.net".
            details: Action-specific metadata (image_id, template, etc.).
            confirmed: Whether the user confirmed the action.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "details": details,
            "confirmed": confirmed,
        }

        try:
            with open(self._path, "a") as f:
                f.write(json.dumps(entry) + "\n")
            os.chmod(self._path, 0o600)
        except Exception as e:
            logger.error("Failed to write OVH audit log: %s", e)

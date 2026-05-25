"""Append-only JSON-lines audit logger for destructive AWS EC2 operations."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class AWSAuditLogger:
    """Append-only JSON-lines audit log for destructive AWS EC2 operations.

    Each mutating action (start/stop/reboot/terminate instance, run_instances)
    is appended as a single JSON line to the configured audit file.  The file
    is created with ``0o600`` permissions so only the owning user can read it.

    Example output line::

        {"ts": "2026-05-21T12:00:00+00:00", "action": "terminate_instance",
         "target": "i-0abc12345678def90", "details": {"region": "us-east-1"},
         "confirmed": true}
    """

    def __init__(self, audit_path: str = "~/.servonaut/aws_audit.jsonl") -> None:
        """Initialize the audit logger.

        Args:
            audit_path: Path to the JSONL audit file.  Tilde-expanded.
                Parent directories are created on first write.
        """
        self._path = Path(audit_path).expanduser()

    def log_action(
        self,
        action: str,
        target: str,
        details: dict,
        *,
        confirmed: bool = True,
    ) -> None:
        """Append a JSON line: ``{ts, action, target, details, confirmed}``.

        Failures are logged at WARNING level but never re-raised — an audit
        write failure must not abort the actual operation.

        Args:
            action: Operation performed, e.g. ``"start_instance"``,
                ``"terminate_instance"``, ``"run_instances"``.
            target: Resource identifier, e.g. ``"i-0abc12345678def90"``.
            details: Action-specific metadata (region, ami_id, etc.).
            confirmed: Whether the user confirmed the action via the modal.
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
            # Open with O_CREAT|O_APPEND|O_WRONLY at mode 0o600 so the file
            # is never world-readable even briefly (unlike open(...,'a') +
            # post-write chmod, which has a TOCTOU window).
            # O_NOFOLLOW: refuse to open if path is a symlink — prevents a
            # pre-planted symlink from redirecting audit writes.
            # getattr fallback covers platforms that lack O_NOFOLLOW (Windows).
            _O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW
            fd = os.open(str(self._path), flags, 0o600)
            try:
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                os.close(fd)
                raise
        except Exception as exc:
            logger.error("Failed to write AWS audit log: %s", exc)

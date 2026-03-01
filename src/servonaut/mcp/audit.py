"""Audit trail for MCP operations."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


class AuditTrail:
    def __init__(self, audit_path: str) -> None:
        self._path = Path(audit_path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, tool: str, args: Dict, result: str, allowed: bool, reason: str = "") -> None:
        """Log an MCP operation to the audit trail."""
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': tool,
            'args': args,
            'allowed': allowed,
            'reason': reason,
            'result_length': len(result) if result else 0,
        }
        try:
            with open(self._path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)

    def read_recent(self, count: int = 50) -> List[Dict]:
        """Read recent audit entries."""
        if not self._path.exists():
            return []
        entries = []
        try:
            with open(self._path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.warning("Skipping corrupt audit log entry")
        except Exception as e:
            logger.error("Failed to read audit log: %s", e)
        return entries[-count:]

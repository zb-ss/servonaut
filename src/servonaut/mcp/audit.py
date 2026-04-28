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

    def log(
        self,
        tool: str,
        args: Dict,
        result: str,
        allowed: bool,
        reason: str = "",
        *,
        source: str = "",
        **extras: object,
    ) -> None:
        """Log an MCP operation to the audit trail.

        Args:
            tool: Tool name as registered in the MCP guard table.
            args: Tool arguments. Logged verbatim — caller must not include
                secrets.
            result: Stringified result; only its byte-length is recorded.
            allowed: Whether the call was permitted by the guard.
            reason: Human-readable reason / rejection code on failure.
            source: Optional provenance tag (``"mcp"``, ``"ai_chat"``).
                Lets us partition the audit stream by which surface
                originated the call without parsing the args dict. New in
                T6 — defaults to ``""`` for backward-compat with existing
                MCP callers.
            **extras: Additional keyword fields persisted into the entry
                (e.g. ``conversation_id``, ``tool_call_id``). Forward-
                compatible: future surfaces can add metadata without
                breaking older audit readers.
        """
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': tool,
            'args': args,
            'allowed': allowed,
            'reason': reason,
            'result_length': len(result) if result else 0,
        }
        if source:
            entry['source'] = source
        # Surplus kwargs land last so they can't accidentally clobber the
        # canonical fields above.
        for key, value in extras.items():
            if key not in entry:
                entry[key] = value
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

"""Audit trail for MCP operations.

Rotation policy: the live ``mcp_audit.jsonl`` is rotated when **either**
of these is true after a write:

- File size exceeds :data:`ROTATE_MAX_BYTES` (default 10 MB).
- Oldest entry on the file is older than :data:`ROTATE_MAX_AGE_DAYS`
  (default 30 days).

On rotation the live file is renamed ``mcp_audit.jsonl.1``; existing
``.1`` shifts to ``.2``, and so on, up to :data:`ROTATE_MAX_HISTORY`
(default 5).  Anything beyond that gets deleted — bounded retention.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)

#: Rotate when the live file passes this byte size.
ROTATE_MAX_BYTES = 10 * 1024 * 1024  # 10 MB

#: Rotate when the OLDEST entry on the live file is older than this.
ROTATE_MAX_AGE_DAYS = 30

#: How many rotated files to keep (``.1`` … ``.N``).  Older drops.
ROTATE_MAX_HISTORY = 5

#: How often (in number of writes) to check the rotation condition.
#: Stat-on-every-write is fine for most installs but unnecessary; a
#: small batch keeps cost amortised on tight tool-call loops.
_ROTATE_CHECK_EVERY = 25


class AuditTrail:
    def __init__(self, audit_path: str) -> None:
        self._path = Path(audit_path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._writes_since_check = 0

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
            return

        self._writes_since_check += 1
        if self._writes_since_check >= _ROTATE_CHECK_EVERY:
            self._writes_since_check = 0
            try:
                self._maybe_rotate()
            except Exception as exc:  # noqa: BLE001
                logger.warning("MCP audit rotation skipped: %s", exc)

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

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    def _maybe_rotate(
        self,
        *,
        max_bytes: int = ROTATE_MAX_BYTES,
        max_age_days: int = ROTATE_MAX_AGE_DAYS,
        max_history: int = ROTATE_MAX_HISTORY,
    ) -> bool:
        """Rotate the live file if size or age threshold tripped.

        Public-ish for tests — the production caller always uses the
        module-level constants.

        Returns:
            True if rotation actually happened, False otherwise.
        """
        if not self._path.exists():
            return False

        try:
            size = self._path.stat().st_size
        except OSError:
            return False

        oversize = size >= max_bytes
        too_old = False
        if not oversize:  # only stat oldest entry when the cheap check fails
            too_old = self._oldest_entry_older_than(max_age_days)

        if not (oversize or too_old):
            return False

        self._rotate_files(max_history=max_history)
        return True

    def _oldest_entry_older_than(self, max_age_days: int) -> bool:
        """Return True if the first entry's timestamp is older than the cutoff."""
        try:
            with open(self._path, 'r') as f:
                first = f.readline().strip()
        except OSError:
            return False
        if not first:
            return False
        try:
            row = json.loads(first)
            ts_raw = row.get('timestamp', '')
            if not ts_raw:
                return False
            ts = datetime.fromisoformat(str(ts_raw).rstrip('Z'))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, json.JSONDecodeError):
            return False
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        return ts < cutoff

    def _rotate_files(self, *, max_history: int) -> None:
        """Shift ``.N`` → ``.N+1`` and rename live file to ``.1``.

        Drops anything beyond ``max_history`` so retention stays bounded.
        Uses :func:`os.replace` so the rename is atomic on POSIX.
        """
        # Drop the last slot if it would push past the window.
        oldest = self._numbered_path(max_history)
        if oldest.exists():
            try:
                oldest.unlink()
            except OSError as exc:
                logger.warning("Could not unlink %s: %s", oldest, exc)

        # Shift remaining N-1 → N (descending so we never overwrite).
        for i in range(max_history - 1, 0, -1):
            src = self._numbered_path(i)
            if not src.exists():
                continue
            dst = self._numbered_path(i + 1)
            try:
                os.replace(src, dst)
            except OSError as exc:
                logger.warning("Could not rotate %s → %s: %s", src, dst, exc)

        # Live file → .1
        try:
            os.replace(self._path, self._numbered_path(1))
        except OSError as exc:
            logger.warning("Could not rotate live audit log: %s", exc)

    def _numbered_path(self, n: int) -> Path:
        return self._path.with_name(self._path.name + f'.{n}')

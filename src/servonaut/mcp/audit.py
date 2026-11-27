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
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from servonaut.mcp.audit_classifier import classify_audit_entry, infer_origin
from servonaut.utils.logging_setup import warn_stderr

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


@dataclass(frozen=True)
class AuditOutcome:
    """What one audit row recorded about a call: its tool and whether it
    was allowed (tools write ``allowed=False`` on every refusal and failure)."""

    tool: str
    allowed: bool
    reason: str


_recorded_outcomes: ContextVar[Optional[List[AuditOutcome]]] = ContextVar(
    "servonaut_audit_outcomes", default=None,
)


@dataclass
class AuditCallContext:
    """Ambient provenance and execution telemetry for one tool invocation.

    Set at the dispatch boundary (MCP stdio server or AI tool bridge) so every
    ``AuditTrail.log`` call automatically receives ``origin``, ``source``,
    ``client``, ``session_id``, and ``duration_ms`` without modifying every
    tool call site.
    """

    origin: str = ""
    source: str = ""
    client: str = ""
    session_id: str = ""
    started_at: float = field(default_factory=time.monotonic)
    suppress_writes: bool = False
    logged_count: int = 0
    extras: Dict[str, Any] = field(default_factory=dict)


_call_context: ContextVar[Optional[AuditCallContext]] = ContextVar(
    "servonaut_audit_call_context", default=None,
)


@contextmanager
def audit_call_context(
    *,
    origin: str = "",
    source: str = "",
    client: str = "",
    session_id: str = "",
    suppress_writes: bool = False,
) -> Iterator[AuditCallContext]:
    """Attach provenance and timing metadata to audit rows written in this block."""
    ctx = AuditCallContext(
        origin=origin,
        source=source,
        client=client,
        session_id=session_id,
        started_at=time.monotonic(),
        suppress_writes=suppress_writes,
    )
    token = _call_context.set(ctx)
    try:
        yield ctx
    finally:
        _call_context.reset(token)


def update_call_context(**extras: Any) -> None:
    """Attach execution telemetry (e.g. ``transport_used``, ``exit_code``, ``target``)
    to the active audit call context, if any."""
    ctx = _call_context.get()
    if ctx is None:
        return
    for key, value in extras.items():
        if value is not None and value != "":
            ctx.extras[key] = value


@contextmanager
def record_outcomes() -> Iterator[List[AuditOutcome]]:
    """Collect the outcome of every audit row written inside the block.

    A caller that only gets a tool's text back (the AI tool bridge) learns
    from the rows the tool wrote whether the call failed, instead of
    guessing from the text, which can be raw server output. The list is
    per context, so concurrent calls on other tasks do not mix.
    """
    outcomes: List[AuditOutcome] = []
    token = _recorded_outcomes.set(outcomes)
    try:
        yield outcomes
    finally:
        _recorded_outcomes.reset(token)


class AuditTrail:
    def __init__(
        self,
        audit_path: str,
        *,
        warn_to_stderr: bool = False,
        default_origin: str = "",
    ) -> None:
        self._path = Path(audit_path).expanduser()
        self._warn_to_stderr = warn_to_stderr
        self._default_origin = default_origin
        self._warned_unavailable = False
        self._writes_since_check = 0
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if warn_to_stderr:
                flags = (
                    os.O_APPEND
                    | os.O_CREAT
                    | os.O_WRONLY
                    | getattr(os, "O_NONBLOCK", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(self._path, flags, 0o600)
                os.close(descriptor)
        except (OSError, ValueError) as error:
            if not warn_to_stderr:
                raise
            self._warn_unavailable(error)

    @property
    def path(self) -> Path:
        """Resolved path to the live JSONL audit log."""
        return self._path

    def _warn_unavailable(self, error: Exception) -> None:
        if not self._warn_to_stderr:
            logger.error("Failed to write audit log: %s", error)
        elif not self._warned_unavailable:
            self._warned_unavailable = True
            warn_stderr("servonaut: MCP audit log is unavailable. Tool activity may go unrecorded.")

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
        ctx = _call_context.get()
        effective_source = source or (ctx.source if ctx is not None else "")
        effective_origin = str(
            extras.get("origin")
            or (ctx.origin if ctx is not None else "")
            or self._default_origin
        )
        entry: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': tool,
            'args': args,
            'allowed': allowed,
            'reason': reason,
            'result_length': len(result) if result else 0,
        }
        if effective_source:
            entry['source'] = effective_source
        if effective_origin:
            entry['origin'] = effective_origin
        else:
            inferred = infer_origin(entry)
            if effective_source:
                entry['origin'] = inferred

        if ctx is not None:
            if ctx.client and 'client' not in extras:
                entry['client'] = ctx.client
            if ctx.session_id and 'session_id' not in extras:
                entry['session_id'] = ctx.session_id
            if 'duration_ms' not in extras:
                entry['duration_ms'] = max(0, int((time.monotonic() - ctx.started_at) * 1000))
            for key, value in ctx.extras.items():
                if key not in entry and key not in extras:
                    entry[key] = value

        # Deterministic remote/command classification (lightweight, pure Python).
        classified = classify_audit_entry(tool, args, allowed=allowed, reason=reason)
        entry['op_class'] = classified['op_class']
        entry['remote_exec'] = classified['remote_exec']
        entry['command_category'] = classified['command_category']
        if classified['command_stems']:
            entry['command_stems'] = classified['command_stems']
        if classified['used_sudo']:
            entry['used_sudo'] = True

        # Surplus kwargs land last so they can't accidentally clobber the
        # canonical fields above (except explicit origin/classification already handled).
        for key, value in extras.items():
            if key not in entry and value is not None:
                entry[key] = value
        outcomes = _recorded_outcomes.get()
        if outcomes is not None:
            outcomes.append(AuditOutcome(tool, bool(allowed), str(reason or "")))

        if ctx is not None:
            ctx.logged_count += 1
            if ctx.suppress_writes:
                # Forward execution telemetry captured by an inner tool call
                # (e.g. ServonautTools called from AIToolBridge) so the single
                # outer audit row carries transport_used / target / exit_code.
                for telemetry_key in (
                    'transport_used', 'ssh_fell_back', 'ssm_command_id',
                    'exit_code', 'target', 'key_source',
                ):
                    if telemetry_key in entry:
                        ctx.extras[telemetry_key] = entry[telemetry_key]
                return

        try:
            self._append_line(json.dumps(entry) + '\n')
        except (OSError, TypeError, ValueError, RecursionError) as error:
            self._warn_unavailable(error)
            return

        self._writes_since_check += 1
        if self._writes_since_check >= _ROTATE_CHECK_EVERY:
            self._writes_since_check = 0
            try:
                self._maybe_rotate()
            except Exception as exc:  # noqa: BLE001
                logger.warning("MCP audit rotation skipped: %s", exc)

    def _append_line(self, line: str) -> None:
        """Append one line atomically with 0o600 permissions and O_NOFOLLOW."""
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | no_follow
        fd = os.open(str(self._path), flags, 0o600)
        try:
            f = os.fdopen(fd, 'a', encoding='utf-8')
        except Exception:
            os.close(fd)
            raise
        with f:
            f.write(line)

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

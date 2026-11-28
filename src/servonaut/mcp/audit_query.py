"""High-performance multi-file query engine for ``mcp_audit.jsonl``.

Designed to stay responsive even when the live log plus rotated archives
(``.1`` … ``.5``) reach their 60 MB ceiling (~100k–300k lines):

- Walks newest-to-oldest across ``mcp_audit.jsonl`` and ``.1`` … ``.N``.
- Skips rotated files whose ``mtime`` predates the ``since`` cutoff without
  opening them.
- Reads each file backwards from EOF in 64 KiB chunks (O(chunk) memory) and
  stops early once entries fall below ``since``.
- Supports cooperative cancellation via ``cancel_check`` so stale background
  scans abort immediately when filters change.
- Streams filter matching and summary aggregation, retaining only the
  requested page in memory.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional

from servonaut.mcp.audit import ROTATE_MAX_HISTORY
from servonaut.mcp.audit_classifier import (
    OP_REMOTE_COMMAND,
    enrich_entry_metadata,
    is_entry_failed_or_denied,
)
from servonaut.utils.markup import single_line_text

# Chunk size for reverse file scanning (64 KiB).
_REVERSE_CHUNK_BYTES = 64 * 1024

# Grace window for mtime pruning to tolerate minor filesystem/clock skew.
_MTIME_GRACE_SECONDS = 5.0

# Number of consecutive entries older than `since` before stopping early, so
# concurrent writes arriving slightly out of order never truncate the window.
_EARLY_STOP_STREAK = 8

# How often (in scanned lines) to poll `cancel_check`.
_CANCEL_CHECK_EVERY = 256

# Fast substring marker to locate `"timestamp": "..."` before json.loads.
_TS_MARKER = '"timestamp":'

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class AuditFilter:
    """Filter specification for querying agent/MCP audit logs."""

    since: Optional[datetime] = None
    until: Optional[datetime] = None
    origin: str = ""      # "", "mcp", "ui", "relay", "proactive", "cli", "unknown"
    scope: str = "all"    # "all", "remote", "commands", "denied"
    category: str = ""    # command_category / op_class
    transport: str = ""   # "", "ssh", "ssm", "scp", "none"
    tool: str = ""        # case-insensitive substring or exact tool name
    host: str = ""        # case-insensitive substring against target/instance_id
    search: str = ""      # free-text search across command, target, tool, client, reason
    denied_only: bool = False


@dataclass
class AuditSummary:
    """Aggregate counters for all entries matching an :class:`AuditFilter`."""

    total: int = 0
    allowed: int = 0
    denied: int = 0
    remote_exec: int = 0
    by_origin: Dict[str, int] = field(default_factory=dict)
    by_transport: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    by_tool: Dict[str, int] = field(default_factory=dict)
    by_target: Dict[str, int] = field(default_factory=dict)
    files_scanned: int = 0
    files_skipped_mtime: int = 0
    lines_scanned: int = 0
    corrupt_lines: int = 0
    read_errors: List[str] = field(default_factory=list)
    cancelled: bool = False
    elapsed_ms: float = 0.0


@dataclass
class AuditQueryPage:
    """One page of newest-first audit rows plus matching summary stats."""

    entries: List[Dict[str, Any]]
    total_matches: int
    page: int
    page_size: int
    total_pages: int
    summary: AuditSummary


def parse_timestamp(raw: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp string into a UTC-aware ``datetime``."""
    if not raw:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_since(spec: str, *, now: Optional[datetime] = None) -> Optional[datetime]:
    """Parse a relative window (``24h``, ``7d``, ``30m``, ``all``) or ISO date.

    Returns ``None`` for ``"all"`` or empty string.
    Raises ``ValueError`` for unrecognized or out-of-range input.
    """
    raw = (spec or "").strip()
    if not raw or raw.lower() == "all":
        return None
    ref = now or datetime.now(timezone.utc)
    m = _DURATION_RE.match(raw)
    if m:
        amount = int(m.group(1))
        unit = m.group(2).lower()
        if amount <= 0:
            raise ValueError(f"Duration must be positive: {spec!r}")
        try:
            if unit == "s":
                return ref - timedelta(seconds=amount)
            if unit == "m":
                return ref - timedelta(minutes=amount)
            if unit == "h":
                return ref - timedelta(hours=amount)
            if unit == "d":
                return ref - timedelta(days=amount)
            if unit == "w":
                return ref - timedelta(weeks=amount)
        except OverflowError as exc:
            raise ValueError(f"Time window out of range: {spec!r}") from exc
    dt = parse_timestamp(raw)
    if dt is not None:
        return dt
    raise ValueError(f"Invalid time window {spec!r} (use e.g. 1h, 24h, 7d, all, or ISO-8601)")


def _extract_ts_prefix(line: str) -> Optional[str]:
    """Cheaply pull the quoted timestamp value from a JSONL line without full parsing."""
    idx = line.find(_TS_MARKER)
    if idx < 0:
        return None
    start = line.find('"', idx + len(_TS_MARKER))
    if start < 0:
        return None
    end = line.find('"', start + 1)
    if end < 0:
        return None
    return line[start + 1 : end]


def _iter_lines_reverse(path: Path, chunk_size: int = _REVERSE_CHUNK_BYTES) -> Iterator[str]:
    """Yield non-empty lines from *path* in reverse order (newest first)."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        remainder = b""
        while pos > 0:
            read_size = min(chunk_size, pos)
            pos -= read_size
            fh.seek(pos)
            chunk = fh.read(read_size)
            data = chunk + remainder
            lines = data.split(b"\n")
            remainder = lines[0]
            # lines[1:] are complete lines in file order; yield in reverse.
            for raw_line in reversed(lines[1:]):
                stripped = raw_line.strip()
                if stripped:
                    yield stripped.decode("utf-8", errors="replace")
        if remainder:
            stripped = remainder.strip()
            if stripped:
                yield stripped.decode("utf-8", errors="replace")


def entry_target_label(entry: Mapping[str, Any]) -> str:
    """Human-friendly target label (e.g. ``prod-web-1 (i-0abc)`` or ``-``)."""
    target = entry.get("target")
    if isinstance(target, Mapping):
        name = str(target.get("name") or "").strip()
        tid = str(target.get("id") or "").strip()
        host = str(target.get("host") or "").strip()
        if name and tid and name != tid:
            return f"{name} ({tid})"
        if name:
            return name
        if tid:
            return tid
        if host:
            return host
    args = entry.get("args")
    if isinstance(args, Mapping):
        for key in ("instance_id", "identifier", "host", "ip", "bucket", "zone", "config_name"):
            val = str(args.get(key) or "").strip()
            if val:
                return val
    return "-"


def entry_command_summary(entry: Mapping[str, Any], *, max_len: int = 160) -> str:
    """Compact one-line summary of what the call executed."""
    args = entry.get("args") if isinstance(entry.get("args"), Mapping) else {}
    tool = str(entry.get("tool") or "")
    text = ""
    if "command" in args and args["command"]:
        text = str(args["command"])
    elif tool == "transfer_file":
        direction = args.get("direction", "download")
        src = args.get("local_path", "") if direction == "upload" else args.get("remote_path", "")
        dst = args.get("remote_path", "") if direction == "upload" else args.get("local_path", "")
        text = f"{direction} {src} -> {dst}"
    elif tool == "get_logs":
        text = f"{args.get('log_path', '/var/log/syslog')} (lines={args.get('lines', 100)})"
    elif tool == "aws_call":
        text = f"{args.get('service', '')}.{args.get('operation', '')}"
        if args.get("mutate"):
            text += " [mutate]"
    elif args:
        parts = []
        for k, v in args.items():
            if k in ("instance_id", "transport") or v in (None, "", False):
                continue
            val = str(v)
            if len(val) > 48:
                val = val[:45] + "..."
            parts.append(f"{k}={val}")
            if len(parts) >= 4:
                break
        text = " ".join(parts)

    if is_entry_failed_or_denied(entry):
        reason = str(entry.get("tool_reason") or entry.get("reason") or "").strip()
        if reason:
            text = f"{text} [{reason}]" if text else f"[{reason}]"

    text = single_line_text(text).strip()
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or "-"


class AuditQueryService:
    """Read-only, rotation-aware, streaming query service for ``mcp_audit.jsonl``."""

    def __init__(
        self,
        audit_path: str | Path,
        *,
        max_history: int = ROTATE_MAX_HISTORY,
    ) -> None:
        self._path = Path(audit_path).expanduser()
        self._max_history = max(0, int(max_history))

    @property
    def path(self) -> Path:
        return self._path

    def log_files(self) -> List[Path]:
        """Return existing audit files ordered newest-to-oldest (live, .1, .2, ...)."""
        files: List[Path] = []
        if self._path.exists() or self._path.is_symlink():
            files.append(self._path)
        for idx in range(1, self._max_history + 1):
            candidate = self._path.with_name(self._path.name + f".{idx}")
            if candidate.exists():
                files.append(candidate)
        return files

    def query(
        self,
        filters: Optional[AuditFilter] = None,
        *,
        page: int = 0,
        page_size: int = 100,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> AuditQueryPage:
        """Query matching entries across rotated files with bounded memory."""
        started = time.monotonic()
        flt = filters or AuditFilter()
        safe_page = max(0, int(page))
        safe_size = max(1, int(page_size))
        start_idx = safe_page * safe_size
        end_idx = start_idx + safe_size

        since_dt = flt.since.astimezone(timezone.utc) if flt.since is not None else None
        until_dt = flt.until.astimezone(timezone.utc) if flt.until is not None else None
        since_epoch = since_dt.timestamp() if since_dt is not None else None
        since_iso_prefix = since_dt.strftime("%Y-%m-%dT%H:%M:%S") if since_dt is not None else ""

        origin_flt = flt.origin.strip().lower()
        scope_flt = (flt.scope or "all").strip().lower()
        cat_flt = flt.category.strip().lower()
        transport_flt = flt.transport.strip().lower()
        tool_flt = flt.tool.strip().lower()
        host_flt = flt.host.strip().lower()
        search_flt = flt.search.strip().lower()
        denied_only = flt.denied_only or scope_flt == "denied"

        by_origin: Counter[str] = Counter()
        by_transport: Counter[str] = Counter()
        by_category: Counter[str] = Counter()
        by_tool: Counter[str] = Counter()
        by_target: Counter[str] = Counter()

        summary = AuditSummary()
        page_entries: List[Dict[str, Any]] = []
        match_count = 0
        stop_all_files = False

        if self._path.is_symlink():
            summary.read_errors.append(
                f"{self._path}: audit path is a symlink (writes are skipped; configure mcp.audit_path to a regular file)"
            )

        for file_path in self.log_files():
            if stop_all_files:
                break
            if cancel_check is not None and cancel_check():
                summary.cancelled = True
                break
            try:
                st = file_path.stat()
            except OSError as exc:
                summary.read_errors.append(f"{file_path}: {exc}")
                continue
            if since_epoch is not None and st.st_mtime < since_epoch - _MTIME_GRACE_SECONDS:
                summary.files_skipped_mtime += 1
                continue

            summary.files_scanned += 1
            below_since_streak = 0

            try:
                line_iter = _iter_lines_reverse(file_path)
                for line in line_iter:
                    summary.lines_scanned += 1
                    if (
                        cancel_check is not None
                        and (summary.lines_scanned % _CANCEL_CHECK_EVERY == 0)
                        and cancel_check()
                    ):
                        summary.cancelled = True
                        stop_all_files = True
                        break

                    # Fast timestamp cutoff check before full JSON deserialization.
                    if since_dt is not None:
                        ts_str = _extract_ts_prefix(line)
                        if ts_str is not None:
                            if (ts_str.endswith("+00:00") or ts_str.endswith("Z")) and len(ts_str) >= 19:
                                if ts_str[:19] < since_iso_prefix:
                                    below_since_streak += 1
                                    if below_since_streak >= _EARLY_STOP_STREAK:
                                        stop_all_files = True
                                        break
                                    continue
                                below_since_streak = 0
                            else:
                                parsed_ts = parse_timestamp(ts_str)
                                if parsed_ts is not None:
                                    if parsed_ts < since_dt:
                                        below_since_streak += 1
                                        if below_since_streak >= _EARLY_STOP_STREAK:
                                            stop_all_files = True
                                            break
                                        continue
                                    below_since_streak = 0

                    # Lossless raw-line pre-filters before full JSON parse.
                    if tool_flt and tool_flt not in line.lower():
                        continue
                    if host_flt and host_flt not in line.lower():
                        continue
                    if transport_flt == "ssm" and "ssm" not in line.lower():
                        continue
                    if origin_flt in ("proactive", "relay", "cli") and origin_flt not in line.lower():
                        continue

                    try:
                        raw_entry = json.loads(line)
                    except json.JSONDecodeError:
                        summary.corrupt_lines += 1
                        continue
                    if not isinstance(raw_entry, dict):
                        summary.corrupt_lines += 1
                        continue

                    entry_ts = parse_timestamp(raw_entry.get("timestamp"))
                    if since_dt is not None and entry_ts is not None:
                        if entry_ts < since_dt:
                            below_since_streak += 1
                            if below_since_streak >= _EARLY_STOP_STREAK:
                                stop_all_files = True
                                break
                            continue
                        below_since_streak = 0
                    if until_dt is not None and entry_ts is not None and entry_ts > until_dt:
                        continue

                    entry = enrich_entry_metadata(raw_entry)
                    if not _matches_filter(
                        entry,
                        origin=origin_flt,
                        scope=scope_flt,
                        category=cat_flt,
                        transport=transport_flt,
                        tool=tool_flt,
                        host=host_flt,
                        search=search_flt,
                        denied_only=denied_only,
                    ):
                        continue

                    # Update streaming counters.
                    summary.total += 1
                    if is_entry_failed_or_denied(entry):
                        summary.denied += 1
                    else:
                        summary.allowed += 1
                    if entry.get("remote_exec"):
                        summary.remote_exec += 1

                    origin_val = str(entry.get("origin") or "unknown")
                    by_origin[origin_val] += 1

                    transport_val = str(entry.get("transport_used") or "")
                    if transport_val:
                        by_transport[transport_val] += 1

                    cat_val = str(entry.get("command_category") or entry.get("op_class") or "")
                    if cat_val:
                        by_category[cat_val] += 1

                    tool_val = str(entry.get("tool") or "")
                    if tool_val:
                        by_tool[tool_val] += 1

                    target_lbl = entry_target_label(entry)
                    if target_lbl != "-":
                        by_target[target_lbl] += 1

                    if start_idx <= match_count < end_idx:
                        page_entries.append(entry)
                    match_count += 1
            except OSError as exc:
                summary.read_errors.append(f"{file_path}: {exc}")
                continue

        summary.by_origin = dict(by_origin)
        summary.by_transport = dict(by_transport)
        summary.by_category = dict(by_category)
        summary.by_tool = dict(by_tool.most_common(25))
        summary.by_target = dict(by_target.most_common(25))
        summary.elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)

        total_pages = (match_count + safe_size - 1) // safe_size if match_count else 0
        return AuditQueryPage(
            entries=page_entries,
            total_matches=match_count,
            page=safe_page,
            page_size=safe_size,
            total_pages=total_pages,
            summary=summary,
        )


def _matches_filter(
    entry: Mapping[str, Any],
    *,
    origin: str,
    scope: str,
    category: str,
    transport: str,
    tool: str,
    host: str,
    search: str,
    denied_only: bool,
) -> bool:
    if denied_only and not is_entry_failed_or_denied(entry):
        return False

    if origin and str(entry.get("origin") or "").lower() != origin:
        return False

    if scope == "remote" and not entry.get("remote_exec"):
        return False
    if scope == "commands" and entry.get("op_class") != OP_REMOTE_COMMAND:
        return False

    if category:
        entry_cat = str(entry.get("command_category") or "").lower()
        entry_op = str(entry.get("op_class") or "").lower()
        if entry_cat != category and entry_op != category:
            return False

    if transport:
        used = str(entry.get("transport_used") or "").lower()
        if transport == "none":
            if used:
                return False
        elif used != transport:
            return False

    if tool:
        if tool not in str(entry.get("tool") or "").lower():
            return False

    if host:
        target_blob = _target_search_blob(entry)
        if host not in target_blob:
            return False

    if search:
        if search not in _full_search_blob(entry):
            return False

    return True


def _target_search_blob(entry: Mapping[str, Any]) -> str:
    parts: List[str] = [entry_target_label(entry)]
    target = entry.get("target")
    if isinstance(target, Mapping):
        for key in ("id", "name", "host", "provider", "account", "region"):
            val = target.get(key)
            if val:
                parts.append(str(val))
    args = entry.get("args")
    if isinstance(args, Mapping):
        for key in ("instance_id", "identifier", "host", "ip"):
            val = args.get(key)
            if val:
                parts.append(str(val))
    return " ".join(parts).lower()


def _full_search_blob(entry: Mapping[str, Any]) -> str:
    parts: List[str] = [
        str(entry.get("tool") or ""),
        str(entry.get("origin") or ""),
        str(entry.get("client") or ""),
        str(entry.get("reason") or ""),
        str(entry.get("tool_reason") or ""),
        str(entry.get("transport_used") or ""),
        str(entry.get("command_category") or ""),
        str(entry.get("ssm_command_id") or ""),
        _target_search_blob(entry),
    ]
    args = entry.get("args")
    if isinstance(args, Mapping):
        if args.get("command"):
            parts.append(str(args["command"]))
        else:
            parts.append(json.dumps(args, default=str))
    return " ".join(parts).lower()


def format_access_line(entry: Mapping[str, Any]) -> str:
    """Format one audit entry as a compact, single-line Apache-style log entry."""
    ts = parse_timestamp(entry.get("timestamp"))
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%SZ") if ts else single_line_text(str(entry.get("timestamp") or "-"))[:20]

    origin = single_line_text(str(entry.get("origin") or "unknown"))
    client = single_line_text(str(entry.get("client") or "")).strip()
    origin_col = f"{origin}:{client}" if client else origin
    if len(origin_col) > 22:
        origin_col = origin_col[:19] + "..."

    allowed = bool(entry.get("allowed", True))
    tool_allowed = entry.get("tool_allowed")
    status_field = str(entry.get("status") or "").lower()
    exit_code = entry.get("exit_code")
    if not allowed or status_field == "denied":
        status = "DENY"
    elif tool_allowed is False or status_field in ("error", "timeout"):
        status = "ERR"
    elif isinstance(exit_code, int) and exit_code != 0:
        status = f"RC={exit_code}"
    else:
        status = "OK"

    tool = single_line_text(str(entry.get("tool") or "-"))
    transport = single_line_text(str(entry.get("transport_used") or "-"))
    if entry.get("ssh_fell_back"):
        transport = f"{transport}(fb)"
    target = single_line_text(entry_target_label(entry))
    category = single_line_text(str(entry.get("command_category") or entry.get("op_class") or "-"))

    dur = entry.get("duration_ms")
    dur_str = f"{int(dur)}ms" if isinstance(dur, (int, float)) else "-"
    rc_str = f"rc={exit_code}" if isinstance(exit_code, int) else ""

    summary = entry_command_summary(entry, max_len=120)
    parts = [
        ts_str,
        f"{origin_col:<16}",
        f"{status:<6}",
        f"{tool:<22}",
        f"{transport:<7}",
        f"{target:<24}",
        f"{category:<17}",
        f"{dur_str:>7}",
    ]
    if rc_str:
        parts.append(rc_str)
    if summary != "-":
        parts.append(json.dumps(summary))
    return "  ".join(parts)


def format_summary_text(summary: AuditSummary) -> str:
    """Render a concise multi-line summary digest for CLI output."""
    lines = [
        f"Total calls: {summary.total} (ok: {summary.allowed}, denied/failed: {summary.denied}, remote: {summary.remote_exec})",
    ]
    if summary.by_origin:
        origins = ", ".join(f"{k}={v}" for k, v in sorted(summary.by_origin.items()))
        lines.append(f"By origin:     {origins}")
    if summary.by_transport:
        transports = ", ".join(f"{k}={v}" for k, v in sorted(summary.by_transport.items()))
        lines.append(f"By transport:  {transports}")
    if summary.by_category:
        top_cats = sorted(summary.by_category.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        cats = ", ".join(f"{k}={v}" for k, v in top_cats)
        lines.append(f"By category:   {cats}")
    if summary.by_target:
        top_targets = sorted(summary.by_target.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        targets = ", ".join(f"{single_line_text(k)}={v}" for k, v in top_targets)
        lines.append(f"Top targets:   {targets}")
    lines.append(
        f"Query stats:   {summary.elapsed_ms:.1f}ms "
        f"(files scanned={summary.files_scanned}, skipped_mtime={summary.files_skipped_mtime}, "
        f"lines={summary.lines_scanned}, corrupt={summary.corrupt_lines})"
    )
    return "\n".join(lines)

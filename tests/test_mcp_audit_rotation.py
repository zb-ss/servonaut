"""Tests for ``mcp/audit.py`` rotation policy.

A long Claude Code session can drive thousands of tool calls in a day;
without rotation the ``mcp_audit.jsonl`` grows unbounded. The rotation
policy:

- Triggers when size > ``ROTATE_MAX_BYTES`` OR oldest entry > ``ROTATE_MAX_AGE_DAYS``.
- Renames the live file to ``.1``, shifts any prior ``.N`` to ``.N+1``,
  drops anything beyond ``ROTATE_MAX_HISTORY``.
- Atomic via :func:`os.replace` so a crash mid-rotation can't leave
  inconsistent state.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from servonaut.mcp.audit import AuditTrail


def _seed_lines(path: Path, n: int, *, ts: str | None = None) -> None:
    timestamp = ts or datetime.now(timezone.utc).isoformat()
    with open(path, "a") as f:
        for i in range(n):
            f.write(json.dumps({
                "timestamp": timestamp,
                "tool": "list_instances",
                "args": {},
                "allowed": True,
                "reason": "",
                "result_length": 100,
                "_seq": i,
            }) + "\n")


def test_rotates_when_oversize(tmp_path: Path) -> None:
    audit_path = tmp_path / "mcp_audit.jsonl"
    trail = AuditTrail(str(audit_path))
    # Seed enough bytes to trip the threshold.
    big_blob = "x" * 1024
    with open(audit_path, "a") as f:
        for i in range(11_000):  # ~11 MB
            f.write(json.dumps({
                "timestamp": "2026-05-01T00:00:00+00:00",
                "tool": "noop", "args": {}, "allowed": True,
                "reason": "", "result_length": 0, "blob": big_blob,
                "_seq": i,
            }) + "\n")

    rotated = trail._maybe_rotate(max_bytes=10 * 1024 * 1024,
                                  max_age_days=30, max_history=5)
    assert rotated is True
    assert not audit_path.exists()
    assert (tmp_path / "mcp_audit.jsonl.1").exists()


def test_rotates_when_oldest_entry_too_old(tmp_path: Path) -> None:
    audit_path = tmp_path / "mcp_audit.jsonl"
    trail = AuditTrail(str(audit_path))
    old_ts = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    _seed_lines(audit_path, 3, ts=old_ts)

    rotated = trail._maybe_rotate(max_bytes=10**9,  # disable size trigger
                                  max_age_days=30, max_history=5)
    assert rotated is True
    assert not audit_path.exists()
    assert (tmp_path / "mcp_audit.jsonl.1").exists()


def test_no_rotation_when_under_thresholds(tmp_path: Path) -> None:
    audit_path = tmp_path / "mcp_audit.jsonl"
    trail = AuditTrail(str(audit_path))
    _seed_lines(audit_path, 5)  # tiny + recent

    rotated = trail._maybe_rotate(max_bytes=10 * 1024 * 1024,
                                  max_age_days=30, max_history=5)
    assert rotated is False
    assert audit_path.exists()
    assert not (tmp_path / "mcp_audit.jsonl.1").exists()


def test_history_window_bounded(tmp_path: Path) -> None:
    """After several rotations only the last ``max_history`` rolled
    files should remain on disk."""
    audit_path = tmp_path / "mcp_audit.jsonl"
    trail = AuditTrail(str(audit_path))
    old_ts = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()

    for _ in range(8):
        _seed_lines(audit_path, 1, ts=old_ts)
        rotated = trail._maybe_rotate(max_bytes=10**9, max_age_days=30,
                                      max_history=3)
        assert rotated is True

    # Three rotated files survive; .4, .5, .6 must not exist.
    for i in (1, 2, 3):
        assert (tmp_path / f"mcp_audit.jsonl.{i}").exists(), f".{i} missing"
    for i in (4, 5, 6, 7, 8):
        assert not (tmp_path / f"mcp_audit.jsonl.{i}").exists(), f".{i} should be pruned"


def test_corrupt_first_line_does_not_crash(tmp_path: Path) -> None:
    """A truncated/corrupt first line shouldn't crash the rotation
    path — it should silently fall through and leave the file alone."""
    audit_path = tmp_path / "mcp_audit.jsonl"
    audit_path.write_text("garbage\n")
    trail = AuditTrail(str(audit_path))
    rotated = trail._maybe_rotate(max_bytes=10**9, max_age_days=30,
                                  max_history=5)
    assert rotated is False
    assert audit_path.exists()

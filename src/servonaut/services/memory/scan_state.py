"""Persistent runtime state for the background fleet memory auto-scan.

The auto-scan loop's "last run" timestamp must survive process restarts.
Without persistence a long interval (the 24 h default) never elapses for the
common usage pattern of opening the TUI for short sessions — every restart
would reset an in-memory clock to zero and the first scan would never arrive.

This is runtime state, not user configuration, so it lives in its own small
JSON file under ``~/.servonaut/`` (following the existing ``cache.json`` /
``keywords.json`` runtime-files convention) rather than churning
``config.json`` on every scan.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_STATE_FILENAME = "memory_scan_state.json"

# Epoch-seconds timestamp of the last completed auto-scan cycle.
_LAST_RUN_KEY = "auto_scan_last_run_at"


def _default_dir() -> Path:
    """Return the base runtime directory (``~/.servonaut``)."""
    return Path.home() / ".servonaut"


def state_path(base_dir: Optional[Path] = None) -> Path:
    """Return the full path to the scan-state file.

    Args:
        base_dir: Override the default ``~/.servonaut`` directory (tests pass
            a temp dir here).
    """
    return (base_dir or _default_dir()) / _STATE_FILENAME


def read_last_run(base_dir: Optional[Path] = None) -> float:
    """Return the persisted last auto-scan timestamp in epoch seconds.

    Fails soft: a missing, unreadable, or malformed file yields ``0.0`` —
    which callers treat as "never run" — so a corrupt state file can never
    crash startup or the scan loop.

    Args:
        base_dir: Override the default ``~/.servonaut`` directory.

    Returns:
        Epoch seconds of the last completed cycle, or ``0.0`` when unknown.
    """
    path = state_path(base_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return 0.0
    except (OSError, ValueError) as exc:
        logger.debug("memory scan-state read failed (%s); treating as never-run", exc)
        return 0.0
    val = data.get(_LAST_RUN_KEY) if isinstance(data, dict) else None
    # Reject bools (isinstance(True, int) is True) and non-positive values.
    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
        return float(val)
    return 0.0


def write_last_run(ts: float, base_dir: Optional[Path] = None) -> None:
    """Persist *ts* (epoch seconds) as the last auto-scan completion time.

    Best-effort and atomic: writes to a temp file then renames, so a reader
    never sees a half-written file.  Write errors (read-only or full disk)
    are logged and swallowed so persistence failure never propagates into
    the scan loop.

    Args:
        ts: Epoch seconds to persist.
        base_dir: Override the default ``~/.servonaut`` directory.
    """
    path = state_path(base_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({_LAST_RUN_KEY: float(ts)}), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        logger.debug("memory scan-state write failed (%s)", exc)

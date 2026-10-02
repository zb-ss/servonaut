"""Atomic JSON file writes.

Readers, in this process or another one, see either the previous file or
the new one, never a partial write. The data goes to a temporary file with a
unique name next to the target, readable by the owner only, and
``os.replace`` swaps it in (atomic on POSIX and Windows within one file
system). Two processes saving at once never share a temporary file; the
last one to finish wins. A writer that died leaves its temporary file
behind; a later save can sweep those away.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional


def write_json_atomic(
    path: Path, data: Any, *, indent: int = 2, sweep_older_than: Optional[float] = None,
) -> None:
    """Write *data* as JSON to *path* atomically, mode 0o600.

    With *sweep_older_than* (seconds), temporary files of *path* older than
    that, left by writers that died, are removed after the save.

    Raises:
        OSError: The file could not be written; *path* is left as it was.
        TypeError: *data* is not JSON serialisable; *path* is left as it was.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp opens with O_EXCL and mode 0o600: never an existing file or link.
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=indent)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise
    if sweep_older_than:
        _sweep_stale_temporaries(path, sweep_older_than)


def _sweep_stale_temporaries(path: Path, seconds: float) -> None:
    """Remove *path*'s temporary files older than *seconds*; errors are ignored."""
    prefix, cutoff = f".{path.name}.", time.time() - seconds
    try:
        entries = list(path.parent.iterdir())
    except OSError:
        return
    for entry in entries:
        if not (entry.name.startswith(prefix) and entry.name.endswith(".tmp")):
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink()
        except OSError:
            continue

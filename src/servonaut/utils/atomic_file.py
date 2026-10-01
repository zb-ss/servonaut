"""Atomic JSON file writes.

Readers, in this process or another one, see either the previous file or
the new one, never a partial write. The data goes to a temporary file with a
unique name next to the target, readable by the owner only, and
``os.replace`` swaps it in (atomic on POSIX and Windows within one file
system). Two processes saving at once never share a temporary file; the
last one to finish wins.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_json_atomic(path: Path, data: Any, *, indent: int = 2) -> None:
    """Write *data* as JSON to *path* atomically, mode 0o600.

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

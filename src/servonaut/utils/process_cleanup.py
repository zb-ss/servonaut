"""Process-local cleanup shared by normal exit and in-place restart."""

from __future__ import annotations

import atexit
import logging
import threading
from collections.abc import Callable

logger = logging.getLogger(__name__)
_callbacks: list[Callable[[], None]] = []
_lock = threading.Lock()


def register_process_cleanup(callback: Callable[[], None]) -> None:
    """Register an idempotent cleanup for resources owned by this process."""
    with _lock:
        if callback not in _callbacks:
            _callbacks.append(callback)


def cleanup_process_resources() -> None:
    """Run registered cleanups in reverse registration order before exit or exec."""
    with _lock:
        callbacks = tuple(reversed(_callbacks))
    for callback in callbacks:
        try:
            callback()
        except Exception:  # noqa: BLE001 — one cleanup must not prevent the rest
            logger.exception("Process cleanup failed for %s", callback.__qualname__)


atexit.register(cleanup_process_resources)

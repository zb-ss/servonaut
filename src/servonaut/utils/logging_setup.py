"""Size-rotated file logging shared by every Servonaut process entry point."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import Final

# Log rotation budget: 5 × 2 MB → ≤10 MB on disk, enough headroom for a
# debug session without surprising users on a small home partition.  Uses
# stdlib RotatingFileHandler so rotation works identically on Linux / macOS
# / Windows — no logrotate / launchd / Windows-service dependency.
_LOG_MAX_BYTES: Final = 2 * 1024 * 1024
_LOG_BACKUP_COUNT: Final = 5
_LOG_FORMAT: Final = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
# httpx and httpcore log every request URL at INFO; some URLs carry tokens
# in their query string (the relay hub's subscriber token), so they stay at
# WARNING like the other chatty libraries.
_NOISY_LOGGERS: Final = ("botocore", "boto3", "urllib3", "textual", "httpx", "httpcore")


def configure_rotating_log(
    log_dir: Path,
    *,
    filename: str = "servonaut.log",
    debug: bool = False,
) -> Path:
    """Route the root logger to a size-rotated file, and to stderr when debugging.

    Args:
        log_dir: Directory holding the log file; created when missing.
        filename: Log file name inside ``log_dir``.
        debug: If True, also log to stderr and use DEBUG level.

    Returns:
        Path to the active log file.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / filename

    handlers: list[logging.Handler] = [
        logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
            encoding="utf-8",
        ),
    ]
    if debug:
        handlers.append(logging.StreamHandler())

    # basicConfig is a no-op if the root logger already has handlers (e.g.
    # when --mcp and --debug are both set and setup runs twice).
    # force=True ensures rotation is always wired, even on the second call.
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format=_LOG_FORMAT,
        handlers=handlers,
        force=True,
    )
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    return log_file

"""Structured lifecycle log for the relay listener.

One JSON line per event at ``~/.servonaut/logs/relay.log``. Separate from the
main ``servonaut.log`` because that file is debug-noisy — this one is meant
to be grep-friendly when diagnosing connection state over time.

Never logs the OAuth bearer, the Mercure JWT, or anything that looks like a
secret. The redaction list is deliberately conservative: if you need a field
logged, spell it out, don't plumb in an `Authorization` header and hope for
the best.
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger(__name__)


_DEFAULT_LOG_PATH = Path.home() / ".servonaut" / "logs" / "relay.log"

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)\b(?:authorization|token|secret|api[_-]?key|password)\b"
)


def _redact_value(value: Any) -> Any:
    """Best-effort scrub of a single value before it hits disk."""
    if isinstance(value, dict):
        return {k: _redact_value(v) if not _SENSITIVE_KEY_RE.search(k) else "***"
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(v) for v in value]
    if isinstance(value, str) and (
        value.startswith("Bearer ") or value.startswith("eyJ")
    ):
        # JWTs start with eyJ (base64 of `{"`). Bearer headers too.
        return "***"
    return value


def log_relay_event(event: str, **fields: Any) -> None:
    """Append a JSON line describing a relay lifecycle event.

    ``event`` is a short machine name (``connected``, ``stopped``, etc.).
    Extra kwargs are merged in after redaction. Silent on I/O errors —
    logging must never break the listener.
    """
    path = _DEFAULT_LOG_PATH
    safe_fields = {k: _redact_value(v) for k, v in fields.items()
                   if not _SENSITIVE_KEY_RE.search(k)}
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        **safe_fields,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError as e:
        logger.debug("Could not append to relay log: %s", e)


def set_log_path(path: Path) -> None:
    """Override the log path (tests only)."""
    global _DEFAULT_LOG_PATH
    _DEFAULT_LOG_PATH = Path(path)

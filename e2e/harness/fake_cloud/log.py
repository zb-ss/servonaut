"""Request log for FakeCloud, with credentials redacted before storage."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Optional

_SECRET_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "device_code",
        "code",
        "api_key",
        "apikey",
        "authorization",
        "password",
        "passphrase",
        "client_secret",
        "secret",
    }
)


def redact(value: Any) -> Any:
    """Return *value* with credential-looking fields replaced."""
    if isinstance(value, dict):
        return {
            key: ("<redacted>" if key.lower() in _SECRET_KEYS else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class RequestLog:
    """Thread-safe list of the requests FakeCloud received."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[dict[str, Any]] = []

    def add(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._entries.append(entry)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def entries(
        self, path: Optional[str] = None, method: Optional[str] = None
    ) -> list[dict[str, Any]]:
        with self._lock:
            entries = list(self._entries)
        return [
            entry
            for entry in entries
            if (path is None or entry["path"] == path)
            and (method is None or entry["method"] == method)
        ]

    def write_jsonl(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8") as handle:
            for entry in self.entries():
                handle.write(json.dumps(entry) + "\n")

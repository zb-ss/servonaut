"""Credential-free exception locations for disposable desktop test processes."""

from __future__ import annotations

import json
import re
import sys
from collections import deque
from pathlib import Path
from traceback import walk_tb
from types import TracebackType

from .config import load_config

PREFIX = "SERVONAUT_PROBE_ERROR "

_MAX_STDERR_LINE_LENGTH = 200
_REDACT_PATTERNS = (
    (re.compile(r"auth\.[A-Za-z0-9_=-]+"), "auth.<redacted>"),
    (re.compile(r"startServonaut\([^)]*\)"), "startServonaut(<redacted>)"),
    (
        re.compile(r"(?i)\b(token|authorization|cookie|secret|password)\s*([:=])\s*\S+"),
        r"\1\2<redacted>",
    ),
    (re.compile(r"\b(?:https?|wss?)://\S+"), "<url>"),
    (re.compile(r"[A-Za-z]:\\[^\s\"'<>|]+"), "<path>"),
    (re.compile(r"(?<![A-Za-z0-9_:])(?:/[A-Za-z0-9_.~+-]+){2,}"), "<path>"),
)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_stderr_tail(
    text: str,
    *,
    max_lines: int | None = None,
    max_line_length: int = _MAX_STDERR_LINE_LENGTH,
) -> list[str]:
    """Return a bounded, credential- and path-scrubbed tail of stderr lines."""
    limit = load_config().max_diagnostic_entries if max_lines is None else max_lines
    if limit <= 0 or max_line_length <= 0:
        return []
    lines = deque(maxlen=limit)
    for raw in text.splitlines():
        cleaned = _CONTROL_CHARS.sub(" ", raw).strip()
        if not cleaned:
            continue
        for pattern, replacement in _REDACT_PATTERNS:
            cleaned = pattern.sub(replacement, cleaned)
        if len(cleaned) > max_line_length:
            cleaned = cleaned[: max_line_length - 1] + "…"
        lines.append(cleaned)
    return list(lines)


def exception_record(error: BaseException) -> dict[str, object]:
    frames = deque(maxlen=load_config().max_diagnostic_entries)
    for frame, line in walk_tb(error.__traceback__):
        frames.append({"file": Path(frame.f_code.co_filename).name, "line": line})
    return {"exception": type(error).__name__, "frames": list(frames)}


def report_exception(error: BaseException) -> None:
    # Never include exception messages, source text, locals, paths or arguments.
    sys.__stderr__.write(PREFIX + json.dumps(exception_record(error)) + "\n")
    sys.__stderr__.flush()


def exception_hook(
    error_type: type[BaseException],
    error: BaseException,
    traceback: TracebackType | None,
) -> None:
    report_exception(error)


def parse_record(line: bytes) -> dict[str, object] | None:
    if not line.startswith(PREFIX.encode()):
        return None
    try:
        value = json.loads(line[len(PREFIX) :])
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict) or set(value) != {"exception", "frames"}:
        return None
    if not isinstance(value["exception"], str) or not re.fullmatch(
        r"[A-Za-z_]+", value["exception"]
    ):
        return None
    frames = value["frames"]
    if (
        not isinstance(frames, list)
        or len(frames) > load_config().max_diagnostic_entries
    ):
        return None
    for frame in frames:
        if not isinstance(frame, dict) or set(frame) != {"file", "line"}:
            return None
        if not isinstance(frame["file"], str) or not re.fullmatch(
            r"[A-Za-z0-9_.<>-]+", frame["file"]
        ):
            return None
        if type(frame["line"]) is not int or frame["line"] < 1:
            return None
    return value

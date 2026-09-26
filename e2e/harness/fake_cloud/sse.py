"""Server-sent event framing shared by the FakeCloud streams.

Both the Mercure hub (relay) and the hosted chat write their frames with
:func:`frame` and :func:`comment`, and read recorded streams with
:func:`parse`, so the two fakes follow the same wire rules:

* a data value spanning several lines becomes one ``data:`` line each, and
  a reader joins them back with ``\\n``;
* a line starting with ``:`` is a comment (a keep-alive nobody sees);
* after ``field:`` exactly one space is dropped and nothing else, so a
  value's own leading or trailing blanks survive the round trip.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# The line terminators the SSE specification accepts.
_LINE_BREAK = re.compile(r"\r\n|\r|\n")


@dataclass(frozen=True)
class ParsedEvent:
    """One event read back from a stream."""

    event: str
    data: str
    event_id: Optional[str] = None


def frame(data: str = "", *, event: Optional[str] = None, event_id: Optional[str] = None) -> bytes:
    """One event, terminated by the blank line that dispatches it."""
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    if event is not None:
        lines.append(f"event: {event}")
    lines += [f"data: {line}" for line in _LINE_BREAK.split(data)]
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def comment(text: str = "") -> bytes:
    """A comment frame: keeps a connection busy without dispatching an event."""
    return "".join(f": {line}\n" for line in _LINE_BREAK.split(text)).encode("utf-8") + b"\n"


def _field(line: str) -> tuple[str, str]:
    name, _, value = line.partition(":")
    return name, value[1:] if value.startswith(" ") else value


def parse(text: str) -> list[ParsedEvent]:
    """The events in *text*, in order (comments and unknown fields skipped)."""
    events: list[ParsedEvent] = []
    name, event_id, data = "", None, []
    for line in [*_LINE_BREAK.split(text), ""]:
        if line == "":
            if data or name:
                events.append(ParsedEvent(name or "message", "\n".join(data), event_id))
            name, event_id, data = "", None, []
        elif line.startswith(":"):
            continue
        else:
            key, value = _field(line)
            if key == "event":
                name = value
            elif key == "data":
                data.append(value)
            elif key == "id":
                event_id = value
    return events

"""Safe URL path segments for ids the service or a teammate supplies."""
from __future__ import annotations

import re

#: Plain identifier characters only: no ``/``, ``%``, dots up front, spaces
#: or control characters.
PATH_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def check_segment(value: object, what: str) -> str:
    """Return *value* if it may sit in a URL path, else raise ``ValueError``."""
    if not isinstance(value, str) or not PATH_SAFE.match(value) or ".." in value:
        raise ValueError(f"{what} is not a valid identifier")
    return value

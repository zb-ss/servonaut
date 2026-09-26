"""What clients actually sent FakeCloud, unredacted, for "never on the wire" checks.

The request log (``log.py``) is redacted before storage because it is copied
into public failure artifacts; a check against it cannot fail on a secret
sent under an innocuous key, in a header or in a query string. This capture
keeps every request byte for byte instead: method, raw path and query, every
header and the raw body. It lives in memory only, is dropped on every reset,
and is never written anywhere.

:func:`find_on_wire` looks for a value in all of it, in the forms a client
could have used to carry it: as is, JSON-escaped, URL-encoded, hex and
base64 (standard and URL-safe alphabets, at every byte alignment, so a
value encoded inside a larger blob is found too). Encoded forms of short
values would match random ciphertext by chance, so values must be at least
:data:`MIN_VALUE_LENGTH` bytes long.

It also holds the named 4xx answers a journey expects (:data:`EXPECTED`),
for :meth:`FakeCloud.assert_no_unexpected_errors`.
"""

from __future__ import annotations

import base64
import json
import re
import threading
from dataclasses import dataclass
from typing import Iterable, Union
from urllib.parse import quote, quote_plus

MIN_VALUE_LENGTH = 8
# The shortest encoded fragment worth matching (48 bits of base64).
_MIN_NEEDLE = 8

Value = Union[str, bytes]


@dataclass(frozen=True)
class WireRequest:
    """One request exactly as it arrived."""

    method: str
    target: bytes  # raw path and query string
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes

    def label(self) -> str:
        return f"{self.method} {self.target.split(b'?', 1)[0].decode('latin-1')}"

    def parts(self) -> Iterable[tuple[str, bytes]]:
        yield "path or query", self.target
        for name, value in self.headers:
            yield f"header {name.decode('latin-1')}", value
        yield "body", self.body


class WireCapture:
    """Thread-safe, in-memory list of raw requests."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: list[WireRequest] = []

    def add(self, request: WireRequest) -> None:
        with self._lock:
            self._requests.append(request)

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()

    def mark(self) -> int:
        """A position to pass as ``since`` to look at later requests only."""
        with self._lock:
            return len(self._requests)

    def requests(self, since: int = 0) -> list[WireRequest]:
        with self._lock:
            return list(self._requests[since:])


def _base64_forms(data: bytes) -> set[bytes]:
    """Base64 fragments that any encoding containing *data* must include."""
    forms: set[bytes] = set()
    for offset in range(3):
        encoded = base64.b64encode(b"\0" * offset + data).rstrip(b"=")
        # Character k carries bits [6k, 6k + 6); keep those that come from
        # *data* alone.
        start = -(-8 * offset // 6)
        end = (8 * (offset + len(data))) // 6
        fragment = encoded[start:end]
        if len(fragment) >= _MIN_NEEDLE:
            forms.add(fragment)
            forms.add(fragment.translate(bytes.maketrans(b"+/", b"-_")))
    return forms


def encoded_forms(value: Value) -> dict[str, set[bytes]]:
    """Every form of *value* to look for, by encoding name."""
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if len(raw) < MIN_VALUE_LENGTH:
        raise ValueError(
            f"a value checked on the wire must be at least {MIN_VALUE_LENGTH} bytes, "
            "or its encoded forms match random ciphertext"
        )
    forms: dict[str, set[bytes]] = {
        "as is": {raw},
        "hex": {raw.hex().encode(), raw.hex().upper().encode()},
        "base64": _base64_forms(raw),
    }
    if isinstance(value, str):
        escaped = json.dumps(value)[1:-1].encode()
        url = {quote(value, safe="").encode(), quote_plus(value, safe="").encode()}
        url |= {re.sub(rb"%[0-9A-F]{2}", lambda m: m.group(0).lower(), u) for u in url}
        forms["JSON-escaped"] = {escaped}
        forms["URL-encoded"] = url - {raw}
    return forms


def find_on_wire(requests: Iterable[WireRequest], value: Value) -> list[str]:
    """Where *value* appears, described without repeating it."""
    forms = encoded_forms(value)
    found = []
    for request in requests:
        for part, data in request.parts():
            for encoding, needles in forms.items():
                if any(needle and needle in data for needle in needles):
                    found.append(f"{encoding} in the {part} of {request.label()}")
    return found


# ---------------------------------------------------------------------------
# Expected error answers
# ---------------------------------------------------------------------------

# (method, path pattern, status) of 4xx answers that are part of a normal
# journey, by what they mean. Anything else a journey receives fails it.
EXPECTED: dict[str, tuple[tuple[str, str, int], ...]] = {
    # No secret store chosen yet: the client falls back to the local one.
    "no secret store on file": (
        ("GET", r"/api/v1/me/secrets-config", 404),
        ("GET", r"/api/v1/teams/[^/]+/secrets-config", 404),
    ),
    # First Memory Sync set-up: no keypair yet, so the client enrols one.
    "no keypair enrolled": (("GET", r"/api/v1/memory/keys/me", 404),),
    # After a sync the client pulls notes back; with none stored the service
    # answers not_found, which the client reads as "nothing to pull".
    "no notes to pull": (
        ("GET", r"/api/v1/memory/[^/]+/annotations", 404),
        ("GET", r"/api/v1/memory/[^/]+/findings", 404),
    ),
    # No SSH key reference stored for an instance.
    "no key reference": (("GET", r"/api/v1/me/instances/[^/]+/[^/]+/ssh-ref", 404),),
}


def expected(*names: str) -> tuple[tuple[str, str, int], ...]:
    """The allowlist entries for the named situations."""
    return tuple(entry for name in names for entry in EXPECTED[name])

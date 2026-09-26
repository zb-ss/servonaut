"""CloudWatch Logs filter patterns for the local AWS endpoint.

moto matches a filter pattern only as plain substrings, and treats anything
else, a JSON selector included, as "match every event". A journey could then
pass while the pattern Servonaut sent would match nothing on AWS, or the
other way round. :func:`install` replaces that with the part of the
documented pattern syntax the journeys rely on, and nothing more:

- an empty pattern matches every event;
- one or more terms, each ``"quoted"`` or made of letters, digits and
  underscores: the event contains every term (case-sensitive);
- a JSON selector with one condition, ``{ $.a.b = "text" }``: the event is
  a JSON object whose string field equals the text.

Everything else is refused rather than guessed at: ``?`` and ``-`` terms,
unquoted terms with punctuation (CloudWatch tokenises those), ``*``
wildcards, ``!=``, ``&&`` and ``||``, numeric comparisons, comparing text
with a field that is not a string, and space-delimited patterns. A refused
pattern gets the ``InvalidParameterException`` AWS answers for a pattern it
cannot parse, and is recorded; the ``moto`` fixture fails the journey that
sent it, naming the pattern, so a gap here is never mistaken for a result.
"""

from __future__ import annotations

import inspect
import json
import re
import threading
from typing import Any, Callable

_PLAIN_TERM = re.compile(r"^[A-Za-z0-9_]+$")
_QUOTED_TERM = re.compile(r'^"([^"*]+)"$')
_SELECTOR = re.compile(r'^\{\s*\$\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\s*=\s*"([^"*]*)"\s*\}$')


class UnsupportedFilterPattern(ValueError):
    """The pattern uses syntax the emulation does not implement."""


def _field(document: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(document, dict) or part not in document:
            return None
        document = document[part]
    return document


def _selector(pattern: str) -> Callable[[str], bool]:
    match = _SELECTOR.match(pattern)
    if match is None:
        raise UnsupportedFilterPattern(
            'only { $.field = "text" } selectors are emulated (one condition, no wildcard)'
        )
    path, expected = match.groups()

    def matches(message: str) -> bool:
        try:
            document = json.loads(message)
        except ValueError:
            return False
        value = _field(document, path)
        if value is None:
            return False
        if not isinstance(value, str):
            raise UnsupportedFilterPattern(
                f"$.{path} holds {type(value).__name__} {value!r}, compared with text"
            )
        return value == expected

    return matches


def _terms(pattern: str) -> Callable[[str], bool]:
    terms = []
    for token in re.findall(r'"[^"]*"|\S+', pattern):
        quoted = _QUOTED_TERM.match(token)
        if quoted:
            terms.append(quoted.group(1))
        elif _PLAIN_TERM.match(token):
            terms.append(token)
        else:
            raise UnsupportedFilterPattern(f"term {token!r} (only quoted or plain terms)")

    def matches(message: str) -> bool:
        return all(term in message for term in terms)

    return matches


def compile_pattern(pattern: str | None) -> Callable[[str], bool]:
    """A predicate over event messages, or :class:`UnsupportedFilterPattern`."""
    text = (pattern or "").strip()
    if not text:
        return lambda message: True
    if text.startswith("{"):
        return _selector(text)
    if text.startswith("["):
        raise UnsupportedFilterPattern("space-delimited patterns are not emulated")
    return _terms(text)


class EmulatedFilterPattern:
    """Drop-in for moto's ``EventMessageFilter`` (same constructor and method)."""

    def __init__(self, pattern: str) -> None:
        self._matches = compile_pattern(pattern)

    def matches(self, message: str) -> bool:
        return self._matches(message)


class _Refusals:
    """Patterns refused while the current journey ran (the server is threaded)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: list[str] = []

    def add(self, pattern: str, reason: str) -> None:
        with self._lock:
            self._items.append(f"{pattern!r}: {reason}")

    def take(self) -> list[str]:
        with self._lock:
            items, self._items = self._items, []
        return items


_REFUSALS = _Refusals()


def take_refused() -> list[str]:
    """Patterns refused since the last call, each with the reason."""
    return _REFUSALS.take()


def install(monkeypatch: Any) -> None:
    """Use the emulation in this process's moto server for one journey."""
    from moto.logs import models
    from moto.logs.exceptions import InvalidParameterException

    backend = getattr(models, "LogsBackend", None)
    if not hasattr(models, "EventMessageFilter") or not hasattr(backend, "filter_log_events"):
        raise RuntimeError(
            "moto.logs.models changed shape; update e2e/harness/aws_logs_filter.py "
            "for this moto version"
        )
    original = backend.filter_log_events
    signature = inspect.signature(original)

    def filter_log_events(*args: Any, **kwargs: Any) -> Any:
        pattern = signature.bind(*args, **kwargs).arguments.get("filter_pattern") or ""
        try:
            compile_pattern(pattern)  # refuse before reading, as AWS does
            return original(*args, **kwargs)
        except UnsupportedFilterPattern as exc:
            _REFUSALS.add(pattern, str(exc))
            raise InvalidParameterException(
                f"Invalid filter pattern (not emulated by the e2e suite): {exc}"
            ) from exc

    _REFUSALS.take()
    monkeypatch.setattr(models, "EventMessageFilter", EmulatedFilterPattern)
    monkeypatch.setattr(backend, "filter_log_events", filter_log_events)

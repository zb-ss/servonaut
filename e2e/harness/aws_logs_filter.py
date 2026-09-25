"""CloudWatch Logs filter patterns for the local AWS endpoint.

moto matches a filter pattern only as plain substrings, and treats anything
else, a JSON selector included, as "match every event". A journey could then
pass while the pattern Servonaut sent would match nothing on AWS, or the
other way round. :func:`install` swaps in the subset of the documented
pattern syntax that Servonaut's screens and tools produce:

- ``"quoted term"``: the event contains the text (case-sensitive);
- bare terms of letters, digits and underscores: the event contains every
  one; ``?term`` terms: it contains at least one; ``-term``: it does not;
- a bare term with any other character (``9.9.9.9``, ``/login``) matches
  nothing, because CloudWatch requires such terms to be quoted;
- ``{ $.a.b = "x" }`` JSON selectors, with ``=`` / ``!=`` joined by ``&&``:
  the event is a JSON object whose field compares as stated.

Any other syntax raises, so an unsupported pattern fails the journey loudly
instead of silently matching everything.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, Callable

_PLAIN_TERM = re.compile(r"^[A-Za-z0-9_]+$")
_SELECTOR_CONDITION = re.compile(r"^\$\.([A-Za-z0-9_.]+)\s*(=|!=)\s*(.+)$")


class UnsupportedFilterPattern(ValueError):
    """The pattern uses syntax the emulation does not implement."""


def _field(document: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(document, dict) or part not in document:
            return None
        document = document[part]
    return document


def _selector(pattern: str) -> Callable[[str], bool]:
    body = pattern.strip()[1:-1].strip()
    if "||" in body:
        raise UnsupportedFilterPattern(f"'||' in JSON selector {pattern!r}")
    checks = []
    for condition in body.split("&&"):
        match = _SELECTOR_CONDITION.match(condition.strip())
        if match is None:
            raise UnsupportedFilterPattern(f"JSON selector condition {condition!r}")
        path, operator, raw = match.groups()
        raw = raw.strip()
        expected = raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw
        checks.append((path, operator == "=", expected))

    def matches(message: str) -> bool:
        try:
            document = json.loads(message)
        except ValueError:
            return False
        for path, want_equal, expected in checks:
            value = _field(document, path)
            if (value is not None and str(value) == expected) != want_equal:
                return False
        return True

    return matches


def _terms(pattern: str) -> Callable[[str], bool]:
    try:
        tokens = shlex.split(pattern, posix=False)
    except ValueError as exc:
        raise UnsupportedFilterPattern(f"unbalanced quotes in {pattern!r}") from exc
    required: list[str] = []
    optional: list[str] = []
    excluded: list[str] = []
    never = False
    for token in tokens:
        target = required
        if token[0] in "?-" and len(token) > 1:
            target = optional if token[0] == "?" else excluded
            token = token[1:]
        if len(token) >= 2 and token.startswith('"') and token.endswith('"'):
            target.append(token[1:-1])
        elif _PLAIN_TERM.match(token):
            target.append(token)
        elif target is required:
            never = True  # an unquoted term with punctuation matches nothing
        else:
            raise UnsupportedFilterPattern(f"unquoted term {token!r} in {pattern!r}")

    def matches(message: str) -> bool:
        if never:
            return False
        if any(term in message for term in excluded):
            return False
        if optional and not any(term in message for term in optional):
            return False
        return all(term in message for term in required)

    return matches


class EmulatedFilterPattern:
    """Drop-in for moto's ``EventMessageFilter`` (same constructor and method)."""

    def __init__(self, pattern: str) -> None:
        text = (pattern or "").strip()
        if not text:
            self._matches: Callable[[str], bool] = lambda message: True
        elif text.startswith("{") and text.endswith("}"):
            self._matches = _selector(text)
        elif text.startswith("["):
            raise UnsupportedFilterPattern(f"space-delimited pattern {pattern!r}")
        else:
            self._matches = _terms(text)

    def matches(self, message: str) -> bool:
        return self._matches(message)


def install(monkeypatch: Any) -> None:
    """Use the emulation in this process's moto server for one journey."""
    from moto.logs import models

    if not hasattr(models, "EventMessageFilter"):
        raise RuntimeError(
            "moto.logs.models no longer defines EventMessageFilter; "
            "update e2e/harness/aws_logs_filter.py for this moto version"
        )
    monkeypatch.setattr(models, "EventMessageFilter", EmulatedFilterPattern)

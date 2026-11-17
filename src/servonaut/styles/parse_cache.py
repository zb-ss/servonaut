"""Share parsed stylesheet sources without sharing values across themes.

Textual's per-stylesheet cache misses again when it reparses into a fresh
stylesheet. The bounded process cache includes every parse input, including
all variables. Parsed rules remain read-only, as in Textual's own cache.
Compatibility checks leave Textual's implementation in place on an unknown
API. The scoped contexts also let tests exercise that unmodified behavior.
"""

from __future__ import annotations

import inspect
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Any

from textual.cache import LRUCache
from textual.css.model import RuleSet
from textual.css.stylesheet import Stylesheet


def _configured_capacity() -> int:
    """A packaged default, overridable per process; zero disables sharing."""
    try:
        value = os.environ.get("SERVONAUT_STYLE_CACHE_SIZE")
        if value is None:
            defaults = json.loads(Path(__file__).with_name("cache.json").read_text())
            value = defaults["parse_cache_entries"]
        return max(0, int(value))
    except (OSError, ValueError, TypeError, KeyError):
        return 0


_capacity = _configured_capacity()
_shared: LRUCache[tuple, Any] = LRUCache(_capacity)
_lock = RLock()
_blocked = 0
_original_parse = getattr(Stylesheet, "_parse_rules", None)
_original_hash = RuleSet.__hash__


def _compatible(stylesheet: Stylesheet) -> bool:
    """Check the private parse seam and identity-hash semantics we depend on."""
    try:
        parameters = tuple(inspect.signature(_original_parse).parameters)
        cache = stylesheet._parse_cache
        variables = stylesheet._variables
    except (AttributeError, TypeError, ValueError):
        return False
    hash_code = getattr(_original_hash, "__code__", None)
    identity_hash = _original_hash is object.__hash__ or (
        hash_code is not None and hash_code.co_names == ("id",)
    )
    return bool(
        parameters == (
            "self", "css", "read_from", "is_default_rules", "tie_breaker", "scope",
        )
        and isinstance(variables, dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in variables.items())
        and all(callable(getattr(cache, name, None)) for name in (
            "__contains__", "__getitem__", "__setitem__",
        ))
        and all(callable(getattr(_shared, name, None)) for name in ("get", "set"))
        and identity_hash
    )


def _parse_rules(
    self: Stylesheet, css: str, read_from: tuple[str, str],
    is_default_rules: bool = False, tie_breaker: int = 0, scope: str = "",
) -> list[RuleSet]:
    key = (css, read_from, is_default_rules, tie_breaker, scope)
    try:
        local = self._parse_cache
        local_hit = key in local
    except (AttributeError, TypeError):
        return _original_parse(self, css, read_from, is_default_rules, tie_breaker, scope)
    if local_hit:
        return _original_parse(self, css, read_from, is_default_rules, tie_breaker, scope)
    try:
        shared_key = (*key, frozenset(self._variables.items()))
    except (AttributeError, TypeError):
        return _original_parse(self, css, read_from, is_default_rules, tie_breaker, scope)
    with _lock:
        rules = _shared.get(shared_key)
    if rules is None:
        rules = _original_parse(self, css, read_from, is_default_rules, tie_breaker, scope)
        with _lock:
            _shared.set(shared_key, rules)
    else:
        local[key] = rules
    return rules


def install_shared_parse_cache(stylesheet: Stylesheet | None = None) -> bool:
    """Enable compatible process-wide caching, without replacing other patches."""
    with _lock:
        if _blocked or not _capacity:
            return False
        if getattr(Stylesheet, "_parse_rules", None) not in (_original_parse, _parse_rules):
            return False
        if RuleSet.__hash__ not in (_original_hash, object.__hash__):
            return False
        if not _compatible(stylesheet if stylesheet is not None else Stylesheet()):
            return False
        Stylesheet._parse_rules = _parse_rules  # type: ignore[method-assign]
        RuleSet.__hash__ = object.__hash__  # type: ignore[method-assign,assignment]
        return True


@contextmanager
def shared_parse_cache() -> Iterator[LRUCache]:
    """Use the product implementation in a scope, restoring its previous state."""
    previous_parse = getattr(Stylesheet, "_parse_rules", None)
    previous_hash = RuleSet.__hash__
    installed = install_shared_parse_cache()
    try:
        yield _shared
    finally:
        if installed:
            Stylesheet._parse_rules = previous_parse  # type: ignore[method-assign]
            RuleSet.__hash__ = previous_hash  # type: ignore[method-assign]


@contextmanager
def stock_parse_cache() -> Iterator[None]:
    """Keep a stock-cache test stock even if it constructs the product app."""
    global _blocked
    previous_parse = getattr(Stylesheet, "_parse_rules", None)
    previous_hash = RuleSet.__hash__
    _blocked += 1
    if previous_parse is _parse_rules:
        Stylesheet._parse_rules = _original_parse  # type: ignore[method-assign]
    if previous_hash is object.__hash__:
        RuleSet.__hash__ = _original_hash  # type: ignore[method-assign]
    try:
        yield
    finally:
        _blocked -= 1
        Stylesheet._parse_rules = previous_parse  # type: ignore[method-assign]
        RuleSet.__hash__ = previous_hash  # type: ignore[method-assign]

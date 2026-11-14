"""Share parsed CSS between the Textual apps one test process starts.

Every app builds its own ``Stylesheet`` with an empty parse cache, and
``Stylesheet.reparse()`` builds another, so the same 300 KB bundle was parsed
about three times per app. Parsed rule sets are only read after parsing
(Textual already shares them between a stylesheet and its ``reparse()``
copy), so one bounded process-wide LRU can serve every stylesheet. Variables
are part of the key: the same source under a different theme parses again.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from textual.cache import LRUCache
from textual.css.stylesheet import Stylesheet

SHARED_PARSE_CACHE_SIZE = 4096

_shared: LRUCache[tuple, Any] = LRUCache(SHARED_PARSE_CACHE_SIZE)


@contextmanager
def shared_parse_cache() -> Iterator[LRUCache]:
    """Route ``Stylesheet._parse_rules`` through the process-wide cache."""
    original = Stylesheet._parse_rules

    def parse_rules(self, css, read_from, is_default_rules=False, tie_breaker=0, scope=""):
        key = (css, read_from, is_default_rules, tie_breaker, scope)
        if key in self._parse_cache:
            return original(self, css, read_from, is_default_rules, tie_breaker, scope)
        shared_key = (*key, frozenset(self._variables.items()))
        rules = _shared.get(shared_key)
        if rules is None:
            rules = original(self, css, read_from, is_default_rules, tie_breaker, scope)
            _shared.set(shared_key, rules)
        else:
            self._parse_cache[key] = rules
        return rules

    Stylesheet._parse_rules = parse_rules  # type: ignore[method-assign]
    try:
        yield _shared
    finally:
        Stylesheet._parse_rules = original  # type: ignore[method-assign]

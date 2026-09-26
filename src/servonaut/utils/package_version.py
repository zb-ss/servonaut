"""Order Python package versions without a third-party dependency.

The update check compares the running version with what the package index
publishes. ``packaging`` is not one of Servonaut's install requirements, so a
pip or pipx install cannot rely on it being present; this module covers the
public PEP 440 versions an index serves in normalized form: a release number
(``1.2.3``) with an optional pre-release (``a1``, ``b2``, ``rc3``),
post-release (``.post1``) and development release (``.dev4``). Epochs and
local versions are not supported: they parse as ``None``, so callers can skip
them instead of guessing an order.
"""

from __future__ import annotations

import functools
import itertools
import re
from dataclasses import dataclass
from typing import Final, Optional

_PUBLIC_VERSION: Final = re.compile(
    r"(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:(?P<pre_label>a|b|rc)(?P<pre_number>[0-9]+))?"
    r"(?:\.post(?P<post>[0-9]+))?"
    r"(?:\.dev(?P<dev>[0-9]+))?"
)
_PRE_RELEASE_ORDER: Final = {"a": 0, "b": 1, "rc": 2}
# Sort positions outside every real pre-release: a development release of a
# final version comes before its alphas, and a final version after its
# release candidates.
_BEFORE_ANY_PRE_RELEASE: Final = (-1, 0)
_AFTER_ANY_PRE_RELEASE: Final = (len(_PRE_RELEASE_ORDER), 0)


@functools.total_ordering
@dataclass(frozen=True, eq=False)
class PackageVersion:
    """A parsed public version, ordered as PEP 440 specifies."""

    text: str
    release: tuple[int, ...]
    pre: Optional[tuple[int, int]] = None
    post: Optional[int] = None
    dev: Optional[int] = None

    @classmethod
    def parse(cls, text: object) -> Optional["PackageVersion"]:
        """Parse a normalized public version, or return None."""
        if not isinstance(text, str):
            return None
        match = _PUBLIC_VERSION.fullmatch(text)
        if match is None:
            return None
        label = match.group("pre_label")
        return cls(
            text=text,
            release=tuple(int(part) for part in match.group("release").split(".")),
            pre=(
                (_PRE_RELEASE_ORDER[label], int(match.group("pre_number")))
                if label
                else None
            ),
            post=_optional_int(match.group("post")),
            dev=_optional_int(match.group("dev")),
        )

    @property
    def is_prerelease(self) -> bool:
        """True for alpha, beta, release-candidate and development releases."""
        return self.pre is not None or self.dev is not None

    def _key(self) -> tuple[object, ...]:
        release = tuple(
            reversed(list(itertools.dropwhile(lambda part: part == 0, reversed(self.release))))
        )
        if self.pre is not None:
            pre = self.pre
        elif self.post is None and self.dev is not None:
            pre = _BEFORE_ANY_PRE_RELEASE
        else:
            pre = _AFTER_ANY_PRE_RELEASE
        post = -1 if self.post is None else self.post
        dev = (1, 0) if self.dev is None else (0, self.dev)
        return (release, pre, post, dev)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PackageVersion):
            return NotImplemented
        return self._key() == other._key()

    def __lt__(self, other: "PackageVersion") -> bool:
        if not isinstance(other, PackageVersion):
            return NotImplemented
        return self._key() < other._key()

    def __hash__(self) -> int:
        return hash(self._key())


def _optional_int(value: Optional[str]) -> Optional[int]:
    return None if value is None else int(value)

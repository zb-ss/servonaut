"""Known product bugs, recorded as strict expected failures.

A journey that documents a bug raises a dedicated exception at the exact
point where the product misbehaves, and is marked with :func:`known_bug`
naming that exception. The fix makes the journey pass, and strict mode then
fails the run as "unexpectedly passing", so the marker is removed in the
same change as the fix. Any other failure is still reported as a failure.
"""

from __future__ import annotations

import pytest


class ProductBug(AssertionError):
    """Base class for the symptom a known-bug journey checks for."""


def known_bug(reason: str, *, raises: type[ProductBug]) -> pytest.MarkDecorator:
    """``xfail(strict=True)`` that only accepts the documented symptom."""
    if not (isinstance(raises, type) and issubclass(raises, ProductBug)):
        raise TypeError("known_bug needs a ProductBug subclass naming the symptom")
    return pytest.mark.xfail(strict=True, raises=raises, reason=reason)

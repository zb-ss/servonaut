"""Mark the exact symptom of a known product gap.

A journey that documents a known bug is ``xfail(strict=True,
raises=KnownGap)`` and raises :class:`KnownGap` only from the check that
observes the bug's symptom. Any other failure (a setup problem, a different
regression) still fails the journey, and once the bug is fixed the journey
passes, which strict mode reports so the marker can be removed.
"""

from __future__ import annotations


class KnownGap(AssertionError):
    """The journey observed the documented symptom of a known product gap."""

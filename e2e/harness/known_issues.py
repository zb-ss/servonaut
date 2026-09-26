"""Pin a journey's expected failure to the exact symptom of a known bug.

A journey that documents a product bug is marked
``xfail(strict=True, raises=KnownIssue)`` and calls :func:`known_issue`
where the bug shows. The test then expected-fails only for that symptom:

* the bug still behaves as documented -> ``KnownIssue`` -> xfail;
* it fails some other way -> an ordinary error, which ``raises=`` does not
  accept -> the test fails and the change gets looked at;
* the bug is fixed -> the journey passes -> strict XPASS fails the run, as
  a reminder to remove the marker in the same change as the fix.
"""

from __future__ import annotations


class KnownIssue(AssertionError):
    """A journey observed the documented symptom of a known product bug."""


def known_issue(observed: bool, symptom: str) -> None:
    """Raise :class:`KnownIssue` when the documented *symptom* was *observed*."""
    if observed:
        raise KnownIssue(symptom)

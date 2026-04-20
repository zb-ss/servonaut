"""Redaction utilities for server memory raw output.

This module provides the callable contract that ``MemoryStore`` uses to
redact sensitive data from ``raw_output`` before it is written to disk.

T9 is responsible for implementing the real regex-based redaction library.
The plumbing (callable slot on MemoryStore, seam in MemoryService) is wired
here so T9 can drop in a real implementation by replacing ``noop_redactor``
with a function that matches the same signature.

TODO: T9 — implement real regex redaction library here.
"""

from __future__ import annotations


def noop_redactor(text: str) -> str:
    """No-op redactor: returns *text* unchanged.

    This is the default redactor used before T9 ships.  It satisfies the
    ``Callable[[str], str]`` contract expected by ``MemoryStore`` so the
    plumbing is live end-to-end.

    Args:
        text: Raw output string (e.g. from a prober command).

    Returns:
        The same string, unmodified.
    """
    return text

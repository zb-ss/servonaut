"""Showing text another user or the service chose, safely, in a terminal."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# Bidirectional-text controls that can make a shown name read differently.
_BIDI_CONTROLS = frozenset("‎‏‪‫‬‭‮⁦⁧⁨⁩")


def terminal_safe(value: object) -> str:
    """*value* as inert text: no control characters, escape sequences or bidi controls."""
    return "".join(
        char for char in str(value)
        if not (ord(char) < 32 or 127 <= ord(char) <= 159 or char in _BIDI_CONTROLS)
    )


def flatten_rows(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Dotted ``key: value`` rows of nested mappings and lists, nested data included."""
    if isinstance(value, Mapping):
        rows: list[tuple[str, Any]] = []
        for key, item in value.items():
            rows.extend(flatten_rows(item, f"{prefix}{key}."))
        return rows if rows or not prefix else [(prefix[:-1], "{}")]
    if isinstance(value, list):
        if not value:
            return [(prefix[:-1], "[]")] if prefix else []
        rows = []
        for index, item in enumerate(value, start=1):
            rows.extend(flatten_rows(item, f"{prefix}{index}."))
        return rows
    return [(prefix[:-1], value)]


def _count(number: int, one: str, many: str) -> str:
    return f"{number} {one if number == 1 else many}"


def grant_summary(results: Any) -> str:
    """What a grant-processing run did, in one or two sentences for people.

    *results* is ``process_grants``' list of per-vault outcomes (``accepted``,
    ``skipped`` and ``pending_confirmation`` entries).
    """
    runs = [run for run in results if isinstance(run, Mapping)] if isinstance(results, list) else []
    granted = sum(len(run.get("accepted") or []) for run in runs)
    skipped = sum(len(run.get("skipped") or []) for run in runs)
    pending = [
        entry for run in runs for entry in (run.get("pending_confirmation") or [])
        if isinstance(entry, Mapping)
    ]
    if not (granted or skipped or pending):
        return "No one is waiting for access."
    sentences = []
    if granted:
        sentences.append(f"Granted access to {_count(granted, 'member', 'members')}.")
    if pending:
        changed = sum(1 for entry in pending if entry.get("identity_changed") is True)
        waiting = f"{_count(len(pending), 'member still needs', 'members still need')} approval before getting access"
        if changed:
            waiting += f" ({changed} with a changed vault identity)"
        sentences.append(waiting + ".")
    if skipped:
        sentences.append(f"{_count(skipped, 'grant was', 'grants were')} not applied.")
    return " ".join(sentences)

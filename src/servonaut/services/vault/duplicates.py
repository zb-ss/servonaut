"""Decide which copies of a duplicated vault key may be pre-selected for deletion.

Pure logic: no Textual, no IO. A copy that is in use, or whose usage is not
known, is never selected.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence

from servonaut.services.vault.errors import VaultKeyInUse

UNKNOWN = "unknown"
IN_USE = "in_use"
UNUSED = "unused"


def copy_state(usage: Optional[Mapping[str, Any]]) -> str:
    """Return "unknown", "in_use" or "unused" for one copy's usage record.

    A copy the usage proves to be in use is in use even when another read for
    it failed; "unused" needs every read to have succeeded.
    """
    if not isinstance(usage, Mapping):
        return UNKNOWN
    try:
        in_use = VaultKeyInUse.from_usage(usage).in_use
    except (KeyError, TypeError, ValueError):
        return UNKNOWN
    if in_use:
        return IN_USE
    return UNKNOWN if usage.get("error") or usage.get("unchecked") else UNUSED


def created_time(item: Mapping[str, Any]) -> Optional[datetime]:
    """Parse ``created_at`` into an aware datetime, or None when absent or invalid."""
    raw = item.get("created_at")
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class DuplicateCopies:
    selected: tuple[str, ...]
    fingerprints: int
    several_in_use: tuple[tuple[str, ...], ...]
    unchecked: tuple[str, ...]
    # Keys that contributed a selected copy; ``fingerprints`` counts every key stored more than once.
    selected_keys: int = 0


def _usage_for(item_id: str, usages: Optional[Mapping[str, Mapping[str, Any]]]) -> Optional[Mapping[str, Any]]:
    if usages is None:
        return None
    found = usages.get(item_id)
    return found if found is not None else usages.get(item_id.lower())


def _oldest_position(group: Sequence[tuple[int, str, Mapping[str, Any]]]) -> int:
    """Position (in ``group``) of the copy to keep: oldest dated, undated last, ties by listing order."""
    def order(entry: tuple[int, tuple[int, str, Mapping[str, Any]]]) -> tuple[int, float, int]:
        _, (index, _item_id, item) = entry
        when = created_time(item)
        return (1, 0.0, index) if when is None else (0, when.timestamp(), index)

    return min(enumerate(group), key=order)[0]


def duplicate_copies(
    items: Sequence[Mapping[str, Any]],
    usages: Optional[Mapping[str, Mapping[str, Any]]],
) -> DuplicateCopies:
    groups: dict[str, list[tuple[int, str, Mapping[str, Any]]]] = {}
    for index, item in enumerate(items):
        fingerprint = item.get("public_fingerprint")
        item_id = item.get("item_id")
        if isinstance(fingerprint, str) and fingerprint and isinstance(item_id, str) and item_id:
            groups.setdefault(fingerprint, []).append((index, item_id, item))

    picked: set[str] = set()
    several: list[tuple[str, ...]] = []
    unchecked: set[str] = set()
    count = 0
    contributing = 0
    for group in groups.values():
        if len(group) < 2:
            continue
        count += 1
        states = [copy_state(_usage_for(item_id, usages)) for _, item_id, _ in group]
        in_use = tuple(entry[1] for entry, state in zip(group, states) if state == IN_USE)
        unknown = {entry[1] for entry, state in zip(group, states) if state == UNKNOWN}
        unchecked |= unknown
        if len(in_use) >= 2:
            several.append(in_use)
        keep = set(in_use) | unknown
        if not keep:
            keep.add(group[_oldest_position(group)][1])
        extra = [entry[1] for entry in group if entry[1] not in keep]
        picked.update(extra)
        contributing += bool(extra)

    ordered = tuple(
        item["item_id"] for item in items
        if isinstance(item.get("item_id"), str) and item["item_id"] in picked
    )
    listed = tuple(
        item["item_id"] for item in items
        if isinstance(item.get("item_id"), str) and item["item_id"] in unchecked
    )
    return DuplicateCopies(ordered, count, tuple(several), listed, contributing)

"""Quick filters of the fleet list: server state and provider.

The two filters are independent single-select choices that combine with AND
(and with the search text). ``ALL`` in either group means "no filter".
Everything here is plain data and functions, so it can be tested without a
screen.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Dict, Iterable, List, Optional

from servonaut.screens._demo_resolve import row_source

ALL = "all"

# State filter values, in the order the chips and the ``f`` key go through.
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"
STATE_OTHER = "other"
STATES = (STATE_RUNNING, STATE_STOPPED, STATE_OTHER)
STATE_LABELS: Dict[str, str] = {
    STATE_RUNNING: "Running",
    STATE_STOPPED: "Stopped",
    STATE_OTHER: "Other",
}

# Provider filter values, in the order the chips and the ``p`` key go through.
PROVIDERS = ("aws", "ovh", "hetzner", "custom", "shared")
PROVIDER_LABELS: Dict[str, str] = {
    "aws": "AWS",
    "ovh": "OVH",
    "hetzner": "Hetzner",
    "custom": "Custom",
    "shared": "Team",
}


def row_state(row: dict) -> str:
    """The state group of a row: running, stopped, or other (pending, unknown, ...)."""
    state = str(row.get("state") or "").strip().lower()
    return state if state in (STATE_RUNNING, STATE_STOPPED) else STATE_OTHER


def row_provider(row: dict) -> str:
    """The provider group of a row (a custom server counts as custom, whatever its label)."""
    return row_source(row)


def provider_label(row: dict) -> str:
    """What the Provider column shows: AWS, OVH or Hetzner by name, otherwise the row's own label.

    A custom or team server keeps the label its owner gave it ("Custom" or
    "Team" when it has none).
    """
    group = row_provider(row)
    if group in ("aws", "ovh", "hetzner"):
        return PROVIDER_LABELS[group]
    return str(row.get("provider") or "").strip() or PROVIDER_LABELS.get(group, group)


@dataclass(frozen=True)
class FleetFilter:
    """Which servers the fleet list shows: one state and one provider, or all."""

    state: str = ALL
    provider: str = ALL

    @property
    def is_active(self) -> bool:
        return self.state != ALL or self.provider != ALL

    def matches(self, row: dict) -> bool:
        """Whether *row* passes both filters."""
        return self.passes_state(row) and self.passes_provider(row)

    def passes_state(self, row: dict) -> bool:
        return self.state == ALL or row_state(row) == self.state

    def passes_provider(self, row: dict) -> bool:
        return self.provider == ALL or row_provider(row) == self.provider

    def with_state(self, state: str) -> "FleetFilter":
        return replace(self, state=state if state in STATES else ALL)

    def with_provider(self, provider: str) -> "FleetFilter":
        return replace(self, provider=provider if provider in PROVIDERS else ALL)

    def describe(self) -> List[str]:
        """The active filters as words, state first ("Running", "AWS")."""
        parts: List[str] = []
        if self.state != ALL:
            parts.append(STATE_LABELS.get(self.state, self.state))
        if self.provider != ALL:
            parts.append(PROVIDER_LABELS.get(self.provider, self.provider))
        return parts


@dataclass(frozen=True)
class FleetFacets:
    """How many servers each chip would show, for the rows the search lets through.

    Each group is counted with the other group's filter applied, so a chip's
    number is what selecting it gives. ``total`` ignores both filters.
    """

    total: int
    states: Dict[str, int]
    providers: Dict[str, int]


def facets(rows: Iterable[dict], active: FleetFilter) -> FleetFacets:
    """Count *rows* (already narrowed by the search) per state and per provider."""
    rows = list(rows)
    states = {state: 0 for state in STATES}
    providers = {provider: 0 for provider in PROVIDERS}
    for row in rows:
        if active.passes_provider(row):
            states[row_state(row)] += 1
        if active.passes_state(row):
            providers[row_provider(row)] += 1
    return FleetFacets(total=len(rows), states=states, providers=providers)


def next_choice(
    current: str, choices: Iterable[str], present: Callable[[str], bool],
) -> str:
    """The choice after *current* in ``ALL`` -> *choices* -> ``ALL``, skipping absent ones.

    A choice counts as absent when nothing in the fleet would match it, so
    the key never lands on a chip that is not shown. The current choice is
    always kept reachable so a filter can still be left.
    """
    order = [ALL, *choices]
    start = order.index(current) if current in order else 0
    for step in range(1, len(order) + 1):
        candidate = order[(start + step) % len(order)]
        if candidate == ALL or present(candidate):
            return candidate
    return ALL


def summary(
    shown: int, total: int, active: FleetFilter, query: Optional[str] = None, *, hint: bool = True,
) -> str:
    """"Showing 9 of 12 · filters: Running · AWS · f cycle state filter · p cycle provider".

    Fixed words and counts, never server text. *query* only says that a search
    is narrowing the list; its text is already visible in the search box.
    Without *hint* the key reminder is left off, for a line with no room for it.
    """
    filters = active.describe()
    if query:
        filters = [*filters, "search"]
    parts = [
        f"Showing {shown} of {total}",
        "filters: " + (", ".join(filters) if filters else "none"),
    ]
    if hint:
        parts += ["f cycle state filter", "p cycle provider"]
    return " · ".join(parts)

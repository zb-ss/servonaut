"""What the fleet list reports while the providers answer.

A load cycle starts when the first provider begins fetching and ends when the
last one answers. Each provider moves from loading to done (with its server
count), or to stale/failed when its answer could not be trusted. The tracker
is plain data; :func:`render_load` turns it into the text the screen shows:

* first run (nothing listed yet): a block with one line per provider;
* refresh (a list is already on screen): one line, so the list stays the
  focus, naming the age of the cached rows it replaces.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from textual.content import Content

from servonaut.screens._fleet_filter import PROVIDER_LABELS
from servonaut.utils.markup import literal

# Longest failure reason shown; the full text is in the notification.
_REASON_WIDTH = 80


class Phase(enum.Enum):
    LOADING = "loading"
    DONE = "done"
    STALE = "stale"
    FAILED = "failed"


@dataclass
class ProviderLoad:
    """One provider's progress in the current cycle."""

    key: str
    phase: Phase = Phase.LOADING
    count: int = 0
    accounts: int = 1
    reason: str = ""


@dataclass
class FleetLoad:
    """Progress of every provider in the current (or last) load cycle."""

    providers: Dict[str, ProviderLoad] = field(default_factory=dict)
    first_run: bool = False
    cached_age: str = ""

    @property
    def active(self) -> bool:
        """Whether any provider is still answering."""
        return any(p.phase is Phase.LOADING for p in self.providers.values())

    @property
    def problems(self) -> List[ProviderLoad]:
        return [
            p for p in self.providers.values() if p.phase in (Phase.STALE, Phase.FAILED)
        ]

    def start(self, key: str, *, accounts: int = 1, has_rows: bool, cached_age: str = "") -> None:
        """A provider began fetching. The first one after a quiet period opens a cycle."""
        if not self.active:
            self.providers = {}
            self.first_run = not has_rows
            self.cached_age = cached_age
        self.providers[key] = ProviderLoad(key=key, accounts=max(1, accounts))

    def drop(self, key: str) -> None:
        """Stop reporting a provider that has nothing to say (no team plan, say)."""
        self.providers.pop(key, None)

    def finish(self, key: str, *, count: int, error: str = "") -> None:
        """A provider answered with *count* servers; *error* says its answer is cached."""
        load = self.providers.get(key)
        if load is None:
            return
        load.count = count
        load.reason = error
        if not error:
            load.phase = Phase.DONE
        else:
            load.phase = Phase.STALE if count else Phase.FAILED


def format_ago(seconds: float) -> str:
    """How long ago, in the coarsest unit that reads naturally: ``12 s ago``, ``6 min ago``."""
    seconds = max(0, int(seconds))
    if seconds < 10:
        return "just now"
    if seconds < 60:
        return f"{seconds} s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    return f"{seconds // 3600} h ago"


def _name(load: ProviderLoad) -> str:
    return PROVIDER_LABELS.get(load.key, load.key.title())


def _clip(reason: str, redact: Callable[[str], str]) -> str:
    text = " ".join(redact(reason).split())
    return text if len(text) <= _REASON_WIDTH else text[: _REASON_WIDTH - 1] + "…"


def _servers(count: int) -> str:
    return f"{count} server" + ("" if count == 1 else "s")


def _line(load: ProviderLoad, redact: Callable[[str], str]) -> Content:
    """One provider's line of the first-run block."""
    name = _name(load)
    if load.phase is Phase.DONE:
        return Content.assemble(literal("✓", "$text-success"), f" {name} · {_servers(load.count)}")
    if load.phase is Phase.LOADING:
        accounts = f" · {load.accounts} accounts" if load.accounts > 1 else ""
        return Content.assemble(literal("◐", "$text-accent"), f" {name}{accounts}")
    glyph, word = ("⚠", "stale") if load.phase is Phase.STALE else ("✗", "failed")
    return Content.assemble(
        literal(glyph, "$text-error"),
        f" {name} · {word}: ",
        literal(_clip(load.reason, redact)),
    )


def _mark(load: ProviderLoad) -> str:
    return {Phase.DONE: "✓", Phase.LOADING: "…", Phase.STALE: "stale", Phase.FAILED: "failed"}[
        load.phase
    ]


def _pill(tracker: FleetLoad, redact: Callable[[str], str]) -> Content:
    """The one-line refresh summary: ``◐ Refreshing · AWS ✓ · OVH …``."""
    parts = " · ".join(f"{_name(p)} {_mark(p)}" for p in tracker.providers.values())
    head = "◐ Refreshing" if tracker.active else "Refreshed"
    pill = literal(f"{head} · {parts}", "$text-accent" if tracker.active else "")
    pieces: List[Content | str] = [pill]
    if tracker.active and tracker.cached_age:
        pieces += ["  ", literal(f"cached {tracker.cached_age}", "dim")]
    for problem in tracker.problems:
        pieces += ["\n", _line(problem, redact)]
    return Content.assemble(*pieces)


def _block(tracker: FleetLoad, redact: Callable[[str], str]) -> Content:
    count = len(tracker.providers)
    plural = "provider" if count == 1 else "providers"
    pieces: List[Content | str] = [f"Loading servers from {count} {plural}…"]
    for load in tracker.providers.values():
        pieces += ["\n", _line(load, redact)]
    return Content.assemble(*pieces)


def render_load(
    tracker: FleetLoad, redact: Optional[Callable[[str], str]] = None,
) -> Optional[Content]:
    """The load report to show, or None when there is nothing to say.

    *redact* maps provider-supplied text (failure reasons) to what the screen
    may show; it is applied before the text is placed, and the text is never
    read as markup.
    """
    redact = redact or (lambda text: text)
    if not tracker.providers:
        return None
    if tracker.active:
        return _block(tracker, redact) if tracker.first_run else _pill(tracker, redact)
    if tracker.problems:
        return Content("\n").join(_line(load, redact) for load in tracker.problems)
    return None

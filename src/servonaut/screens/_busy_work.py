"""Slow work on a screen or dialog, shown on its BusyIndicator while it runs."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from typing import TypeVar

from textual.css.query import NoMatches
from textual.dom import DOMNode
from textual.widget import Widget

from servonaut.widgets.busy_indicator import BusyIndicator

_W = TypeVar("_W", bound=Widget)


class BusyJob:
    """One piece of running work: what it says and the widgets it holds back."""

    def __init__(self, message: str, holds: tuple[str, ...]) -> None:
        self.message = message
        self.holds = holds


class BusyWork:
    """Show the newest running work on one BusyIndicator, holding widgets back meanwhile.

    Work that overlaps (a status reload during a host write) shares the line,
    newest first. Each piece is its own job, so a piece that ends, or a
    cancelled worker that unwinds late, clears only its own message. A held
    widget stays disabled while any job holds it, then gets back the state it
    had before the first one did. A held widget that had the focus leaves it
    with nothing meanwhile (Textual would hand it to a neighbour, where Enter
    starts other work) and gets it back unless the user focused something
    else. Widgets that are already gone (the dialog closed, the worker was
    cancelled with its screen) are skipped.
    """

    def __init__(self, owner: DOMNode, indicator: str, *, display: Callable[[str], str] = str) -> None:
        self._owner = owner
        self._indicator = indicator
        # Demo-mode scrubbing, applied on every draw so a toggle redraws the kept raw message.
        self._display = display
        self._jobs: list[BusyJob] = []
        # Held selector -> (disabled, focused) before the first job held it.
        self._held: dict[str, tuple[bool, bool]] = {}

    @property
    def is_busy(self) -> bool:
        return bool(self._jobs)

    def holds(self, selector: str) -> bool:
        """Whether running work holds *selector* back."""
        return any(selector in job.holds for job in self._jobs)

    @contextmanager
    def running(self, message: str, *, hold: Iterable[str] = ()) -> Iterator[BusyJob]:
        """Show *message* and hold *hold* back for the body, also when it fails or is cancelled."""
        job = self.begin(message, hold=hold)
        try:
            yield job
        finally:
            self.end(job)

    def begin(self, message: str, *, hold: Iterable[str] = ()) -> BusyJob:
        job = BusyJob(message, tuple(hold))
        self._jobs.append(job)
        for selector in job.holds:
            widget = self._find(selector, Widget)
            if widget is None:
                continue
            focused = widget.screen.focused is widget
            self._held.setdefault(selector, (widget.disabled, focused))
            widget.disabled = True
            if focused:
                widget.screen.set_focus(None)
        self._draw()
        return job

    def say(self, job: BusyJob, message: str) -> None:
        """Change what *job* says it is doing."""
        job.message = message
        self._draw()

    def end(self, job: BusyJob) -> None:
        if job not in self._jobs:
            return
        self._jobs.remove(job)
        for selector in job.holds:
            if self.holds(selector) or selector not in self._held:
                continue
            disabled, focused = self._held.pop(selector)
            widget = self._find(selector, Widget)
            if widget is None:
                continue
            widget.disabled = disabled
            if focused and not disabled and widget.screen.focused is None:
                widget.focus()
        self._draw()

    def redraw(self) -> None:
        """Draw the message again, e.g. after a demo-mode toggle."""
        self._draw()

    def _draw(self) -> None:
        indicator = self._find(self._indicator, BusyIndicator)
        if indicator is None:
            return
        if self._jobs:
            indicator.start(self._display(self._jobs[-1].message))
        else:
            indicator.stop()

    def _find(self, selector: str, kind: type[_W]) -> _W | None:
        try:
            return self._owner.query_one(selector, kind)
        except NoMatches:
            return None

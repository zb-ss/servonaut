"""Collapsible section widget for the persistent sidebar navigation.

A :class:`SidebarSection` wraps a labeled group of nav buttons under a
clickable header that toggles collapsed / expanded state. Sections are
how the sidebar scales: any number of nav buttons stay reachable
without overflowing small terminals, because every section can be
collapsed to a single header row, and the active section auto-expands
when its screen is opened.

Caller pattern (see :mod:`servonaut.widgets.sidebar` for the full
build-out):

.. code-block:: python

    yield SidebarSection(
        "Core",
        Button("📋 Instances", id="nav_list", classes="nav-button"),
        Button("💻 Custom Servers", id="nav_custom_servers", classes="nav-button"),
        Button("🔑 SSH Keys", id="nav_keys", classes="nav-button"),
        section_id="section_core",
    )

Children pressed inside the section continue to bubble normally — the
parent :class:`Sidebar` handles button presses and posts
``NavigationRequested``. Only the section header click is consumed
locally to flip the collapsed reactive.
"""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.css.query import NoMatches
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Button


class SidebarSection(Widget):
    """A collapsible group of nav buttons with a clickable header.

    The header shows ``▼`` when expanded and ``▶`` when collapsed, with
    the section title alongside. Clicking the header toggles the
    section. Programmatic callers can also use :meth:`expand`,
    :meth:`collapse`, and :meth:`toggle` (or set :attr:`collapsed`
    directly).

    Args:
        title: Display text for the section header.
        *children: Widgets to mount inside the collapsible content
            area. Typically a sequence of nav ``Button`` widgets.
        section_id: Optional ``id`` to set on the section itself (for
            ``query_one`` lookups). The header button has class
            ``section-header`` and no id; the inner content container
            has class ``section-content``.
        collapsed: Initial state. Defaults to ``False`` (expanded).
    """

    DEFAULT_CSS = """
    SidebarSection {
        layout: vertical;
        height: auto;
        width: 100%;
    }
    SidebarSection > Button.section-header {
        width: 100%;
        height: 1;
        background: transparent;
        color: $accent;
        text-style: bold;
        border: none;
        padding: 0 1;
        margin: 0;
        content-align: left middle;
    }
    SidebarSection > Button.section-header:hover {
        background: $boost;
        text-style: bold;
        border: none;
    }
    SidebarSection > Button.section-header:focus {
        background: transparent;
        text-style: bold;
        border: none;
    }
    SidebarSection > Vertical.section-content {
        height: auto;
        layout: vertical;
    }
    SidebarSection.-collapsed > Vertical.section-content {
        display: none;
    }
    """

    class SectionToggled(Message):
        """Posted when the section's collapsed state changes."""

        def __init__(self, section_id: str, collapsed: bool) -> None:
            self.section_id = section_id
            self.collapsed = collapsed
            super().__init__()

    collapsed: reactive[bool] = reactive(False, init=False)

    def __init__(
        self,
        title: str,
        *children: Widget,
        section_id: Optional[str] = None,
        collapsed: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(id=section_id, **kwargs)
        self._title = title
        self._initial_collapsed = collapsed
        self._children_to_compose = list(children)

    def compose(self) -> ComposeResult:
        header = Button(self._header_label(False), classes="section-header")
        # Headers should never steal keyboard focus from the table /
        # inputs in the main pane.
        header.can_focus = False
        yield header
        yield Vertical(*self._children_to_compose, classes="section-content")

    def on_mount(self) -> None:
        # Apply initial collapsed state after compose so watchers fire
        # against fully-mounted children.
        if self._initial_collapsed:
            self.collapsed = True

    def watch_collapsed(self, value: bool) -> None:
        if value:
            self.add_class("-collapsed")
        else:
            self.remove_class("-collapsed")
        try:
            header = self.query_one("Button.section-header", Button)
            header.label = self._header_label(value)
        except NoMatches:
            pass
        self.post_message(self.SectionToggled(self.id or "", value))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # Only consume header clicks. Nav-button presses bubble up to
        # the Sidebar parent, which posts NavigationRequested.
        if event.button.has_class("section-header"):
            event.stop()
            self.collapsed = not self.collapsed

    def expand(self) -> None:
        self.collapsed = False

    def collapse(self) -> None:
        self.collapsed = True

    def toggle(self) -> None:
        self.collapsed = not self.collapsed

    def contains_button(self, button_id: str) -> bool:
        """Whether a nav button with the given id lives in this section."""
        try:
            self.query_one(f"#{button_id}")
            return True
        except NoMatches:
            return False

    def _header_label(self, collapsed: bool) -> str:
        chevron = "▶" if collapsed else "▼"
        return f"{chevron} {self._title}"

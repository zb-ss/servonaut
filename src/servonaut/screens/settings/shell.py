"""Settings shell — master/detail side-menu screen.

A left nav rail of grouped category buttons + a content pane that shows ONLY
the selected panel. All panels are instantiated once (via registry factories,
each wrapped in a per-panel try/except so one broken panel can't break the
screen) and mounted hidden except the active one; switching toggles ``display``
and the ``--active`` nav class. A search box filters nav buttons by title +
keywords, and an unsaved-changes guard intercepts panel switches and back.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Input, Static

from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.registry import PANELS, PanelSpec
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.sidebar_section import SidebarSection

logger = logging.getLogger(__name__)


class DiscardChangesModal(ModalScreen[bool]):
    """Tiny confirm modal: discard unsaved changes in a panel and proceed.

    Returns ``True`` (discard + proceed) or ``False`` (stay) via ``dismiss``.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    DEFAULT_CSS = """
    DiscardChangesModal { align: center middle; }
    DiscardChangesModal #discard-box {
        width: 60;
        height: auto;
        border: round $warning;
        background: $surface;
        padding: 1 2;
    }
    DiscardChangesModal #discard-title {
        text-style: bold;
        margin-bottom: 1;
    }
    DiscardChangesModal #discard-buttons {
        height: auto;
        align: right middle;
        margin-top: 1;
    }
    DiscardChangesModal #discard-buttons Button { margin-left: 1; }
    """

    def __init__(self, panel_title: str) -> None:
        super().__init__()
        self._panel_title = panel_title

    def compose(self) -> ComposeResult:
        """Compose the discard-changes prompt."""
        yield Vertical(
            Static("Unsaved changes", id="discard-title"),
            Static(
                escape(
                    f"Discard unsaved changes in {self._panel_title}?"
                ),
                id="discard-message",
            ),
            Horizontal(
                Button("Keep editing", variant="default", id="discard-cancel"),
                Button("Discard", variant="warning", id="discard-confirm"),
                id="discard-buttons",
            ),
            id="discard-box",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Resolve the modal based on the chosen button."""
        self.dismiss(event.button.id == "discard-confirm")

    def action_cancel(self) -> None:
        """Escape = keep editing."""
        self.dismiss(False)


class SettingsScreen(Screen):
    """Master/detail settings editor with per-panel save + unsaved guard."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+f", "focus_search", "Search", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # panel_id -> mounted SettingsPanel (only successfully-built panels).
        self._panels: Dict[str, SettingsPanel] = {}
        self._active_id: Optional[str] = None
        # group name -> its collapsible SidebarSection, and panel id -> group.
        self._sections: Dict[str, SidebarSection] = {}
        self._group_of: Dict[str, str] = {spec.id: spec.group for spec in PANELS}

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Compose the nav rail + search + content switcher."""
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Horizontal(id="settings-body"):
                with Vertical(id="settings-nav"):
                    yield Input(placeholder="Search settings…", id="settings-search")
                    yield VerticalScroll(id="settings-nav-list")
                yield Vertical(id="settings-content")
        yield Footer()

    def on_mount(self) -> None:
        """Build nav buttons and mount every panel (hidden except the first)."""
        self._build_nav()
        self._mount_panels()
        # Nav buttons live inside SidebarSections that mount asynchronously, so
        # the initial _set_nav_active (during _mount_panels) can run before the
        # active button exists. Re-assert the highlight once everything settled.
        if self._active_id is not None:
            self.call_after_refresh(self._set_nav_active, self._active_id)

    def _build_nav(self) -> None:
        """Mount one collapsible :class:`SidebarSection` per group.

        Groups appear as contiguous runs in ``PANELS``. Only the first group
        (which holds the initially-active panel) starts expanded; the rest
        start collapsed so the rail stays compact, mirroring the main sidebar.
        Search re-expands groups that contain matches (see :meth:`_apply_filter`).
        """
        nav = self.query_one("#settings-nav-list", VerticalScroll)
        # Preserve PANELS order while grouping.
        ordered_groups: list[str] = []
        buttons_by_group: Dict[str, list[Button]] = {}
        for spec in PANELS:
            if spec.group not in buttons_by_group:
                buttons_by_group[spec.group] = []
                ordered_groups.append(spec.group)
            # Preview features get a dim "· preview" tag so the not-yet-live
            # state is signalled before the user even opens the panel.
            label = escape(spec.title)
            if spec.preview:
                label = f"{label} [dim]· preview[/dim]"
            buttons_by_group[spec.group].append(
                Button(
                    label,
                    id=f"navbtn_{spec.id}",
                    classes="settings-nav-btn",
                )
            )
        for index, group in enumerate(ordered_groups):
            section = SidebarSection(
                group,
                *buttons_by_group[group],
                section_id=f"settings_sec_{index}",
                collapsed=index != 0,
            )
            self._sections[group] = section
            nav.mount(section)

    def _mount_panels(self) -> None:
        """Instantiate + mount panels; first visible, rest hidden.

        A factory that raises (panel not built / broken) mounts a placeholder
        Static instead so a single bad panel never breaks the whole screen.
        """
        content = self.query_one("#settings-content", Vertical)
        first = True
        for spec in PANELS:
            try:
                panel = spec.factory()()
            except Exception as exc:
                logger.error("Settings panel %s failed to build: %s", spec.id, exc)
                content.mount(
                    Static(
                        escape(f"⚠ {spec.title}: unavailable"),
                        id=f"placeholder_{spec.id}",
                        classes="settings-panel panel-unavailable",
                    )
                )
                continue
            panel.display = first
            content.mount(panel)
            self._panels[spec.id] = panel
            if first:
                self._active_id = spec.id
                self._set_nav_active(spec.id)
                first = False

    # ------------------------------------------------------------------
    # Navigation + switching
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle nav button clicks (panel Save buttons are handled in-panel)."""
        button_id = event.button.id or ""
        if not button_id.startswith("navbtn_"):
            return
        event.stop()
        target_id = button_id[len("navbtn_"):]
        self._request_switch(target_id)

    def _request_switch(self, target_id: str) -> None:
        """Switch to *target_id*, guarding unsaved changes in the current panel."""
        if target_id == self._active_id or target_id not in self._panels:
            return
        current = self._current_panel()
        if current is not None and current.is_dirty():
            self.app.push_screen(
                DiscardChangesModal(current.TITLE),
                lambda discard: self._after_guard(discard, current, target_id),
            )
            return
        self._switch_to(target_id)

    def _after_guard(
        self, discard: bool, current: SettingsPanel, target_id: str
    ) -> None:
        """Resume a guarded switch once the discard modal resolves."""
        if not discard:
            return
        current.discard()
        self._switch_to(target_id)

    def _switch_to(self, target_id: str) -> None:
        """Hide the current panel, show *target_id*, update nav highlight."""
        current = self._current_panel()
        if current is not None:
            current.display = False
        panel = self._panels[target_id]
        panel.display = True
        self._active_id = target_id
        self._set_nav_active(target_id)
        # Keep only the active group expanded (sections are mounted by now, so
        # the chevron updates correctly). Skip while searching — the filter owns
        # section state then.
        if not self._search_query():
            self._apply_default_collapse()

    def _set_nav_active(self, target_id: str) -> None:
        """Move the ``--active`` class to the *target_id* nav button.

        When not filtering, keep only the active panel's group expanded so the
        active item is always visible (mirrors the main sidebar). During a
        search, leave section state to :meth:`_apply_filter`.
        """
        for button in self.query(".settings-nav-btn"):
            button.remove_class("--active")
        try:
            self.query_one(f"#navbtn_{target_id}", Button).add_class("--active")
        except Exception:
            pass

    def _search_query(self) -> str:
        """Current lowercased search text, or ``""`` if the box is empty/absent."""
        try:
            return self.query_one("#settings-search", Input).value.strip().lower()
        except Exception:
            return ""

    def _apply_default_collapse(self) -> None:
        """Show every section; expand only the active panel's group."""
        active_group = self._group_of.get(self._active_id or "", "")
        for group, section in self._sections.items():
            section.display = True
            section.collapsed = group != active_group

    def _current_panel(self) -> Optional[SettingsPanel]:
        if self._active_id is None:
            return None
        return self._panels.get(self._active_id)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Filter nav buttons + group labels by the search query."""
        if event.input.id != "settings-search":
            return
        event.stop()
        self._apply_filter(event.value.strip().lower())

    def _apply_filter(self, query: str) -> None:
        """Show only nav buttons whose title/keywords match *query*.

        Search is section-aware: groups containing a match are shown and
        force-expanded (so a match is never hidden inside a collapsed group),
        and groups with no match are hidden entirely. Clearing the query
        restores every button and the default collapse state.
        """
        if not query:
            for spec in PANELS:
                try:
                    self.query_one(f"#navbtn_{spec.id}", Button).display = True
                except Exception:
                    pass
            self._apply_default_collapse()
            return

        groups_with_match = set()
        for spec in PANELS:
            match = self._spec_matches(spec, query)
            try:
                self.query_one(f"#navbtn_{spec.id}", Button).display = match
            except Exception:
                continue
            if match:
                groups_with_match.add(spec.group)
        for group, section in self._sections.items():
            has_match = group in groups_with_match
            section.display = has_match
            if has_match:
                section.collapsed = False

    @staticmethod
    def _spec_matches(spec: PanelSpec, query: str) -> bool:
        if not query:
            return True
        haystack = " ".join([spec.title.lower(), *(k.lower() for k in spec.keywords)])
        return query in haystack

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_focus_search(self) -> None:
        """Focus the search box."""
        try:
            self.query_one("#settings-search", Input).focus()
        except Exception:
            pass

    def action_back(self) -> None:
        """Leave settings, guarding unsaved changes in the current panel."""
        current = self._current_panel()
        if current is not None and current.is_dirty():
            self.app.push_screen(
                DiscardChangesModal(current.TITLE),
                self._after_back_guard,
            )
            return
        self._do_back()

    def _after_back_guard(self, discard: bool) -> None:
        if not discard:
            return
        current = self._current_panel()
        if current is not None:
            current.discard()
        self._do_back()

    def _do_back(self) -> None:
        """Pop back to the previous screen."""
        self.app.pop_screen()

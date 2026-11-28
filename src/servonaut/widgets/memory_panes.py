"""Embedded pane widgets for FleetMemoryScreen's TabbedContent."""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, DataTable

from servonaut.screens._busy_work import BusyWork
from servonaut.screens.memory_drift import _MemoryDriftContentMixin, compose_drift_container
from servonaut.screens.memory_export import _MemoryExportContentMixin
from servonaut.screens.memory_sync_setup import _MemorySyncContentMixin, compose_sync_container
from servonaut.utils.theme_text import rebuild_keeping_cursor

logger = logging.getLogger(__name__)


class MemorySyncPane(_MemorySyncContentMixin, Vertical):
    """Embedded Memory Sync tab pane inside FleetMemoryScreen."""

    _rendered: bool = False

    def compose(self) -> ComposeResult:
        yield from compose_sync_container()

    def _build_status_card(self, auth: Any, sync: Any) -> Container:
        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        return MemorySyncSetupScreen._build_status_card(self, auth, sync)

    def _kv_row(
        self, label: str, value: str, *, value_id: Optional[str] = None
    ) -> Horizontal:
        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        return MemorySyncSetupScreen._kv_row(self, label, value, value_id=value_id)

    def activate(self, *, force_refresh: bool = False) -> None:
        """Render status/setup cards lazily when the Sync tab opens."""
        if not self.is_attached:
            return
        if force_refresh or not self._rendered:
            self._rendered = True
            self._render_state()

    def refresh_state(self) -> None:
        """Re-render status cards when already active/rendered and refresh tab gates."""
        if not self.is_attached:
            return
        active = getattr(self.screen, "_active_tab_key", "fleet")
        if self._rendered or active == "sync":
            self._rendered = True
            self._render_state()

    def refresh_after_demo_toggle(self) -> None:
        if self._rendered or getattr(self.screen, "_active_tab_key", "fleet") == "sync":
            self._rendered = True
            self._render_state()


class MemoryDriftPane(_MemoryDriftContentMixin, Vertical):
    """Embedded Drift tab pane inside FleetMemoryScreen."""

    def __init__(self, *, busy: Optional[BusyWork] = None, id: str | None = None) -> None:
        super().__init__(id=id)
        self._read_loading = busy if busy is not None else BusyWork(self, "#read_loading")
        self._show_unack_only: bool = False
        self._events: List[Any] = []
        self._loaded_once: bool = False
        self._focus_table_after_load: bool = True

    def compose(self) -> ComposeResult:
        yield from compose_drift_container(include_busy=False)

    def on_mount(self) -> None:
        self.app.theme_changed_signal.subscribe(self, self._restyle_rows)
        table = self.query_one("#drift-table", DataTable)
        table.cursor_type = "row"
        table.add_column("When", key="when")
        table.add_column("Instance", key="instance")
        table.add_column("Module", key="module")
        table.add_column("Severity", key="severity")
        table.add_column("Status", key="status")

    def _restyle_rows(self, _theme: Any = None) -> None:
        if not self.is_attached or not self._loaded_once:
            return
        self.call_after_refresh(
            rebuild_keeping_cursor,
            self.query_one("#drift-table", DataTable),
            self._render_table,
        )

    def _render_table(self) -> None:
        super()._render_table()
        if self._focus_table_after_load:
            self._focus_table_if_active()

    def _focus_table_if_active(self) -> None:
        if not self.is_attached:
            return
        active = getattr(self.screen, "_active_tab_key", "")
        nav_focused = bool(getattr(self.screen, "navigation_focused", False))
        if active != "drift" or nav_focused:
            return
        try:
            table = self.query_one("#drift-table", DataTable)
        except NoMatches:
            return
        if table.row_count > 0 and table.cursor_row < 0:
            table.move_cursor(row=0)
        table.focus()

    def activate(self, *, force_refresh: bool = False, focus_table: bool = True) -> None:
        """Gate check, load events when Drift opens, and focus the table."""
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_drift"):
            from servonaut.widgets.upsell_modal import UpsellModal

            self.app.push_screen(UpsellModal("memory_drift"))
            return
        self._focus_table_after_load = focus_table
        if force_refresh or not self._loaded_once:
            self._load_drift_events()
        elif focus_table:
            self.call_after_refresh(self._focus_table_if_active)

    def refresh_after_demo_toggle(self) -> None:
        if self._events:
            self._render_table()

    def action_refresh(self) -> None:
        self._load_drift_events()
        self.app.notify("Refreshing drift events…")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-drift-refresh":
            self.action_refresh()
        elif bid == "btn-drift-ack":
            self.action_ack_selected()
        elif bid == "btn-drift-unack":
            self.action_toggle_unack()
        elif bid == "btn-drift-diff":
            self.action_view_diff()
        else:
            return
        event.stop()


class MemoryExportPane(_MemoryExportContentMixin, Vertical):
    """Embedded Compliance Export tab pane inside FleetMemoryScreen."""

    def compose(self) -> ComposeResult:
        yield from self._compose_export_body(show_back=False)

    def activate(self) -> None:
        """Enforce entitlement only when the user actually opens Export."""
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_compliance_export"):
            from servonaut.widgets.upsell_modal import UpsellModal

            self.app.push_screen(UpsellModal("memory_compliance_export"))

"""Embedded pane widgets for FleetMemoryScreen's TabbedContent."""

from __future__ import annotations

from typing import Any, Callable, List, Optional

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, DataTable, Static

from servonaut.screens._busy_work import BusyWork
from servonaut.screens.memory_drift import (
    _SEVERITY_STYLE,  # noqa: F401
    compose_drift_container,
)
from servonaut.screens.memory_export import _MemoryExportContentMixin
from servonaut.screens.memory_sync_setup import compose_sync_container
from servonaut.utils.theme_text import follow_theme, rebuild_keeping_cursor

_SYNC_FORWARDED_METHODS = (
    "_apply_sync_state",
    "_render_state",
    "_set_status",
    "_build_logged_out_card",
    "_build_upsell_card",
    "_build_setup_card",
    "_build_status_card",
    "_build_benefits_list",
    "_kv_row",
    "_refresh_status_card",
    "refresh_memory_sync_progress",
    "_publish_manual_sync_progress",
    "_finish_manual_sync",
    "_refresh_visible_sync_screen",
    "_start_sync_now",
    "_run_sync_now_background",
    "on_button_pressed",
    "_do_setup",
    "_show_setup_error",
    "_set_busy",
    "_clear_busy",
    "_do_sync_now",
    "_do_rotate",
    "_do_remember",
    "_store_remembered_passphrase",
    "_do_disable",
    "_do_forget",
)


def _sync_screen_cls():
    from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

    return MemorySyncSetupScreen


def _drift_screen_cls():
    from servonaut.screens.memory_drift import MemoryDriftScreen

    return MemoryDriftScreen


def _make_sync_forwarder(name: str) -> Callable[..., Any]:
    def _forwarded(self: "MemorySyncPane", *args: Any, **kwargs: Any) -> Any:
        target = getattr(_sync_screen_cls(), name)
        return target(self, *args, **kwargs)

    _forwarded.__name__ = name
    return _forwarded


class MemorySyncPane(Vertical):
    """Embedded Memory Sync tab pane inside FleetMemoryScreen."""

    _rendered: bool = False

    for _method_name in _SYNC_FORWARDED_METHODS:
        locals()[_method_name] = _make_sync_forwarder(_method_name)
    del _method_name

    @property
    def _MAX_DRAIN_BATCHES(self) -> int:
        return _sync_screen_cls()._MAX_DRAIN_BATCHES

    @staticmethod
    def _open_url(url: str) -> None:
        _sync_screen_cls()._open_url(url)

    def compose(self) -> ComposeResult:
        yield from compose_sync_container()

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


def _make_drift_forwarder(name: str) -> Callable[..., Any]:
    def _forwarded(self: "MemoryDriftPane", *args: Any, **kwargs: Any) -> Any:
        target = getattr(_drift_screen_cls(), name)
        return target(self, *args, **kwargs)

    _forwarded.__name__ = name
    return _forwarded


_DRIFT_FORWARDED_METHODS = (
    "_load_drift_events",
    "_do_load",
    "_event_for_row_key",
    "_event_at_cursor",
    "action_ack_selected",
    "_do_ack",
    "action_toggle_unack",
    "action_view_diff",
    "on_data_table_row_selected",
    "_open_diff",
)


class MemoryDriftPane(Vertical):
    """Embedded Drift tab pane inside FleetMemoryScreen."""

    for _method_name in _DRIFT_FORWARDED_METHODS:
        locals()[_method_name] = _make_drift_forwarder(_method_name)
    del _method_name

    def __init__(self, *, busy: Optional[BusyWork] = None, id: str | None = None) -> None:
        super().__init__(id=id)
        self._read_loading = busy if busy is not None else BusyWork(self, "#read_loading")
        self._show_unack_only: bool = False
        self._events: List[Any] = []
        self._loaded_once: bool = False

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
        if not self.is_attached:
            return
        self.call_after_refresh(
            rebuild_keeping_cursor,
            self.query_one("#drift-table", DataTable),
            self._render_table,
        )

    def _render_table(self) -> None:
        _drift_screen_cls()._render_table(self)
        self._loaded_once = True
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
            if table.row_count > 0 and table.cursor_row < 0:
                table.move_cursor(row=0)
            table.focus()
        except Exception:
            pass

    def activate(self, *, force_refresh: bool = False) -> None:
        """Gate check, load events when Drift opens, and focus the table."""
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_drift"):
            from servonaut.widgets.upsell_modal import UpsellModal

            self.app.push_screen(UpsellModal("memory_drift"))
            return
        if force_refresh or not self._loaded_once:
            self._load_drift_events()
        else:
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

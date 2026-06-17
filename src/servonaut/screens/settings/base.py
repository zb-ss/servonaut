"""Base class + shared helpers for settings category panels.

Each settings category is a :class:`SettingsPanel` subclass. The shell
(``shell.py``) mounts every panel once into the content pane and toggles
``display`` to show the active one. A panel owns its own widgets, load,
validate (``collect``), save (``persist``), and dirty-state tracking, plus a
per-panel Save dock so each category saves independently.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Static

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised by :meth:`SettingsPanel.collect` when a field value is invalid.

    Carries the offending field's widget id so the panel can highlight and
    focus it via :meth:`SettingsPanel.mark_field_error`.
    """

    def __init__(self, field_id: str, message: str) -> None:
        super().__init__(message)
        self.field_id = field_id
        self.message = message


class SettingsPanel(Vertical):
    """One settings category. Owns its widgets, load, validate, save, dirty-state.

    Subclasses set :pyattr:`PANEL_ID` / :pyattr:`TITLE` and implement
    :meth:`form_rows`, :meth:`load`, :meth:`collect`, and :meth:`persist`.

    Config and services are reached via ``self.app`` (e.g.
    ``self.app.config_manager``), never constructor injection — this mirrors
    the legacy single screen and keeps panels free of wiring.
    """

    PANEL_ID: str = ""
    TITLE: str = ""

    def __init__(self) -> None:
        super().__init__(id=f"panel_{self.PANEL_ID}", classes="settings-panel")
        # Snapshot of last-saved widget values, used by the default is_dirty().
        self._snapshot: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Yield the panel header, subclass form rows, and the Save dock.

        The form rows live in a ``1fr`` scrollable body so the title stays at
        the top and the status row + Save dock stay pinned at the bottom of the
        visible area — tall panels scroll their body internally instead of
        pushing Save off-screen.
        """
        yield Static(escape(self.TITLE), classes="panel-title")
        with VerticalScroll(classes="panel-body"):
            yield from self.form_rows()
        yield Static("", id=f"status_{self.PANEL_ID}", classes="panel-status")
        yield Horizontal(
            Button("Save", id=f"save_{self.PANEL_ID}", variant="primary"),
            Static("", id=f"dirty_{self.PANEL_ID}", classes="dirty-marker"),
            id=f"panel_save_dock_{self.PANEL_ID}",
            classes="panel-save-dock",
        )

    def form_rows(self) -> ComposeResult:
        """Yield the panel-specific form rows. Subclasses MUST override."""
        return iter(())

    def on_mount(self) -> None:
        """Populate widgets from config and snapshot for dirty calculation."""
        try:
            self.load()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Panel %s load failed: %s", self.PANEL_ID, exc)
            self.app.notify(
                f"Could not load {self.TITLE} settings: {exc}",
                severity="error",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Lifecycle hooks (subclass contract)
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and set ``self._snapshot``.

        Subclasses MUST override and call :meth:`_snapshot_now` (or assign
        ``self._snapshot``) at the end so dirty-tracking has a baseline.
        """
        raise NotImplementedError

    def collect(self) -> Dict[str, Any]:
        """Read widgets into a ``{field: value}`` dict, validating as we go.

        Raise :class:`ValidationError` on the first invalid field. Subclasses
        MUST override.
        """
        raise NotImplementedError

    def persist(self) -> None:
        """Validate via :meth:`collect` and apply through ``config_manager``.

        Subclasses MUST override to perform the actual write, then call
        :meth:`_finish_save` to re-snapshot + notify.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Dirty tracking
    # ------------------------------------------------------------------

    def current_values(self) -> Dict[str, Any]:
        """Return the panel's current widget values for dirty comparison.

        The default :meth:`is_dirty` compares this against ``self._snapshot``.
        Panels backed by tables / list editors should override
        :meth:`is_dirty` directly instead.
        """
        return {}

    def is_dirty(self) -> bool:
        """Return ``True`` when current widget values differ from last save."""
        try:
            return self.current_values() != self._snapshot
        except Exception:  # pragma: no cover - defensive
            return False

    def discard(self) -> None:
        """Revert widgets to the last-saved state."""
        self.clear_field_errors()
        self.load()
        self._refresh_dirty_marker()

    # Number of post-refresh frames over which the baseline is re-captured so
    # asynchronously-mounted editor rows are reflected before dirty-tracking
    # treats them as user edits. A handful of frames is ample in practice.
    _REBASELINE_FRAMES = 4

    def _snapshot_now(self) -> None:
        """Re-baseline the dirty snapshot from the current widget values.

        List/map editors (``StringListEditor`` / ``KeyValueEditor``) mount their
        rows asynchronously, so in the same frame as ``load()`` their
        ``get_values()`` / ``get_map()`` still return empty collections. Taking
        the baseline only synchronously would capture those empties and leave the
        panel permanently "dirty" once the rows settle. We therefore re-baseline
        over the next few refresh frames, when the editor rows have mounted.
        """
        self._snapshot = self.current_values()
        self._schedule_rebaseline(self._REBASELINE_FRAMES)

    def _schedule_rebaseline(self, frames_left: int) -> None:
        """Queue a post-refresh re-baseline, if the panel is attached to an app."""
        if frames_left <= 0:
            return
        try:
            self.call_after_refresh(self._rebaseline_after_refresh, frames_left)
        except Exception:
            # No running app (e.g. a panel constructed in isolation). The
            # synchronous snapshot above is the best we can do.
            pass

    def _rebaseline_after_refresh(self, frames_left: int) -> None:
        """Re-capture the snapshot after async editor rows have mounted.

        Re-arms only while the editor values are still *settling* (changing
        frame-to-frame) — once two consecutive reads agree, the rows have
        finished mounting and we stop. This keeps the window to load time and
        avoids swallowing a user edit that lands after the editors are stable
        (such an edit yields equal consecutive reads, so we never re-baseline
        over it).
        """
        settled = self.current_values()
        if settled == self._snapshot:
            return  # Stable — rows mounted, nothing left to absorb.
        self._snapshot = settled
        self._refresh_dirty_marker()
        self._schedule_rebaseline(frames_left - 1)

    def _dirty_watch(self) -> None:
        """Refresh the dirty marker. Call from Input/Select/Switch Changed."""
        self._refresh_dirty_marker()

    def _refresh_dirty_marker(self) -> None:
        try:
            marker = self.query_one(f"#dirty_{self.PANEL_ID}", Static)
        except Exception:
            return
        marker.update("● unsaved" if self.is_dirty() else "")

    # ------------------------------------------------------------------
    # Validation cues
    # ------------------------------------------------------------------

    def mark_field_error(self, field_id: str, message: str) -> None:
        """Highlight *field_id*, focus it, and show *message* in the status row."""
        try:
            widget = self.query_one(f"#{field_id}")
            widget.add_class("field-error")
            widget.focus()
        except Exception:
            pass
        try:
            status = self.query_one(f"#status_{self.PANEL_ID}", Static)
            status.update(escape(message))
        except Exception:
            pass

    def clear_field_errors(self) -> None:
        """Remove all ``.field-error`` highlights and clear the status row."""
        for widget in self.query(".field-error"):
            widget.remove_class("field-error")
        try:
            self.query_one(f"#status_{self.PANEL_ID}", Static).update("")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Save plumbing
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the per-panel Save button; delegate others to subclasses."""
        if event.button.id != f"save_{self.PANEL_ID}":
            return
        event.stop()
        self.clear_field_errors()
        try:
            self.persist()
        except ValidationError as exc:
            self.mark_field_error(exc.field_id, exc.message)
        except Exception as exc:
            logger.error("Panel %s save failed: %s", self.PANEL_ID, exc)
            self.app.notify(
                f"Could not save {self.TITLE} settings: {exc}",
                severity="error",
                markup=False,
            )

    def _finish_save(self, message: str = "Saved") -> None:
        """Re-snapshot, clear the dirty marker, and notify success.

        Call at the end of a successful :meth:`persist`.
        """
        self._snapshot_now()
        self._refresh_dirty_marker()
        self.app.notify(message, severity="information", markup=False)

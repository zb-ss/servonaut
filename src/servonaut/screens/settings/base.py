"""Base class + shared helpers for settings category panels.

Each settings category is a :class:`SettingsPanel` subclass. The shell
(``shell.py``) mounts every panel once into the content pane and toggles
``display`` to show the active one. A panel owns its own widgets, load,
validate (``collect``), save (``persist``), and dirty-state tracking, plus a
per-panel Save dock so each category saves independently.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from rich.markup import escape
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import Button, Input, Static

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

    # Fields holding an identifier of the user's infrastructure (key paths,
    # project ids …), mapped to the ``RedactionService`` method that hides
    # it. In demo mode such a field shows the stand-in; panels fill it with
    # :meth:`_show_field` and read it back with :meth:`_field_value`, which
    # maps an untouched stand-in back to the real value, so saving never
    # writes a fake into the config. Input, EnvVarInput and StringListEditor
    # fields name one method; a KeyValueEditor field names a (key, value) pair.
    DEMO_REDACTED_FIELDS: Dict[str, Any] = {}

    def __init__(self) -> None:
        super().__init__(id=f"panel_{self.PANEL_ID}", classes="settings-panel")
        # Snapshot of last-saved widget values, used by the default is_dirty().
        self._snapshot: Dict[str, Any] = {}
        # Per demo-redacted field: the real value and what was put on screen,
        # our own writes still to be echoed back as Changed events, and
        # whether the user has typed in it since it was last shown.
        self._demo_real: Dict[str, Any] = {}
        self._demo_shown: Dict[str, Any] = {}
        self._demo_pending: Dict[str, List[str]] = {}
        self._demo_edited: Set[str] = set()

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

    def refresh_after_demo_toggle(self) -> None:
        """Re-show every demo-redacted field for the new demo-mode state.

        Unsaved edits survive: each field is re-shown from its current
        real value, not reloaded from the config.
        """
        for field_id in self.DEMO_REDACTED_FIELDS:
            self._show_field(field_id, self._field_value(field_id))
        # List editors re-mount their rows; re-check once they have settled.
        self.call_after_refresh(self._refresh_dirty_marker)

    # ------------------------------------------------------------------
    # Demo-mode field redaction
    # ------------------------------------------------------------------

    def _show_field(self, field_id: str, real: Any) -> None:
        """Put *real* into the field, or its redacted stand-in in demo mode."""
        shown = self._redact_for_display(field_id, real)
        self._demo_real[field_id] = real
        self._demo_shown[field_id] = shown
        self._demo_edited.discard(field_id)
        if isinstance(shown, str) and self._read_field(field_id) != shown:
            # The Changed event this write posts is ours, not the user's.
            self._demo_pending.setdefault(field_id, []).append(shown)
        self._write_field(field_id, shown)

    def _field_value(self, field_id: str) -> Any:
        """The field's value, with an untouched stand-in mapped to the real one.

        Once the user has typed in a field, what it holds is theirs, even
        when it happens to equal the stand-in (usernames and key names come
        from a small pool, so "ubuntu" can be both).
        """
        value = self._read_field(field_id)
        if field_id not in self._demo_shown:
            return value
        shown = self._demo_shown[field_id]
        real = self._demo_real[field_id]
        if isinstance(value, list):
            # By row, not by text: two entries can share a stand-in.
            return [
                real[tag] if isinstance(tag, int) and tag < len(real)
                and text == str(shown[tag]).strip() else text
                for text, tag in self._list_entries(field_id)
            ]
        if isinstance(value, dict):
            # Keys are redacted injectively; each value maps back via its key.
            real_key = dict(zip(shown, real))
            out = {}
            for key, item in value.items():
                original = real_key.get(key, key)
                untouched = key in shown and item == shown[key]
                out[original] = real[original] if untouched else item
            return out
        if field_id in self._demo_edited:
            return value
        return real if value.strip() == str(shown).strip() else value

    @on(Input.Changed)
    def _note_demo_field_edit(self, event: Input.Changed) -> None:
        """Tell the user's edits of a demo-redacted field from our own writes."""
        node: Any = event.input
        while node is not None and node is not self:
            field_id = getattr(node, "id", None)
            if field_id in self._demo_shown:
                pending = self._demo_pending.get(field_id) or []
                if pending and pending[0] == event.value:
                    pending.pop(0)
                elif isinstance(self._demo_shown[field_id], str):
                    self._demo_edited.add(field_id)
                return
            node = node.parent

    def _redact_for_display(self, field_id: str, real: Any) -> Any:
        method = self.DEMO_REDACTED_FIELDS.get(field_id)
        app = self.app
        redaction = getattr(app, "redaction_service", None)
        if not method or not getattr(app, "demo_mode", False) or redaction is None:
            return real
        if isinstance(method, tuple):
            key_method, value_method = (getattr(redaction, name) for name in method)
        else:
            key_method = value_method = getattr(redaction, method)
        if isinstance(real, dict):
            shown: Dict[str, Any] = {}
            for k, v in real.items():
                key = key_method(str(k)) if k else k
                while key in shown:  # never merge two entries into one
                    key = f"{key}'"
                shown[key] = value_method(str(v)) if v else v
            return shown
        if isinstance(real, list):
            return [value_method(v) if v else v for v in real]
        return value_method(real) if real else real

    def _list_entries(self, field_id: str) -> List[tuple]:
        widget = self.query_one(f"#{field_id}")
        entries = getattr(widget, "get_entries", None)
        if callable(entries):
            return entries()
        return [(value, None) for value in widget.get_values()]

    def _read_field(self, field_id: str) -> Any:
        from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor

        widget = self.query_one(f"#{field_id}")
        if isinstance(widget, StringListEditor):
            return widget.get_values()
        if isinstance(widget, KeyValueEditor):
            return {str(k): str(v) for k, v in widget.get_map().items()}
        return widget.value

    def _write_field(self, field_id: str, value: Any) -> None:
        from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor

        widget = self.query_one(f"#{field_id}")
        if isinstance(widget, StringListEditor):
            widget.set_values(list(value), tags=list(range(len(value))))
        elif isinstance(widget, KeyValueEditor):
            widget.set_map(dict(value))
        else:
            widget.value = value

    def refresh_external_state(self) -> None:
        """Refresh state managed outside this settings form.

        Called when the parent Settings screen resumes after a pushed screen.
        Most panels have no external state and intentionally do nothing.
        """

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

        The callback is deferred, so the user may have left Settings before it
        runs. The screen is then being torn down: the panel is detached, or
        still linked while its fields are already removed. Either way there is
        nothing left to re-baseline.
        """
        if not self.is_attached:
            return
        try:
            settled = self.current_values()
        except NoMatches:
            return
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

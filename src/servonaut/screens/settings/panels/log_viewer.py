"""Log Viewer settings panel.

Covers all log-viewer tunables in :class:`~servonaut.config.schema.AppConfig`:

- ``log_viewer_scan_max_depth`` (int)
- ``log_viewer_max_lines`` (int)
- ``log_viewer_tail_lines`` (int)
- ``log_viewer_default_paths`` (List[str])
- ``log_viewer_scan_directories`` (List[str])
- ``log_viewer_custom_paths`` (Dict[str, List[str]] — map of label → paths)

The ``log_viewer_custom_paths`` field maps a free-form label (e.g. an instance
name or group tag) to a list of log paths.  Because :class:`KeyValueEditor`
stores scalar string values, custom-paths values are stored as a
newline-separated string in the editor and round-tripped through a
``|``-delimited representation for display.  The per-entry format presented to
the user is::

    <label>  →  /path/one,/path/two

(comma-joined paths as the "value").  On save the comma-split list is stored
as the dict value.  An empty paths string is accepted as an empty list.
"""

from __future__ import annotations

from typing import Any, Dict, List

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor


class LogViewerPanel(SettingsPanel):
    """Settings panel for log-viewer tunables.

    Scalar limits (scan depth, max lines, tail lines) are plain integer
    inputs.  The three list/map fields use :class:`StringListEditor` and a
    custom :class:`KeyValueEditor` whose "value" column holds a
    comma-separated path list.
    """

    PANEL_ID = "log_viewer"
    TITLE = "Log Viewer"

    DEFAULT_CSS = """
    LogViewerPanel .lv-section-header {
        color: $accent;
        text-style: bold;
        margin: 1 0 0 0;
        height: auto;
    }
    LogViewerPanel .lv-help {
        color: $text-muted;
        height: auto;
        padding: 0 0 0 1;
        margin: 0 0 1 0;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the log-viewer form rows."""
        # --- Scalar limits ---
        yield Static("Scan limits", classes="lv-section-header")
        yield Horizontal(
            Static("Max scan depth", classes="label"),
            Input(placeholder="2", id="lv_scan_max_depth"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Max lines to load", classes="label"),
            Input(placeholder="10000", id="lv_max_lines"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Tail lines (follow mode)", classes="label"),
            Input(placeholder="100", id="lv_tail_lines"),
            classes="setting_row",
        )

        # --- Default log paths ---
        yield Static("Default log paths", classes="lv-section-header")
        yield Static(
            "Paths offered in the log-viewer path picker by default.",
            classes="lv-help",
        )
        yield StringListEditor(
            placeholder="/var/log/syslog",
            id="lv_default_paths",
        )

        # --- Scan directories ---
        yield Static("Scan directories", classes="lv-section-header")
        yield Static(
            "Directories searched when scanning for log files.",
            classes="lv-help",
        )
        yield StringListEditor(
            placeholder="/var/log",
            id="lv_scan_directories",
        )

        # --- Custom paths per label ---
        yield Static("Custom paths (per label)", classes="lv-section-header")
        yield Static(
            "Map a label (e.g. instance name) to a comma-separated list of paths.",
            classes="lv-help",
        )
        yield KeyValueEditor(
            key_placeholder="label",
            value_placeholder="/path/one,/path/two",
            value_is_int=False,
            id="lv_custom_paths",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()

        self.query_one("#lv_scan_max_depth", Input).value = str(
            config.log_viewer_scan_max_depth
        )
        self.query_one("#lv_max_lines", Input).value = str(config.log_viewer_max_lines)
        self.query_one("#lv_tail_lines", Input).value = str(config.log_viewer_tail_lines)

        self.query_one("#lv_default_paths", StringListEditor).set_values(
            list(config.log_viewer_default_paths)
        )
        self.query_one("#lv_scan_directories", StringListEditor).set_values(
            list(config.log_viewer_scan_directories)
        )

        # Flatten Dict[str, List[str]] → Dict[str, str] (comma-joined paths).
        flat: Dict[str, str] = {
            label: ",".join(paths)
            for label, paths in (config.log_viewer_custom_paths or {}).items()
        }
        self.query_one("#lv_custom_paths", KeyValueEditor).set_map(flat)

        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "lv_scan_max_depth": self.query_one("#lv_scan_max_depth", Input).value.strip(),
            "lv_max_lines": self.query_one("#lv_max_lines", Input).value.strip(),
            "lv_tail_lines": self.query_one("#lv_tail_lines", Input).value.strip(),
            "lv_default_paths": self.query_one(
                "#lv_default_paths", StringListEditor
            ).get_values(),
            "lv_scan_directories": self.query_one(
                "#lv_scan_directories", StringListEditor
            ).get_values(),
            "lv_custom_paths": dict(
                self.query_one("#lv_custom_paths", KeyValueEditor).get_map()
            ),
        }

    # ------------------------------------------------------------------
    # Validation and persistence
    # ------------------------------------------------------------------

    def collect(self) -> Dict[str, Any]:
        """Validate widgets and return field dict ready for persistence.

        Raises:
            ValidationError: When a numeric field is not a valid positive integer.
        """
        scan_max_depth = self._parse_positive_int(
            "#lv_scan_max_depth", "lv_scan_max_depth", "Max scan depth"
        )
        max_lines = self._parse_positive_int(
            "#lv_max_lines", "lv_max_lines", "Max lines to load"
        )
        tail_lines = self._parse_positive_int(
            "#lv_tail_lines", "lv_tail_lines", "Tail lines"
        )

        default_paths: List[str] = self.query_one(
            "#lv_default_paths", StringListEditor
        ).get_values()
        scan_directories: List[str] = self.query_one(
            "#lv_scan_directories", StringListEditor
        ).get_values()

        # Parse the flat comma-joined map back to Dict[str, List[str]].
        flat_map = self.query_one("#lv_custom_paths", KeyValueEditor).get_map()
        custom_paths: Dict[str, List[str]] = {}
        for label, raw_paths in flat_map.items():
            paths = [p.strip() for p in str(raw_paths).split(",") if p.strip()]
            custom_paths[str(label)] = paths

        return {
            "log_viewer_scan_max_depth": scan_max_depth,
            "log_viewer_max_lines": max_lines,
            "log_viewer_tail_lines": tail_lines,
            "log_viewer_default_paths": default_paths,
            "log_viewer_scan_directories": scan_directories,
            "log_viewer_custom_paths": custom_paths,
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` then write through config_manager."""
        fields = self.collect()
        self.app.config_manager.update(**fields)
        self._finish_save()

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any input edit."""
        self._dirty_watch()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_positive_int(
        self, query: str, field_id: str, label: str
    ) -> int:
        """Parse a required positive integer from the named Input.

        Args:
            query: CSS query for the Input widget (e.g. ``"#lv_max_lines"``).
            field_id: Widget id used by :meth:`mark_field_error` on failure.
            label: Human-readable field name included in the error message.

        Returns:
            The parsed integer value (>= 1).

        Raises:
            ValidationError: When the value is not a valid integer or is < 1.
        """
        raw = self.query_one(query, Input).value.strip()
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValidationError(
                field_id, f"{escape(label)} must be a whole number"
            ) from exc
        if value < 1:
            raise ValidationError(
                field_id, f"{escape(label)} must be 1 or greater"
            )
        return value

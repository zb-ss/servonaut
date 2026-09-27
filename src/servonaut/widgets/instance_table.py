"""Instance table widget for Servonaut v2.0."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from rich.text import Text
from textual.widgets import DataTable

# What an empty cell shows.
_EMPTY = "-"


@dataclass(frozen=True)
class _Column:
    """One fleet-table column.

    Attributes:
        key: Column key, also used by ``get_column_index``.
        label: Header text.
        max_width: Longest value shown in full; a longer one is cut short with
            an ellipsis (the detail panel below the table shows it whole).
            ``None`` for columns whose values are short by construction.
        optional: Left out while no row has a value for it.
    """

    key: str
    label: str
    max_width: Optional[int] = None
    optional: bool = False


# Every column is as wide as its longest value, up to its maximum, so short
# values leave room for the rest. Most important first: when the terminal is
# too narrow, the table scrolls sideways and the last columns are the ones
# out of view.
COLUMNS: Sequence[_Column] = (
    _Column("index", "#"),
    _Column("name", "Name", max_width=32),
    _Column("state", "State"),
    _Column("provider", "Provider", max_width=14),
    _Column("public_ip", "Public IP", max_width=24),
    _Column("type", "Type", max_width=20),
    _Column("region", "Region", max_width=16),
    _Column("private_ip", "Private IP", max_width=24),
    # 25 fits an OVH VPS service name; AWS ids are 19.
    _Column("id", "ID", max_width=25),
    _Column("key", "Key", max_width=20),
    # SSH verify status — at-a-glance BW probe result badge. Shown once any
    # server has a result, so a fleet that never verifies keeps the room.
    _Column("ssh", "SSH", optional=True),
    # Memory discoverability — at-a-glance status so users learn the
    # feature exists without needing to drill into a server.
    _Column("memory", "Mem"),
)

# Shown in the table's bottom border while some columns are out of view.
SCROLL_HINT = "← → more columns"


def _fit(value: str, max_width: Optional[int]) -> Text:
    """*value* as plain text (never markup), cut to *max_width* with an ellipsis."""
    text = Text(value, no_wrap=True, end="")
    if max_width is not None and text.cell_len > max_width:
        text.truncate(max_width, overflow="ellipsis")
    return text


def _key_label(key: str) -> str:
    """A key as the table lists it: the file name of a key file path.

    Custom servers name a key file (``~/.ssh/web1_ed25519``); cloud servers
    name a key pair. The directory rarely tells servers apart, so the table
    keeps to the file name and the detail panel shows the full path.
    """
    if "/" in key or "\\" in key:
        name = key.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        return name or key
    return key


class InstanceTable(DataTable):
    """DataTable subclass for displaying EC2 instances."""

    ALLOW_SELECT = True

    def __init__(self) -> None:
        """Initialize instance table."""
        super().__init__(cursor_type="row")
        self._all_instances: List[dict] = []
        self._filtered_instances: List[dict] = []
        self._shown_columns: List[_Column] = []
        self._setup_columns([column for column in COLUMNS if not column.optional])

    def _setup_columns(self, columns: Sequence[_Column]) -> None:
        """Add *columns*, each sized to its content (see ``COLUMNS``)."""
        for column in columns:
            self.add_column(column.label, key=column.key)
        self._shown_columns = list(columns)

    def on_resize(self) -> None:
        """Re-check the scroll hint: the view got wider or narrower."""
        self._sync_scroll_hint()

    def _sync_scroll_hint(self) -> None:
        """Say so in the bottom border while columns are out of view."""
        hidden = self.virtual_size.width > self.scrollable_content_region.width
        self.border_subtitle = SCROLL_HINT if hidden else ""

    def _update_dimensions(self, *args: Any, **kwargs: Any) -> None:
        """Size the columns for new rows, then redraw rows drawn too early.

        DataTable measures new rows for its auto-width columns on its idle
        pass, not when they are added, and it keeps the lines it rendered
        before that pass. A frame drawn in between (a busy event loop, a slow
        terminal) would leave a long server name cut to the old column width
        until the next repopulate, so drop those lines once a width changes.

        Both hooks are DataTable internals. Arguments pass through untouched,
        and a missing cache-clearing method only costs the redraw, never the
        screen; the unit tests fail when either internal changes upstream.
        """
        widths_before = self._render_widths()
        super()._update_dimensions(*args, **kwargs)
        self._sync_scroll_hint()
        if self._render_widths() == widths_before:
            return
        clear_caches = getattr(self, "_clear_caches", None)
        if callable(clear_caches):
            clear_caches()
            self.refresh()

    def _render_widths(self) -> List[int]:
        return [column.get_render_width(self) for column in self.columns.values()]

    def populate(self, instances: List[dict]) -> None:
        """Populate table with instances.

        Args:
            instances: List of instance dictionaries.
        """
        self._all_instances = instances
        self._filtered_instances = instances.copy()
        self._refresh_table()

    def filter(self, query: str) -> None:
        """Filter table rows by query string.

        Filters by instance name or type (case-insensitive substring match).

        Args:
            query: Search query string.
        """
        if not query:
            self._filtered_instances = self._all_instances.copy()
        else:
            query_lower = query.lower()
            self._filtered_instances = [
                inst for inst in self._all_instances
                if query_lower in inst.get('name', '').lower()
                or query_lower in inst.get('type', '').lower()
                or query_lower in inst.get('id', '').lower()
                or query_lower in inst.get('provider', '').lower()
            ]
        self._refresh_table()

    def refresh_memory_status(self) -> None:
        """Re-render rows so the memory status column recomputes, keeping cursor.

        Called (via the screen) after a background fleet auto-scan cycle so the
        "Mem" column reflects freshly-probed servers immediately.  Re-renders
        from the current ``_filtered_instances`` (so the active filter is
        preserved) and restores the cursor row so a background refresh never
        yanks the user's selection to the top.  A no-op when the table is empty.
        """
        if not self._filtered_instances:
            return
        saved_row = self.cursor_row
        self._refresh_table()
        try:
            if 0 <= saved_row < len(self._filtered_instances):
                self.move_cursor(row=saved_row)
        except Exception:
            pass

    def get_selected_instance(self) -> Optional[dict]:
        """Get the currently selected instance.

        Returns:
            Instance dictionary for selected row, or None if no selection.
        """
        if not self._filtered_instances:
            return None

        cursor_row = self.cursor_row
        if cursor_row < 0 or cursor_row >= len(self._filtered_instances):
            return None

        return self._filtered_instances[cursor_row]

    def get_selected_field(self, field: str) -> Optional[str]:
        """Get a specific field value from the selected instance.

        Args:
            field: Field key (e.g. 'public_ip', 'private_ip', 'name', 'id').

        Returns:
            Field value string, or None if no selection or field is empty.
        """
        instance = self.get_selected_instance()
        if not instance:
            return None
        value = instance.get(field, '') or ''
        return value if value else None

    def _refresh_table(self) -> None:
        """Refresh table display with current filtered instances."""
        memory_service = getattr(self.app, "memory_service", None)
        # Judged on the whole fleet, not the filtered rows, so a search does
        # not make an optional column come and go.
        columns = [
            column
            for column in COLUMNS
            if not column.optional
            or any(self._optional_cell(column.key, i) for i in self._all_instances)
        ]
        if columns == self._shown_columns:
            self.clear()
        else:
            self.clear(columns=True)
            self._setup_columns(columns)
        for idx, instance in enumerate(self._filtered_instances):
            cells = self._row_cells(idx, instance, memory_service)
            self.add_row(*(cells[column.key] for column in columns))

    def _row_cells(self, idx: int, instance: dict, memory_service: Any) -> Dict[str, Any]:
        """Every column's cell for one server, by column key."""
        limits = {column.key: column.max_width for column in COLUMNS}

        def plain(key: str, value: Any) -> Text:
            return _fit(str(value or "") or _EMPTY, limits[key])

        state = instance.get("state", "") or ""
        coloured = self._colorize_state(state)
        return {
            "index": str(idx + 1),
            "name": plain("name", instance.get("name")),
            # A state without a colour is provider text: never read as markup.
            "state": coloured if coloured != state else plain("state", state),
            "provider": plain("provider", instance.get("provider", "AWS")),
            "public_ip": plain("public_ip", instance.get("public_ip")),
            "type": plain("type", instance.get("type")),
            "region": plain("region", instance.get("region")),
            "private_ip": plain("private_ip", instance.get("private_ip")),
            "id": plain("id", instance.get("id")),
            "key": plain("key", _key_label(instance.get("key_name") or "")),
            "ssh": self._ssh_verify_cell(instance),
            "memory": self._memory_icon(instance, memory_service),
        }

    def _optional_cell(self, key: str, instance: dict) -> Optional[str]:
        """The cell an optional column shows for *instance*, or None if nothing."""
        if key == "ssh":
            from servonaut.utils.formatting import format_ssh_verify_state

            cell = self._ssh_verify_cell(instance)
            return None if cell == format_ssh_verify_state(None, None) else cell
        return None

    def _ssh_verify_cell(self, instance: dict) -> str:
        """Return Rich-markup badge for the SSH verify status column.

        Delegates to :func:`format_ssh_verify_state` so the formatter is the
        single source of truth for badge text / colour.
        """
        from servonaut.utils.formatting import format_ssh_verify_state
        return format_ssh_verify_state(
            instance.get("ssh_verify_status"),
            instance.get("ssh_verified_at"),
        )

    def _memory_icon(self, instance: dict, memory_service) -> str:
        """Return a compact Rich-markup icon for the memory column.

        Delegates to :func:`compute_memory_status` from the fleet screen so
        the instance list and fleet view stay in lockstep on status vocabulary.
        """
        if memory_service is None:
            return "[dim]—[/dim]"
        try:
            from servonaut.screens.fleet_memory import (
                compute_memory_status,
                STATUS_FRESH,
                STATUS_STALE,
                STATUS_OPT_OUT,
            )
            status = compute_memory_status(instance, memory_service)
        except Exception:
            return "[dim]—[/dim]"
        if status == STATUS_FRESH:
            return "[green]●[/green]"
        if status == STATUS_STALE:
            return "[yellow]●[/yellow]"
        if status == STATUS_OPT_OUT:
            return "[red]⛔[/red]"
        return "[dim]○[/dim]"

    def _colorize_state(self, state: str) -> str:
        """Add color markup to instance state.

        Args:
            state: Instance state string.

        Returns:
            Colorized state string with markup.
        """
        state_colors = {
            'running': '[green]running[/green]',
            'stopped': '[red]stopped[/red]',
            'stopping': '[yellow]stopping[/yellow]',
            'pending': '[cyan]pending[/cyan]',
            'terminated': '[dim]terminated[/dim]',
        }
        return state_colors.get(state, state)

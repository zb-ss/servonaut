"""Log picker modal for selecting log files to view."""

from __future__ import annotations

from typing import Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.events import Key
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import Input, OptionList, Static
from textual.widgets.option_list import Option

# Sentinel value returned when user picks "+ Add custom path..."
ADD_PATH_SENTINEL = "__add_custom_path__"

# Max options rendered in the list to keep the UI responsive
_MAX_VISIBLE = 50

# Debounce delay in seconds for search input
_DEBOUNCE_SECONDS = 0.15


class LogPickerModal(ModalScreen[str]):
    """Modal for picking a log file from available and discovered logs.

    Dismisses with the selected log path, ADD_PATH_SENTINEL for add-path,
    or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(
        self,
        available_logs: List[str],
        discovered_logs: List[str],
        current_log: Optional[str] = None,
        classify_fn=None,
    ) -> None:
        """Initialize log picker.

        Args:
            available_logs: Probed readable log paths.
            discovered_logs: Paths found by directory scan (not in available).
            current_log: Currently viewed log path (will be marked).
            classify_fn: Callable(path) -> "active"|"rotated"|"compressed".
        """
        super().__init__()
        self._available_logs = available_logs
        self._discovered_logs = discovered_logs
        self._current_log = current_log
        self._classify_fn = classify_fn
        self._option_map: Dict[str, str] = {}
        self._debounce_timer: Optional[Timer] = None
        self._first_selectable: Optional[int] = None
        # Pre-compute the discovered-only set once
        self._discovered_only: List[str] = [
            p for p in discovered_logs if p not in set(available_logs)
        ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Log Picker[/bold cyan]  "
                "[dim]Type to filter, Enter to select, Escape to cancel[/dim]",
                id="log_picker_header",
            ),
            Input(
                placeholder="Search log files...",
                id="log_picker_search",
            ),
            Static("", id="log_picker_count"),
            OptionList(id="log_picker_list"),
            id="log_picker_container",
        )

    def on_mount(self) -> None:
        """Populate the option list and focus search."""
        self._rebuild_options("")
        self.query_one("#log_picker_search", Input).focus()

    def on_key(self, event: Key) -> None:
        """Move focus between search field and option list."""
        search = self.query_one("#log_picker_search", Input)
        option_list = self.query_one("#log_picker_list", OptionList)

        if event.key == "down" and search.has_focus:
            option_list.focus()
            if self._first_selectable is not None:
                option_list.highlighted = self._first_selectable
            event.prevent_default()
        elif event.key == "up" and option_list.has_focus:
            if option_list.highlighted is not None and option_list.highlighted == self._first_selectable:
                search.focus()
                event.prevent_default()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Debounce search to avoid rebuilding on every keystroke."""
        if event.input.id != "log_picker_search":
            return
        if self._debounce_timer is not None:
            self._debounce_timer.stop()
        query = event.value.strip().lower()
        self._debounce_timer = self.set_timer(
            _DEBOUNCE_SECONDS, lambda: self._rebuild_options(query)
        )

    def _rebuild_options(self, query: str) -> None:
        """Rebuild the option list filtered by query, capped for performance.

        Builds the full option list in memory first, then applies it in a
        single ``set_options()`` call to avoid per-item DOM mutations.
        """
        self._option_map.clear()
        self._first_selectable = None
        all_options: list = []
        idx = 0

        # Filter available logs
        filtered_available = [
            p for p in self._available_logs
            if not query or query in p.lower()
        ]

        # Filter discovered-only logs
        filtered_discovered = [
            p for p in self._discovered_only
            if not query or query in p.lower()
        ]

        total_matches = len(filtered_available) + len(filtered_discovered)

        # --- Available Logs section ---
        if filtered_available:
            all_options.append(Option("── Available Logs ──", disabled=True))
            idx += 1
            for path in filtered_available:
                option_id = f"avail:{path}"
                self._option_map[option_id] = path
                marker = " [bold green]●[/bold green]" if path == self._current_log else ""
                all_options.append(Option(f"  {path}{marker}", id=option_id))
                if self._first_selectable is None:
                    self._first_selectable = idx
                idx += 1

        # Separator
        if filtered_available and filtered_discovered:
            all_options.append(Option("", disabled=True))
            idx += 1

        # --- Discovered Logs section (capped) ---
        truncated_discovered = filtered_discovered[:_MAX_VISIBLE]
        hidden_count = len(filtered_discovered) - len(truncated_discovered)

        if truncated_discovered:
            all_options.append(Option("── Discovered Logs ──", disabled=True))
            idx += 1
            for path in truncated_discovered:
                option_id = f"disc:{path}"
                self._option_map[option_id] = path
                tag = ""
                if self._classify_fn:
                    classification = self._classify_fn(path)
                    if classification == "compressed":
                        tag = " [yellow]\\[zip][/yellow]"
                    elif classification == "rotated":
                        tag = " [dim]\\[rot][/dim]"
                all_options.append(Option(f"  {path}{tag}", id=option_id))
                if self._first_selectable is None:
                    self._first_selectable = idx
                idx += 1
            if hidden_count > 0:
                all_options.append(Option(
                    f"  [dim]... {hidden_count} more — refine search to narrow[/dim]",
                    disabled=True,
                ))
                idx += 1

        # Separator before add
        if filtered_available or truncated_discovered:
            all_options.append(Option("", disabled=True))
            idx += 1

        # --- Add custom path option ---
        if not query or "add" in query or "custom" in query or "path" in query:
            option_id = "action:add_path"
            self._option_map[option_id] = ADD_PATH_SENTINEL
            all_options.append(
                Option("  [bold]+[/bold] Add custom path...", id=option_id)
            )
            if self._first_selectable is None:
                self._first_selectable = idx
            idx += 1

        if not filtered_available and not filtered_discovered and query:
            all_options.append(Option("  (no matches)", disabled=True))

        # Single DOM operation — replaces everything at once
        option_list = self.query_one("#log_picker_list", OptionList)
        focused_before = self.focused
        option_list.set_options(all_options)
        # Restore focus to search input if set_options caused a focus change
        if self.focused is not focused_before:
            self.query_one("#log_picker_search", Input).focus()

        # Update match count
        count_label = self.query_one("#log_picker_count", Static)
        if query:
            count_label.update(
                f"[dim]{total_matches} match{'es' if total_matches != 1 else ''}"
                f" (of {len(self._available_logs) + len(self._discovered_only)} total)[/dim]"
            )
        else:
            count_label.update(
                f"[dim]{total_matches} log file{'s' if total_matches != 1 else ''}[/dim]"
            )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Select first visible option on Enter in search field."""
        if event.input.id != "log_picker_search":
            return
        option_list = self.query_one("#log_picker_list", OptionList)
        for i in range(option_list.option_count):
            option = option_list.get_option_at_index(i)
            if not option.disabled and option.id and option.id in self._option_map:
                self.dismiss(self._option_map[option.id])
                return

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle option selection."""
        option_id = event.option.id
        if option_id and option_id in self._option_map:
            self.dismiss(self._option_map[option_id])

    def action_cancel(self) -> None:
        """Close without selecting."""
        self.dismiss(None)


class AddPathModal(ModalScreen[str]):
    """Simple modal for entering a custom log file path.

    Dismisses with the path string, or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Add Custom Log Path[/bold cyan]",
                id="add_path_header",
            ),
            Static(
                "[dim]Enter an absolute path to a log file on the remote server.[/dim]",
                id="add_path_hint",
            ),
            Input(
                placeholder="/var/log/myapp/app.log",
                id="add_path_input",
            ),
            id="add_path_container",
        )

    def on_mount(self) -> None:
        """Focus the path input."""
        self.query_one("#add_path_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Validate and submit on Enter."""
        if event.input.id != "add_path_input":
            return
        path = event.value.strip()
        if not path:
            self.notify("Path cannot be empty", severity="warning")
        elif not path.startswith("/"):
            self.notify("Path must be absolute (start with /)", severity="warning")
        else:
            self.dismiss(path)

    def action_cancel(self) -> None:
        """Close without adding."""
        self.dismiss(None)

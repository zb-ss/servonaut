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
        """Move focus from search to option list on down arrow."""
        if event.key == "down" and self.query_one("#log_picker_search", Input).has_focus:
            option_list = self.query_one("#log_picker_list", OptionList)
            option_list.focus()
            # Highlight first selectable option
            for i in range(option_list.option_count):
                option = option_list.get_option_at_index(i)
                if not option.disabled:
                    option_list.highlighted = i
                    break
            event.prevent_default()
        elif event.key == "up" and self.query_one("#log_picker_list", OptionList).has_focus:
            option_list = self.query_one("#log_picker_list", OptionList)
            # Find first non-disabled index
            first_selectable = None
            for i in range(option_list.option_count):
                if not option_list.get_option_at_index(i).disabled:
                    first_selectable = i
                    break
            # If at the first selectable item, go back to search
            if option_list.highlighted is not None and option_list.highlighted == first_selectable:
                self.query_one("#log_picker_search", Input).focus()
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
        """Rebuild the option list filtered by query, capped for performance."""
        option_list = self.query_one("#log_picker_list", OptionList)
        option_list.clear_options()
        self._option_map.clear()

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

        # --- Available Logs section (always show all — these are small) ---
        if filtered_available:
            option_list.add_option(Option("── Available Logs ──", disabled=True))
            for path in filtered_available:
                option_id = f"avail:{path}"
                self._option_map[option_id] = path
                marker = " [bold green]●[/bold green]" if path == self._current_log else ""
                option_list.add_option(
                    Option(f"  {path}{marker}", id=option_id)
                )

        # Separator
        if filtered_available and filtered_discovered:
            option_list.add_option(Option("", disabled=True))

        # --- Discovered Logs section (capped) ---
        truncated_discovered = filtered_discovered[:_MAX_VISIBLE]
        hidden_count = len(filtered_discovered) - len(truncated_discovered)

        if truncated_discovered:
            option_list.add_option(Option("── Discovered Logs ──", disabled=True))
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
                option_list.add_option(
                    Option(f"  {path}{tag}", id=option_id)
                )
            if hidden_count > 0:
                option_list.add_option(
                    Option(
                        f"  [dim]... {hidden_count} more — refine search to narrow[/dim]",
                        disabled=True,
                    )
                )

        # Separator before add
        if filtered_available or truncated_discovered:
            option_list.add_option(Option("", disabled=True))

        # --- Add custom path option ---
        if not query or "add" in query or "custom" in query or "path" in query:
            option_id = "action:add_path"
            self._option_map[option_id] = ADD_PATH_SENTINEL
            option_list.add_option(
                Option("  [bold]+[/bold] Add custom path...", id=option_id)
            )

        if not filtered_available and not filtered_discovered and query:
            option_list.add_option(Option("  (no matches)", disabled=True))

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

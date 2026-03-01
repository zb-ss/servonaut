"""Command picker modal for selecting saved and recent commands."""

from __future__ import annotations

from typing import List, Dict

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Input, OptionList, Static
from textual.widgets.option_list import Option


class CommandPickerModal(ModalScreen[str]):
    """Modal for picking saved commands or recent history with search.

    Dismisses with the selected command string, or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(
        self,
        saved_commands: List[Dict[str, str]],
        recent_commands: List[str],
    ) -> None:
        """Initialize command picker.

        Args:
            saved_commands: List of dicts with 'name' and 'command' keys.
            recent_commands: List of recent command strings (newest first).
        """
        super().__init__()
        self._saved_commands = saved_commands
        self._recent_commands = recent_commands
        self._option_map: Dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Command Picker[/bold cyan]  "
                "[dim]Type to filter, Enter to select, Escape to cancel[/dim]",
                id="picker_header",
            ),
            Input(
                placeholder="Search commands...",
                id="picker_search",
            ),
            OptionList(id="picker_list"),
            id="picker_container",
        )

    def on_mount(self) -> None:
        """Populate the option list and focus search."""
        self._rebuild_options("")
        self.query_one("#picker_search", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Filter options as the user types."""
        if event.input.id == "picker_search":
            self._rebuild_options(event.value.strip().lower())

    def _rebuild_options(self, query: str) -> None:
        """Rebuild the option list filtered by query.

        Args:
            query: Lowercase search string to filter by.
        """
        option_list = self.query_one("#picker_list", OptionList)
        option_list.clear_options()
        self._option_map.clear()

        # Filter saved commands
        filtered_saved = [
            entry for entry in self._saved_commands
            if not query
            or query in entry['name'].lower()
            or query in entry['command'].lower()
        ]

        # Filter recent commands (deduplicated against saved)
        saved_cmds = {e['command'] for e in self._saved_commands}
        filtered_recent = [
            cmd for cmd in self._recent_commands
            if cmd not in saved_cmds
            and (not query or query in cmd.lower())
        ]

        # Saved commands section
        if filtered_saved:
            option_list.add_option(Option("── Saved Commands ──", disabled=True))
            for entry in filtered_saved:
                option_id = f"saved:{entry['name']}"
                self._option_map[option_id] = entry['command']
                option_list.add_option(
                    Option(
                        f"  [bold]★[/bold] {entry['name']}  [dim]{entry['command']}[/dim]",
                        id=option_id,
                    )
                )

        # Separator between sections
        if filtered_saved and filtered_recent:
            option_list.add_option(Option("", disabled=True))

        # Recent commands section
        if filtered_recent:
            option_list.add_option(Option("── Recent Commands ──", disabled=True))
            for i, cmd in enumerate(filtered_recent):
                option_id = f"recent:{i}"
                self._option_map[option_id] = cmd
                option_list.add_option(Option(f"  {cmd}", id=option_id))

        if not filtered_saved and not filtered_recent:
            if query:
                option_list.add_option(Option("  (no matches)", disabled=True))
            else:
                option_list.add_option(Option("  (no commands yet)", disabled=True))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Select first visible option on Enter in search field."""
        if event.input.id != "picker_search":
            return
        option_list = self.query_one("#picker_list", OptionList)
        # Find first selectable option
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


class SaveCommandModal(ModalScreen[str]):
    """Small modal prompting for a name to save a command under.

    Dismisses with the name string, or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(self, command: str) -> None:
        """Initialize save modal.

        Args:
            command: The command being saved (shown for reference).
        """
        super().__init__()
        self._command = command

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Save Command[/bold cyan]",
                id="save_header",
            ),
            Static(f"[dim]Command:[/dim] {self._command}", id="save_command_preview"),
            Input(
                placeholder="Enter a name for this command...",
                id="save_name_input",
            ),
            id="save_container",
        )

    def on_mount(self) -> None:
        """Focus the name input."""
        self.query_one("#save_name_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Save on Enter."""
        if event.input.id != "save_name_input":
            return
        name = event.value.strip()
        if name:
            self.dismiss(name)
        else:
            self.notify("Name cannot be empty", severity="warning")

    def action_cancel(self) -> None:
        """Close without saving."""
        self.dismiss(None)

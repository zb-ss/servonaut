"""Command picker modal for selecting saved and recent commands."""

from __future__ import annotations

from typing import Dict, List, Optional

from rich.markup import escape

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import Button, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from servonaut.widgets.dialogs import (
    DialogActions, DialogBody, DialogContent, DialogFrame, DialogNotificationSpace,
)

_DEBOUNCE_SECONDS = 0.15


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
        super().__init__(classes="dialog-screen")
        self._saved_commands = saved_commands
        self._recent_commands = recent_commands
        self._option_map: Dict[str, str] = {}
        self._debounce_timer: Optional[Timer] = None

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Vertical(
                Static("[bold $text-accent]Command Picker[/bold $text-accent]", id="picker_header"),
                Static(
                    "Type to filter, Enter to select, Escape to cancel",
                    id="picker_hint",
                ),
            ),
            body=DialogContent(
                Input(placeholder="Search commands...", id="picker_search"),
                OptionList(id="picker_list"),
                id="picker_body",
            ),
            status=Static(
                "Selecting a command fills the prompt. Press Enter there to execute it.",
                id="picker_selection_hint",
            ),
            actions=DialogActions(Button("Cancel", id="picker_cancel")),
            id="picker_container",
            size="large",
        )

    def on_mount(self) -> None:
        """Populate the option list and focus search."""
        self._rebuild_options("")
        self.query_one("#picker_search", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Debounce search to avoid rebuilding on every keystroke."""
        if event.input.id != "picker_search":
            return
        if self._debounce_timer is not None:
            self._debounce_timer.stop()
        query = event.value.strip().lower()
        self._debounce_timer = self.set_timer(
            _DEBOUNCE_SECONDS, lambda: self._rebuild_options(query)
        )

    def _rebuild_options(self, query: str) -> None:
        """Rebuild the option list filtered by query.

        Args:
            query: Lowercase search string to filter by.
        """
        self._option_map.clear()
        all_options: list = []

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
            all_options.append(Option("── Saved Commands ──", disabled=True))
            for entry in filtered_saved:
                option_id = f"saved:{entry['name']}"
                self._option_map[option_id] = entry['command']
                all_options.append(
                    Option(
                        f"  [bold]★[/bold] {escape(entry['name'])}  [dim]{escape(entry['command'])}[/dim]",
                        id=option_id,
                    )
                )

        # Separator between sections
        if filtered_saved and filtered_recent:
            all_options.append(Option("", disabled=True))

        # Recent commands section
        if filtered_recent:
            all_options.append(Option("── Recent Commands ──", disabled=True))
            for i, cmd in enumerate(filtered_recent):
                option_id = f"recent:{i}"
                self._option_map[option_id] = cmd
                all_options.append(Option(f"  {escape(cmd)}", id=option_id))

        if not filtered_saved and not filtered_recent:
            if query:
                all_options.append(Option("  (no matches)", disabled=True))
            else:
                all_options.append(Option("  (no commands yet)", disabled=True))

        # Single DOM operation
        self.query_one("#picker_list", OptionList).set_options(all_options)

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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "picker_cancel":
            event.stop()
            self.action_cancel()


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
        super().__init__(classes="dialog-screen")
        self._command = command

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                "[bold $text-accent]Save Command[/bold $text-accent]",
                id="save_header",
            ),
            body=DialogBody(
                Static(
                    f"[dim]Command:[/dim] {escape(self._command)}",
                    id="save_command_preview",
                ),
            ),
            status=Vertical(
                Label("Saved command name", id="save_name_label"),
                Input(
                    placeholder="Enter a name for this command...",
                    id="save_name_input",
                ),
            ),
            actions=DialogActions(
                Button("Cancel", id="save_cancel"),
                Button("Save", variant="primary", id="save_submit"),
            ),
            id="save_container",
            size="compact",
        )

    def on_mount(self) -> None:
        """Focus the name input."""
        self.query_one("#save_name_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Save on Enter."""
        if event.input.id != "save_name_input":
            return
        self._submit_name(event.value)

    def _submit_name(self, value: str) -> None:
        name = value.strip()
        if name:
            self.dismiss(name)
        else:
            self.notify("Name cannot be empty", severity="warning")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save_cancel":
            event.stop()
            self.action_cancel()
        elif event.button.id == "save_submit":
            event.stop()
            self._submit_name(self.query_one("#save_name_input", Input).value)

    def action_cancel(self) -> None:
        """Close without saving."""
        self.dismiss(None)

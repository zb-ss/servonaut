"""Log picker modal for selecting log files to view."""

from __future__ import annotations

from typing import Dict, List, Optional, TYPE_CHECKING

from textual.content import Content
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.events import Key
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import Button, Footer, Input, Label, OptionList, Static, Tree
from textual.widgets.option_list import Option
from servonaut.screens._demo_resolve import connection_instance
from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogContent,
    DialogFrame,
    DialogNotificationSpace,
)
from servonaut.utils.markup import literal
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

if TYPE_CHECKING:
    from servonaut.services.log_viewer_service import LogViewerService

# Sentinel value returned when user picks "+ Add custom path..."
ADD_PATH_SENTINEL = "__add_custom_path__"

# Sentinel prefix returned when user removes a custom path
REMOVE_PATH_SENTINEL = "__remove_path__:"

# Sentinel prefix for edit: "__edit_path__:old_path\nnew_path"
EDIT_PATH_SENTINEL = "__edit_path__:"

# Max options rendered in the list to keep the UI responsive
_MAX_VISIBLE = 50

# Debounce delay in seconds for search input
_DEBOUNCE_SECONDS = 0.15


class LogPickerModal(ModalScreen[str]):
    """Modal for picking a log file from available and discovered logs.

    Dismisses with the selected log path, ADD_PATH_SENTINEL for add-path,
    a REMOVE_PATH_SENTINEL-prefixed path for removal, or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("f2", "manage_paths", "Manage paths", show=True),
    ]

    DEFAULT_CLASSES = "dialog-screen"

    def __init__(
        self,
        available_logs: List[str],
        discovered_logs: List[str],
        current_log: Optional[str] = None,
        classify_fn=None,
        instance: Optional[dict] = None,
        log_viewer_service: Optional["LogViewerService"] = None,
    ) -> None:
        """Initialize log picker.

        Args:
            available_logs: Probed readable log paths.
            discovered_logs: Paths found by directory scan (not in available).
            current_log: Currently viewed log path (will be marked).
            classify_fn: Callable(path) -> "active"|"rotated"|"compressed".
            instance: Instance dict, used for manage-paths flow.
            log_viewer_service: Service for reading/writing custom paths.
        """
        super().__init__()
        self._available_logs = available_logs
        self._discovered_logs = discovered_logs
        self._current_log = current_log
        self._classify_fn = classify_fn
        self._instance = instance
        self._log_viewer_service = log_viewer_service
        self._option_map: Dict[str, str] = {}
        self._debounce_timer: Optional[Timer] = None
        self._first_selectable: Optional[int] = None
        # Pre-compute the discovered-only set once
        self._discovered_only: List[str] = [
            p for p in discovered_logs if p not in set(available_logs)
        ]
        # Load saved custom paths (shown even if not readable)
        self._custom_paths: List[str] = []
        if instance and log_viewer_service:
            instance_id = instance.get("id", "")
            all_custom = log_viewer_service.get_custom_paths(instance_id)
            available_set = set(available_logs)
            # Only show custom paths not already in available (avoid duplicates)
            self._custom_paths = [
                p for p in all_custom
                if not p.startswith("dir:") and p not in available_set
            ]

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Vertical(
                Static("[bold $text-accent]Log picker[/bold $text-accent]", id="log_picker_header"),
                Static("Type to filter, Enter to select, Escape to cancel", id="log_picker_hint"),
            ),
            body=DialogContent(
                Input(placeholder="Search log files...", id="log_picker_search"),
                Static("", id="log_picker_count"),
                OptionList(id="log_picker_list"),
                id="log_picker_body",
            ),
            actions=DialogActions(
                Button("Add path", id="log_picker_add", variant="primary"),
                Button("Manage paths (F2)", id="log_picker_manage"),
                Button("Cancel", id="log_picker_cancel"),
            ),
            id="log_picker_container",
            size="large",
        )

    def on_mount(self) -> None:
        """Populate the option list and focus search."""
        self._rebuild_options("")
        self.query_one("#log_picker_manage", Button).display = bool(
            self._instance is not None and self._log_viewer_service is not None
        )
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

        # Filter custom paths (saved but not in available)
        filtered_custom = [
            p for p in self._custom_paths
            if not query or query in p.lower()
        ]

        # Filter discovered-only logs
        filtered_discovered = [
            p for p in self._discovered_only
            if not query or query in p.lower()
        ]

        total_matches = len(filtered_available) + len(filtered_custom) + len(filtered_discovered)

        # --- Available logs section ---
        if filtered_available:
            all_options.append(Option("── Available logs ──", disabled=True))
            idx += 1
            for path in filtered_available:
                option_id = f"avail:{path}"
                self._option_map[option_id] = path
                marker = (" ●", "bold $text-success") if path == self._current_log else ""
                all_options.append(Option(Content.assemble("  ", literal(path), marker), id=option_id))
                if self._first_selectable is None:
                    self._first_selectable = idx
                idx += 1

        # --- Custom paths section (saved but not confirmed readable) ---
        if filtered_custom:
            if filtered_available:
                all_options.append(Option("", disabled=True))
                idx += 1
            all_options.append(Option("── Custom paths ──", disabled=True))
            idx += 1
            for path in filtered_custom:
                option_id = f"custom:{path}"
                self._option_map[option_id] = path
                marker = (" ●", "bold $text-success") if path == self._current_log else ""
                all_options.append(Option(
                    Content.assemble("  ", literal(path), " ", ("[saved]", "$text-accent"), marker),
                    id=option_id,
                ))
                if self._first_selectable is None:
                    self._first_selectable = idx
                idx += 1

        # Separator
        if (filtered_available or filtered_custom) and filtered_discovered:
            all_options.append(Option("", disabled=True))
            idx += 1

        # --- Discovered logs section (capped) ---
        truncated_discovered = filtered_discovered[:_MAX_VISIBLE]
        hidden_count = len(filtered_discovered) - len(truncated_discovered)

        if truncated_discovered:
            all_options.append(Option("── Discovered logs ──", disabled=True))
            idx += 1
            for path in truncated_discovered:
                option_id = f"disc:{path}"
                self._option_map[option_id] = path
                tag = ""
                if self._classify_fn:
                    classification = self._classify_fn(path)
                    if classification == "compressed":
                        tag = (" [zip]", "$text-warning")
                    elif classification == "rotated":
                        tag = (" [rot]", "dim")
                all_options.append(Option(Content.assemble("  ", literal(path), tag), id=option_id))
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

        # --- Action options ---
        if not query or "add" in query or "custom" in query or "path" in query:
            option_id = "action:add_path"
            self._option_map[option_id] = ADD_PATH_SENTINEL
            all_options.append(
                Option("  [bold]+[/bold] Add custom path...", id=option_id)
            )
            if self._first_selectable is None:
                self._first_selectable = idx
            idx += 1

        if (self._instance and self._log_viewer_service) and (
            not query or "manage" in query or "custom" in query or "browse" in query
        ):
            option_id = "action:manage_paths"
            self._option_map[option_id] = "__manage_paths__"
            all_options.append(
                Option("  [bold]⚙[/bold] Manage custom paths... [dim](browse, add, remove)[/dim]", id=option_id)
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

    def _handle_selection(self, value: str) -> None:
        """Route a selected value — either open manage modal or dismiss."""
        if value == "__manage_paths__":
            self.action_manage_paths()
        else:
            self.dismiss(value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Select first visible option on Enter in search field."""
        if event.input.id != "log_picker_search":
            return
        option_list = self.query_one("#log_picker_list", OptionList)
        for i in range(option_list.option_count):
            option = option_list.get_option_at_index(i)
            if not option.disabled and option.id and option.id in self._option_map:
                self._handle_selection(self._option_map[option.id])
                return

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle option selection."""
        option_id = event.option.id
        if option_id and option_id in self._option_map:
            self._handle_selection(self._option_map[option_id])

    def action_manage_paths(self) -> None:
        """Open the manage custom paths modal."""
        if self._instance is None or self._log_viewer_service is None:
            self.notify("Custom path management not available", severity="warning")
            return
        instance_id = self._instance.get("id", "")
        current_paths = self._log_viewer_service.get_custom_paths(instance_id)
        self.app.push_screen(
            ManagePathsModal(
                custom_paths=current_paths,
                instance=self._instance,
            ),
            callback=self._on_manage_paths_result,
        )

    def _on_manage_paths_result(self, result: Optional[str]) -> None:
        """Handle result from ManagePathsModal.

        result may be:
          - None: modal closed with no action
          - A path string prefixed with REMOVE_PATH_SENTINEL: remove that path
          - ADD_PATH_SENTINEL: open add-file flow
          - "adddir:<directory>": open add-directory flow
          - Any other string: select that path for viewing
        """
        if result is None:
            return
        # Pass sentinel results back up to LogViewerScreen unchanged
        self.dismiss(result)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Expose the existing list actions without changing picker results."""
        if event.button.id == "log_picker_cancel":
            event.stop()
            self.action_cancel()
        elif event.button.id == "log_picker_add":
            event.stop()
            self.dismiss(ADD_PATH_SENTINEL)
        elif event.button.id == "log_picker_manage":
            event.stop()
            self.action_manage_paths()

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

    DEFAULT_CLASSES = "dialog-screen"

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static('[bold $text-accent]Add custom log path[/bold $text-accent]', id='add_path_header'),
            body=DialogBody(
                Label("Remote file path", classes="log_path_field_label"),
                Input(placeholder='/var/log/myapp/app.log', id='add_path_input'),
                Static('[dim]Enter an absolute path to a log file on the remote server.[/dim]', id='add_path_hint'),
            ),
            actions=DialogActions(
                Button("Cancel", id="add_path_cancel"),
                Button("Add", variant="primary", id="add_path_submit"),
            ),
            id="add_path_container",
            size="compact",
        )

    def on_mount(self) -> None:
        """Focus the path input."""
        self.query_one("#add_path_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Validate and submit on Enter."""
        if event.input.id != "add_path_input":
            return
        self._submit(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """The buttons act exactly as Enter and Escape do."""
        if event.button.id == "add_path_submit":
            event.stop()
            self._submit(self.query_one("#add_path_input", Input).value)
        elif event.button.id == "add_path_cancel":
            event.stop()
            self.action_cancel()

    def _submit(self, value: str) -> None:
        path = value.strip()
        if not path:
            self.notify("Path cannot be empty", severity="warning")
        elif not path.startswith("/"):
            self.notify("Path must be absolute (start with /)", severity="warning")
        else:
            self.dismiss(path)

    def action_cancel(self) -> None:
        """Close without adding."""
        self.app.pop_screen()


class AddDirectoryModal(ModalScreen[str]):
    """Modal for entering a remote directory path to scan for log files.

    Dismisses with the directory path prefixed by ``adddir:``, or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CLASSES = "dialog-screen"

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static('[bold $text-accent]Add log directory[/bold $text-accent]', id='add_dir_header'),
            body=DialogBody(
                Label("Remote directory", classes="log_path_field_label"),
                Input(placeholder='/var/log/myapp', id='add_dir_input'),
                Static('[dim]Enter an absolute directory path on the remote server.\nServonaut will scan it for log files (maxdepth 2).[/dim]', id='add_dir_hint'),
            ),
            actions=DialogActions(
                Button("Cancel", id="add_dir_cancel"),
                Button("Add", variant="primary", id="add_dir_submit"),
            ),
            id="add_dir_container",
            size="compact",
        )

    def on_mount(self) -> None:
        """Focus the directory input."""
        self.query_one("#add_dir_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Validate and submit on Enter."""
        if event.input.id != "add_dir_input":
            return
        self._submit(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """The buttons act exactly as Enter and Escape do."""
        if event.button.id == "add_dir_submit":
            event.stop()
            self._submit(self.query_one("#add_dir_input", Input).value)
        elif event.button.id == "add_dir_cancel":
            event.stop()
            self.action_cancel()

    def _submit(self, value: str) -> None:
        path = value.strip()
        if not path:
            self.notify("Path cannot be empty", severity="warning")
        elif not path.startswith("/"):
            self.notify("Path must be absolute (start with /)", severity="warning")
        else:
            self.dismiss(f"adddir:{path}")

    def action_cancel(self) -> None:
        """Close without adding."""
        self.app.pop_screen()


class ManagePathsModal(ModalScreen[str]):
    """Modal for managing custom log paths for a server.

    Shows the current custom paths (files and directories) and lets the user:
    - Add a file path (opens AddPathModal)
    - Add a directory (opens AddDirectoryModal, triggers remote scan)
    - Browse the remote filesystem to pick files/directories
    - Remove a selected path

    Dismisses with:
    - ADD_PATH_SENTINEL to trigger add-file flow upstream
    - "adddir:<directory>" to trigger add-directory flow upstream
    - "browse:<path>" to add a browsed file path
    - REMOVE_PATH_SENTINEL + path to remove a path upstream
    - None on close
    """

    BINDINGS = [
        Binding("escape", "close_modal", "Close", show=True),
    ]

    DEFAULT_CLASSES = "dialog-screen"

    def __init__(
        self,
        custom_paths: List[str],
        instance: Optional[dict] = None,
    ) -> None:
        super().__init__()
        self._custom_paths = list(custom_paths)
        self._instance = instance

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Vertical(
                Static(
                    "[bold $text-accent]Manage custom paths[/bold $text-accent]",
                    id="manage_paths_header",
                ),
                Static(
                    "[dim]Custom log files and directories for this server.[/dim]",
                    id="manage_paths_subtitle",
                ),
                Static(f"{len(self._custom_paths)} saved paths", id="manage_paths_count"),
            ),
            # The option list is its own scroll owner.
            body=OptionList(id="manage_paths_list"),
            actions=DialogActions(
                Button("Browse", id="manage_browse", variant="primary"),
                Button("+ File", id="manage_add_file"),
                Button("+ Dir", id="manage_add_dir"),
                Button("Edit", id="manage_edit"),
                Button("Remove", id="manage_remove", variant="error"),
                Button("Close", id="manage_close"),
                id="manage_paths_buttons",
            ),
            id="manage_paths_container",
            size="large",
        )

    def on_mount(self) -> None:
        """Populate the list."""
        self._rebuild_list()

    def _rebuild_list(self) -> None:
        """Refresh the OptionList from current custom_paths."""
        option_list = self.query_one("#manage_paths_list", OptionList)
        options: list = []
        for path in self._custom_paths:
            if path.startswith("dir:"):
                display = path[4:]
                label = f"  {display} [$text-accent]\\[dir][/$text-accent]"
            else:
                label = f"  {path} [dim]\\[file][/dim]"
            options.append(Option(label, id=f"path:{path}"))
        if not options:
            options.append(Option("  [dim](no custom paths configured)[/dim]", disabled=True))
        option_list.set_options(options)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id
        if button_id == "manage_close":
            self.action_close_modal()
        elif button_id == "manage_browse":
            if self._instance is None:
                self.notify("Browse not available", severity="warning")
                return
            self.app.push_screen(
                BrowseRemoteScreen(instance=self._instance),
                callback=self._on_browse_result,
            )
        elif button_id == "manage_add_file":
            self.dismiss(ADD_PATH_SENTINEL)
        elif button_id == "manage_add_dir":
            self.app.push_screen(
                AddDirectoryModal(),
                callback=self._on_add_directory_result,
            )
        elif button_id == "manage_edit":
            self._edit_selected()
        elif button_id == "manage_remove":
            self._remove_selected()

    def _on_browse_result(self, result: Optional[str]) -> None:
        """Forward browse result upstream."""
        if result is not None:
            self.dismiss(result)

    def _on_add_directory_result(self, result: Optional[str]) -> None:
        """Forward directory result upstream."""
        if result is not None:
            self.dismiss(result)

    def _get_selected_path(self) -> Optional[str]:
        """Get the path string from the highlighted option, or None."""
        option_list = self.query_one("#manage_paths_list", OptionList)
        if option_list.highlighted is None:
            return None
        option = option_list.get_option_at_index(option_list.highlighted)
        if option.id is None or not option.id.startswith("path:"):
            return None
        return option.id[len("path:"):]

    def _edit_selected(self) -> None:
        """Edit the highlighted path."""
        path = self._get_selected_path()
        if not path:
            self.notify("Select a path first", severity="warning")
            return
        self.app.push_screen(
            EditPathModal(current_path=path),
            callback=self._on_edit_result,
        )

    def _on_edit_result(self, result: Optional[str]) -> None:
        """Forward edit result upstream as EDIT_PATH_SENTINEL."""
        if result is not None:
            self.dismiss(result)

    def _remove_selected(self) -> None:
        """Remove the highlighted path."""
        path = self._get_selected_path()
        if not path:
            self.notify("Select a path first", severity="warning")
            return
        self.dismiss(f"{REMOVE_PATH_SENTINEL}{path}")

    def action_close_modal(self) -> None:
        """Close without changes."""
        self.dismiss(None)


class EditPathModal(ModalScreen[str]):
    """Modal for editing an existing custom log path.

    Dismisses with EDIT_PATH_SENTINEL + "old_path\\nnew_path", or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CLASSES = "dialog-screen"

    def __init__(self, current_path: str) -> None:
        super().__init__()
        self._current_path = current_path

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static('[bold $text-accent]Edit custom log path[/bold $text-accent]', id='edit_path_header'),
            body=DialogBody(
                Label("Saved path", classes="log_path_field_label"),
                Input(value=self._current_path, id='edit_path_input'),
                Static('[dim]Modify the path and press Enter to save.[/dim]', id='edit_path_hint'),
            ),
            actions=DialogActions(
                Button("Cancel", id="edit_path_cancel"),
                Button("Save", variant="primary", id="edit_path_submit"),
            ),
            id="edit_path_container",
            size="compact",
        )

    def on_mount(self) -> None:
        inp = self.query_one("#edit_path_input", Input)
        inp.focus()
        # Move cursor to end
        inp.cursor_position = len(inp.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "edit_path_input":
            return
        self._submit(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """The buttons act exactly as Enter and Escape do."""
        if event.button.id == "edit_path_submit":
            event.stop()
            self._submit(self.query_one("#edit_path_input", Input).value)
        elif event.button.id == "edit_path_cancel":
            event.stop()
            self.action_cancel()

    def _submit(self, value: str) -> None:
        new_path = value.strip()
        if not new_path:
            self.notify("Path cannot be empty", severity="warning")
        elif not new_path.startswith("/") and not new_path.startswith("dir:"):
            self.notify("Path must be absolute (start with /)", severity="warning")
        elif new_path == self._current_path:
            self.app.pop_screen()  # No change
        else:
            self.dismiss(f"{EDIT_PATH_SENTINEL}{self._current_path}\n{new_path}")

    def action_cancel(self) -> None:
        self.app.pop_screen()


class BrowseRemoteScreen(WorkspaceScreen):
    """Full-screen remote file browser for picking log file/directory paths.

    Uses the existing RemoteTree widget. Enter adds the highlighted file as a
    custom log path, or opens/closes the highlighted directory; ``d`` adds a
    directory to scan for log files.

    Dismisses with the selected path (``browse:<file>`` or ``adddir:<dir>``),
    or None.
    """

    CHAT_REFLOW = True
    # The container's padding and the tree's border (4) plus a readable path
    # column and the header hint beside the chat column.
    CHAT_MIN_CONTENT_WIDTH = 48
    # Keep the complete path action labels readable beside the navigation rail.
    CONTENT_NARROW_WIDTH = 80
    AUTO_FOCUS = "#browse_tree"

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        # priority: the focused Tree binds Enter itself (select + expand), so
        # a plain screen binding never fires. Directories are handed back to
        # the tree, so Enter still expands them.
        Binding("enter", "select_node", "Add file / open dir", show=True, priority=True),
        Binding("f", "select_as_file", "Add as file", show=True),
        Binding("d", "select_as_dir", "Add as dir", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        super().__init__()
        self._instance = instance

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Browse remote")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            with Container(id="browse_container", classes="workspace-content"):
                yield VerticalScroll(
                    Static(self._header_text(), id="browse_header", markup=False),
                    id="browse_header_scroll",
                )
                with Horizontal(id="browse_browser"):
                    yield Container(id="browse_workspace")
                    with Vertical(id="browse_selection"):
                        yield Static("[bold]Selected source[/bold]", id="browse_selection_title")
                        yield VerticalScroll(
                            Static("Select a file or directory", id="browse_path", markup=False),
                            id="browse_path_scroll",
                        )
                        yield Static(
                            "Add a file directly, or include a directory in log discovery.",
                            id="browse_selection_hint",
                        )
                        yield Horizontal(
                            Button("Add as file", id="browse_add_file", variant="primary"),
                            Button("Add directory", id="browse_add_directory"),
                            Button("Back", id="browse_back"),
                            id="browse_actions",
                        )
        yield Footer()

    async def on_mount(self) -> None:
        """Mount the RemoteTree into the container."""
        from servonaut.widgets.remote_tree import RemoteTree
        from servonaut.services.log_viewer_service import LogViewerService

        # Demo mode redacts the row on screen; browse the real record.
        instance = connection_instance(self.app, self._instance)
        ssh_service = self.app.ssh_service
        connection_service = self.app.connection_service
        profile = connection_service.resolve_profile(instance)

        if instance.get("is_custom"):
            username = instance.get("username") or "root"
        elif instance.get("is_shared") is True:
            from servonaut.services.shared_servers import shared_login

            username = shared_login(
                instance, profile, self.app.config_manager.get().default_username,
            )
        else:
            username = (
                (profile.username if profile else None)
                or self.app.config_manager.get().default_username
            )

        # Start browsing from common log locations and root
        scan_paths = ["/var/log", "/home", "/"]

        tree = RemoteTree(
            instance=instance,
            ssh_service=ssh_service,
            connection_service=connection_service,
            username=username,
            scan_paths=scan_paths,
            id="browse_tree",
        )
        self.query_one("#browse_workspace").border_title = "Remote files"
        await self.query_one("#browse_workspace").mount(tree)
        if (
            self.is_attached
            and tree.is_attached
            and self.app.screen_stack
            and self.app.screen is self
            and self.focused is None
        ):
            self.set_focus(tree)

    def _header_text(self) -> str:
        from servonaut.screens._demo_resolve import display_text
        from servonaut.services.vault.display import terminal_safe

        name = self._instance.get("name") or self._instance.get("id") or "Unknown server"
        shown = terminal_safe(display_text(self.app, str(name)))
        return f"Browse Remote Server: {shown}\nEnter opens directories or adds a file."

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        if event.control.id == "browse_tree":
            self._render_path_context()

    def _render_path_context(self) -> None:
        from servonaut.screens._demo_resolve import display_text
        from servonaut.services.vault.display import terminal_safe

        data = self._get_selected_path() or {}
        path = data.get("path")
        shown = terminal_safe(display_text(self.app, str(path or "")))
        self.query_one("#browse_path", Static).update(
            f"Selected path: {shown}" if path else "Select a file or directory"
        )

    def refresh_after_demo_toggle(self) -> None:
        self.query_one("#browse_header", Static).update(self._header_text())
        self._render_path_context()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "browse_add_file": "select_as_file",
            "browse_add_directory": "select_as_dir",
            "browse_back": "back",
        }
        action = actions.get(event.button.id)
        if action:
            await self.run_action(action)

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        """Enter acts on the tree only while the tree has focus.

        Returning ``None`` disables the binding without hiding it, so Enter
        falls through to whatever else is focused.
        """
        from servonaut.widgets.remote_tree import RemoteTree

        # The tree scoping comes first: the priority Enter binding must stay
        # off whatever else has focus, including the navigation rail.
        if action == "select_node" and not isinstance(self.focused, RemoteTree):
            return None
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return True

    def on_sidebar_navigation_requested(self, message: Sidebar.NavigationRequested) -> None:
        stack = self.app.screen_stack
        owner_index = len(stack) - 2
        if owner_index < 0 or not isinstance(stack[owner_index], ManagePathsModal):
            return
        message.stop()
        if self.app._refuse_navigation():
            return
        while isinstance(stack[owner_index], (ManagePathsModal, LogPickerModal)):
            owner_index -= 1
        stack[owner_index].pop_until_active()
        self.app.call_later(self.app.on_sidebar_navigation_requested, message)

    def _get_selected_path(self) -> Optional[dict]:
        """Get the currently highlighted node's path and type."""
        from servonaut.widgets.remote_tree import RemoteTree

        tree = self.query_one("#browse_tree", RemoteTree)
        node = tree.cursor_node
        if node is None or node.data is None:
            return None
        return node.data

    def action_select_node(self) -> None:
        """Enter: add the highlighted file; open or close a highlighted directory."""
        from servonaut.widgets.remote_tree import RemoteTree

        data = self._get_selected_path()
        if data and data.get("path") and data.get("type") != "directory":
            self.dismiss(f"browse:{data['path']}")
            return
        # Directories (and the root) get the tree's own Enter: select + toggle.
        self.query_one("#browse_tree", RemoteTree).action_select_cursor()

    def action_select_as_file(self) -> None:
        """Force-add the selected node as a file path."""
        data = self._get_selected_path()
        if not data or not data.get("path"):
            self.notify("Select a node first", severity="warning")
            return
        self.dismiss(f"browse:{data['path']}")

    def action_select_as_dir(self) -> None:
        """Force-add the selected node as a directory scan."""
        data = self._get_selected_path()
        if not data or not data.get("path"):
            self.notify("Select a node first", severity="warning")
            return
        self.dismiss(f"adddir:{data['path']}")

    def action_back(self) -> None:
        self.app.pop_screen()

"""Log picker modal for selecting log files to view."""

from __future__ import annotations

from typing import Dict, List, Optional, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.events import Key
from textual.screen import ModalScreen, Screen
from textual.timer import Timer
from textual.widgets import Button, Footer, Header, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

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
        Binding("f2", "manage_paths", "Manage Paths", show=True),
    ]

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

        # --- Custom Paths section (saved but not confirmed readable) ---
        if filtered_custom:
            if filtered_available:
                all_options.append(Option("", disabled=True))
                idx += 1
            all_options.append(Option("── Custom Paths ──", disabled=True))
            idx += 1
            for path in filtered_custom:
                option_id = f"custom:{path}"
                self._option_map[option_id] = path
                marker = " [bold green]●[/bold green]" if path == self._current_log else ""
                all_options.append(Option(f"  {path} [cyan]\\[saved][/cyan]{marker}", id=option_id))
                if self._first_selectable is None:
                    self._first_selectable = idx
                idx += 1

        # Separator
        if (filtered_available or filtered_custom) and filtered_discovered:
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

    def action_cancel(self) -> None:
        """Close without selecting."""
        self.app.pop_screen()


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
        self.app.pop_screen()


class AddDirectoryModal(ModalScreen[str]):
    """Modal for entering a remote directory path to scan for log files.

    Dismisses with the directory path prefixed by ``adddir:``, or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Add Log Directory[/bold cyan]",
                id="add_dir_header",
            ),
            Static(
                "[dim]Enter an absolute directory path on the remote server.\n"
                "Servonaut will scan it for log files (maxdepth 2).[/dim]",
                id="add_dir_hint",
            ),
            Input(
                placeholder="/var/log/myapp",
                id="add_dir_input",
            ),
            id="add_dir_container",
        )

    def on_mount(self) -> None:
        """Focus the directory input."""
        self.query_one("#add_dir_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Validate and submit on Enter."""
        if event.input.id != "add_dir_input":
            return
        path = event.value.strip()
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

    def __init__(
        self,
        custom_paths: List[str],
        instance: Optional[dict] = None,
    ) -> None:
        super().__init__()
        self._custom_paths = list(custom_paths)
        self._instance = instance

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Manage Custom Paths[/bold cyan]",
                id="manage_paths_header",
            ),
            Static(
                "[dim]Custom log files and directories for this server.[/dim]",
                id="manage_paths_subtitle",
            ),
            OptionList(id="manage_paths_list"),
            Horizontal(
                Button("Browse", id="manage_browse", variant="primary"),
                Button("+ File", id="manage_add_file"),
                Button("+ Dir", id="manage_add_dir"),
                Button("Edit", id="manage_edit"),
                Button("Remove", id="manage_remove", variant="error"),
                Button("Close", id="manage_close"),
                id="manage_paths_buttons",
            ),
            id="manage_paths_container",
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
                label = f"  {display} [cyan]\\[dir][/cyan]"
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
            self.app.pop_screen()
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
        self.app.pop_screen()


class EditPathModal(ModalScreen[str]):
    """Modal for editing an existing custom log path.

    Dismisses with EDIT_PATH_SENTINEL + "old_path\\nnew_path", or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(self, current_path: str) -> None:
        super().__init__()
        self._current_path = current_path

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Edit Custom Log Path[/bold cyan]",
                id="edit_path_header",
            ),
            Static(
                "[dim]Modify the path and press Enter to save.[/dim]",
                id="edit_path_hint",
            ),
            Input(
                value=self._current_path,
                id="edit_path_input",
            ),
            id="edit_path_container",
        )

    def on_mount(self) -> None:
        inp = self.query_one("#edit_path_input", Input)
        inp.focus()
        # Move cursor to end
        inp.cursor_position = len(inp.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "edit_path_input":
            return
        new_path = event.value.strip()
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


class BrowseRemoteScreen(Screen[str]):
    """Full-screen remote file browser for picking log file/directory paths.

    Uses the existing RemoteTree widget. Select a file to add it as a custom
    log path, or select a directory to scan it for log files.

    Dismisses with the selected path (file or ``adddir:<dir>``), or None.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("enter", "select_node", "Select", show=True),
        Binding("f", "select_as_file", "Add as File", show=True),
        Binding("d", "select_as_dir", "Add as Dir", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        super().__init__()
        self._instance = instance

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static(
                "[bold cyan]Browse Remote Server[/bold cyan]  "
                "[dim]Navigate the tree, then Enter to add file / D to add directory[/dim]",
                id="browse_header",
            ),
            id="browse_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Mount the RemoteTree into the container."""
        from servonaut.widgets.remote_tree import RemoteTree
        from servonaut.services.log_viewer_service import LogViewerService

        instance = self._instance
        ssh_service = self.app.ssh_service
        connection_service = self.app.connection_service
        profile = connection_service.resolve_profile(instance)

        if instance.get("is_custom"):
            username = instance.get("username") or "root"
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
        self.query_one("#browse_container").mount(tree)

    def _get_selected_path(self) -> Optional[dict]:
        """Get the currently highlighted node's path and type."""
        from servonaut.widgets.remote_tree import RemoteTree

        tree = self.query_one("#browse_tree", RemoteTree)
        node = tree.cursor_node
        if node is None or node.data is None:
            return None
        return node.data

    def action_select_node(self) -> None:
        """Select the highlighted node — file adds as file, directory adds as dir scan."""
        data = self._get_selected_path()
        if not data or not data.get("path"):
            self.notify("Select a file or directory first", severity="warning")
            return
        path = data["path"]
        if data.get("type") == "directory":
            self.dismiss(f"adddir:{path}")
        else:
            self.dismiss(f"browse:{path}")

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

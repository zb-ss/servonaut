"""File browser screen for Servonaut v2.0."""

from __future__ import annotations
from typing import List, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Footer, Static, Tree

from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

from servonaut.widgets.remote_tree import RemoteTree
from servonaut.widgets.safe_header import SafeHeader
from servonaut.utils.match_utils import matches_conditions
from servonaut.screens._demo_resolve import connection_instance, display_text as redact_display_text
from servonaut.services.shared_servers import shared_login
from servonaut.services.vault.display import markup_literal, terminal_safe


if TYPE_CHECKING:
    from servonaut.services.scan_service import ScanService


def get_scan_paths_for_instance(config, instance: dict) -> List[str]:
    """Resolve the scan paths to show for *instance*.

    Combines ``default_scan_paths`` with any matching ``scan_rules`` paths,
    de-duplicates, ensures trailing slashes, and defaults to ``['~']``.

    Shared by :class:`FileBrowserScreen` and the inline browser on
    ``ServerActionsScreen`` so the two never drift.
    """
    paths = config.default_scan_paths.copy()
    for rule in config.scan_rules:
        if matches_conditions(instance, rule.match_conditions):
            paths.extend(rule.scan_paths)
    unique_paths = list(set(paths))
    normalized = [p if p.endswith('/') else p + '/' for p in unique_paths]
    return normalized or ['~']


def build_remote_tree(app, instance: dict, tree_id: str = "remote_tree") -> RemoteTree:
    """Build a :class:`RemoteTree` for *instance* using *app*'s services.

    Username resolution: custom servers use their own ``username``; everything
    else uses the connection profile's username, falling back to the configured
    default. Mirrors the original inline logic so behaviour is identical whether
    the tree is shown full-screen or embedded.
    """
    # Demo mode redacts the row on screen; browse the real record.
    instance = connection_instance(app, instance)
    config = app.config_manager.get()
    scan_paths = get_scan_paths_for_instance(config, instance)
    if instance.get('is_custom'):
        username = instance.get('username') or 'root'
    elif instance.get('is_shared') is True:
        username = shared_login(
            instance, app.connection_service.resolve_profile(instance), config.default_username,
        )
    else:
        profile = app.connection_service.resolve_profile(instance)
        username = (profile.username if profile else None) or config.default_username
    return RemoteTree(
        instance=instance,
        ssh_service=app.ssh_service,
        connection_service=app.connection_service,
        username=username,
        scan_paths=scan_paths,
        id=tree_id,
    )


class FileBrowserScreen(WorkspaceScreen):
    """Screen for browsing remote server filesystem via SSH.

    Displays a RemoteTree widget populated with configured scan paths.
    Files and directories are loaded lazily on demand via SSH ls commands.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    AUTO_FOCUS = "#remote_tree"
    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 48
    CONTENT_NARROW_WIDTH = 80

    def __init__(self, instance: dict) -> None:
        """Initialize file browser screen.

        Args:
            instance: Instance dictionary with connection details.
        """
        super().__init__()
        self._instance = instance
        self._remote_tree = None

    def compose(self) -> ComposeResult:
        """Compose the file browser UI."""
        yield SafeHeader()
        yield WorkspaceControls("Files")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield Container(
                VerticalScroll(
                    Static(self._build_header_text(), id="browser_header"),
                    id="browser_header_scroll",
                ),
                Container(
                    Container(
                        Static("Selected entry", id="browser_selection_heading"),
                        VerticalScroll(
                            Static("Path · Select a directory", id="browser_path", markup=False),
                            id="browser_path_scroll",
                        ),
                        id="browser_selection",
                    ),
                    self._create_remote_tree(),
                    id="browser_workspace",
                ),
                Static("Expand folders to load.  r Refresh · Esc Back", id="browser_help", markup=False),
                id="file_browser_container",
                classes="workspace-content",
            )
        yield Footer()

    def _build_header_text(self) -> str:
        """Build header text with server name and connection info.

        Returns:
            Rich-formatted header string.
        """
        name = markup_literal(terminal_safe(redact_display_text(
            self.app, self._instance.get('name') or self._instance.get('id', 'Unknown')
        )))
        profile = self.app.connection_service.resolve_profile(self._instance)

        if profile and profile.bastion_host:
            bastion = redact_display_text(self.app, profile.bastion_host)
            conn_text = f"via {markup_literal(terminal_safe(bastion))}"
        else:
            conn_text = "Direct"

        return (
            f"[bold]File Browser:[/bold] {name}\n"
            f"Connection: {conn_text}"
        )

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        """Keep the full cursor path visible without changing native navigation."""
        if event.control is not self._remote_tree:
            return
        self._render_path_context()

    def _render_path_context(self) -> None:
        """Scrub only the displayed path; the operational tree data stays intact."""
        node = self._remote_tree.cursor_node if self._remote_tree else None
        data = (node.data if node else None) or {}
        path = data.get("path")
        shown = terminal_safe(redact_display_text(self.app, str(path or "")))
        self.query_one("#browser_path", Static).update(
            f"Path · {shown}" if path else "Path · Select a directory"
        )
        kind = data.get("type")
        self.query_one("#browser_selection_heading", Static).update(
            "Selected file" if kind == "file" else
            "Selected directory" if kind == "directory" else
            "Selected entry"
        )

    def refresh_after_demo_toggle(self) -> None:
        """Refresh visible context without rebuilding the tree or moving its cursor."""
        self.query_one("#browser_header", Static).update(
            redact_display_text(self.app, self._build_header_text())
        )
        self._render_path_context()

    def _create_remote_tree(self) -> RemoteTree:
        """Create RemoteTree widget with configured scan paths.

        Returns:
            RemoteTree widget instance.
        """
        self._remote_tree = build_remote_tree(self.app, self._instance)
        return self._remote_tree

    def action_back(self) -> None:
        """Navigate back to server actions screen."""
        self.app.pop_screen()

    def action_refresh(self) -> None:
        """Refresh the file tree by clearing cache and reloading."""
        if self._remote_tree:
            # Clear the cache
            self._remote_tree._cache.clear()

            # Collapse and re-expand root to trigger reload
            root = self._remote_tree.root
            root.collapse()
            root.expand()

            self.app.notify("File tree refreshed", severity="information")

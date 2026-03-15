"""File browser screen for Servonaut v2.0."""

from __future__ import annotations
from typing import List, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Header, Footer, Static

from servonaut.widgets.sidebar import Sidebar

from servonaut.widgets.remote_tree import RemoteTree
from servonaut.utils.match_utils import matches_conditions

if TYPE_CHECKING:
    from servonaut.services.scan_service import ScanService


class FileBrowserScreen(Screen):
    """Screen for browsing remote server filesystem via SSH.

    Displays a RemoteTree widget populated with configured scan paths.
    Files and directories are loaded lazily on demand via SSH ls commands.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

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
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(self._build_header_text(), id="browser_header"),
                self._create_remote_tree(),
                id="file_browser_container"
            )
        yield Footer()

    def _build_header_text(self) -> str:
        """Build header text with server name and connection info.

        Returns:
            Rich-formatted header string.
        """
        name = self._instance.get('name') or self._instance.get('id', 'Unknown')
        profile = self.app.connection_service.resolve_profile(self._instance)

        if profile and profile.bastion_host:
            conn_text = f"via {profile.bastion_host}"
        else:
            conn_text = "Direct"

        return (
            f"[bold cyan]File Browser:[/bold cyan] {name}\n"
            f"[dim]Connection:[/dim] {conn_text}"
        )

    def _create_remote_tree(self) -> RemoteTree:
        """Create RemoteTree widget with configured scan paths.

        Returns:
            RemoteTree widget instance.
        """
        # Get scan paths for this instance
        config = self.app.config_manager.get()
        scan_paths = self._get_scan_paths_for_instance()

        # Resolve username: custom > profile > default
        if self._instance.get('is_custom'):
            username = self._instance.get('username') or 'root'
        else:
            profile = self.app.connection_service.resolve_profile(self._instance)
            username = (
                (profile.username if profile else None)
                or config.default_username
            )
        self._remote_tree = RemoteTree(
            instance=self._instance,
            ssh_service=self.app.ssh_service,
            connection_service=self.app.connection_service,
            username=username,
            scan_paths=scan_paths,
            id="remote_tree"
        )
        return self._remote_tree

    def _get_scan_paths_for_instance(self) -> List[str]:
        """Get scan paths for the current instance from configuration.

        Combines default_scan_paths with any matching scan_rules paths.

        Returns:
            List of paths to scan.
        """
        config = self.app.config_manager.get()
        paths = config.default_scan_paths.copy()

        # Check scan_rules for additional paths
        for rule in config.scan_rules:
            if matches_conditions(self._instance, rule.match_conditions):
                paths.extend(rule.scan_paths)

        # Remove duplicates and ensure trailing slashes
        unique_paths = list(set(paths))
        normalized_paths = [
            path if path.endswith('/') else path + '/'
            for path in unique_paths
        ]

        # Default to home directory if no paths configured
        if not normalized_paths:
            normalized_paths = ['~']

        return normalized_paths

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

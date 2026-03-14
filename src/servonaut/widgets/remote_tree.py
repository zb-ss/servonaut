"""Remote file tree widget for browsing SSH server filesystems."""

from __future__ import annotations
import asyncio
import subprocess
import logging
import shlex
from typing import List, Optional, Dict, TYPE_CHECKING

from textual.widgets import Tree
from textual.widgets.tree import TreeNode
from textual.worker import Worker

if TYPE_CHECKING:
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService

logger = logging.getLogger(__name__)


class RemoteTree(Tree):
    """Tree widget for browsing remote server filesystem via SSH.

    Populates nodes lazily by executing SSH ls commands on node expansion.
    Caches expanded directories to avoid redundant SSH calls.
    """

    def __init__(
        self,
        instance: dict,
        ssh_service: SSHService,
        connection_service: ConnectionService,
        username: str,
        scan_paths: List[str],
        **kwargs
    ) -> None:
        """Initialize remote tree widget.

        Args:
            instance: Instance dictionary with connection details.
            ssh_service: SSH service for building commands.
            connection_service: Connection service for profile resolution.
            username: SSH username for connection.
            scan_paths: List of root paths to display in tree.
            **kwargs: Additional arguments passed to Tree.
        """
        super().__init__("Remote Files", **kwargs)
        self._instance = instance
        self._ssh_service = ssh_service
        self._connection_service = connection_service
        self._username = username
        self._scan_paths = scan_paths
        self._cache: Dict[str, List] = {}
        self._pending_fetch = None

        # Resolve connection details once
        self._profile = connection_service.resolve_profile(instance)
        self._host = connection_service.get_target_host(instance, self._profile)
        self._proxy_args: List[str] = []
        if self._profile:
            self._proxy_args = connection_service.get_proxy_args(self._profile)
        if instance.get('is_custom'):
            self._key_path = instance.get('ssh_key') or instance.get('key_name') or None
        else:
            self._key_path = ssh_service.get_key_path(instance['id'])
            if not self._key_path and instance.get('key_name'):
                self._key_path = ssh_service.discover_key(instance['key_name'])

    def on_mount(self) -> None:
        """Populate root nodes on mount."""
        root = self.root
        root.expand()

        # Add scan paths as root nodes
        for path in self._scan_paths:
            # Create expandable directory node
            node = root.add(f"📁 {path}", expand=False)
            node.data = {"path": path, "type": "directory"}
            node.allow_expand = True

    def on_tree_node_expanded(self, event: Tree.NodeExpanded) -> None:
        """Handle node expansion by loading directory contents.

        Args:
            event: Node expanded event.
        """
        node = event.node
        if node.data is None:
            return

        path = node.data.get("path")
        if not path:
            return

        # Check if already cached
        if path in self._cache:
            self._populate_node_from_cache(node, path)
            return

        # Show loading indicator
        loading_node = node.add("⏳ Loading...")
        self.refresh()

        # Fetch in background worker (exit_on_error=False prevents crash on SSH failures)
        self.run_worker(
            self._fetch_directory_async(path),
            name=f"fetch_dir",
            group="fetch_dir",
            exit_on_error=False
        )
        # Store node reference for callback
        self._pending_fetch = (node, loading_node, path)

    async def _fetch_directory_async(self, path: str) -> List[dict]:
        """Fetch directory contents asynchronously.

        Args:
            path: Directory path to list.

        Returns:
            List of entry dictionaries.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._fetch_directory_contents(path)
        )

    def on_worker_state_changed(self, event) -> None:
        """Handle worker completion for directory fetches.

        Args:
            event: Worker state changed event.
        """
        if not hasattr(self, '_pending_fetch') or self._pending_fetch is None:
            return

        if event.worker.group == "fetch_dir" and event.worker.is_finished:
            node, loading_node, path = self._pending_fetch
            self._pending_fetch = None

            try:
                loading_node.remove()
            except Exception:
                pass

            if event.worker.error:
                error_str = str(event.worker.error).lower()
                if "permission denied" in error_str:
                    node.add("🔒 Permission denied").allow_expand = False
                    logger.warning("Permission denied accessing %s", path)
                elif ("no such file" in error_str
                      or "cannot access" in error_str
                      or "does not exist" in error_str
                      or "not found" in error_str
                      or "not a directory" in error_str):
                    node.add("📭 Path not found on server").allow_expand = False
                    logger.info("Path not found on server: %s", path)
                elif "timed out" in error_str:
                    node.add("⏱ Connection timed out").allow_expand = False
                    logger.error("SSH timeout loading %s", path)
                elif "authentication" in error_str:
                    node.add("🔑 Authentication failed").allow_expand = False
                    logger.error("SSH auth failed for %s: %s", path, event.worker.error)
                elif "connection refused" in error_str:
                    node.add("🚫 Connection refused").allow_expand = False
                    logger.error("Connection refused for %s", path)
                else:
                    node.add(f"❌ {event.worker.error}").allow_expand = False
                    logger.error("Failed to load %s: %s", path, event.worker.error)
            else:
                entries = event.worker.result
                self._cache[path] = entries
                if not entries:
                    empty_node = node.add("📭 Empty directory")
                    empty_node.allow_expand = False
                else:
                    self._add_entries_to_node(node, entries)

            self.refresh()

    def _fetch_directory_contents(self, path: str) -> List[dict]:
        """Fetch directory contents via SSH ls command.

        Args:
            path: Directory path to list.

        Returns:
            List of entry dictionaries with keys: name, type, size, permissions.

        Raises:
            RuntimeError: If SSH command fails or times out.
        """
        # Expand ~ to $HOME for remote shell (shlex.quote prevents tilde expansion)
        if path.startswith('~/'):
            safe_path = '$HOME/' + path[2:]
        elif path == '~':
            safe_path = '$HOME'
        else:
            safe_path = path
        remote_command = f'ls -la "{safe_path}"'
        ssh_cmd = self._ssh_service.build_ssh_command(
            host=self._host,
            username=self._username,
            key_path=self._key_path,
            remote_command=remote_command,
            proxy_args=self._proxy_args
        )

        logger.debug("Fetching directory contents: %s", path)

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL
            )

            if result.returncode != 0:
                stderr = result.stderr.strip()
                # Extract the meaningful last line (skip SSH warnings)
                stderr_lines = [
                    line for line in stderr.splitlines()
                    if not line.startswith("Warning:")
                ]
                error_msg = stderr_lines[-1] if stderr_lines else stderr
                raise RuntimeError(error_msg)

            return self._parse_ls_output(result.stdout, path)

        except subprocess.TimeoutExpired:
            raise RuntimeError("Connection timed out")
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(str(e))

    def _parse_ls_output(self, output: str, parent_path: str) -> List[dict]:
        """Parse ls -la output into entry dictionaries.

        Args:
            output: Raw ls -la output.
            parent_path: Parent directory path.

        Returns:
            List of entry dictionaries with keys: name, type, size, permissions, path.
        """
        entries = []
        lines = output.strip().split('\n')

        for line in lines[1:]:  # Skip "total" line
            parts = line.split(None, 8)  # Split on whitespace, max 9 parts
            if len(parts) < 9:
                continue

            permissions = parts[0]
            size = parts[4]
            name = parts[8]

            # Skip . and ..
            if name in ('.', '..'):
                continue

            # Determine type
            is_directory = permissions.startswith('d')
            is_link = permissions.startswith('l')

            # Handle symlinks — strip target, treat as expandable (may be dir)
            link_target = None
            if is_link and ' -> ' in name:
                name, link_target = name.split(' -> ', 1)

            # Build full path
            full_path = f"{parent_path.rstrip('/')}/{name}"

            # Symlinks are treated as directories (expandable) so mount points
            # and linked directories (e.g. EFS/NFS) can be navigated.
            # If the link points to a file, expanding will show an error or
            # empty, which is acceptable.
            entry_type = "directory" if (is_directory or is_link) else "file"

            entries.append({
                'name': name,
                'type': entry_type,
                'size': size,
                'permissions': permissions,
                'path': full_path,
            })

        # Sort: directories first, then files, both alphabetically
        entries.sort(key=lambda e: (e['type'] != 'directory', e['name'].lower()))
        return entries

    def _populate_node_from_cache(self, node: TreeNode, path: str) -> None:
        """Populate node from cached directory contents.

        Args:
            node: Tree node to populate.
            path: Directory path (cache key).
        """
        entries = self._cache.get(path, [])
        self._add_entries_to_node(node, entries)

    def _add_entries_to_node(self, parent: TreeNode, entries: List[dict]) -> None:
        """Add entries to a tree node.

        Args:
            parent: Parent tree node.
            entries: List of entry dictionaries.
        """
        for entry in entries:
            if entry['type'] == 'directory':
                icon = "📁"
                child = parent.add(f"{icon} {entry['name']}", expand=False)
                child.data = {
                    "path": entry['path'],
                    "type": "directory"
                }
                child.allow_expand = True
            else:
                icon = "📄"
                size_str = self._format_size(entry['size'])
                child = parent.add(f"{icon} {entry['name']} ({size_str})")
                child.data = {
                    "path": entry['path'],
                    "type": "file"
                }
                child.allow_expand = False

    def _format_size(self, size_str: str) -> str:
        """Format file size for display.

        Args:
            size_str: Size string from ls output.

        Returns:
            Formatted size string.
        """
        try:
            size = int(size_str)
            if size < 1024:
                return f"{size}B"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f}KB"
            elif size < 1024 * 1024 * 1024:
                return f"{size / (1024 * 1024):.1f}MB"
            else:
                return f"{size / (1024 * 1024 * 1024):.1f}GB"
        except ValueError:
            return size_str

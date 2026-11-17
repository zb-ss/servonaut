"""Remote file tree widget for browsing SSH server filesystems."""

from __future__ import annotations
import asyncio
import subprocess
import logging
import re
from typing import List, Optional, Dict, TYPE_CHECKING

from rich.text import Text
from textual.widgets import Tree
from textual.widgets.tree import TreeNode
from textual.worker import Worker
from textual.message import Message

from servonaut.utils.markup import single_line_text
from servonaut.utils.ssh_names import SSHRefusal
from servonaut.utils.remote_shell import shell_path, posix_command
from servonaut.utils.ssh_utils import run_ssh
from servonaut.config.schema import SSHConfig

if TYPE_CHECKING:
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService

logger = logging.getLogger(__name__)


class RemoteTree(Tree):
    """Tree widget for browsing remote server filesystem via SSH.

    Populates nodes lazily by executing SSH ls commands on node expansion.
    Caches expanded directories to avoid redundant SSH calls.
    """

    DEFAULT_CSS = """
    RemoteTree:ansi:focus > .tree--cursor {
        text-style: underline not bold;
    }
    """

    class LoadState(Message):
        """A directory's settled or pending listing, with its real path."""

        def __init__(self, path: str, loading: bool, error: str = "", empty: bool = False) -> None:
            super().__init__()
            self.path, self.loading, self.error, self.empty = path, loading, error, empty

    def __init__(
        self,
        instance: dict,
        ssh_service: SSHService,
        connection_service: ConnectionService,
        username: str,
        scan_paths: List[str],
        connection_options: Optional[dict] = None,
        connection_timeout: Optional[int] = None,
        literal_paths: bool = False,
        scrub=None,
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
        self._current_path = scan_paths[0] if scan_paths else '~'
        self._cache: Dict[str, List] = {}
        self._pending_fetch: dict[Worker, tuple[TreeNode, str, int]] = {}
        self._generation = 0
        self._errors: dict[str, str] = {}
        self._connection_timeout = (
            connection_timeout if connection_timeout is not None
            else SSHConfig().connect_timeout + SSHConfig().listing_allowance_seconds
        )
        self._literal_paths = literal_paths
        self._scrub = scrub
        self._vault_lock = asyncio.Lock()

        # Resolve connection details once
        self._profile = connection_service.resolve_profile(instance)
        self._host = connection_service.get_target_host(instance, self._profile)
        self._proxy_args: List[str] = []
        if self._profile:
            self._proxy_args = connection_service.get_proxy_args(self._profile)
        self._extra_options: List[str] = connection_service.get_extra_options(
            instance, self._profile
        )
        self._port: Optional[int] = connection_service.get_target_port(instance)
        if connection_options is not None:
            self._key_path = connection_options.get('key_path')
        elif instance.get('is_custom'):
            self._key_path = instance.get('ssh_key') or instance.get('key_name') or None
        else:
            self._key_path = ssh_service.get_key_path(instance['id'])
            if not self._key_path and instance.get('key_name'):
                self._key_path = ssh_service.discover_key(instance['key_name'])
        # The server's vault credential, applied before the first listing
        # (None until then): identity arguments for the ssh builder.
        self._identity: Optional[dict] = None
        if connection_options is not None:
            self._host = connection_options['host']
            self._username = connection_options['username']
            self._key_path = connection_options.get('key_path')
            self._proxy_args = list(connection_options.get('proxy_args') or [])
            self._port = connection_options.get('port')
            self._extra_options = list(connection_options.get('extra_options') or [])
            self._identity = {
                key: connection_options[key] for key in (
                    'identity_agent', 'identity_file', 'certificate_file', 'known_hosts_file',
                ) if connection_options.get(key)
            }

    def on_mount(self) -> None:
        """Populate root nodes on mount."""
        root = self.root
        root.expand()

        # Add scan paths as root nodes
        for path in self._scan_paths:
            # Create expandable directory node
            node = root.add(self._label(f"📁 {path}"), expand=False)
            node.data = {"path": path, "type": "directory"}
            node.allow_expand = True

    @property
    def is_listing(self) -> bool:
        return bool(self._pending_fetch)

    @property
    def current_path(self) -> str:
        return self._current_path

    @property
    def selected_entry(self) -> Optional[dict]:
        node = self.cursor_node
        return dict(node.data) if node is not None and node.data else None

    def selection_ready(self) -> bool:
        entry = self.selected_entry
        if not entry:
            return False
        path = entry['path']
        if entry['type'] == 'directory' and not entry.get('verified') and path not in self._cache:
            return False
        return not self.is_listing and path not in self._errors

    def _label(self, text: str) -> Text:
        text = single_line_text(text)
        return Text(single_line_text(self._scrub(text) if self._scrub else text))

    def refresh_labels(self) -> None:
        def visit(node: TreeNode) -> None:
            if node.data:
                data = node.data
                if data.get('type') == 'error':
                    node.set_label(self._label(self._error_label(data['error'], refused=data.get('refused', False))))
                    return
                name = data.get('name', data['path'])
                prefix = '📁' if data['type'] == 'directory' else '📄'
                suffix = f" ({self._format_size(data['size'])})" if 'size' in data else ''
                node.set_label(self._label(f'{prefix} {name}{suffix}'))
            for child in node.children:
                visit(child)
        visit(self.root)

    def cancel_loads(self) -> None:
        self._generation += 1
        for worker in self._pending_fetch:
            worker.cancel()
        self._pending_fetch.clear()

    def on_unmount(self) -> None:
        self.cancel_loads()

    def navigate(self, path: str, *, include_scan_paths: bool = False) -> None:
        """Replace the visible roots and invalidate late results."""
        self.cancel_loads()
        self._current_path = path
        self._errors.clear()
        self._cache.pop(path, None)
        self.root.remove_children()
        node = self.root.add(self._label(f'📁 {path}'), data={'path': path, 'type': 'directory'})
        node.allow_expand = True
        if include_scan_paths:
            for extra in self._scan_paths:
                if extra.rstrip('/') != path.rstrip('/'):
                    self.root.add(self._label(f'📁 {extra}'), data={'path': extra, 'type': 'directory'}).allow_expand = True
        self.root.expand()
        node.expand()
        self.move_cursor(node)
        self.call_after_refresh(self._restore_root_cursor, node, self._generation)
        self._load_node(node, path)

    def _restore_root_cursor(self, node: TreeNode, generation: int) -> None:
        if generation == self._generation and self.is_attached and self._node_current(node):
            self.move_cursor(node)

    def refresh_paths(self) -> None:
        """Refresh expanded folders through the public loading contract."""
        self.cancel_loads()
        self._cache.clear()
        self._errors.clear()
        def visit(node: TreeNode) -> None:
            if node.data and node.is_expanded:
                self._load_node(node, node.data['path'])
            else:
                for child in list(node.children):
                    visit(child)
        visit(self.root)

    def retry(self, path: str) -> None:
        def visit(node: TreeNode) -> None:
            if node.data and node.data['path'] == path:
                self._cache.pop(path, None)
                self._load_node(node, path)
            else:
                for child in list(node.children):
                    visit(child)
        visit(self.root)

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

        self._load_node(node, path)

    def _load_node(self, node: TreeNode, path: str) -> None:
        if any(pending[0] is node for pending in self._pending_fetch.values()):
            return
        node.remove_children()
        self._errors.pop(path, None)
        if path in self._cache:
            self._populate_node_from_cache(node, path)
            self.post_message(self.LoadState(path, self.is_listing, empty=not self._cache[path]))
            return
        node.add('⏳ Loading...').allow_expand = False
        worker = self.run_worker(
            self._fetch_directory_async(path), name='fetch_dir',
            group='remote_directory', exit_on_error=False,
        )
        self._pending_fetch[worker] = (node, path, self._generation)
        self.post_message(self.LoadState(path, True))

    async def _fetch_directory_async(self, path: str) -> List[dict]:
        """Fetch directory contents asynchronously.

        Args:
            path: Directory path to list.

        Returns:
            List of entry dictionaries.
        """
        async with self._vault_lock:
            await self._apply_vault()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._fetch_directory_contents(path)
        )

    async def _apply_vault(self) -> None:
        """Use the server's Servonaut Vault key, if it has one (once per tree).

        Raises:
            RuntimeError: the server's vault credential cannot be used.
        """
        if self._identity is not None:
            return
        from servonaut.screens._demo_resolve import fleet_rows, team_rows
        from servonaut.services.ssh_credentials import (
            VaultCredentialError, resolve_with_vault, ssh_identity_kwargs,
        )

        app = self.app
        try:
            resolved = await resolve_with_vault(
                {
                    "host": self._host, "username": self._username, "key_path": self._key_path,
                    "proxy_args": self._proxy_args, "port": self._port,
                    "extra_options": self._extra_options, "profile": self._profile,
                },
                self._instance,
                vault_runtime=getattr(app, "vault_command_service", None),
                connection_service=self._connection_service,
                cache=getattr(app, "vault_lease_cache", None),
                team_rows=team_rows(app),
                rows=fleet_rows(app),
            )
        except VaultCredentialError as exc:
            raise RuntimeError(str(exc)) from exc
        self._host = resolved["host"]
        self._username = resolved["username"]
        self._key_path = resolved.get("key_path")
        self._proxy_args = list(resolved.get("proxy_args") or [])
        self._port = resolved.get("port")
        self._identity = {key: value for key, value in ssh_identity_kwargs(resolved).items() if value}

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker not in self._pending_fetch or not event.worker.is_finished:
            return
        node, path, generation = self._pending_fetch.pop(event.worker)
        if generation != self._generation or not self.is_attached or event.worker.is_cancelled or not self._node_current(node):
            return
        node.remove_children()
        error = str(event.worker.error) if event.worker.error else ''
        if error:
            refused = isinstance(event.worker.error, SSHRefusal)
            self._errors[path] = error
            logger.warning('Could not list remote folder %s: %s', path, error)
            node.add(
                self._label(self._error_label(error, refused=refused)),
                data={'path': path, 'type': 'error', 'error': error, 'refused': refused},
            ).allow_expand = False
            if refused:
                self.app.notify(error, severity='error', markup=False)
        else:
            self._cache[path] = event.worker.result
            self._populate_node_from_cache(node, path)
        self.post_message(self.LoadState(
            path, self.is_listing, error, not error and not self._cache.get(path),
        ))
        self.refresh()

    def _node_current(self, node: TreeNode) -> bool:
        while node is not self.root:
            parent = node.parent
            if parent is None or node not in parent.children:
                return False
            node = parent
        return True

    def _error_label(self, error: str, *, refused: bool = False) -> str:
        if refused:
            return error
        if not self._literal_paths:
            return f'❌ {error}'
        lowered = error.lower()
        if 'permission denied' in lowered:
            return '🔒 Permission denied'
        if any(word in lowered for word in ('no such file', 'cannot access', 'does not exist', 'not found', 'not a directory')):
            return '📭 Path not found on server'
        if 'timed out' in lowered:
            return '⏱ Connection timed out'
        if 'authentication' in lowered:
            return '🔑 Authentication failed'
        if 'connection refused' in lowered:
            return '🚫 Connection refused'
        return '❌ Could not open this folder.'

    def _fetch_directory_contents(self, path: str) -> List[dict]:
        """Fetch directory contents via SSH ls command.

        Args:
            path: Directory path to list.

        Returns:
            List of entry dictionaries with keys: name, type, size, permissions.

        Raises:
            RuntimeError: If SSH command fails or times out.
        """
        safe_path = shell_path(path)

        logger.debug("Fetching directory contents: %s", path)

        flags = '-lab' if self._literal_paths else '-la'
        command = f'ls {flags} {safe_path}'
        portable = False
        if self._literal_paths:
            stdout, error_msg, portable = self._read_literal_listing(safe_path)
        else:
            stdout, error_msg = self._run_ls(command)
        if error_msg is not None:
            # EFS / NFS shares and other root-owned mounts are commonly
            # unreadable by the login user (ec2-user / ubuntu). Retry once with
            # non-interactive sudo — read-only, and `-n` never prompts, so it
            # fails fast where passwordless sudo isn't available and we fall
            # back to the original "Permission denied" message.
            if "permission denied" in error_msg.lower():
                if self._literal_paths:
                    sudo_out, sudo_err, sudo_portable = self._read_literal_listing(safe_path, sudo=True)
                else:
                    sudo_out, sudo_err = self._run_ls(f'sudo -n ls {flags} {safe_path}')
                    sudo_portable = False
                if sudo_err is None:
                    stdout, error_msg = sudo_out, None
                    portable = sudo_portable
            if error_msg is not None:
                raise RuntimeError(error_msg)

        if portable:
            return self._parse_portable_listing(stdout, path)

        if self._literal_paths and re.match(r'^[bcdlps-][rwxstST-]{9}[.+@]?\s', stdout):
            raise RuntimeError('Not a directory: enter a folder location')
        return self._resolve_symlinks(self._parse_ls_output(stdout, path), safe_path)

    def _read_literal_listing(self, safe_path: str, *, sudo: bool = False) -> tuple:
        prefix = 'sudo -n ' if sudo else ''
        stdout, error = self._run_ls(prefix + self._literal_listing_command(safe_path))
        unsupported = error and re.search(
            r'''(?mi)^ls:\s+(?:invalid|illegal|unrecognized|unknown) option(?: --|:)?\s+['"`-]*b\b''', error,
        )
        if unsupported:
            stdout, error = self._run_ls(prefix + self._portable_listing_command(safe_path))
        return stdout, error, bool(unsupported)

    @staticmethod
    def _literal_listing_command(safe_path: str) -> str:
        """A successful ls of a file must never validate it as a folder."""
        return posix_command(
            f'if [ -d {safe_path} ]; then cd {safe_path} && ls -lab .; '
            f'elif [ -e {safe_path} ] || [ -L {safe_path} ]; then '
            'printf "%s\\n" "Not a directory" >&2; exit 1; '
            f'else ls -ld {safe_path} >&2; exit 1; fi'
        )

    @staticmethod
    def _portable_listing_command(safe_path: str) -> str:
        """BusyBox-compatible NUL records; never parse a filename from ls text."""
        return posix_command(
            f'cd {safe_path} && ls -a . >/dev/null && {{ '
            'printf "%s\\0" servonaut-paths-v1; '
            'for f in ./* ./.[!.]* ./..?*; do '
            'if [ -e "$f" ] || [ -L "$f" ]; then '
            'if [ -d "$f" ]; then kind=directory; '
            'elif [ -f "$f" ]; then kind=file; else kind=other; fi; '
            'if [ -L "$f" ]; then link=1; else link=0; fi; '
            'printf "%s\\0%s\\0%s\\0" "$kind" "${f#./}" "$link"; '
            'fi; done; }'
        )

    def _parse_portable_listing(self, output: str, parent_path: str) -> List[dict]:
        fields = output.split('\0')
        if fields[0] != 'servonaut-paths-v1' or fields[-1] or (len(fields) - 2) % 3:
            raise RuntimeError('The server returned an invalid folder listing')
        entries = []
        for offset in range(1, len(fields) - 1, 3):
            kind, name, link = fields[offset:offset + 3]
            if kind not in {'directory', 'file', 'other'} or link not in {'0', '1'}:
                raise RuntimeError('The server returned an invalid folder entry')
            if self._valid_basename(name):
                entries.append(dict(
                    name=name, path=parent_path.rstrip('/') + '/' + name,
                    type=kind, size='?', permissions='', symlink=link == '1',
                ))
        return sorted(entries, key=lambda entry: (entry['type'] != 'directory', entry['name'].lower()))

    @staticmethod
    def _valid_basename(name: str) -> bool:
        return bool(name) and name not in {'.', '..'} and '/' not in name and '\0' not in name

    def _resolve_symlinks(self, entries: List[dict], safe_path: str) -> List[dict]:
        """Type each symlink by what it points to: a file link becomes a file.

        ``ls -la`` only says "link". Links stay expandable directories unless
        one extra read-only call shows they point at a regular file; if that
        call fails, the listing is kept as it was.
        """
        if not any(e.get('symlink') for e in entries):
            return entries
        if self._literal_paths:
            return self._resolve_literal_symlinks(entries, safe_path)
        stdout, error_msg = self._run_ls(
            f'cd {safe_path} && for f in * .*; do [ -L "$f" ] && [ -f "$f" ] '
            '&& printf "%s\\n" "$f"; done; true'
        )
        if error_msg is not None:
            logger.debug("Could not resolve symlinks in %s: %s", safe_path, error_msg)
            return entries
        file_links = set(stdout.splitlines())
        for entry in entries:
            if entry.get('symlink') and entry['name'] in file_links:
                entry['type'] = 'file'
        entries.sort(key=lambda e: (e['type'] != 'directory', e['name'].lower()))
        return entries

    def _resolve_literal_symlinks(self, entries: List[dict], safe_path: str) -> List[dict]:
        """NUL records keep link names containing newlines unambiguous."""
        stdout, error = self._run_ls(posix_command(
            f'cd {safe_path} && for f in * .*; do if [ -L "$f" ]; then '
            'if [ -d "$f" ]; then printf "directory\\0%s\\0" "$f"; '
            'elif [ -f "$f" ]; then printf "file\\0%s\\0" "$f"; '
            'else printf "other\\0%s\\0" "$f"; fi; fi; done'
        ))
        if error is not None:
            # An unknown target must not become a selectable source folder.
            for entry in entries:
                if entry.get('symlink'):
                    entry['type'] = 'other'
            return entries
        records = stdout.split('\0')
        kinds = dict(zip(records[1::2], records[0::2]))
        for entry in entries:
            if entry.get('symlink'):
                entry['type'] = kinds.get(entry['name'], 'other')
        entries.sort(key=lambda item: (item['type'] != 'directory', item['name'].lower()))
        return entries

    def _run_ls(self, remote_command: str) -> tuple:
        """Run a remote listing command. Returns ``(stdout, error_or_None)``.

        A non-None second element is a cleaned, user-facing error string; the
        caller decides whether to retry (e.g. with sudo) or surface it.
        """
        ssh_cmd = self._ssh_service.build_ssh_command(
            host=self._host,
            username=self._username,
            key_path=self._key_path,
            remote_command=remote_command,
            proxy_args=self._proxy_args,
            port=self._port,
            extra_options=self._extra_options,
            **(self._identity or {}),
        )
        try:
            # No terminal to prompt on; ssh's messages go to a private log
            # and come back at the start of stderr.
            result = run_ssh(
                ssh_cmd,
                capture_output=True,
                text=not self._literal_paths,
                timeout=self._connection_timeout,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return "", "Connection timed out"
        except Exception as e:  # noqa: BLE001
            return "", str(e)

        stdout = result.stdout.decode('utf-8', errors='surrogateescape') if isinstance(result.stdout, bytes) else result.stdout
        stderr = result.stderr.decode('utf-8', errors='replace') if isinstance(result.stderr, bytes) else result.stderr
        if result.returncode != 0:
            stderr = stderr.strip()
            # Extract the meaningful last line (skip SSH warnings).
            stderr_lines = [
                line for line in stderr.splitlines()
                if not line.startswith("Warning:")
            ]
            detail = '\n'.join(stderr_lines) if self._literal_paths else (stderr_lines[-1] if stderr_lines else stderr)
            return "", detail or "ls failed"

        return stdout, None

    def _parse_ls_output(self, output: str, parent_path: str) -> List[dict]:
        """Parse ls -la output into entry dictionaries.

        Args:
            output: Raw ls -la output.
            parent_path: Parent directory path.

        Returns:
            List of entry dictionaries with keys: name, type, size, permissions, path.
        """
        entries = []
        lines = output.split('\n')

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
            if self._literal_paths:
                name = self._unescape_name(name)
            if not self._valid_basename(name):
                continue

            # Build full path
            full_path = f"{parent_path.rstrip('/')}/{name}"

            # Symlinks start as directories (expandable) so mount points and
            # linked directories (e.g. EFS/NFS) can be navigated;
            # _resolve_symlinks retypes the ones that point at a file.
            entry_type = "directory" if (is_directory or is_link) else "file" if permissions.startswith('-') else "other"

            entries.append({
                'name': name,
                'type': entry_type,
                'size': size,
                'permissions': permissions,
                'path': full_path,
                'symlink': is_link,
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
        node.remove_children()
        if not entries:
            node.add('📭 Empty directory').allow_expand = False
        self._add_entries_to_node(node, entries)

    @staticmethod
    def _unescape_name(name: str) -> str:
        """Decode ls -b escapes without interpreting unescaped Unicode."""
        escapes = {'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}
        result = bytearray()
        offset = 0
        for match in re.finditer(r'\\([0-3][0-7]{2}|.)', name):
            result.extend(name[offset:match.start()].encode('utf-8'))
            token = match.group(1)
            if len(token) == 3 and token.isdigit():
                result.append(int(token, 8))
            else:
                result.extend(escapes.get(token, token).encode('utf-8'))
            offset = match.end()
        result.extend(name[offset:].encode('utf-8'))
        return result.decode('utf-8', errors='surrogateescape')

    def _add_entries_to_node(self, parent: TreeNode, entries: List[dict]) -> None:
        """Add entries to a tree node.

        Args:
            parent: Parent tree node.
            entries: List of entry dictionaries.
        """
        for entry in entries:
            if entry['type'] == 'directory':
                icon = "📁"
                child = parent.add(self._label(f"{icon} {entry['name']}"), expand=False)
                child.data = {
                    "path": entry['path'],
                    "type": "directory", "name": entry['name'], "verified": True,
                }
                child.allow_expand = True
            else:
                icon = "📄"
                size_str = self._format_size(entry['size'])
                child = parent.add(self._label(f"{icon} {entry['name']} ({size_str})"))
                child.data = {
                    "path": entry['path'],
                    "type": entry['type'], "name": entry['name'], "size": entry['size'],
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

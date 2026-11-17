"""Local filesystem tree with literal labels and observable directory loading."""

from __future__ import annotations

import os
import re
import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from rich.text import Text
from textual.message import Message
from textual.await_complete import AwaitComplete
from textual.widgets import DirectoryTree, Tree
from textual.widgets.tree import TreeNode
from textual.worker import Worker

from servonaut.utils.markup import single_line_text


def local_display_path(path: Path) -> str:
    """Represent the local home without exposing its account name."""
    try:
        relative = path.relative_to(Path.home())
    except ValueError:
        return str(path)
    return "~" if not relative.parts else "~" + os.sep + str(relative)


def local_display_text(value: str) -> str:
    """Hide the local account prefix in paths embedded in filesystem errors."""
    home = str(Path.home())
    for prefix in {home, home.replace('\\', '\\\\')}:
        value = re.sub(re.escape(prefix) + r'''(?=$|[/\\'"\s:),])''', '~', value)
    return value


class LocalDirectoryTree(DirectoryTree):
    """Display-only reuse; retain DirectoryTree's native loading and events."""

    def __init__(
        self, *args, directories_only: bool = False,
        scrub: Callable[[str], str] | None = None, **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._directories_only, self._scrub = directories_only, scrub

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        return [
            path for path in paths
            if path.is_dir() or (not self._directories_only and path.is_file())
        ]

    def refresh_labels(self) -> None:
        self._clear_line_cache()
        self.refresh()

    def render_label(self, node, base_style, style) -> Text:
        original = node._label
        shown = single_line_text(original.plain)
        path = getattr(node.data, "path", None)
        if self._scrub is not None and path is not None and Path(path) == Path.home():
            shown = "~"
        elif self._scrub is not None:
            shown = self._scrub(shown)
        shown = single_line_text(shown)
        if shown == original.plain:
            return super().render_label(node, base_style, style)
        node._label = Text(shown)
        try:
            return super().render_label(node, base_style, style)
        finally:
            node._label = original


@dataclass
class LocalEntry:
    path: Path
    is_directory: bool = True
    loaded: bool = False


class LocalPathTree(LocalDirectoryTree):
    """Native directory navigation with owned, generation-scoped listing workers.

    Filesystem threads return plain entries. Only the worker completion handler
    updates nodes, so a dismissed or replaced root never waits on a UI callback.
    """

    class LoadState(Message):
        def __init__(self, path: Path, loading: bool, error: str = "", empty: bool = False) -> None:
            super().__init__()
            self.path, self.loading, self.error, self.empty = path, loading, error, empty

    def __init__(self, *args, **kwargs) -> None:
        self._generation = 0
        self._pending: dict[Worker, tuple[TreeNode, Path, int]] = {}
        self._initial_loading = True
        self._errors: dict[Path, str] = {}
        self._directory_cache: dict[Path, list[LocalEntry]] = {}
        super().__init__(*args, **kwargs)

    @property
    def is_listing(self) -> bool:
        return self._initial_loading or bool(self._pending)

    def path_error(self, path: Path) -> bool:
        return any(parent == path or parent in path.parents for parent in self._errors)

    def navigate(self, path: Path) -> None:
        self.set_reactive(DirectoryTree.path, path)
        self._reset_root(path)

    async def watch_path(self) -> None:
        self._reset_root(Path(self.path))

    def _reset_root(self, path: Path) -> None:
        self.cancel_loads()
        self._errors.clear()
        self._directory_cache.pop(path, None)
        self.reset_node(self.root, str(path), LocalEntry(path))
        self.root.allow_expand = True
        self.root.expand()
        self.move_cursor(self.root)
        self.call_after_refresh(self._restore_root_cursor, self._generation)
        self._load_node(self.root)

    def _restore_root_cursor(self, generation: int) -> None:
        if generation == self._generation and self.is_attached:
            self.move_cursor(self.root)

    def reload(self) -> AwaitComplete:
        self.navigate(Path(self.path))
        return AwaitComplete(self._wait_for_listing(list(self._pending)))

    async def _wait_for_listing(self, workers: list[Worker]) -> None:
        await asyncio.gather(*(worker.wait() for worker in workers), return_exceptions=True)

    def on_tree_node_expanded(self, event: Tree.NodeExpanded) -> None:
        # Native selection/rendering stays; this picker owns the loading lifecycle.
        event.prevent_default()
        event.stop()
        self._load_node(event.node)

    def _load_node(self, node: TreeNode) -> None:
        if node.data is None or not node.allow_expand or not self._node_current(node):
            return
        if any(pending[0] is node for pending in self._pending.values()):
            return
        path = node.data.path
        node.remove_children()
        self._errors.pop(path, None)
        if path in self._directory_cache:
            self._populate_entries(node, self._directory_cache[path])
            self.post_message(self.LoadState(path, self.is_listing, empty=not self._directory_cache[path]))
            return
        node.add('Loading folder...').allow_expand = False
        worker = self.run_worker(self._list_directory(path), group='local_directory', exit_on_error=False)
        self._pending[worker] = (node, path, self._generation)
        self.post_message(self.LoadState(path, True))

    async def _list_directory(self, path: Path) -> list[LocalEntry]:
        return await asyncio.to_thread(self._read_directory, path, self._directories_only)

    @staticmethod
    def _read_directory(path: Path, directories_only: bool) -> list[LocalEntry]:
        entries = []
        with os.scandir(path) as listing:
            for item in listing:
                try:
                    is_directory = item.is_dir()
                    if is_directory or (not directories_only and item.is_file()):
                        entries.append(LocalEntry(Path(item.path), is_directory))
                except OSError:
                    continue  # vanished/unresolvable entries cannot be selected
        return sorted(entries, key=lambda entry: (not entry.is_directory, entry.path.name.lower()))

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker not in self._pending or not event.worker.is_finished:
            return
        node, path, generation = self._pending.pop(event.worker)
        if generation != self._generation or not self.is_attached or event.worker.is_cancelled or not self._node_current(node):
            return
        self._initial_loading = False
        error = str(event.worker.error) if event.worker.error else ''
        node.remove_children()
        if error:
            self._errors[path] = error
            node.add('Could not load this folder').allow_expand = False
        else:
            self._directory_cache[path] = event.worker.result
            self._populate_entries(node, event.worker.result)
        self.post_message(self.LoadState(path, self.is_listing, error, not error and not self._directory_cache.get(path)))

    def _populate_entries(self, node: TreeNode, entries: list[LocalEntry]) -> None:
        node.remove_children()
        node.data.loaded = True
        for entry in entries:
            node.add(entry.path.name, data=entry, allow_expand=entry.is_directory)
        if not entries:
            node.add('This folder is empty').allow_expand = False

    def _node_current(self, node: TreeNode) -> bool:
        while node is not self.root:
            parent = node.parent
            if parent is None or node not in parent.children:
                return False
            node = parent
        return True

    def cancel_loads(self) -> None:
        self._generation += 1
        for worker in self._pending:
            worker.cancel()
        self._pending.clear()

    def on_unmount(self) -> None:
        self.cancel_loads()

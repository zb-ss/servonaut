"""Brief local and remote path selection, without copying anything."""

from __future__ import annotations

import os
import asyncio
import posixpath
import logging
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, LoadingIndicator, Static, Tree

from servonaut.screens._demo_resolve import display_text
from servonaut.utils.instance_resolver import display_name
from servonaut.utils.markup import single_line_text
from servonaut.widgets.dialogs import (
    DIALOG_VERTICAL_BREAKPOINTS, DialogActions, DialogContent, DialogFrame,
    DialogNotificationSpace,
)
from servonaut.widgets.local_path_tree import LocalPathTree, local_display_path, local_display_text
from servonaut.widgets.remote_tree import RemoteTree
from servonaut.services.remote_paths import path_error_message

logger = logging.getLogger(__name__)


def remote_parent(path: str) -> str:
    """Use POSIX paths even when the client runs on Windows."""
    stripped = path.rstrip('/')
    if stripped in {'', '/', '~', '$HOME', '${HOME}'}:
        return '/' if path.startswith('/') else '~'
    return posixpath.dirname(stripped) or '.'


def local_start(path: str, source: bool) -> Path:
    """Find the nearest usable parent of a typed path, without resolving links."""
    try:
        candidate = Path(path).expanduser().absolute() if path else Path.home()
        if source and candidate.is_file():
            candidate = candidate.parent
        while not candidate.is_dir() and candidate.parent != candidate:
            candidate = candidate.parent
        return candidate if candidate.is_dir() else Path.home()
    except (OSError, ValueError, RuntimeError):
        return Path.home()


class PathPickerModal(ModalScreen[str | None]):
    """Shared location, load state, selection and keyboard contract."""

    DEFAULT_CLASSES = 'dialog-screen'
    VERTICAL_BREAKPOINTS = DIALOG_VERTICAL_BREAKPOINTS
    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel'),
        # Modal screens isolate the application's ordinary bindings.
        Binding('ctrl+shift+d', 'app.toggle_demo', 'Demo mode', show=False),
        Binding('ctrl+e', 'app.toggle_demo', 'Demo mode', show=False),
    ]
    AUTO_FOCUS = '#path_picker_location'
    DEFAULT_CSS = """
    PathPickerModal #path_picker_title { height: 1; text-wrap: nowrap; text-overflow: ellipsis; }
    PathPickerModal #path_picker_location_row { height: 3; }
    PathPickerModal #path_picker_location { width: 1fr; margin: 0 1 0 0; }
    PathPickerModal #path_picker_go, PathPickerModal #path_picker_up { width: 6; min-width: 6; margin: 0; }
    PathPickerModal #path_picker_tree { height: 1fr; min-height: 2; }
    PathPickerModal #path_picker_state { height: auto; max-height: 3; }
    PathPickerModal #path_picker_loading { height: 1; display: none; }
    PathPickerModal #path_picker_error { height: auto; max-height: 2; color: $text-error; }
    PathPickerModal #path_picker_retry { height: 3; display: none; }
    PathPickerModal #path_picker_selected { height: 2; }
    PathPickerModal #path_picker_hint { height: 1; color: $text-muted; }
    """

    def __init__(self, *, source: bool, title: str) -> None:
        super().__init__()
        self.source, self._title = source, title
        self._selected: str | None = None
        self._is_directory = False
        self._error = ''
        self._retry_path = ''

    def scrub(self, text: str) -> str:
        text = display_text(self.app, single_line_text(local_display_text(text)))
        redactor = getattr(self.app, 'redaction_service', None)
        if getattr(self.app, 'demo_mode', False) and redactor is not None:
            text = str(redactor.scrub_stream(text))
        return single_line_text(text)

    def compose(self) -> ComposeResult:
        location = self.initial_location()
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(self.scrub(self._title), id='path_picker_title', markup=False),
            body=DialogContent(
                Static('Location', markup=False),
                Horizontal(
                    Input(
                        value=location, id='path_picker_location',
                        password=bool(getattr(self.app, 'demo_mode', False)) or single_line_text(location) != location,
                    ),
                    Button('Go', id='path_picker_go'), Button('Up', id='path_picker_up'),
                    id='path_picker_location_row',
                ),
                self.make_tree(),
                LoadingIndicator(id='path_picker_loading'),
                Static('', id='path_picker_state', markup=False),
                Static('', id='path_picker_error', markup=False),
                Button('Retry', id='path_picker_retry'),
                Static('Arrows navigate · Space expands · Esc cancels', id='path_picker_hint', markup=False),
            ),
            status=Static('Selected: Choose an entry', id='path_picker_selected', markup=False),
            actions=DialogActions(
                Button('Cancel', id='path_picker_cancel'),
                Button('Choose file' if self.source else 'Choose folder', id='path_picker_choose', variant='primary', disabled=True),
            ),
            size='large', overflow_hint=False, id='path_picker_frame',
        )

    def initial_location(self) -> str:
        raise NotImplementedError

    def make_tree(self):
        raise NotImplementedError

    def on_mount(self) -> None:
        self.refresh_after_demo_toggle()

    def refresh_after_demo_toggle(self) -> None:
        field = self.query_one('#path_picker_location', Input)
        field.password = bool(getattr(self.app, 'demo_mode', False)) or single_line_text(field.value) != field.value
        self.query_one('#path_picker_tree').refresh_labels()
        self.query_one('#path_picker_title', Static).update(self.scrub(self._title))
        self._render_selection()
        self.query_one('#path_picker_error', Static).update(self.scrub(path_error_message(self._error)) if self._error else '')

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == 'path_picker_location':
            event.input.password = bool(getattr(self.app, 'demo_mode', False)) or single_line_text(event.input.value) != event.input.value

    def _render_selection(self) -> None:
        shown = self.scrub(self.display_selection()) if self._selected is not None else 'Choose an entry'
        self.query_one('#path_picker_selected', Static).update(f'Selected: {shown}')
        choose = self.query_one('#path_picker_choose', Button)
        choose.label = 'Choose folder' if self._is_directory or not self.source else 'Choose file'
        choose.disabled = bool(self._error) or not self._selected or self.is_loading() or not self.selection_valid() or not (self.source or self._is_directory)

    def display_selection(self) -> str:
        return self._selected or ''

    def selection_valid(self) -> bool:
        return not self._error

    def is_loading(self) -> bool:
        return self.query_one('#path_picker_tree').is_listing

    def _load_state(self, event) -> None:
        self._error = event.error
        self._retry_path = str(event.path)
        loading = event.loading or self.is_loading()
        self.query_one('#path_picker_loading', LoadingIndicator).display = loading
        self.query_one('#path_picker_state', Static).update(
            'Loading folder...' if loading else 'This folder is empty' if event.empty and not event.error else '',
        )
        if event.error:
            logger.warning('Folder listing failed for %s: %s', event.path, event.error)
        self.query_one('#path_picker_error', Static).update(self.scrub(path_error_message(event.error)) if event.error else '')
        self.query_one('#path_picker_retry', Button).display = bool(event.error)
        self._render_selection()

    def on_local_path_tree_load_state(self, event: LocalPathTree.LoadState) -> None:
        self._load_state(event)

    def on_remote_tree_load_state(self, event: RemoteTree.LoadState) -> None:
        self._load_state(event)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        actions = {
            'path_picker_cancel': self.action_cancel,
            'path_picker_choose': self.action_choose,
            'path_picker_go': self.action_go,
            'path_picker_up': self.action_up,
            'path_picker_retry': self.action_retry,
        }
        if event.button.id in actions:
            actions[event.button.id]()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == 'path_picker_location':
            event.stop()
            self.action_go()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_choose(self) -> None:
        if not self.query_one('#path_picker_choose', Button).disabled and self.selection_valid() and not self.is_loading():
            suffix = '' if self.source else self.separator
            path = self._selected
            self.dismiss(path if not suffix or path.endswith(suffix) else path + suffix)


class LocalPathPickerModal(PathPickerModal):
    separator = os.sep

    def __init__(self, path: str = '', *, source: bool) -> None:
        self._typed_path, self._start = path, Path.home()
        self._initializing = True
        self._navigating = False
        super().__init__(source=source, title='Choose source · This computer' if source else 'Choose destination folder · This computer')

    def initial_location(self) -> str:
        return local_display_path(self._start)

    def display_selection(self) -> str:
        return local_display_path(Path(self._selected))

    def make_tree(self) -> LocalPathTree:
        return LocalPathTree(self._start, scrub=self.scrub, id='path_picker_tree')

    def on_mount(self) -> None:
        super().on_mount()
        self._load_state(LocalPathTree.LoadState(self._start, True))
        self.run_worker(self._initialize(), group='path_picker', exclusive=True, exit_on_error=False)

    async def _initialize(self) -> None:
        start = await asyncio.to_thread(local_start, self._typed_path, self.source)
        if self.is_attached:
            self._initializing = False
            self.query_one('#path_picker_location', Input).value = local_display_path(start)
            self.query_one('#path_picker_tree', LocalPathTree).navigate(start)
            self._set_selection(start, True)

    def is_loading(self) -> bool:
        return self._initializing or self._navigating or super().is_loading()

    def selection_valid(self) -> bool:
        tree = self.query_one('#path_picker_tree', LocalPathTree)
        node = tree.cursor_node
        return (
            bool(self._selected) and node is not None and node.data is not None
            and str(node.data.path) == self._selected
            and not tree.path_error(Path(self._selected))
        )

    def _set_selection(self, path: Path, is_directory: bool) -> None:
        self._selected, self._is_directory = str(path), is_directory
        self._render_selection()

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        tree = self.query_one('#path_picker_tree', LocalPathTree)
        if event.node is tree.cursor_node and event.node.data is not None:
            self._set_selection(event.node.data.path, event.node.allow_expand)

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        if event.node is not self.query_one('#path_picker_tree', LocalPathTree).cursor_node:
            return
        self._set_selection(event.path, False)
        if self.source:
            self.action_choose()

    def action_go(self) -> None:
        raw = self.query_one('#path_picker_location', Input).value
        self._initializing, self._navigating = False, True
        self._load_state(LocalPathTree.LoadState(Path(raw), True))
        self.run_worker(self._navigate_local(raw), group='path_picker', exclusive=True, exit_on_error=False)

    async def _navigate_local(self, raw: str) -> None:
        try:
            path = Path(raw).expanduser().absolute()
            if not raw or not await asyncio.to_thread(path.is_dir):
                raise ValueError('Enter an existing folder')
        except (OSError, ValueError, RuntimeError) as exc:
            self._navigating = False
            self._load_state(LocalPathTree.LoadState(Path(raw), False, str(exc)))
            return
        self._error = ''
        self._navigating = False
        self.query_one('#path_picker_tree', LocalPathTree).navigate(path)
        self._set_selection(path, True)
        self.query_one('#path_picker_location', Input).value = local_display_path(path)

    def action_up(self) -> None:
        tree = self.query_one('#path_picker_tree', LocalPathTree)
        self.query_one('#path_picker_location', Input).value = local_display_path(Path(tree.path).parent)
        self.action_go()

    def action_retry(self) -> None:
        self._error = ''
        tree = self.query_one('#path_picker_tree', LocalPathTree)
        tree.navigate(Path(tree.path))

    def action_choose(self) -> None:
        if not self.query_one('#path_picker_choose', Button).disabled and self.selection_valid() and not self.is_loading():
            self.run_worker(self._validate_choice(), group='path_picker_choice', exclusive=True, exit_on_error=False)

    async def _validate_choice(self) -> None:
        selected = self._selected
        path = Path(selected)
        valid = await asyncio.to_thread(lambda: path.is_dir() or (self.source and path.is_file()))
        if selected != self._selected or not self.is_attached:
            return
        if not valid:
            self._load_state(LocalPathTree.LoadState(path, False, 'Choose an existing file or folder' if self.source else 'Choose an existing folder'))
            self.query_one('#path_picker_choose', Button).disabled = True
            return
        super().action_choose()


class RemotePathPickerModal(PathPickerModal):
    separator = '/'

    def __init__(self, instance: dict, *, source: bool, root: str, options: dict) -> None:
        self._instance, self._root, self._options = instance, root, options
        self._resolving_parent = False
        self._retry_parent = False
        self._parent_worker = None
        role = 'Choose source' if source else 'Choose destination folder'
        super().__init__(source=source, title=f'{role} · {display_name(instance) or "Remote server"}')

    def initial_location(self) -> str:
        return self._root

    def is_loading(self) -> bool:
        return self._resolving_parent or super().is_loading()

    def selection_valid(self) -> bool:
        tree = self.query_one('#path_picker_tree', RemoteTree)
        entry = tree.selected_entry or {}
        return entry.get('path') == self._selected and entry.get('type') in {'file', 'directory'} and tree.selection_ready()

    def make_tree(self) -> RemoteTree:
        from servonaut.screens.file_browser import build_remote_tree
        return build_remote_tree(
            self.app, self._instance, tree_id='path_picker_tree',
            connection_options=self._options, literal_paths=True, scrub=self.scrub,
        )

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one('#path_picker_tree', RemoteTree).navigate(self._root, include_scan_paths=True)

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        tree = self.query_one('#path_picker_tree', RemoteTree)
        data = tree.selected_entry or {}
        self._selected = data.get('path')
        self._is_directory = data.get('type') == 'directory'
        self._render_selection()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        tree = self.query_one('#path_picker_tree', RemoteTree)
        data = tree.selected_entry or {}
        if event.node is tree.cursor_node and data.get('type') == 'file' and self.source:
            self.action_choose()

    def action_go(self) -> None:
        if self._parent_worker is not None:
            self._parent_worker.cancel()
            self._parent_worker = None
        self._resolving_parent = self._retry_parent = False
        path = self.query_one('#path_picker_location', Input).value
        if path:
            self._error = ''
            self.query_one('#path_picker_tree', RemoteTree).navigate(path, include_scan_paths=True)

    def action_up(self) -> None:
        tree = self.query_one('#path_picker_tree', RemoteTree)
        current = tree.current_path.rstrip('/')
        if current in {'~', '$HOME', '${HOME}', '.', '..'} or posixpath.basename(current) in {'.', '..'}:
            self._resolving_parent, self._retry_parent = True, False
            self._load_state(RemoteTree.LoadState(tree.current_path, True))
            self._parent_worker = self.run_worker(self._resolve_parent(tree.current_path), group='remote_picker_location', exclusive=True, exit_on_error=False)
        else:
            self.query_one('#path_picker_location', Input).value = remote_parent(tree.current_path)
            self.action_go()

    async def _resolve_parent(self, path: str) -> None:
        from servonaut.services.remote_paths import remote_parent_directory
        try:
            parent = await remote_parent_directory(self.app, self._options, path)
        except (OSError, RuntimeError, ValueError) as error:
            self._parent_worker = None
            self._resolving_parent, self._retry_parent = False, True
            self._load_state(RemoteTree.LoadState(path, False, str(error)))
            return
        self._parent_worker = None
        self.query_one('#path_picker_location', Input).value = parent
        self.action_go()

    def action_retry(self) -> None:
        if self._retry_parent:
            self.action_up()
        else:
            self.query_one('#path_picker_tree', RemoteTree).retry(self._retry_path)

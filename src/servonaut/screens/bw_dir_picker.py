"""Bitwarden key-import directory picker.

A brief blocking interaction (pick one directory), so it is a
:class:`~textual.screen.ModalScreen`. Shows a directories-only tree rooted at
the user's home (hidden directories are kept — ``~/.ssh`` is one) plus an
editable path Input prefilled with ``~/.ssh``.

Demo mode: tree labels are routed through ``redaction_service.scrub_stream``
(same treatment as the sibling :class:`BwKeyImportModal`), with the home node
special-cased to ``~`` because its label is the bare local username — a bare
word ``scrub_stream`` cannot recognise. The path Input is different — its
value doubles as the functional selection, so it cannot be scrubbed (a
scrubbed path no longer exists on disk); instead demo mode keeps it in
``~``-relative form, which ``expanduser()`` restores at select time and which
never displays the real local username. Residual (deliberate): directory
basenames stay visible in both surfaces — they must, to remain navigable —
matching what ``scrub_stream`` itself leaves untouched on bare names.

Dismisses the chosen :class:`~pathlib.Path`, or ``None`` on cancel.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterable, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, Static


class _DirsOnlyTree(DirectoryTree):
    """A :class:`DirectoryTree` that shows directories only.

    Hidden directories are deliberately KEPT — the primary use case is
    ``~/.ssh``, which is a dot-directory.

    ``scrub`` (optional) is a display-only label scrubber (demo mode). It
    never touches node *data* — clicks still deliver the real
    :class:`~pathlib.Path`, so selection keeps working while recordings only
    ever show scrubbed labels.
    """

    def __init__(self, *args, scrub: Optional[Callable[[str], str]] = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._scrub = scrub

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        return [path for path in paths if path.is_dir()]

    def render_label(self, node, base_style, style) -> Text:
        """Render the node label, demo-scrubbed when a scrubber is bound.

        The swap-render-restore dance keeps all of ``DirectoryTree``'s own
        styling (folder icon, dot-dir dimming) intact — only the text the
        base implementation copies from ``node._label`` changes.
        """
        if self._scrub is not None:
            original = node._label
            display = self._demo_label(node, original.plain)
            if display != original.plain:
                node._label = Text(display)
                try:
                    return super().render_label(node, base_style, style)
                finally:
                    node._label = original
        return super().render_label(node, base_style, style)

    def _demo_label(self, node, plain: str) -> str:
        """Demo-mode display text for one node.

        The home node's label is the home directory's basename — i.e. the
        real local username, which ``scrub_stream`` cannot recognise as a
        bare word — so it is special-cased to ``~``. Every other label goes
        through the scrubber (catches secret/IP/email-shaped content).
        """
        path = getattr(getattr(node, "data", None), "path", None)
        try:
            if path is not None and Path(path) == Path.home():
                return "~"
        except (OSError, ValueError):  # pragma: no cover - exotic path objects
            pass
        return self._scrub(plain)


class BwDirPickerModal(ModalScreen[Optional[Path]]):
    """Pick the local directory to scan for SSH private keys.

    Dismisses the validated directory :class:`Path`, or ``None`` on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = ""  # styling lives in the styles bundle (secrets.tcss)

    def _demo_scrub_active(self) -> bool:
        """True when demo mode is on and the redaction service exists."""
        try:
            app = self.app
        except Exception:  # noqa: BLE001 — screen not attached (unit tests)
            return False
        return bool(
            getattr(app, "demo_mode", False)
            and getattr(app, "redaction_service", None)
        )

    def _display_path(self, path: Path) -> str:
        """Path string for the editable Input, username-free in demo mode.

        The Input's value IS the functional selection (``action_select``
        parses it), so it cannot go through ``scrub_stream`` — a scrubbed
        path would no longer exist on disk. The ``~``-relative form is both
        leak-free for the local username and functionally equivalent
        (``expanduser()`` restores it at select time).
        """
        if not self._demo_scrub_active():
            return str(path)
        home = Path.home()
        if path == home:
            return "~"
        try:
            return "~" + os.sep + str(path.relative_to(home))
        except ValueError:
            return str(path)

    def compose(self) -> ComposeResult:
        scrub: Optional[Callable[[str], str]] = None
        if self._demo_scrub_active():
            scrub = self.app.redaction_service.scrub_stream
        yield Container(
            Static(
                "[bold cyan]Import SSH keys — pick a directory[/bold cyan]",
                id="bw_dir_picker_title",
            ),
            Static(
                "[dim]Click a directory in the tree or edit the path below. "
                "Enter = Select.[/dim]",
                id="bw_dir_picker_hint",
            ),
            _DirsOnlyTree(Path.home(), id="bw_dir_tree", scrub=scrub),
            Input(
                value=self._display_path(Path.home() / ".ssh"),
                id="bw_dir_input",
            ),
            Horizontal(
                Button("Cancel", variant="default", id="bw_dir_cancel_btn"),
                Button("Select", variant="primary", id="bw_dir_select_btn"),
                classes="bw_dir_actions",
            ),
            id="bw_dir_picker_container",
        )

    def on_directory_tree_directory_selected(
        self, event: DirectoryTree.DirectorySelected
    ) -> None:
        """Clicking a tree directory updates the path Input."""
        try:
            self.query_one("#bw_dir_input", Input).value = self._display_path(
                event.path
            )
        except Exception:  # noqa: BLE001 — input not mounted yet
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "bw_dir_input":
            self.action_select()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "bw_dir_cancel_btn":
            self.dismiss(None)
        elif event.button.id == "bw_dir_select_btn":
            self.action_select()

    def action_select(self) -> None:
        """Validate the typed path; dismiss it when it is a directory."""
        raw = self.query_one("#bw_dir_input", Input).value.strip()
        try:
            path = Path(raw).expanduser() if raw else None
        except (RuntimeError, ValueError):
            # '~nosuchuser/...' — expanduser cannot resolve that user's home.
            # Must not escape a Textual action (it would tear the app down).
            path = None
        if path is None or not path.is_dir():
            self.app.notify(
                f"Not a directory: {raw or '(empty)'}",
                severity="warning",
                markup=False,
            )
            return
        self.dismiss(path)

    def action_cancel(self) -> None:
        self.dismiss(None)

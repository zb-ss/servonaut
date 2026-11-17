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
from typing import Callable, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen

from servonaut.widgets.dialogs import (
    DialogActions, DialogFrame, DialogNotificationSpace,
)
from textual.widgets import Button, DirectoryTree, Input, Static
from servonaut.widgets.local_path_tree import LocalDirectoryTree


class _DirsOnlyTree(LocalDirectoryTree):
    """A :class:`DirectoryTree` that shows directories only.

    Hidden directories are deliberately KEPT — the primary use case is
    ``~/.ssh``, which is a dot-directory.

    ``scrub`` (optional) is a display-only label scrubber (demo mode). It
    never touches node *data* — clicks still deliver the real
    :class:`~pathlib.Path`, so selection keeps working while recordings only
    ever show scrubbed labels.
    """

    def __init__(self, *args, scrub: Optional[Callable[[str], str]] = None, **kwargs) -> None:
        super().__init__(*args, directories_only=True, scrub=scrub, **kwargs)


class BwDirPickerModal(ModalScreen[Optional[Path]]):
    """Pick the local directory to scan for SSH private keys.

    Dismisses the validated directory :class:`Path`, or ``None`` on cancel.
    """

    DEFAULT_CLASSES = "dialog-screen"

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
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Vertical(
                Static(
                    "[bold $text-accent]Import SSH keys — pick a directory[/bold $text-accent]",
                    id="bw_dir_picker_title",
                ),
                Static(
                    "[dim]Click a directory in the tree or edit the path below. "
                    "Enter = Select.[/dim]",
                    id="bw_dir_picker_hint",
                ),
            ),
            body=_DirsOnlyTree(Path.home(), id="bw_dir_tree", scrub=scrub),
            status=Input(
                value=self._display_path(Path.home() / ".ssh"),
                id="bw_dir_input",
            ),
            actions=DialogActions(
                Button("Cancel", variant="default", id="bw_dir_cancel_btn"),
                Button("Select", variant="primary", id="bw_dir_select_btn"),
                classes="bw_dir_actions",
            ),
            size="large",
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

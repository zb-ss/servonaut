"""DbScanRootsScreen — define extra root paths for the DB-credential scan.

The DB-credential scan defaults to a fixed set of web roots. On boxes with
apps installed outside those roots (or deeper than the default depth), the
scan misses them. This screen lets the operator add explicit root paths —
either by browsing the server's filesystem or by typing a path — and persists
them per-instance so the choice sticks across sessions.

Reuses :class:`RemoteTree` (the SSH-backed browser from the file browser) so
directory selection walks the *remote* box, not the local machine.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, OptionList, Static
from textual.widgets.option_list import Option

from servonaut.widgets.remote_tree import RemoteTree
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

# Starting points for the remote browser — common places apps live. The tree
# lazily expands over SSH, so listing several roots is cheap until opened.
_BROWSE_ROOTS = ["/home", "/var/www", "/srv", "/opt", "/usr/share/nginx", "/"]


class DbScanRootsScreen(Screen):
    """Add / remove per-instance root paths for the DB-credential scan."""

    BINDINGS = [
        Binding("escape", "cancel", "Back", show=True),
        Binding("a", "add_typed", "Add typed path", show=True),
        Binding("b", "add_browsed", "Add selected dir", show=True),
        Binding("d", "remove_selected", "Remove", show=True),
        Binding("ctrl+s", "save", "Save", show=True),
    ]

    def __init__(self, instance: dict, roots: Optional[List[str]] = None) -> None:
        super().__init__()
        self._instance = instance
        # Working copy — committed to config only on Save.
        self._roots: List[str] = list(roots or [])

    def compose(self) -> ComposeResult:
        yield Header()
        name = escape(str(self._instance.get("name") or self._instance.get("id") or "?"))
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(f"📁 DB scan roots — {name}", id="db_roots_title"),
                Static(
                    "Extra directories to scan for app DB config. Empty = the "
                    "built-in web roots. Browse the server below or type a path.",
                    id="db_roots_subtitle",
                ),
                Static("", id="db_roots_current"),
                OptionList(id="db_roots_list"),
                Horizontal(
                    Input(
                        placeholder="/absolute/path/to/app  (Enter or 'a' to add)",
                        id="db_roots_input",
                    ),
                    Button("Add", id="db_roots_add_typed", variant="primary"),
                    id="db_roots_add_row",
                ),
                Static("[dim]Browse the server — select a directory, then 'b':[/dim]"),
                self._build_tree(),
                Horizontal(
                    Button("Add selected directory", id="db_roots_add_browsed"),
                    Button("Remove selected", id="db_roots_remove", variant="warning"),
                    Button("Save", id="db_roots_save", variant="success"),
                    Button("Cancel", id="db_roots_cancel"),
                    id="db_roots_buttons",
                ),
                id="db_roots_container",
            )
        yield Footer()

    def _build_tree(self) -> RemoteTree:
        app = self.app
        if self._instance.get("is_custom"):
            username = self._instance.get("username") or "root"
        else:
            profile = app.connection_service.resolve_profile(self._instance)
            username = (
                (profile.username if profile else None)
                or app.config_manager.get().default_username
            )
        return RemoteTree(
            instance=self._instance,
            ssh_service=app.ssh_service,
            connection_service=app.connection_service,
            username=username,
            scan_paths=_BROWSE_ROOTS,
            id="db_roots_tree",
        )

    def on_mount(self) -> None:
        self._render_roots()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render_roots(self) -> None:
        current = self.query_one("#db_roots_current", Static)
        if self._roots:
            current.update(f"[dim]{len(self._roots)} custom root(s):[/dim]")
        else:
            current.update("[dim]No custom roots — using the built-in defaults.[/dim]")
        option_list = self.query_one("#db_roots_list", OptionList)
        option_list.clear_options()
        for r in self._roots:
            option_list.add_option(Option(escape(r), id=r))

    def _set_status(self, msg: str) -> None:
        self.query_one("#db_roots_subtitle", Static).update(msg)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def _add_root(self, path: str) -> None:
        path = (path or "").strip()
        if not path:
            return
        if not path.startswith("/") and not path.startswith("~"):
            self._set_status(
                "[yellow]Enter an absolute path (starting with / or ~).[/yellow]"
            )
            return
        if path in self._roots:
            self._set_status("[yellow]That path is already in the list.[/yellow]")
            return
        self._roots.append(path)
        self._render_roots()

    def action_add_typed(self) -> None:
        inp = self.query_one("#db_roots_input", Input)
        self._add_root(inp.value)
        inp.value = ""

    def action_add_browsed(self) -> None:
        tree = self.query_one("#db_roots_tree", RemoteTree)
        node = tree.cursor_node
        data = getattr(node, "data", None) if node is not None else None
        if not data or data.get("type") != "directory" or not data.get("path"):
            self._set_status(
                "[yellow]Select a directory in the tree first (files can't be "
                "roots).[/yellow]"
            )
            return
        self._add_root(str(data["path"]))

    def action_remove_selected(self) -> None:
        option_list = self.query_one("#db_roots_list", OptionList)
        idx = option_list.highlighted
        if idx is None or idx < 0 or idx >= len(self._roots):
            self._set_status("[yellow]Highlight a root in the list to remove it.[/yellow]")
            return
        del self._roots[idx]
        self._render_roots()

    def action_save(self) -> None:
        config = self.app.config_manager.get()
        instance_id = str(
            self._instance.get("id") or self._instance.get("name") or ""
        )
        if not instance_id:
            self._set_status("[red]Cannot save — instance has no id.[/red]")
            return
        if self._roots:
            config.db_scan_roots[instance_id] = list(self._roots)
        else:
            # Empty → drop the key so we fall back to built-in defaults.
            config.db_scan_roots.pop(instance_id, None)
        try:
            self.app.config_manager.save(config)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to save db_scan_roots: %s", exc)
            self._set_status(f"[red]Save failed: {escape(str(exc))}[/red]")
            return
        self.dismiss(list(self._roots))

    def action_cancel(self) -> None:
        self.dismiss(None)

    # ------------------------------------------------------------------
    # Buttons
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        handlers = {
            "db_roots_add_typed": self.action_add_typed,
            "db_roots_add_browsed": self.action_add_browsed,
            "db_roots_remove": self.action_remove_selected,
            "db_roots_save": self.action_save,
            "db_roots_cancel": self.action_cancel,
        }
        handler = handlers.get(event.button.id or "")
        if handler is not None:
            handler()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "db_roots_input":
            self.action_add_typed()

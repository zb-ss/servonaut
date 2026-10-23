"""Confirmation for the Teams screen's Share All: which servers go to the team.

Share All used to send every eligible server the moment it was pressed. This
modal lists each of them by name and address, all ticked, so the user can
untick any that should stay private. Nothing is sent unless they confirm:
Cancel has focus when it opens and Escape cancels.
"""

from __future__ import annotations

from typing import List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, SelectionList, Static
from textual.widgets.selection_list import Selection


def server_address(server: dict) -> str:
    """The address a share sends for *server*: its public IP, else its private IP."""
    return server.get("public_ip") or server.get("private_ip") or ""


def _server_name(server: dict) -> str:
    return str(server.get("name") or server.get("id") or "?")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


class ShareServersConfirmModal(ModalScreen[Optional[List[dict]]]):
    """Ask which of *servers* Share All may send to the team.

    Dismisses with the ticked servers (in the order given), or ``None`` when
    the user cancels. The rows are the app's own instance records, which the
    app redacts in place in demo mode, so they are shown as they are.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    # Shorter terminals get a shorter list, so Cancel and Share stay on screen.
    VERTICAL_BREAKPOINTS = [(0, "-short"), (30, "-medium"), (40, "-tall")]

    DEFAULT_CSS = """
    ShareServersConfirmModal { align: center middle; }
    ShareServersConfirmModal #share_confirm_modal {
        width: 84;
        max-width: 94%;
        height: auto;
        max-height: 94%;
        padding: 1 2;
        border: round $warning;
        background: $surface;
    }
    ShareServersConfirmModal #share_confirm_title { text-style: bold; color: $text-warning; }
    ShareServersConfirmModal #share_confirm_intro { margin: 1 0 0 0; }
    ShareServersConfirmModal #share_confirm_pick { height: auto; margin: 1 0 0 0; }
    ShareServersConfirmModal #share_confirm_pick Button { min-width: 14; margin: 0 1 0 0; }
    ShareServersConfirmModal #share_confirm_list { height: auto; max-height: 14; margin: 1 0 0 0; }
    ShareServersConfirmModal #share_confirm_skipped { color: $text-muted; margin: 1 0 0 0; }
    ShareServersConfirmModal #share_confirm_actions { height: auto; margin: 1 0 0 0; align: right middle; }
    ShareServersConfirmModal #share_confirm_cancel { margin: 0 1 0 0; }
    ShareServersConfirmModal.-medium #share_confirm_list { max-height: 8; }
    ShareServersConfirmModal.-short #share_confirm_intro,
    ShareServersConfirmModal.-short #share_confirm_pick,
    ShareServersConfirmModal.-short #share_confirm_skipped,
    ShareServersConfirmModal.-short #share_confirm_actions { margin: 0; }
    ShareServersConfirmModal.-short #share_confirm_list { max-height: 4; margin: 0; }
    """

    def __init__(
        self,
        team_name: str,
        servers: List[dict],
        *,
        skipped_existing: int = 0,
        skipped_no_address: int = 0,
    ) -> None:
        super().__init__()
        self._team_name = team_name
        self._servers = list(servers)
        self._skipped_existing = skipped_existing
        self._skipped_no_address = skipped_no_address

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("", id="share_confirm_title"),
            Static("", id="share_confirm_intro"),
            Horizontal(
                Button("Select All", id="share_confirm_all"),
                Button("Select None", id="share_confirm_none"),
                id="share_confirm_pick",
            ),
            SelectionList(id="share_confirm_list"),
            Static(self._skipped_text(), id="share_confirm_skipped"),
            Horizontal(
                Button("Cancel", id="share_confirm_cancel"),
                Button("", variant="primary", id="share_confirm_share"),
                id="share_confirm_actions",
            ),
            id="share_confirm_modal",
        )

    def on_mount(self) -> None:
        self._render_text()
        self._render_rows(selected=set(range(len(self._servers))))
        self.query_one("#share_confirm_skipped", Static).display = bool(self._skipped_text())
        self.query_one("#share_confirm_cancel", Button).focus()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the team name and rows for the new mode, keeping the ticks."""
        self._render_text()
        self._render_rows(selected=set(self._list().selected))

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _list(self) -> SelectionList:
        return self.query_one("#share_confirm_list", SelectionList)

    def _render_text(self) -> None:
        team_name = self._team_name
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            team_name = str(redactor.redact_name(team_name))
        team = escape(team_name)
        self.query_one("#share_confirm_title", Static).update(f"Share servers with {team}?")
        self.query_one("#share_confirm_intro", Static).update(
            f"Every member of {team} will be able to see and connect to the ticked servers. "
            "Untick any server that should stay private."
        )

    def _render_rows(self, *, selected: set) -> None:
        listing = self._list()
        highlighted = listing.highlighted or 0
        # Names padded to the longest one, so the addresses line up in a column.
        width = max((len(_server_name(server)) for server in self._servers), default=0)
        listing.clear_options()
        listing.add_options([
            Selection(self._row_label(server, width), index, index in selected)
            for index, server in enumerate(self._servers)
        ])
        if self._servers:
            # Space then toggles a row as soon as the list has focus.
            listing.highlighted = min(highlighted, len(self._servers) - 1)
        self._render_confirm()

    @staticmethod
    def _row_label(server: dict, width: int) -> str:
        name = _server_name(server).ljust(width)
        return f"{escape(name)}  [dim]{escape(server_address(server))}[/dim]"

    def _skipped_text(self) -> str:
        parts = []
        if self._skipped_existing:
            parts.append(f"{_plural(self._skipped_existing, 'server')} already shared")
        if self._skipped_no_address:
            parts.append(f"{_plural(self._skipped_no_address, 'server')} without an address")
        return "Not listed: " + ", ".join(parts) + "." if parts else ""

    def _render_confirm(self) -> None:
        count = len(self._list().selected)
        button = self.query_one("#share_confirm_share", Button)
        button.label = f"Share {_plural(count, 'server')}"
        button.disabled = count == 0

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def on_selection_list_selected_changed(self, event: SelectionList.SelectedChanged) -> None:
        event.stop()
        self._render_confirm()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        button_id = event.button.id
        if button_id == "share_confirm_all":
            self._list().select_all()
        elif button_id == "share_confirm_none":
            self._list().deselect_all()
        elif button_id == "share_confirm_cancel":
            self.dismiss(None)
        elif button_id == "share_confirm_share":
            chosen = set(self._list().selected)
            if chosen:
                self.dismiss([server for index, server in enumerate(self._servers) if index in chosen])

    def action_cancel(self) -> None:
        self.dismiss(None)

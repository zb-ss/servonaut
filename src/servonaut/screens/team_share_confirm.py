"""Confirmation for the Teams screen's Share All: which servers go to the team.

Share All used to send every eligible server the moment it was pressed. This
modal lists each of them by name and address, all ticked, so the user can
untick any that should stay private. Nothing is sent unless they confirm:
Cancel has focus when it opens and Escape cancels.
"""

from __future__ import annotations

from typing import List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, SelectionList, Static
from textual.widgets.selection_list import Selection
from servonaut.services.team_sharing import SHARE_ADDRESS, share_address
from servonaut.services.vault.display import terminal_safe


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
        height: 90%;
        max-height: 40;
        padding: 1 2;
        border: round $warning;
        background: $surface;
    }
    ShareServersConfirmModal #share_confirm_title { text-style: bold; color: $text-warning; }
    ShareServersConfirmModal #share_confirm_intro { margin: 1 0 0 0; }
    ShareServersConfirmModal #share_confirm_body { height: 1fr; }
    ShareServersConfirmModal #share_confirm_pick { height: auto; margin: 1 0 0 0; }
    ShareServersConfirmModal #share_confirm_pick Button { min-width: 14; margin: 0 1 0 0; }
    ShareServersConfirmModal #share_confirm_list { height: auto; max-height: 14; margin: 1 0 0 0; }
    ShareServersConfirmModal #share_confirm_skipped { color: $text-muted; margin: 1 0 0 0; }
    ShareServersConfirmModal #share_confirm_actions { height: auto; margin: 1 0 0 0; align: right middle; }
    ShareServersConfirmModal #share_confirm_cancel { margin: 0 1 0 0; }
    ShareServersConfirmModal #share_confirm_connection { height: 3; }
    ShareServersConfirmModal #share_confirm_username { width: 2fr; margin-right: 1; }
    ShareServersConfirmModal #share_confirm_port { width: 1fr; }
    ShareServersConfirmModal #share_confirm_editor_label { height: auto; }
    ShareServersConfirmModal #share_confirm_name { width: 1fr; }
    ShareServersConfirmModal.-medium #share_confirm_list { max-height: 4; }
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
        self._servers = [dict(server) for server in servers]
        self._skipped_existing = skipped_existing
        self._skipped_no_address = skipped_no_address
        self._drafts = [{
            "name": terminal_safe(_server_name(server)),
            "username": terminal_safe(server.get("username") or server.get("login_user") or ""),
            "port": str(server.get("port") or 22),
        } for server in servers]
        self._editing_index: int | None = None
        self._editor_display: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("", id="share_confirm_title"),
            Static("", id="share_confirm_intro"),
            VerticalScroll(
                Horizontal(
                    Button("Select All", id="share_confirm_all"),
                    Button("Select None", id="share_confirm_none"),
                    id="share_confirm_pick",
                ),
                SelectionList(id="share_confirm_list"),
                Static("Highlight a server to edit its name, SSH username and port:", id="share_confirm_editor_label"),
                Input(placeholder="Server name", id="share_confirm_name"),
                Horizontal(
                    Input(placeholder="SSH username (cloud default if blank)", id="share_confirm_username"),
                    Input(placeholder="SSH port", type="integer", id="share_confirm_port"),
                    id="share_confirm_connection",
                ),
                Static(self._skipped_text(), id="share_confirm_skipped"),
                id="share_confirm_body",
            ),
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
        if self._servers:
            self._show_editor(0)
        self.query_one("#share_confirm_skipped", Static).display = bool(self._skipped_text())
        self.query_one("#share_confirm_cancel", Button).focus()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the team name and rows for the new mode, keeping the ticks."""
        self._save_editor()
        self._render_text()
        self._render_rows(selected=set(self._list().selected))
        if self._editing_index is not None:
            self._show_editor(self._editing_index)

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
        team = terminal_safe(team_name)
        self.query_one("#share_confirm_title", Static).update(Text(f"Share servers with {team}?"))
        intro = (f"Every member of {team} will be able to see and connect to the ticked servers. "
                 "Untick any server that should stay private.")
        if any(server.get(SHARE_ADDRESS) for server in self._servers):
            intro += (" Servers your connection rules reach through a bastion are shared under their "
                      "private address: members reach them the same way.")
        self.query_one("#share_confirm_intro", Static).update(Text(intro))

    def _render_rows(self, *, selected: set) -> None:
        listing = self._list()
        highlighted = listing.highlighted or 0
        # Names padded to the longest one, so the addresses line up in a column.
        rows = [dict(server, name=draft["name"]) for server, draft in zip(self._servers, self._drafts)]
        width = max((len(self._display(_server_name(server), field="name")) for server in rows), default=0)
        listing.clear_options()
        listing.add_options([
            Selection(self._row_label(server, width), index, index in selected)
            for index, server in enumerate(rows)
        ])
        if self._servers:
            # Space then toggles a row as soon as the list has focus.
            listing.highlighted = min(highlighted, len(self._servers) - 1)
        self._render_confirm()

    def _row_label(self, server: dict, width: int) -> Text:
        name = self._display(_server_name(server), field="name").ljust(width)
        address = self._display(share_address(server), field="host")
        if server.get(SHARE_ADDRESS):
            address += " (private address)"
        return Text.assemble(name, "  ", (address, "dim"))

    def _display(self, value: str, *, field: str) -> str:
        value = terminal_safe(value)
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            if field == "name":
                return str(redactor.redact_name(value))
            if field == "username":
                return str(redactor.redact_username(value))
            if field == "host":
                return str(redactor.redact_host(value))
            return str(redactor.scrub_stream(value))
        return value

    def _save_editor(self) -> None:
        if self._editing_index is None:
            return
        draft = self._drafts[self._editing_index]
        for field in ("name", "username", "port"):
            value = self.query_one(f"#share_confirm_{field}", Input).value
            # Redrawing demo labels must not change what is sent to the team.
            if value != self._editor_display.get(field):
                draft[field] = value
        rows = [dict(server, name=entry["name"]) for server, entry in zip(self._servers, self._drafts)]
        width = max((len(self._display(_server_name(server), field="name")) for server in rows), default=0)
        for index, server in enumerate(rows):
            self._list().replace_option_prompt_at_index(index, self._row_label(server, width))

    def _show_editor(self, index: int) -> None:
        self._editing_index = index
        self._editor_display = {key: self._display(value, field=key) for key, value in self._drafts[index].items()}
        for field, value in self._editor_display.items():
            self.query_one(f"#share_confirm_{field}", Input).value = value

    def _chosen_servers(self) -> list[dict] | None:
        self._save_editor()
        chosen = []
        for index in sorted(self._list().selected):
            draft = self._drafts[index]
            name, username = draft["name"].strip(), draft["username"].strip()
            try:
                port = int(draft["port"].strip() or "22")
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                self._editor_error(index, "port", "Port must be a number between 1 and 65535.")
                return None
            if not name or terminal_safe(name) != name:
                self._editor_error(index, "name", "Give each selected server a nonempty name without control characters.")
                return None
            if username.startswith("-") or any(char.isspace() for char in username) or terminal_safe(username) != username:
                self._editor_error(index, "username", "Enter an SSH username without spaces or control characters.")
                return None
            chosen.append({**self._servers[index], "name": name, "username": username, "port": port})
        return chosen

    def _editor_error(self, index: int, field: str, message: str) -> None:
        self._list().highlighted = index
        self._show_editor(index)
        self.query_one(f"#share_confirm_{field}", Input).focus()
        self.notify(message, severity="error", markup=False)

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

    def on_selection_list_selection_highlighted(self, event: SelectionList.SelectionHighlighted) -> None:
        event.stop()
        if event.selection_index != self._editing_index:
            self._save_editor()
            self._show_editor(event.selection_index)

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
            chosen = self._chosen_servers()
            if chosen:
                self.dismiss(chosen)

    def action_cancel(self) -> None:
        self.dismiss(None)

"""Auto-bind: give each server the vault SSH key named like it, after one review.

The screen lists every server of the user's own (not a team's) with the key
from their personal vault that would be bound to it, the login and address
SSH uses, and the host keys this machine already trusts for it. Servers that
cannot be bound say why. Nothing is bound until the user has ticked that they
checked the host-key fingerprints and pressed Bind.
"""
from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, DataTable, Footer, Static

from servonaut.screens._busy_work import BusyWork
from servonaut.screens._demo_resolve import connection_instance
from servonaut.services.vault import crypto
from servonaut.services.vault.auto_bind import (
    AutoBindRow,
    apply_auto_bind,
    plan_auto_bind,
)
from servonaut.services.vault.errors import vault_failure_reason
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

# Held back while the review loads or the keys are being bound.
_ACTIONS = ("#auto_bind_apply", "#auto_bind_all", "#auto_bind_none", "#auto_bind_trust")

INTRO = (
    "Each of your servers gets the key from your personal vault that is named like its "
    "key pair (an AWS server's key pair name) or like the server. The host keys pinned are "
    "the ones this computer already trusts from earlier SSH connections. A server that "
    "already has a vault key is left alone."
)


class VaultAutoBindScreen(Screen):
    """Review and bind vault SSH keys to the servers named like them."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("space", "toggle_row", "Select", show=True),
        Binding("r", "reload", "Check again", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[AutoBindRow] = []
        self._selected: set[int] = set()
        self._vault_id: Optional[str] = None
        # Real record (by identity) -> the row as the instance list shows it,
        # so demo mode shows its stand-in names while the real ones are bound.
        self._shown_as: dict[int, Mapping[str, Any]] = {}
        self._status_raw = ""
        self._busy = BusyWork(self, "#auto_bind_busy", display=self.scrub_for_display)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="auto_bind_layout"):
            yield Sidebar()
            with Vertical(id="auto_bind_content"):
                yield Static("[bold]Auto-bind vault keys[/bold]", id="auto_bind_title")
                yield Static(INTRO, id="auto_bind_intro", markup=False)
                yield BusyIndicator(id="auto_bind_busy")
                yield Static("", id="auto_bind_status", markup=False)
                yield DataTable(id="auto_bind_table", cursor_type="row", zebra_stripes=True)
                yield Static("", id="auto_bind_detail", markup=False)
                yield Checkbox("I checked these host-key fingerprints: pin them", id="auto_bind_trust")
                with Horizontal(id="auto_bind_actions"):
                    yield Button("Bind selected", variant="primary", id="auto_bind_apply")
                    yield Button("Select all", id="auto_bind_all")
                    yield Button("Select none", id="auto_bind_none")
                    yield Button("Back", id="auto_bind_back")
        yield Footer()

    def on_mount(self) -> None:
        self._sync_compact_layout()
        table = self.query_one("#auto_bind_table", DataTable)
        table.add_columns("Bind", "Server", "Status", "Vault key", "Matched by", "Login", "Address")
        self._sync_apply()
        self.action_reload()

    def on_resize(self) -> None:
        self._sync_compact_layout()

    def _sync_compact_layout(self) -> None:
        """Two buttons to a row once four labels no longer fit; no intro on a short terminal."""
        self.set_class(self.size.width <= 110, "-narrow")
        self.set_class(self.size.height <= 32, "-short")

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def scrub_for_display(self, value: object) -> str:
        """Demo-safe text: key names, logins and addresses are hidden in demo mode."""
        text = str(value)
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            return str(redactor.scrub_stream(text))
        return text

    def refresh_after_demo_toggle(self) -> None:
        self._render_rows()
        self._status(self._status_raw)
        self._busy.redraw()

    def _status(self, message: str) -> None:
        self._status_raw = message
        self.query_one("#auto_bind_status", Static).update(self.scrub_for_display(message))

    def _server_name(self, row: AutoBindRow) -> str:
        shown = self._shown_as.get(id(row.instance), row.instance)
        return str(shown.get("name") or shown.get("id") or "server")

    def _render_rows(self) -> None:
        table = self.query_one("#auto_bind_table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for index, row in enumerate(self._rows):
            if index in self._selected:
                mark = "[x]"
            elif row.ready and row.result is None:
                mark = "[ ]"
            else:
                mark = ""
            key_name = row.match.name if row.match is not None else ""
            matched_by = row.match.matched_by if row.match is not None else ""
            address = f"{row.host}:{row.port}" if row.host and row.port != 22 else (row.host or "")
            # Every value comes from a provider, the vault or the user: inert text.
            table.add_row(
                Text(mark),
                Text(self._server_name(row)),
                Text(row.status_label),
                Text(self.scrub_for_display(key_name)),
                Text(matched_by),
                Text(self.scrub_for_display(row.login or "")),
                Text(self.scrub_for_display(address)),
                key=str(index),
            )
        if self._rows:
            table.move_cursor(row=min(max(cursor, 0), len(self._rows) - 1))
        self._show_detail()
        self._sync_apply()

    def _show_detail(self) -> None:
        detail = self.query_one("#auto_bind_detail", Static)
        table = self.query_one("#auto_bind_table", DataTable)
        if not self._rows or not 0 <= table.cursor_row < len(self._rows):
            detail.update("")
            return
        row = self._rows[table.cursor_row]
        text = f"{self._server_name(row)}: {row.status_text}"
        if row.host_keys:
            prints = "\n".join(f"  {crypto.ssh_public_fingerprint(key)}" for key in row.host_keys)
            text += f"\nHost keys this computer trusts for {row.host}:\n{prints}"
        detail.update(self.scrub_for_display(text))

    def _sync_apply(self) -> None:
        apply = self.query_one("#auto_bind_apply", Button)
        if self._busy.holds("#auto_bind_apply"):
            return  # running work gives the button back its state when it ends
        count = len(self._selected)
        apply.label = f"Bind selected ({count})" if count else "Bind selected"
        apply.disabled = count == 0

    # ------------------------------------------------------------------
    # Loading the review
    # ------------------------------------------------------------------

    def _service(self) -> Any:
        return getattr(self.app, "vault_command_service", None)

    def _servers(self) -> list[Mapping[str, Any]]:
        """The real records of the servers the instance list shows."""
        has_real = getattr(self.app, "has_real_record", None)
        self._shown_as = {}
        servers = []
        for shown in getattr(self.app, "instances", None) or []:
            if not isinstance(shown, dict):
                continue
            if callable(has_real) and has_real(shown) is False:
                continue  # a demo stand-in with no real server behind it is never bound
            real = connection_instance(self.app, shown)
            self._shown_as[id(real)] = shown
            servers.append(real)
        return servers

    def action_reload(self) -> None:
        if self._busy.is_busy:
            return
        self.run_worker(self._load(), group="vault_auto_bind", exclusive=True)

    async def _load(self) -> None:
        service = self._service()
        if service is None:
            self._status("Vault services are unavailable: sign in, then open the Vault screen.")
            return
        with self._busy.running("Finding your personal vault…", hold=_ACTIONS) as job:
            try:
                vaults = await service.vault_choices()
            except Exception as exc:
                self._status(f"Could not load your vaults ({vault_failure_reason(exc)}).")
                return
            personal = [vault for vault in vaults if vault.get("kind") == "personal"]
            if not personal:
                self._status(
                    "You have no personal vault yet: create one on the Vault screen and import your SSH keys into it."
                )
                return
            self._vault_id = str(personal[0]["vault_id"])
            # Every key's name is decrypted locally to compare it.
            self._busy.say(job, "Reading the names of your vault's SSH keys… this can take a few seconds")
            try:
                keys = await service.ssh_key_choices(vault_id=self._vault_id, name_limit=None)
            except Exception as exc:
                self._status(f"Could not read your vault's SSH keys ({vault_failure_reason(exc)}).")
                return
            if not keys:
                self._status("Your personal vault has no SSH key yet: import your keys with Import SSH on the Vault screen.")
                return
            self._busy.say(job, "Checking each server's vault key, login and trusted host keys…")
            try:
                rows = await plan_auto_bind(service, self._servers(), keys)
            except Exception as exc:
                logger.warning("Auto-bind review failed: %s", type(exc).__name__)
                self._status(f"Could not check your servers ({vault_failure_reason(exc)}).")
                return
        self._rows = rows
        self._selected = {index for index, row in enumerate(rows) if row.ready}
        self._render_rows()
        ready = len(self._selected)
        if not rows:
            self._status("You have no servers of your own to bind a key to.")
        elif ready:
            self._status(
                f"{ready} of {len(rows)} servers can get a vault key. Check their host-key fingerprints "
                "(shown for the highlighted server), tick the box and press Bind selected."
            )
        else:
            self._status(f"None of your {len(rows)} servers can get a vault key automatically: see each status.")

    # ------------------------------------------------------------------
    # Choosing and binding
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_toggle_row()

    def action_toggle_row(self) -> None:
        if self._busy.is_busy or not self._rows:
            return
        index = self.query_one("#auto_bind_table", DataTable).cursor_row
        if not 0 <= index < len(self._rows):
            return
        row = self._rows[index]
        if not row.ready or row.result is not None:
            return
        self._selected.symmetric_difference_update({index})
        self._render_rows()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id
        if button == "auto_bind_back":
            self.action_back()
        elif button == "auto_bind_all":
            self._selected = {i for i, row in enumerate(self._rows) if row.ready and row.result is None}
            self._render_rows()
        elif button == "auto_bind_none":
            self._selected.clear()
            self._render_rows()
        elif button == "auto_bind_apply":
            self._start_binding()

    def _start_binding(self) -> None:
        if self._busy.is_busy or not self._selected:
            return
        if not self.query_one("#auto_bind_trust", Checkbox).value:
            self._status("Check the host-key fingerprints of the selected servers, then tick the box to pin them.")
            return
        self.run_worker(self._bind(), group="vault_auto_bind", exclusive=True)

    async def _bind(self) -> None:
        service = self._service()
        chosen = [self._rows[index] for index in sorted(self._selected)]
        if service is None or self._vault_id is None or not chosen:
            return
        with self._busy.running(f"Binding vault keys to {len(chosen)} servers…", hold=_ACTIONS) as job:
            def progress(index: int, row: AutoBindRow) -> None:
                self._busy.say(job, f"Binding {index + 1} of {len(chosen)}: {self._server_name(row)}…")

            await apply_auto_bind(service, chosen, vault_id=self._vault_id, on_progress=progress)
        self._selected.clear()
        self.query_one("#auto_bind_trust", Checkbox).value = False
        self._render_rows()
        bound = sum(row.result == "bound" for row in chosen)
        failed = len(chosen) - bound
        message = f"Bound vault keys to {bound} of {len(chosen)} servers."
        if failed:
            message += f" {failed} failed: see their status."
        self._status(message)
        self.app.notify(message, severity="warning" if failed else "information", markup=False)

    def action_back(self) -> None:
        # Leaving while binding stops the servers not reached yet; those bound stay bound.
        self.app.pop_screen()

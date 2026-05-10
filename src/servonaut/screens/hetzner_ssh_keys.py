"""Hetzner Cloud project-level SSH key management screen.

These are the keys held in the Hetzner Cloud project's SSH-key
registry — the same registry the create-server wizard injects keys
from at provision time. The screen is intentionally separate from the
local-SSH-keys management surface (``~/.ssh``); this one only touches
Hetzner's side.

Mirrors :class:`servonaut.screens.ovh_ssh_keys.OVHSSHKeysScreen` in
shape (table + add form + bottom-docked Save/Cancel + confirm-on-
delete) so the OVH and Hetzner SSH-key surfaces feel like one app.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, Static,
)

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp


logger = logging.getLogger(__name__)


class HetznerSSHKeysScreen(Screen):
    """Manage Hetzner Cloud project SSH keys."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("n", "add_key", "Add", show=True),
        Binding("d", "delete_key", "Delete", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._keys: list[dict] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]Hetzner SSH Keys[/bold cyan]",
                    id="hetzner_ssh_keys_header",
                ),
                Static(
                    "[dim]Project-level SSH keys registered with Hetzner "
                    "Cloud. The create-server wizard injects keys from "
                    "this list at provision time — they do NOT touch "
                    "your local ~/.ssh.[/dim]",
                    id="hetzner_ssh_keys_hint",
                ),

                DataTable(id="hetzner_ssh_keys_table"),
                Static("", id="hetzner_ssh_keys_status"),

                Horizontal(
                    Button(
                        "Refresh (r)", id="btn_hetzner_ssh_refresh",
                    ),
                    Button(
                        "+ Add Key (n)", variant="primary",
                        id="btn_hetzner_ssh_add",
                    ),
                    Button(
                        "Delete (d)", variant="error",
                        id="btn_hetzner_ssh_delete",
                        disabled=True,
                    ),
                    Button(
                        "Back",
                        id="btn_hetzner_ssh_back",
                    ),
                    id="hetzner_ssh_keys_actions",
                ),

                # Add form — hidden by default (atomic show/hide via
                # the global ``.hidden`` rule).
                Container(
                    Static(
                        "[bold]Add SSH Key[/bold]",
                        classes="section_header",
                    ),
                    Label("Key name:"),
                    Input(
                        placeholder="my-laptop",
                        id="hetzner_ssh_input_name",
                    ),
                    Label(
                        "Public key (paste full ssh-ed25519 / ssh-rsa "
                        "line):",
                    ),
                    Input(
                        placeholder="ssh-ed25519 AAAA... user@host",
                        id="hetzner_ssh_input_public_key",
                    ),
                    id="hetzner_ssh_add_form",
                    classes="hidden",
                ),

                # Bottom-docked Save/Cancel — visibility mirrors the
                # form's. Same pattern as the custom-servers and OVH
                # cloud-create wizards.
                Horizontal(
                    Button(
                        "Save", id="btn_hetzner_ssh_save",
                        variant="primary",
                    ),
                    Button(
                        "Cancel", id="btn_hetzner_ssh_cancel",
                    ),
                    id="hetzner_ssh_add_form_actions",
                    classes="hidden",
                ),

                id="hetzner_ssh_keys_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        table = self.query_one("#hetzner_ssh_keys_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "ID", "Fingerprint")
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if getattr(self.app, "hetzner_service", None) is None:
            self._set_status(
                "[red]Hetzner Cloud is not configured. "
                "Visit Settings → Hetzner Cloud first.[/red]"
            )
            return
        self._set_status("[dim]Loading keys…[/dim]")
        self.run_worker(
            self._load_keys(), exclusive=True, name="hetzner_ssh_load",
        )

    async def _load_keys(self) -> None:
        svc = self.app.hetzner_service
        try:
            self._keys = list(await svc.list_ssh_keys())
        except Exception as exc:
            logger.error("Failed to load Hetzner SSH keys: %s", exc)
            self._set_status(
                f"[red]Failed to load keys: {self._short_err(exc)}[/red]"
            )
            return

        table = self.query_one("#hetzner_ssh_keys_table", DataTable)
        table.clear()
        for key in self._keys:
            fp = key.get("fingerprint", "") or ""
            table.add_row(
                str(key.get("name", "")),
                str(key.get("id", "")),
                fp[:32],
                key=str(key.get("id", "")) or str(key.get("name", "")),
            )
        n = len(self._keys)
        if n == 0:
            self._set_status(
                "[dim]No SSH keys registered yet. Press [b]n[/b] to "
                "add one — required before creating servers.[/dim]"
            )
        else:
            self._set_status(
                f"[dim]{n} key{'s' if n != 1 else ''}.[/dim]"
            )
        self._sync_action_buttons()

    # ------------------------------------------------------------------
    # Selection-driven button enablement
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event) -> None:
        self._sync_action_buttons()

    def _selected_key(self) -> dict | None:
        table = self.query_one("#hetzner_ssh_keys_table", DataTable)
        row = table.cursor_row
        if row < 0 or row >= len(self._keys):
            return None
        return self._keys[row]

    def _sync_action_buttons(self) -> None:
        try:
            self.query_one(
                "#btn_hetzner_ssh_delete", Button,
            ).disabled = self._selected_key() is None
        except Exception:  # pragma: no cover - defensive
            pass

    # ------------------------------------------------------------------
    # Form visibility
    # ------------------------------------------------------------------

    def _show_form(self) -> None:
        for sel in (
            "#hetzner_ssh_add_form", "#hetzner_ssh_add_form_actions",
        ):
            self.query_one(sel).remove_class("hidden")
        self.query_one("#hetzner_ssh_input_name", Input).value = ""
        self.query_one("#hetzner_ssh_input_public_key", Input).value = ""
        self.query_one("#hetzner_ssh_input_name", Input).focus()

    def _hide_form(self) -> None:
        for sel in (
            "#hetzner_ssh_add_form", "#hetzner_ssh_add_form_actions",
        ):
            self.query_one(sel).add_class("hidden")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "btn_hetzner_ssh_refresh":
            self.action_refresh()
        elif button_id == "btn_hetzner_ssh_add":
            self.action_add_key()
        elif button_id == "btn_hetzner_ssh_delete":
            self.action_delete_key()
        elif button_id == "btn_hetzner_ssh_save":
            self._save_key()
        elif button_id == "btn_hetzner_ssh_cancel":
            self._hide_form()
        elif button_id == "btn_hetzner_ssh_back":
            self.action_back()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._refresh()

    def action_add_key(self) -> None:
        if getattr(self.app, "hetzner_service", None) is None:
            self.notify(
                "Hetzner Cloud is not configured.",
                severity="warning", markup=False,
            )
            return
        self._show_form()

    def action_delete_key(self) -> None:
        key = self._selected_key()
        if key is None:
            self.notify("No key selected.", severity="warning",
                        markup=False)
            return
        # ``push_screen_wait`` requires a worker context in Textual 8.x —
        # spawn the confirm + delete chain explicitly.
        self.run_worker(
            self._do_delete(key),
            exclusive=True, name="hetzner_ssh_delete",
        )

    def _save_key(self) -> None:
        name = self.query_one("#hetzner_ssh_input_name", Input).value.strip()
        public_key = (
            self.query_one("#hetzner_ssh_input_public_key", Input).value.strip()
        )
        if not name:
            self.notify("Key name is required.", severity="warning",
                        markup=False)
            self.query_one("#hetzner_ssh_input_name", Input).focus()
            return
        if not public_key:
            self.notify(
                "Public key is required (paste the full ssh-ed25519 / "
                "ssh-rsa line).",
                severity="warning", markup=False,
            )
            self.query_one(
                "#hetzner_ssh_input_public_key", Input,
            ).focus()
            return

        self._hide_form()
        self.run_worker(
            self._do_add(name, public_key),
            exclusive=True, name="hetzner_ssh_add",
        )

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    async def _do_add(self, name: str, public_key: str) -> None:
        self._set_status(f"[dim]Adding key {name}…[/dim]")
        svc = self.app.hetzner_service
        try:
            await svc.create_ssh_key(name, public_key)
        except Exception as exc:
            logger.error("Hetzner SSH key add failed for %s: %s", name, exc)
            self._set_status(
                f"[red]Add failed: {self._short_err(exc)}[/red]"
            )
            self.notify(
                f"Add failed: {exc}", severity="error", markup=False,
            )
            return
        self.notify(
            f"SSH key {name!r} registered.",
            severity="information", markup=False,
        )
        await self._load_keys()

    async def _do_delete(self, key: dict) -> None:
        identifier = str(key.get("id") or key.get("name") or "")
        if not identifier:
            return
        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete SSH Key",
                description=(
                    f"Remove [bold]{key.get('name', identifier)}[/bold] "
                    f"from your Hetzner Cloud project."
                ),
                consequences=[
                    "The key is removed from Hetzner's project registry",
                    "Existing servers that already have this key in "
                    "authorized_keys are unaffected",
                    "New servers can no longer reference this key by name",
                ],
                confirm_text="delete",
                action_label="Delete Key",
                severity="warning",
            )
        )
        if not confirmed:
            return

        self._set_status(
            f"[dim]Deleting key {key.get('name', identifier)}…[/dim]"
        )
        svc = self.app.hetzner_service
        try:
            await svc.delete_ssh_key(identifier)
        except Exception as exc:
            logger.error(
                "Hetzner SSH key delete failed for %s: %s", identifier, exc,
            )
            self._set_status(
                f"[red]Delete failed: {self._short_err(exc)}[/red]"
            )
            self.notify(
                f"Delete failed: {exc}", severity="error", markup=False,
            )
            return
        self.notify(
            f"SSH key {identifier!r} deleted.",
            severity="information", markup=False,
        )
        await self._load_keys()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: str) -> None:
        try:
            self.query_one(
                "#hetzner_ssh_keys_status", Static,
            ).update(text)
        except Exception:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"

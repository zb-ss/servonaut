"""OVH account-level SSH key management screen."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class OVHSSHKeysScreen(Screen):
    """Manage OVH account-level SSH keys (/me/sshKey API)."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("n", "add_key", "Add", show=True),
        Binding("d", "delete_key", "Delete", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]OVH SSH Keys[/bold cyan]", id="ovh_ssh_keys_header"),
                Static(
                    "[dim]Manage account-level SSH keys stored on OVHcloud (/me/sshKey)[/dim]",
                    classes="note",
                ),

                DataTable(id="ssh_keys_table"),

                Horizontal(
                    Button("Add Key", id="btn_add_key", variant="primary"),
                    Button("Delete Key", id="btn_delete_key", variant="error"),
                    Button("Refresh", id="btn_refresh", variant="default"),
                    Button("Back", id="btn_back", variant="default"),
                    classes="add_row",
                ),

                # Add Key form (hidden by default)
                Container(
                    Static("[bold]Add SSH Key[/bold]", classes="section_header"),
                    Label("Key Name:"),
                    Input(placeholder="my-ssh-key", id="input_key_name"),
                    Label("Public Key:"),
                    Input(placeholder="ssh-rsa AAAA...", id="input_public_key"),
                    Horizontal(
                        Button("Save Key", id="btn_save_key", variant="primary"),
                        Button("Cancel", id="btn_cancel_form", variant="default"),
                        classes="add_row",
                    ),
                    id="add_key_form",
                ),

                id="ovh_ssh_keys_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._setup_table()
        self._hide_form()
        self.run_worker(self._load_keys(), exclusive=True)

    def _setup_table(self) -> None:
        table = self.query_one("#ssh_keys_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "Key (first 40 chars)", "Default")

    def _hide_form(self) -> None:
        self.query_one("#add_key_form").display = False

    def _show_form(self) -> None:
        form = self.query_one("#add_key_form")
        self.query_one("#input_key_name", Input).value = ""
        self.query_one("#input_public_key", Input).value = ""
        form.display = True
        self.query_one("#input_key_name", Input).focus()

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def _get_client(self):
        return self.app.ovh_service.client

    async def _fetch_keys(self) -> List[dict]:
        """Fetch all keys: GET /me/sshKey then GET /me/sshKey/{name} for each."""
        client = self._get_client()
        key_names: List[str] = await asyncio.to_thread(client.get, "/me/sshKey")
        keys: List[dict] = []
        for name in key_names:
            try:
                detail = await asyncio.to_thread(client.get, f"/me/sshKey/{name}")
                keys.append(detail)
            except Exception as exc:
                logger.warning("Failed to fetch OVH SSH key detail for %s: %s", name, exc)
        return keys

    async def _load_keys(self) -> None:
        """Worker: load keys from OVH and populate the table."""
        try:
            keys = await self._fetch_keys()
            table = self.query_one("#ssh_keys_table", DataTable)
            table.clear()
            for key in keys:
                name = key.get("keyName", "")
                public_key = key.get("key", "")
                truncated = public_key[:40] + "..." if len(public_key) > 40 else public_key
                default = "Yes" if key.get("default", False) else "No"
                table.add_row(name, truncated, default)
        except Exception as exc:
            logger.error("Failed to load OVH SSH keys: %s", exc)
            self.app.notify(f"Failed to load SSH keys: {exc}", severity="error")

    async def _add_key(self, key_name: str, public_key: str) -> None:
        """Worker: add a new SSH key via POST /me/sshKey."""
        client = self._get_client()
        try:
            await asyncio.to_thread(
                client.post,
                "/me/sshKey",
                keyName=key_name,
                key=public_key,
            )
            self.app.notify(f"SSH key '{key_name}' added", severity="information")
            await self._load_keys()
        except Exception as exc:
            logger.error("Failed to add OVH SSH key: %s", exc)
            self.app.notify(f"Failed to add SSH key: {exc}", severity="error")

    async def _delete_key(self, key_name: str) -> None:
        """Worker: delete an SSH key via DELETE /me/sshKey/{keyName}."""
        client = self._get_client()
        try:
            await asyncio.to_thread(client.delete, f"/me/sshKey/{key_name}")
            self.app.notify(f"SSH key '{key_name}' deleted", severity="information")
            await self._load_keys()
        except Exception as exc:
            logger.error("Failed to delete OVH SSH key %s: %s", key_name, exc)
            self.app.notify(f"Failed to delete SSH key: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn_add_key":
            self.action_add_key()
        elif button_id == "btn_delete_key":
            self.action_delete_key()
        elif button_id == "btn_refresh":
            self.action_refresh()
        elif button_id == "btn_save_key":
            self._save_key()
        elif button_id == "btn_cancel_form":
            self._hide_form()
        elif button_id == "btn_back":
            self.action_back()

    def action_add_key(self) -> None:
        self._show_form()

    def action_delete_key(self) -> None:
        table = self.query_one("#ssh_keys_table", DataTable)
        row = table.cursor_row
        if table.row_count == 0 or row < 0:
            self.app.notify("No key selected", severity="warning")
            return

        row_data = table.get_row_at(row)
        key_name = str(row_data[0])

        async def _confirm_and_delete() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Delete SSH Key",
                    description=f"Remove the SSH key [bold]{key_name}[/bold] from your OVH account.",
                    consequences=["The key will be removed from OVHcloud", "Servers using this key will not be affected"],
                    confirm_text=key_name,
                    action_label="Delete Key",
                    severity="warning",
                )
            )
            if confirmed:
                await self._delete_key(key_name)

        self.run_worker(_confirm_and_delete(), exclusive=False)

    def action_refresh(self) -> None:
        self.run_worker(self._load_keys(), exclusive=True)

    def _save_key(self) -> None:
        key_name = self.query_one("#input_key_name", Input).value.strip()
        public_key = self.query_one("#input_public_key", Input).value.strip()

        if not key_name:
            self.app.notify("Key name is required", severity="error")
            self.query_one("#input_key_name", Input).focus()
            return

        if not public_key:
            self.app.notify("Public key is required", severity="error")
            self.query_one("#input_public_key", Input).focus()
            return

        self._hide_form()
        self.run_worker(self._add_key(key_name, public_key), exclusive=False)

    def action_back(self) -> None:
        self.app.pop_screen()

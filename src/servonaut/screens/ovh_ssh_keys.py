"""OVH project-level SSH key management screen.

Manages keys stored in a Public Cloud project's registry
(``/cloud/project/{id}/sshkey``) — the same registry the
``OVHCloudCreateScreen`` wizard injects from at instance-create
time. Account-level keys (``/me/sshKey``) used by VPS / dedicated
bare-metal are a separate registry and not managed here; users
who need them can use the OVH web console.

Pre-restructure this screen managed ``/me/sshKey``, so a key added
via this surface never appeared in the cloud-create wizard's keys
table — the wizard reads ``/cloud/project/{id}/sshkey``. The two
registries do not sync, which led to "I added a key, why does the
wizard say I have none?" reports.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

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


class OVHSSHKeysScreen(Screen):
    """Manage OVH Public Cloud project SSH keys."""

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
        self._keys: List[dict] = []
        self._project_id: str = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]OVH Public Cloud SSH Keys[/bold cyan]",
                    id="ovh_ssh_keys_header",
                ),
                Static(
                    "[dim]Project-level keys registered with OVHcloud "
                    "(/cloud/project/{id}/sshkey). The Public Cloud "
                    "create wizard injects keys from this list at "
                    "provision time. Account-level /me/sshKey keys "
                    "(used by VPS / dedicated bare-metal) are a "
                    "separate registry — manage those via the OVH "
                    "web console.[/dim]",
                    classes="note",
                ),
                Static("", id="ovh_ssh_keys_project_label", classes="note"),

                DataTable(id="ssh_keys_table"),
                Static("", id="ovh_ssh_keys_status"),

                Horizontal(
                    Button("Refresh (r)", id="btn_refresh"),
                    Button(
                        "+ Add Key (n)", id="btn_add_key",
                        variant="primary",
                    ),
                    Button(
                        "Delete (d)", id="btn_delete_key",
                        variant="error", disabled=True,
                    ),
                    Button("Back", id="btn_back"),
                    id="ovh_ssh_keys_actions",
                ),

                # Add Key form (hidden by default).
                Container(
                    Static(
                        "[bold]Add SSH Key[/bold]",
                        classes="section_header",
                    ),
                    Label("Key name:"),
                    Input(placeholder="my-laptop", id="input_key_name"),
                    Label(
                        "Public key (full ssh-ed25519 / ssh-rsa line):",
                    ),
                    Input(
                        placeholder="ssh-ed25519 AAAA... user@host",
                        id="input_public_key",
                    ),
                    id="add_key_form",
                    classes="hidden",
                ),
                # Bottom-docked Save / Cancel — visibility mirrors the
                # form's. Same pattern as the Hetzner SSH-keys screen.
                Horizontal(
                    Button(
                        "Save", id="btn_save_key", variant="primary",
                    ),
                    Button("Cancel", id="btn_cancel_form"),
                    id="add_key_form_actions",
                    classes="hidden",
                ),

                id="ovh_ssh_keys_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#ssh_keys_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "Fingerprint", "Public Key (first 40 chars)")
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _resolve_project_id(self) -> Optional[str]:
        config_manager = getattr(self.app, "config_manager", None)
        if config_manager is None:
            return None
        try:
            config = config_manager.get()
        except Exception:
            return None
        ovh_cfg = getattr(config, "ovh", None)
        if ovh_cfg is None:
            return None
        ids = list(getattr(ovh_cfg, "cloud_project_ids", []))
        return ids[0] if ids else None

    def _refresh(self) -> None:
        cloud_svc = getattr(self.app, "ovh_cloud_service", None)
        if cloud_svc is None:
            self._set_status(
                "[red]OVH Cloud service is not initialised. "
                "Configure OVHcloud in Settings first.[/red]"
            )
            return
        project_id = self._resolve_project_id()
        if not project_id:
            self._set_status(
                "[red]No OVH cloud project ID configured. Add one in "
                "Settings → OVHcloud → Cloud project IDs.[/red]"
            )
            return
        self._project_id = project_id
        self.query_one(
            "#ovh_ssh_keys_project_label", Static,
        ).update(
            f"[dim]Project:[/dim] [b]{project_id}[/b]"
        )
        self._set_status("[dim]Loading keys…[/dim]")
        self.run_worker(
            self._load_keys(), exclusive=True, name="ovh_ssh_load",
        )

    async def _load_keys(self) -> None:
        cloud_svc = self.app.ovh_cloud_service
        try:
            self._keys = list(
                await cloud_svc.list_ssh_keys(self._project_id)
            )
        except Exception as exc:
            logger.error("Failed to load OVH project SSH keys: %s", exc)
            self._set_status(
                f"[red]Failed to load keys: {self._short_err(exc)}[/red]"
            )
            return

        table = self.query_one("#ssh_keys_table", DataTable)
        table.clear()
        for key in self._keys:
            public_key = key.get("public_key", "") or ""
            truncated = (
                public_key[:40] + "…" if len(public_key) > 40 else public_key
            )
            table.add_row(
                str(key.get("name", "")),
                str(key.get("fingerprint", "") or "")[:32],
                truncated,
                key=str(key.get("id", "")) or str(key.get("name", "")),
            )
        n = len(self._keys)
        if n == 0:
            self._set_status(
                "[dim]No keys registered yet. Press [b]n[/b] to add "
                "one — the create-instance wizard injects from this "
                "list.[/dim]"
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

    def _selected_key(self) -> Optional[dict]:
        table = self.query_one("#ssh_keys_table", DataTable)
        row = table.cursor_row
        if row < 0 or row >= len(self._keys):
            return None
        return self._keys[row]

    def _sync_action_buttons(self) -> None:
        try:
            self.query_one(
                "#btn_delete_key", Button,
            ).disabled = self._selected_key() is None
        except Exception:  # pragma: no cover - defensive
            pass

    # ------------------------------------------------------------------
    # Form visibility
    # ------------------------------------------------------------------

    def _hide_form(self) -> None:
        for sel in ("#add_key_form", "#add_key_form_actions"):
            self.query_one(sel).add_class("hidden")

    def _show_form(self) -> None:
        for sel in ("#add_key_form", "#add_key_form_actions"):
            self.query_one(sel).remove_class("hidden")
        self.query_one("#input_key_name", Input).value = ""
        self.query_one("#input_public_key", Input).value = ""
        self.query_one("#input_key_name", Input).focus()

    # ------------------------------------------------------------------
    # Actions
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

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._refresh()

    def action_add_key(self) -> None:
        if not self._project_id:
            self.notify(
                "Configure an OVH cloud project ID in Settings first.",
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
        # ``push_screen_wait`` requires a worker context in Textual
        # 8.x — spawn the confirm + delete chain explicitly.
        self.run_worker(
            self._do_delete(key),
            exclusive=True, name="ovh_ssh_delete",
        )

    def _save_key(self) -> None:
        key_name = self.query_one("#input_key_name", Input).value.strip()
        public_key = self.query_one(
            "#input_public_key", Input,
        ).value.strip()
        if not key_name:
            self.notify("Key name is required.", severity="warning",
                        markup=False)
            self.query_one("#input_key_name", Input).focus()
            return
        if not public_key:
            self.notify(
                "Public key is required (paste the full ssh-ed25519 "
                "/ ssh-rsa line).",
                severity="warning", markup=False,
            )
            self.query_one("#input_public_key", Input).focus()
            return

        self._hide_form()
        self.run_worker(
            self._do_add(key_name, public_key),
            exclusive=True, name="ovh_ssh_add",
        )

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    async def _do_add(self, name: str, public_key: str) -> None:
        self._set_status(f"[dim]Adding key {name}…[/dim]")
        cloud_svc = self.app.ovh_cloud_service
        try:
            await cloud_svc.add_ssh_key(self._project_id, name, public_key)
        except Exception as exc:
            logger.error("OVH project SSH key add failed for %s: %s",
                         name, exc)
            self._set_status(
                f"[red]Add failed: {self._short_err(exc)}[/red]"
            )
            self.notify(f"Add failed: {exc}", severity="error",
                        markup=False)
            return
        self.notify(
            f"SSH key {name!r} registered with project {self._project_id}.",
            severity="information", markup=False,
        )
        await self._load_keys()

    async def _do_delete(self, key: dict) -> None:
        key_id = str(key.get("id") or "")
        key_name = str(key.get("name") or key_id)
        if not key_id:
            return
        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete SSH Key",
                description=(
                    f"Remove [bold]{key_name}[/bold] from project "
                    f"[bold]{self._project_id}[/bold]."
                ),
                consequences=[
                    "The key is removed from this OVH project's registry",
                    "Existing instances that already had this key in "
                    "authorized_keys are unaffected",
                    "New instances can no longer reference this key",
                ],
                confirm_text=key_name,
                action_label="Delete Key",
                severity="warning",
            )
        )
        if not confirmed:
            return
        self._set_status(f"[dim]Deleting key {key_name}…[/dim]")
        cloud_svc = self.app.ovh_cloud_service
        try:
            await cloud_svc.delete_ssh_key(self._project_id, key_id)
        except Exception as exc:
            logger.error(
                "OVH project SSH key delete failed for %s: %s",
                key_id, exc,
            )
            self._set_status(
                f"[red]Delete failed: {self._short_err(exc)}[/red]"
            )
            self.notify(f"Delete failed: {exc}", severity="error",
                        markup=False)
            return
        self.notify(
            f"SSH key {key_name!r} deleted from project {self._project_id}.",
            severity="information", markup=False,
        )
        await self._load_keys()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: str) -> None:
        try:
            self.query_one(
                "#ovh_ssh_keys_status", Static,
            ).update(text)
        except Exception:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"

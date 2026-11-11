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

With several OVH accounts configured, a picker chooses the account whose
first Public Cloud project is listed and changed.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import (
    Button, DataTable, Footer, Input, Label, Static,
)

from servonaut.screens._compact_actions import sync_compact_buttons
from servonaut.utils.markup import inert_text, literal, with_bold_values
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._provider_accounts import (
    UnknownAccountError,
    account_settings,
    ovh_services,
    registry_for,
    show_account_labels,
)
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class _ProjectKeysTable(DataTable):
    """Keep the selected key visible after the catalog's native rows reflow."""

    def on_resize(self) -> None:
        # A content-sized table can shrink after its rows are populated.
        # Textual retains its old scroll offset across that resize, which
        # otherwise leaves the selected key below the shorter viewport.
        self.call_after_refresh(self._restore_cursor_visibility)

    def on_focus(self) -> None:
        # Focus can arrive before the catalog has finished its native reflow.
        self.call_after_refresh(self._restore_cursor_visibility)

    def _restore_cursor_visibility(self) -> None:
        self.move_cursor(row=self.cursor_row, column=self.cursor_column, animate=False)
        if self.has_focus:
            self.scroll_visible(animate=False, immediate=True)


class OVHSSHKeysScreen(WorkspaceScreen):
    """Manage OVH Public Cloud project SSH keys."""

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 64
    CONTENT_NARROW_WIDTH = 96

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("n", "add_key", "Add", show=True),
        Binding("d", "delete_key", "Delete", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    # Label of the chosen account; "" is the default account.
    _account: str = ""
    # Counts list loads; see _load_keys.
    _loads: int = 0

    @property
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._keys: List[dict] = []
        self._project_id: str = ""

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("SSH keys")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield ScrollableContainer(
                VerticalScroll(
                    Static(
                        "[bold]OVH Public Cloud SSH keys[/bold]",
                        id="ovh_ssh_keys_header",
                        classes="screen-title",
                    ),
                    AccountPicker.for_provider(
                        registry_for(self.app, "ovh"), "ovh",
                        id="ovh_ssh_keys_account",
                    ),
                    Static("", id="ovh_ssh_keys_project_label", classes="note"),
                    id="ovh_ssh_keys_scope",
                ),
                VerticalScroll(
                    Horizontal(
                        Container(
                            Static("[bold]Registered project keys[/bold]", classes="provider_catalog_heading"),
                            Static("", id="ovh_ssh_keys_status"),
                            _ProjectKeysTable(id="ssh_keys_table"),
                            classes="provider_key_catalog",
                        ),
                        Vertical(
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
                            Static("Selected key", classes="provider-key-selection-heading"),
                            Static("Select a registered key to inspect its identity.", id="provider_key_selection", classes="provider-key-selection", markup=False),
                            classes="provider-key-context",
                        ),
                        classes="provider-key-inventory",
                    ),
                    Container(
                        Static(
                            "[bold]Add SSH key[/bold]",
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
                        classes="hidden provider_key_editor",
                    ),
                    id="ovh_ssh_keys_document",
                ),
                ActionRow(
                    ActionButton("Refresh", "r", id="btn_refresh"),
                    ActionButton("Add key", "n", role="primary", id="btn_add_key"),
                    ActionButton("Delete", "d", role="error", id="btn_delete_key", disabled=True),
                    ActionButton("Back", "esc", id="btn_back"),
                    id="ovh_ssh_keys_actions",
                ),
                Horizontal(
                    Button(
                        "Save", id="btn_save_key", variant="primary",
                    ),
                    Button("Cancel", id="btn_cancel_form"),
                    id="add_key_form_actions",
                    classes="hidden",
                ),
                id="ovh_ssh_keys_container",
                classes="workspace-content provider-key-workspace",
            )
        yield Footer()

    def sync_workspace_controls(self) -> None:
        super().sync_workspace_controls()
        sync_compact_buttons(self)

    def on_mount(self) -> None:
        sync_compact_buttons(self)
        table = self.query_one("#ssh_keys_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "Fingerprint", "Public key")
        picker = self.query_one("#ovh_ssh_keys_account", AccountPicker)
        self._account = picker.account
        show_account_labels(picker)
        self._refresh()

    def on_account_picker_changed(self, event: AccountPicker.Changed) -> None:
        """Another account was picked: list its project's keys instead."""
        self._account = event.account
        self._project_id = ""
        self._keys = []
        self._hide_form()
        self.query_one("#ovh_ssh_keys_project_label", Static).update("")
        self._render_keys()
        self._refresh()

    def _cloud_service(self):
        """The chosen account's Public Cloud service (None when unavailable)."""
        try:
            return ovh_services(self.app, self._account).cloud
        except UnknownAccountError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return None

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _resolve_project_id(self) -> Optional[str]:
        config_manager = getattr(self.app, "config_manager", None)
        if config_manager is None:
            return None
        try:
            ovh_cfg = account_settings(self.app, "ovh", self._account)
        except Exception:
            return None
        if ovh_cfg is None:
            return None
        ids = list(getattr(ovh_cfg, "cloud_project_ids", []))
        return ids[0] if ids else None

    def _refresh(self) -> None:
        cloud_svc = self._cloud_service()
        if cloud_svc is None:
            self._set_status(
                "[$text-error]OVH Cloud service is not initialised. "
                "Configure OVHcloud in Settings first.[/$text-error]"
            )
            return
        project_id = self._resolve_project_id()
        if not project_id:
            self._set_status(
                "[$text-error]No OVH cloud project ID configured. Add one in "
                "Settings → OVHcloud → Cloud project IDs.[/$text-error]"
            )
            return
        self._project_id = project_id
        self._render_project_label()
        self._set_status("[dim]Loading keys…[/dim]")
        # A group of its own: a reload cancels an older load, never a key
        # being added or deleted.
        self.run_worker(
            self._load_keys(), group="ovh_ssh_load", exclusive=True,
            name="ovh_ssh_load",
        )

    async def _load_keys(self) -> None:
        cloud_svc = self._cloud_service()
        if cloud_svc is None:
            return
        # Only the latest load draws: a change reloads the list itself, and an
        # older load still running must not draw over it.
        self._loads += 1
        load = self._loads
        try:
            keys = list(await cloud_svc.list_ssh_keys(self._project_id))
        except Exception as exc:
            logger.error("Failed to load OVH project SSH keys: %s", exc)
            if load == self._loads:
                self._set_status(
                    f"[$text-error]Failed to load keys: {self._short_err(exc)}[/$text-error]"
                )
            return
        if load != self._loads:
            return
        self._keys = keys
        self._render_keys()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the project label and key rows for the new demo-mode state."""
        show_account_labels(self.query_one("#ovh_ssh_keys_account", AccountPicker))
        if self._project_id:
            self._render_project_label()
        self._render_keys()

    def _render_project_label(self) -> None:
        """Show the project id (a demo-mode fake when demo mode is on)."""
        self.query_one("#ovh_ssh_keys_project_label", Static).update(
            f"[dim]Project:[/dim] [b]{self._display_project_id()}[/b]"
        )

    def _render_keys(self) -> None:
        """Draw the fetched keys; labels, fingerprints and keys hidden in demo mode."""
        def _s(x: str) -> str:
            # Key labels are user-chosen (client names, an email address) --
            # shown as a pool key name in demo mode, like the instance list.
            if self.app.demo_mode:
                redactor = self.app.redaction_service
                return redactor.redact_key_name(x) if redactor else "Hidden"
            return x

        table = self.query_one("#ssh_keys_table", DataTable)
        table.clear()
        for key in self._keys:
            public_key = key.get("public_key", "") or ""
            truncated = (
                public_key[:24] + "…" if len(public_key) > 24 else public_key
            )
            table.add_row(
                Text(inert_text(_s(str(key.get("name", ""))))),
                Text(inert_text("Hidden" if self.app.demo_mode else str(key.get("fingerprint", "") or "")[:32])),
                Text(inert_text("Hidden" if self.app.demo_mode else truncated)),
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
        self._update_selected_context()

    # ------------------------------------------------------------------
    # Selection-driven button enablement
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event) -> None:
        self._sync_action_buttons()
        self._update_selected_context()

    def _update_selected_context(self) -> None:
        """Show the chosen key identity using the registry's demo rules."""
        try:
            context = self.query_one("#provider_key_selection", Static)
        except NoMatches:
            return
        key = self._selected_key()
        if key is None:
            context.update("Select a registered key to inspect its identity.")
            return
        name = str(key.get("name") or "—")
        identifier = str(key.get("id") or "—")
        if self.app.demo_mode:
            redactor = self.app.redaction_service
            name = redactor.redact_key_name(name) if redactor else "Hidden"
            identifier = "Hidden"
        context.update(literal(f"{name}\nID: {identifier}"))

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
        cloud_svc = self._cloud_service()
        if cloud_svc is None:
            return
        # The project of the account the key was added in, even if another
        # account is picked while the request runs.
        project_id = self._project_id
        try:
            await cloud_svc.add_ssh_key(project_id, name, public_key)
        except Exception as exc:
            logger.error("OVH project SSH key add failed for %s: %s",
                         name, exc)
            self._set_status(
                f"[$text-error]Add failed: {self._short_err(exc)}[/$text-error]"
            )
            self.notify(f"Add failed: {self._short_err(exc)}", severity="error",
                        markup=False)
            return
        self.notify(
            f"SSH key {name!r} registered with project "
            f"{self._display_project_id(project_id)}.",
            severity="information", markup=False,
        )
        await self._load_keys()

    async def _do_delete(self, key: dict) -> None:
        key_id = str(key.get("id") or "")
        key_name = str(key.get("name") or key_id)
        if not key_id:
            return
        if self.app.demo_mode:
            redactor = self.app.redaction_service
            key_name = redactor.redact_key_name(key_name) if redactor else "Hidden"
        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete SSH key",
                description=with_bold_values(
                    "Remove {} from project {}.", key_name, self._display_project_id(),
                ),
                consequences=[
                    "The key is removed from this OVH project's registry",
                    "Existing instances that already had this key in "
                    "authorized_keys are unaffected",
                    "New instances can no longer reference this key",
                ],
                confirm_text=key_name,
                action_label="Delete key",
                severity="warning",
            )
        )
        if not confirmed:
            return
        self._set_status(f"[dim]Deleting key {key_name}…[/dim]")
        cloud_svc = self._cloud_service()
        if cloud_svc is None:
            return
        project_id = self._project_id
        try:
            await cloud_svc.delete_ssh_key(project_id, key_id)
        except Exception as exc:
            logger.error(
                "OVH project SSH key delete failed for %s: %s",
                key_id, exc,
            )
            self._set_status(
                f"[$text-error]Delete failed: {self._short_err(exc)}[/$text-error]"
            )
            self.notify(f"Delete failed: {self._short_err(exc)}", severity="error",
                        markup=False)
            return
        self.notify(
            f"SSH key {key_name!r} deleted from project "
            f"{self._display_project_id(project_id)}.",
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

    def _display_project_id(self, project_id: Optional[str] = None) -> str:
        """*project_id* (default: the listed project) as the screen shows it."""
        project_id = self._project_id if project_id is None else project_id
        if not self.app.demo_mode:
            return project_id
        redactor = self.app.redaction_service
        return redactor.redact_name(project_id) if redactor else "Hidden"

    def _short_err(self, exc: Exception) -> str:
        if self.app.demo_mode:
            return "OVH request failed"
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"

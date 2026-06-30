"""Bitwarden item picker — browse-and-pick an SSH key from the vault.

Replaces "paste an item UUID" with a live, folder-scoped list of the user's
native SSH-key items. Entirely local: the listing comes from the ``bw`` CLI on
the user's machine (via :class:`BwSessionService`); Servonaut's servers never
see the vault.

Returns the chosen ``{"item_id": ..., "collection_id"?: ..., "vault_url"?: ...}``
dict (the same shape the editor stores) or ``None`` on cancel.

Gating: the paid entitlement is enforced here too (defense in depth) — a Free /
unentitled session sees the upgrade card, never the list.
"""

from __future__ import annotations

import logging
import webbrowser
from typing import List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Static

from servonaut.screens.bw_unlock_modal import BwUnlockModal
from servonaut.services.bw_errors import BwError
from servonaut.services.bw_session_service import (
    BwAuthState,
    BwItemSummary,
    BwSessionService,
)

logger = logging.getLogger(__name__)

_ENTITLEMENT_FEATURE = "secrets_management"
_PRICING_URL = "https://servonaut.dev/pricing"
_DOCS_URL = "https://servonaut.dev/docs/secrets-management"
_DEFAULT_FOLDER_NAME = "Servonaut"


class BwItemPickerModal(ModalScreen[Optional[dict]]):
    """Folder-scoped Bitwarden SSH-item picker.

    Dismisses the chosen ref dict, or ``None`` on cancel / unentitled / error.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("u", "open_pricing", "Pricing", show=False),
        Binding("o", "open_docs", "Docs", show=False),
    ]

    DEFAULT_CSS = ""  # styling lives in app.css

    def __init__(
        self,
        default_collection_id: Optional[str] = None,
        default_vault_url: Optional[str] = None,
        folder_name: Optional[str] = None,
        session_service: Optional[BwSessionService] = None,
    ) -> None:
        super().__init__()
        self._default_collection_id = default_collection_id or None
        self._default_vault_url = default_vault_url or None
        self._folder_name = folder_name
        self._svc = session_service
        # Resolved Servonaut folder id (None until ensured / when whole-vault).
        self._folder_id: Optional[str] = None
        # Whether the list is scoped to the Servonaut folder (toggle default on).
        self._folder_scoped: bool = True
        # item_id -> display name, populated on each render so a row selection
        # can carry the human-readable name back to the editor.
        self._name_by_id: dict = {}

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _service(self) -> Optional[BwSessionService]:
        return self._svc or getattr(self.app, "bw_session_service", None)

    def _resolved_folder_name(self) -> str:
        if self._folder_name:
            return self._folder_name
        config = getattr(self.app, "config", None)
        return getattr(config, "bw_vault_folder", None) or _DEFAULT_FOLDER_NAME

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold cyan]Pick SSH key from Bitwarden[/bold cyan]", id="bw_picker_title"),
            Vertical(
                Static("[dim]Loading…[/dim]"),
                id="bw_picker_body",
            ),
            id="bw_picker_container",
        )

    def on_mount(self) -> None:
        self.run_worker(self._load(), group="bw_picker", exclusive=True)

    def _body(self) -> Vertical:
        body = self.query_one("#bw_picker_body", Vertical)
        body.remove_children()
        return body

    # ------------------------------------------------------------------
    # load pipeline
    # ------------------------------------------------------------------

    async def _load(self) -> None:
        """Gate → ensure unlocked → ensure folder → list → render."""
        if not self._check_entitled():
            return

        svc = self._service()
        if svc is None:
            self._render_message("Bitwarden session service unavailable. Sign in and try again.")
            return

        # Lazy unlock — push the unlock modal if not already unlocked.
        try:
            state = await svc.status()
        except Exception as exc:  # noqa: BLE001
            logger.debug("bw status failed in picker: %s", exc)
            self._render_message(f"Could not query Bitwarden: {exc}")
            return

        if state is not BwAuthState.UNLOCKED:
            unlocked = await self._lazy_unlock()
            if not unlocked:
                self._render_message(
                    "Vault is locked. Unlock Bitwarden to browse your SSH keys."
                )
                return

        self._render_list_shell()
        await self._reload_items()

    def _check_entitled(self) -> bool:
        """Render the upgrade card and return False when not entitled."""
        guard = getattr(self.app, "entitlement_guard", None)
        if guard is None:
            # No guard wired (not signed in) — treat as unentitled.
            self._render_upgrade_card("Sign in to Servonaut to use the Bitwarden SSH key picker.")
            return False
        allowed, reason = guard.check(_ENTITLEMENT_FEATURE)
        if not allowed:
            self._render_upgrade_card(reason)
            return False
        return True

    async def _lazy_unlock(self) -> bool:
        """Push the unlock modal and return whether the vault ended up unlocked."""
        result = await self.app.push_screen_wait(BwUnlockModal(self._service()))
        return bool(result)

    async def _reload_items(self) -> None:
        """(Re)list items for the current search + folder scope."""
        svc = self._service()
        if svc is None:
            return
        try:
            search = self.query_one("#bw_picker_search", Input).value.strip() or None
        except Exception:  # noqa: BLE001
            search = None

        try:
            folder_id = None
            if self._folder_scoped:
                folder_id = await svc.ensure_servonaut_folder(self._resolved_folder_name())
                self._folder_id = folder_id
            items = await svc.list_items(folder_id=folder_id, search=search, ssh_only=True)
        except BwError as exc:
            self.app.notify(exc.message, severity="error", markup=False)
            self._render_table([])
            return
        except Exception as exc:  # noqa: BLE001
            self.app.notify(f"Could not list vault items: {exc}", severity="error", markup=False)
            self._render_table([])
            return

        self._render_table(items)

    # ------------------------------------------------------------------
    # renderers
    # ------------------------------------------------------------------

    def _render_message(self, text: str) -> None:
        self._body().mount(
            Static(escape(text)),
            Horizontal(Button("Close", variant="default", id="bw_picker_close")),
        )

    def _render_upgrade_card(self, reason: str) -> None:
        self._body().mount(
            Static("[bold yellow]Upgrade required[/bold yellow]"),
            Static(
                "The Bitwarden SSH key picker is available on the Solo and Teams plans."
            ),
            Static(f"[dim]{escape(reason)}[/dim]"),
            Static("[dim][u] Pricing   ·   [o] Docs[/dim]"),
            Horizontal(Button("Close", variant="default", id="bw_picker_close")),
        )

    def _render_list_shell(self) -> None:
        """Mount the search box, folder toggle, table, and action row once."""
        body = self._body()
        table = DataTable(id="bw_picker_table", cursor_type="row", zebra_stripes=True)
        table.add_columns("Name", "Type", "Username")
        body.mount(
            Input(placeholder="Search vault items…", id="bw_picker_search"),
            Checkbox(
                f"{escape(self._resolved_folder_name())} folder only",
                value=True,
                id="bw_picker_folder_toggle",
            ),
            table,
            Horizontal(
                Button("Cancel", variant="default", id="bw_picker_cancel"),
                classes="bw_picker_actions",
            ),
        )

    def _render_table(self, items: List[BwItemSummary]) -> None:
        try:
            table = self.query_one("#bw_picker_table", DataTable)
        except Exception:  # noqa: BLE001
            return
        table.clear()
        self._name_by_id = {}
        if not items:
            table.add_row("[dim]No SSH-key items found[/dim]", "", "", key="__empty__")
            return
        # Demo-mode: vault item names / usernames can reveal real server identity,
        # so scrub them before they reach the rendered row (and the name we carry
        # back to the editor) — mirrors the aws_manager redact-before-render rule.
        demo = getattr(self.app, "demo_mode", False)
        redactor = getattr(self.app, "redaction_service", None) if demo else None
        for item in items:
            name = item.name or ""
            username = item.username or ""
            if redactor is not None:
                name = redactor.scrub_stream(name) if name else name
                username = redactor.scrub_stream(username) if username else username
            self._name_by_id[item.id] = name
            table.add_row(
                escape(name) or "[dim](unnamed)[/dim]",
                "SSH",
                escape(username) if username else "—",
                key=item.id,
            )

    # ------------------------------------------------------------------
    # events / actions
    # ------------------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "bw_picker_search":
            self.run_worker(self._reload_items(), group="bw_picker", exclusive=True)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "bw_picker_folder_toggle":
            self._folder_scoped = bool(event.value)
            self.run_worker(self._reload_items(), group="bw_picker", exclusive=True)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        key = event.row_key.value if event.row_key is not None else None
        if not key or key == "__empty__":
            return
        result: dict = {"item_id": key}
        name = self._name_by_id.get(key)
        if name:
            # Display-only — the editor uses this to show the name, not the UUID.
            # The save path persists only item_id/collection_id/vault_url.
            result["item_name"] = name
        if self._default_collection_id:
            result["collection_id"] = self._default_collection_id
        if self._default_vault_url:
            result["vault_url"] = self._default_vault_url
        self.dismiss(result)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id in {"bw_picker_cancel", "bw_picker_close"}:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_open_pricing(self) -> None:
        try:
            webbrowser.open(_PRICING_URL)
        except Exception:  # noqa: BLE001
            self.app.notify(f"Open {_PRICING_URL}", markup=False)

    def action_open_docs(self) -> None:
        try:
            webbrowser.open(_DOCS_URL)
        except Exception:  # noqa: BLE001
            self.app.notify(f"Open {_DOCS_URL}", markup=False)

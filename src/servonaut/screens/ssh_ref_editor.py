"""Per-instance Bitwarden SSH ref manager modal."""

from __future__ import annotations

import logging
from typing import Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Collapsible, Input, Label, Static

from servonaut.screens.bw_item_picker import BwItemPickerModal
from servonaut.services.bw_ssh_config_service import BITWARDEN_PM_PROVIDER
from servonaut.utils.validation import validate_instance_id, ValidationError

logger = logging.getLogger(__name__)

_HELP_TEXT = (
    "Browse your Bitwarden vault and pick the SSH key for this server. "
    "The item must be a native SSH item (BW 2023.10+). The picker is local — "
    "Servonaut's servers never see your vault."
)


class SshRefEditorModal(ModalScreen[bool]):
    """Per-instance BW SSH ref manager.

    Returns True if a ref was saved or deleted (so the caller can refresh
    the instance table). Returns False if the user cancelled.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = ""  # all styling lives in the styles/ bundle

    def __init__(
        self,
        instance: dict,
        existing_ref: Optional[dict] = None,
    ) -> None:
        """
        Args:
            instance: Servonaut instance dict (must have 'id', 'provider',
                'name'). Used to render context + scope the PUT call.
            existing_ref: If set, the modal is in EDIT mode (Delete + Save
                buttons enabled, fields pre-populated from
                existing_ref['ssh_credential_ref']). If None, ADD mode
                (only Save + Cancel, no Delete).
        """
        super().__init__()
        self._instance = instance
        self._existing_ref = existing_ref
        self._edit_mode = existing_ref is not None
        # Display name of the currently selected item (set by the picker, or the
        # stored UUID when editing a pre-existing ref whose name we don't have).
        self._selected_item_name: str = ""
        # Defaults sourced from the saved personal ssh-config (loaded in on_mount).
        self._default_collection_id: str = ""
        self._default_vault_url: str = ""

    def _selected_text(self) -> str:
        """Markup for the read-only "Selected:" line."""
        if self._selected_item_name:
            return f"[bold]Selected:[/bold] {escape(self._selected_item_name)}"
        return "[dim]No SSH key selected — pick one from your vault (or use Advanced).[/dim]"

    def compose(self) -> ComposeResult:
        """Compose the SSH ref editor modal."""
        ref = (
            self._existing_ref.get("ssh_credential_ref", {})
            if self._existing_ref
            else {}
        )
        safe_name = escape(self._instance.get("name") or self._instance.get("id", ""))

        mode_label = "Edit" if self._edit_mode else "Add"
        title = f"[bold]{mode_label} BW SSH Ref — {safe_name}[/bold]"

        existing_item_id = ref.get("item_id", "") if isinstance(ref, dict) else ""
        existing_collection_id = ref.get("collection_id", "") if isinstance(ref, dict) else ""
        existing_vault_url = ref.get("vault_url", "") if isinstance(ref, dict) else ""

        # Pre-existing ref: we only persisted the UUID, so show it on the
        # Selected line until/unless the user re-picks from the vault.
        if existing_item_id:
            self._selected_item_name = existing_item_id

        buttons: list = [
            Button("Cancel", variant="default", id="cancel_btn"),
        ]
        if self._edit_mode:
            buttons.append(Button("Delete", variant="error", id="delete_btn"))
        buttons.append(Button("Save", variant="primary", id="save_btn"))

        yield Container(
            Static(title, id="ssh_ref_editor_title"),
            Static(_HELP_TEXT, id="ssh_ref_editor_help"),
            Vertical(
                Static(self._selected_text(), id="ssh_ref_selected"),
                Horizontal(
                    Button("Pick from vault…", variant="primary", id="pick_btn"),
                    classes="ssh_ref_pick_row",
                ),
                Collapsible(
                    Label("Item ID"),
                    Input(
                        value=existing_item_id,
                        id="item_id",
                        placeholder="Bitwarden item UUID",
                    ),
                    Label("Collection ID (optional)"),
                    Input(
                        value=existing_collection_id,
                        id="collection_id",
                        placeholder="(optional) collection UUID",
                    ),
                    Label("Vault URL (optional)"),
                    Input(
                        value=existing_vault_url,
                        id="vault_url",
                        placeholder="(optional) https://vault.bitwarden.com",
                    ),
                    title="Advanced — paste UUID / collection / vault",
                    collapsed=True,
                    id="ssh_ref_advanced",
                ),
                id="ssh_ref_fields",
            ),
            Horizontal(*buttons, classes="ssh_ref_actions_row"),
            id="ssh_ref_editor_container",
        )

    def on_mount(self) -> None:
        """Load saved ssh-config defaults so the user never re-enters them."""
        self.run_worker(self._load_defaults(), group="ssh_ref_io", exclusive=False)

    async def _load_defaults(self) -> None:
        """Pre-fill empty collection/vault fields from the personal ssh-config."""
        svc = getattr(self.app, "bw_ssh_config_service", None)
        if svc is None:
            return
        try:
            cfg = await svc.get_personal_config()
        except Exception as exc:  # noqa: BLE001 — defaults are best-effort
            logger.debug("ssh-config default load failed: %s", exc)
            return
        if not cfg:
            return
        inner = cfg.get("config") or {}
        self._default_vault_url = inner.get("vault_url", "") or ""
        self._default_collection_id = inner.get("default_collection_id", "") or ""
        try:
            vault_input = self.query_one("#vault_url", Input)
            if not vault_input.value and self._default_vault_url:
                vault_input.value = self._default_vault_url
            coll_input = self.query_one("#collection_id", Input)
            if not coll_input.value and self._default_collection_id:
                coll_input.value = self._default_collection_id
        except Exception:  # noqa: BLE001
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route button presses."""
        btn_id = event.button.id
        if btn_id == "cancel_btn":
            self.dismiss(False)
        elif btn_id == "pick_btn":
            self.run_worker(self._do_pick(), group="ssh_ref_io", exclusive=True)
        elif btn_id == "save_btn":
            self.run_worker(self._do_save(), group="ssh_ref_io", exclusive=True)
        elif btn_id == "delete_btn":
            self.run_worker(self._do_delete(), group="ssh_ref_io", exclusive=True)

    def action_cancel(self) -> None:
        """Escape binding — dismiss False."""
        self.dismiss(False)

    async def _do_pick(self) -> None:
        """Launch the vault picker and apply the chosen item to the form."""
        current_collection = self.query_one("#collection_id", Input).value.strip()
        current_vault = self.query_one("#vault_url", Input).value.strip()
        result = await self.app.push_screen_wait(
            BwItemPickerModal(
                default_collection_id=current_collection or self._default_collection_id or None,
                default_vault_url=current_vault or self._default_vault_url or None,
            )
        )
        if not result:
            return
        item_id = result.get("item_id")
        if not item_id:
            return
        # The Advanced item_id Input is the canonical store the save path reads.
        self.query_one("#item_id", Input).value = item_id
        display_name = result.get("item_name") or item_id
        # Demo-mode: the picker already scrubs item_name, but guard here too so
        # the Selected line never renders an un-redacted vault name.
        if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None):
            display_name = self.app.redaction_service.scrub_stream(display_name)
        self._selected_item_name = display_name
        self.query_one("#ssh_ref_selected", Static).update(self._selected_text())
        if result.get("collection_id"):
            self.query_one("#collection_id", Input).value = result["collection_id"]
        if result.get("vault_url"):
            self.query_one("#vault_url", Input).value = result["vault_url"]

    async def _do_save(self) -> None:
        """Validate inputs and call PUT API."""
        from servonaut.services.api_client import APIError

        item_id_input = self.query_one("#item_id", Input)
        collection_id_input = self.query_one("#collection_id", Input)
        vault_url_input = self.query_one("#vault_url", Input)

        item_id_value = item_id_input.value.strip()
        collection_id_value = collection_id_input.value.strip()
        vault_url_value = vault_url_input.value.strip()

        # Validate item_id is non-empty and UUID-ish (reuse instance_id regex:
        # [A-Za-z0-9_\-]{1,64} — covers hyphenated UUID format).
        if not item_id_value:
            self.app.notify(
                "Pick an SSH key from your vault first (or paste an Item ID under Advanced).",
                severity="error",
                markup=False,
            )
            return

        try:
            validate_instance_id(item_id_value.replace("-", "X"))  # dashes are UUID-legal
        except ValidationError:
            self.app.notify(
                "Item ID looks invalid — expected a Bitwarden UUID (alphanumeric + hyphens).",
                severity="error",
                markup=False,
            )
            return

        bw_service = getattr(self.app, "bw_ssh_config_service", None)
        if bw_service is None:
            self.app.notify(
                "BW SSH service not available (sign in required).",
                severity="warning",
                markup=False,
            )
            return

        provider = self._instance.get("provider", "aws").lower()
        instance_id = self._instance.get("id", "")

        ssh_credential_ref: dict = {"item_id": item_id_value}
        if collection_id_value:
            ssh_credential_ref["collection_id"] = collection_id_value
        if vault_url_value:
            ssh_credential_ref["vault_url"] = vault_url_value

        try:
            await bw_service.put_personal_instance_ref(
                provider=provider,
                instance_id=instance_id,
                ssh_credential_ref=ssh_credential_ref,
                ssh_credential_provider=BITWARDEN_PM_PROVIDER,
            )
        except APIError as exc:
            if exc.status == 402:
                self.app.notify(
                    "Personal SSH refs require a paid plan. Upgrade at /pricing.",
                    severity="warning",
                    markup=False,
                )
            elif exc.status == 422:
                self.app.notify(exc.message, severity="error", markup=False)
            else:
                self.app.notify(
                    f"Failed to save SSH ref: {exc.message}",
                    severity="error",
                    markup=False,
                )
            return
        except Exception as exc:
            self.app.notify(
                f"Failed to save SSH ref: {exc}",
                severity="error",
                markup=False,
            )
            return

        self.dismiss(True)

    async def _do_delete(self) -> None:
        """Call DELETE API and dismiss."""
        from servonaut.services.api_client import APIError

        bw_service = getattr(self.app, "bw_ssh_config_service", None)
        if bw_service is None:
            self.app.notify(
                "BW SSH service not available (sign in required).",
                severity="warning",
                markup=False,
            )
            return

        provider = self._instance.get("provider", "aws").lower()
        instance_id = self._instance.get("id", "")

        try:
            await bw_service.delete_personal_instance_ref(
                provider=provider,
                instance_id=instance_id,
            )
        except APIError as exc:
            self.app.notify(
                f"Failed to delete SSH ref: {exc.message}",
                severity="error",
                markup=False,
            )
            return
        except Exception as exc:
            self.app.notify(
                f"Failed to delete SSH ref: {exc}",
                severity="error",
                markup=False,
            )
            return

        self.dismiss(True)

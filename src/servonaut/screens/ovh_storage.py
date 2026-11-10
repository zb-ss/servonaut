"""OVH block storage management screen for Servonaut.

With several OVH accounts configured, a picker chooses the account whose
Public Cloud projects are listed and changed.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, DataTable, Footer, Input, Label, Static

from servonaut.screens._busy_work import BusyWork
from servonaut.utils.markup import with_bold_values
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._provider_accounts import (
    UnknownAccountError,
    account_settings,
    ovh_services,
    registry_for,
    show_account_labels,
    with_account,
)
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

logger = logging.getLogger(__name__)


class OVHStorageScreen(WorkspaceScreen):
    """Manage OVH Public Cloud block storage volumes."""

    DEFAULT_CSS = """
    OVHStorageScreen .add_row {
        height: auto;
    }
    OVHStorageScreen .workspace-content > BusyIndicator.read-loading {
        dock: top;
        height: 1;
    }
    """

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 64
    CONTENT_NARROW_WIDTH = 112

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    # Label of the chosen account; "" is the default account.
    _account: str = ""
    # Counts volume list loads; see _load_volumes.
    _loads: int = 0

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def __init__(
        self, name: str | None = None, id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._read_loading = BusyWork(self, "#read_loading")

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Block storage")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            inventory_panel = Vertical(
                Static("Volumes", classes="resource-section-title"),
                DataTable(id="volumes_table"),
                classes="resource-panel provider-aux-inventory",
            )
            actions = Vertical(
                Horizontal(
                    Static("Volumes", classes="resource-action-label"),
                    Horizontal(
                        Button("Create volume", id="btn_create", variant="primary"),
                        Button("Attach", id="btn_attach", variant="default"),
                        Button("Detach", id="btn_detach", variant="default"),
                        Button("Delete", id="btn_delete", variant="error"),
                        classes="resource-action-buttons",
                    ),
                    classes="resource-action-group",
                ),
                Horizontal(
                    Static("Tools", classes="resource-action-label"),
                    Horizontal(
                        Button("Snapshot", id="btn_snapshot", variant="default"),
                        Button("Refresh", id="btn_refresh", variant="default"),
                        Button("Back", id="btn_back", variant="default"),
                        classes="resource-action-buttons",
                    ),
                    classes="resource-action-group",
                ),
                id="storage_actions",
                classes="resource-grouped-actions",
            )
            operations = Vertical(
                Static("Selected resource", classes="provider-aux-section-heading"),
                Static(
                    "Select a volume to review its ID and attachments.", id="storage_selected_resource",
                    classes="provider-aux-selection", markup=False,
                ),
                actions,
                Container(
                    Static("[bold]Create volume[/bold]", classes="section_header"),
                    Label("Name:"),
                    Input(placeholder="my-volume", id="input_vol_name"),
                    Label("Size (GB):"),
                    Input(placeholder="50", id="input_vol_size"),
                    Label("Region:"),
                    Input(placeholder="GRA11", id="input_vol_region"),
                    Label("Type:"),
                    Input(placeholder="classic", id="input_vol_type"),
                    Horizontal(
                        Button("Save volume", id="btn_save_vol", variant="primary"),
                        Button("Cancel", id="btn_cancel_form", variant="default"),
                        classes="add_row",
                    ),
                    id="create_vol_form",
                ),
                Container(
                    Static("[bold]Attach volume[/bold]", classes="section_header"),
                    Label("Instance ID:"),
                    Input(placeholder="instance-uuid", id="input_attach_instance_id"),
                    Horizontal(
                        Button("Attach", id="btn_confirm_attach", variant="primary"),
                        Button("Cancel", id="btn_cancel_attach", variant="default"),
                        classes="add_row",
                    ),
                    id="attach_vol_form",
                ),
                Container(
                    Static("[bold]Create snapshot[/bold]", classes="section_header"),
                    Label("Snapshot name:"),
                    Input(placeholder="snapshot-name", id="input_snapshot_name"),
                    Horizontal(
                        Button("Create snapshot", id="btn_confirm_snapshot", variant="primary"),
                        Button("Cancel", id="btn_cancel_snapshot", variant="default"),
                        classes="add_row",
                    ),
                    id="snapshot_form",
                ),
                classes="provider-aux-operations",
            )
            operations.border_title = "Volume operations"
            yield ScrollableContainer(
                BusyIndicator(id="read_loading", classes="read-loading"),
                Horizontal(
                    Vertical(
                        Static(
                            "OVH block storage",
                            id="storage_title",
                            classes="screen-title",
                        ),
                        Static(
                            "Public Cloud volumes: select a volume to attach, detach "
                            "or snapshot it.",
                            classes="resource-context",
                        ),
                        classes="provider-aux-heading",
                    ),
                    AccountPicker.for_provider(
                        registry_for(self.app, "ovh"), "ovh", id="storage_account",
                    ),
                    classes="provider-aux-heading-row",
                ),
                Horizontal(
                    inventory_panel, operations, classes="provider-aux-body",
                ),
                id="storage_container",
                classes="workspace-content resource-workspace-content provider-aux-workspace",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._setup_table()
        self._hide_all_forms()
        picker = self.query_one("#storage_account", AccountPicker)
        self._account = picker.account
        show_account_labels(picker)
        self._start_load()

    def on_account_picker_changed(self, event: AccountPicker.Changed) -> None:
        """Another account was picked: list its volumes instead."""
        self._account = event.account
        self._volumes = []
        self.query_one("#volumes_table", DataTable).clear()
        self.action_refresh()

    def _setup_table(self) -> None:
        table = self.query_one("#volumes_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "Size (GB)", "Region", "Status", "Attached To")

    def _hide_all_forms(self) -> None:
        self.query_one("#create_vol_form").display = False
        self.query_one("#attach_vol_form").display = False
        self.query_one("#snapshot_form").display = False

    def _show_create_form(self) -> None:
        self._hide_all_forms()
        form = self.query_one("#create_vol_form")
        self.query_one("#input_vol_name", Input).value = ""
        self.query_one("#input_vol_size", Input).value = ""
        self.query_one("#input_vol_region", Input).value = ""
        self.query_one("#input_vol_type", Input).value = "classic"
        form.display = True
        self.query_one("#input_vol_name", Input).focus()

    def _show_attach_form(self) -> None:
        self._hide_all_forms()
        form = self.query_one("#attach_vol_form")
        self.query_one("#input_attach_instance_id", Input).value = ""
        form.display = True
        self.query_one("#input_attach_instance_id", Input).focus()

    def _show_snapshot_form(self) -> None:
        self._hide_all_forms()
        form = self.query_one("#snapshot_form")
        self.query_one("#input_snapshot_name", Input).value = ""
        form.display = True
        self.query_one("#input_snapshot_name", Input).focus()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _get_storage_service(self):
        """The chosen account's storage service (None when unavailable)."""
        try:
            return ovh_services(self.app, self._account).storage
        except UnknownAccountError as exc:
            self.app.notify(str(exc), severity="error", markup=False)
            return None

    def _display_name(self, value: str) -> str:
        if not self.app.demo_mode:
            return value
        redactor = self.app.redaction_service
        return redactor.redact_name(value) if redactor else "Hidden"

    def _display_instance_id(self, value: str) -> str:
        if not self.app.demo_mode:
            return value
        redactor = self.app.redaction_service
        return redactor.redact_instance_id(value) if redactor else "Hidden"

    def _provider_error(self, error: Exception) -> str:
        return "Provider request failed. See logs for details." if self.app.demo_mode else str(error)

    @staticmethod
    def _attachment_instance_ids(volume: dict) -> List[str]:
        """Read OVH instance IDs, retaining compatibility with cached older rows."""
        if "attachedTo" in volume:
            return [identifier for identifier in volume["attachedTo"] or [] if identifier]
        return [attachment.get("serverId") or attachment.get("id")
                for attachment in volume.get("attachments") or []
                if attachment.get("serverId") or attachment.get("id")]

    def _get_project_ids(self) -> List[str]:
        # ConfigManager exposes the loaded config via ``.get()``, NOT
        # ``.config`` — the latter never existed, so the previous
        # implementation silently returned [] for every user and
        # tripped the "No cloud_project_ids configured" warning even
        # when projects WERE configured (#1391).
        config_manager = getattr(self.app, "config_manager", None)
        if config_manager is None:
            return []
        try:
            ovh_cfg = account_settings(self.app, "ovh", self._account)
        except Exception:
            return []
        if ovh_cfg is None:
            return []
        return list(getattr(ovh_cfg, "cloud_project_ids", []))

    def _update_selected_resource(self) -> None:
        """Keep the complete volume identity next to its operations."""
        try:
            selected = self.query_one("#storage_selected_resource", Static)
        except NoMatches:
            return
        volume = self._get_selected_volume()
        if volume is None:
            selected.update("Select a volume to review its ID and attachments.")
            return
        name = str(volume.get("name") or volume.get("id") or "—")
        identifier = str(volume.get("id") or "—")
        content = Text(self._display_name(name), style="bold")
        content.append(f"\n{self._display_name(identifier)}", style="")
        attachments = self._attachment_instance_ids(volume)
        attached_to = ", ".join(self._display_instance_id(item) for item in attachments)
        content.append(f"\nAttached to: {attached_to or '—'}", style="")
        selected.update(content)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "volumes_table":
            self._update_selected_resource()

    def _get_selected_volume(self) -> Optional[dict]:
        """Return the _volumes list entry for the currently selected row."""
        table = self.query_one("#volumes_table", DataTable)
        row = table.cursor_row
        if table.row_count == 0 or row < 0 or row >= len(self._volumes):
            return None
        return self._volumes[row]

    async def _load_volumes(self) -> None:
        svc = self._get_storage_service()
        if svc is None:
            self.app.notify("OVHStorageService not initialised", severity="error")
            return

        project_ids = self._get_project_ids()
        if not project_ids:
            self.app.notify(
                "No cloud_project_ids configured for OVH", severity="warning"
            )
            return

        # Only the latest load draws: a change reloads the list itself, and an
        # older load still running must not draw over it.
        self._loads += 1
        load = self._loads
        all_volumes: List[dict] = []
        with self._read_loading.running('Loading volumes…'):
            for pid in project_ids:
                try:
                    vols = await svc.list_volumes(pid)
                    for v in vols:
                        v["_project_id"] = pid
                    all_volumes.extend(vols)
                except Exception as exc:
                    logger.error("list_volumes failed for project %s: %s", pid, exc)
                    self.app.notify(f"Failed to load volumes: {self._provider_error(exc)}", severity="error", markup=False)

            if load != self._loads:
                return
            self._volumes: List[dict] = all_volumes

            table = self.query_one("#volumes_table", DataTable)
            table.clear()

            for vol in all_volumes:
                name = vol.get("name") or vol.get("id", "—")
                size = str(vol.get("size", "—"))
                region = vol.get("region") or "—"
                status = vol.get("status") or "—"
                attachments = self._attachment_instance_ids(vol)
                if attachments:
                    attached_to = ", ".join(
                        self._display_instance_id(identifier) for identifier in attachments
                    )
                else:
                    attached_to = "—"
                table.add_row(self._display_name(name), size, region, status, attached_to)
            self._update_selected_resource()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""

        if button_id == "btn_back":
            self.action_back()
        elif button_id == "btn_refresh":
            self.action_refresh()
        elif button_id == "btn_create":
            self._show_create_form()
        elif button_id == "btn_attach":
            self._action_attach()
        elif button_id == "btn_detach":
            self._action_detach()
        elif button_id == "btn_delete":
            self._action_delete()
        elif button_id == "btn_snapshot":
            self._action_snapshot()
        # Form confirmations
        elif button_id == "btn_save_vol":
            self._save_volume()
        elif button_id == "btn_cancel_form":
            self._hide_all_forms()
        elif button_id == "btn_confirm_attach":
            self._submit_attach()
        elif button_id == "btn_cancel_attach":
            self._hide_all_forms()
        elif button_id == "btn_confirm_snapshot":
            self._submit_snapshot()
        elif button_id == "btn_cancel_snapshot":
            self._hide_all_forms()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._hide_all_forms()
        self._start_load()

    def _start_load(self) -> None:
        """Load the volumes in a group of their own.

        A reload cancels an older load, never a volume change that is
        still running.
        """
        self.run_worker(self._load_volumes(), group="ovh_storage_load", exclusive=True)

    # ------------------------------------------------------------------
    # Create volume
    # ------------------------------------------------------------------

    def _save_volume(self) -> None:
        name = self.query_one("#input_vol_name", Input).value.strip()
        size_str = self.query_one("#input_vol_size", Input).value.strip()
        region = self.query_one("#input_vol_region", Input).value.strip()
        vol_type = self.query_one("#input_vol_type", Input).value.strip() or "classic"

        if not name:
            self.app.notify("Name is required", severity="error")
            self.query_one("#input_vol_name", Input).focus()
            return
        if not size_str.isdigit() or int(size_str) <= 0:
            self.app.notify("Size must be a positive integer", severity="error")
            self.query_one("#input_vol_size", Input).focus()
            return
        if not region:
            self.app.notify("Region is required", severity="error")
            self.query_one("#input_vol_region", Input).focus()
            return

        project_ids = self._get_project_ids()
        if not project_ids:
            self.app.notify("No cloud_project_ids configured", severity="error")
            return

        self._hide_all_forms()
        self.run_worker(
            self._create_volume(project_ids[0], name, int(size_str), region, vol_type),
            exclusive=False,
        )

    async def _create_volume(
        self, project_id: str, name: str, size_gb: int, region: str, volume_type: str
    ) -> None:
        svc = self._get_storage_service()
        if svc is None:
            self.app.notify("OVHStorageService not initialised", severity="error")
            return
        try:
            await svc.create_volume(project_id, name, size_gb, region, volume_type)
            self.app.notify(f"Volume '{self._display_name(name)}' created", severity="information")
            await self._load_volumes()
        except Exception as exc:
            logger.error("create_volume failed: %s", exc)
            self.app.notify(f"Failed to create volume: {self._provider_error(exc)}", severity="error", markup=False)

    # ------------------------------------------------------------------
    # Delete volume
    # ------------------------------------------------------------------

    def _action_delete(self) -> None:
        vol = self._get_selected_volume()
        if vol is None:
            self.app.notify("No volume selected", severity="warning")
            return

        volume_name = vol.get("name") or vol.get("id", "unknown")
        project_id = vol.get("_project_id", "")
        volume_id = vol.get("id", "")

        async def _confirm_and_delete() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Delete volume",
                    description=with_bold_values("Permanently delete volume {}.", self._display_name(volume_name)),
                    consequences=[
                        "All data on this volume will be permanently lost",
                        "Any remaining snapshots may also be affected",
                    ],
                    confirm_text=self._display_name(volume_name),
                    action_label="Delete volume",
                    severity="danger",
                )
            )
            if confirmed:
                audit = getattr(self.app, "ovh_audit", None)
                if audit:
                    audit.log_action(
                        "volume_delete",
                        volume_id,
                        with_account(self.app, "ovh", self._account, {
                            "name": volume_name, "project_id": project_id,
                        }),
                        confirmed=True,
                    )
                await self._delete_volume(project_id, volume_id, volume_name)

        self.run_worker(_confirm_and_delete(), exclusive=False)

    async def _delete_volume(
        self, project_id: str, volume_id: str, volume_name: str
    ) -> None:
        svc = self._get_storage_service()
        if svc is None:
            self.app.notify("OVHStorageService not initialised", severity="error")
            return
        try:
            await svc.delete_volume(project_id, volume_id)
            self.app.notify(f"Volume '{self._display_name(volume_name)}' deleted", severity="information")
            await self._load_volumes()
        except Exception as exc:
            logger.error("delete_volume failed for %s: %s", volume_id, exc)
            self.app.notify(f"Failed to delete volume: {self._provider_error(exc)}", severity="error", markup=False)

    # ------------------------------------------------------------------
    # Attach volume
    # ------------------------------------------------------------------

    def _action_attach(self) -> None:
        vol = self._get_selected_volume()
        if vol is None:
            self.app.notify("No volume selected", severity="warning")
            return
        self._show_attach_form()

    def _submit_attach(self) -> None:
        vol = self._get_selected_volume()
        if vol is None:
            self.app.notify("No volume selected", severity="warning")
            self._hide_all_forms()
            return

        instance_id = self.query_one("#input_attach_instance_id", Input).value.strip()
        if self.app.demo_mode and self.app.redaction_service:
            instance_id = self.app.redaction_service.real_instance_id(instance_id)
        if not instance_id:
            self.app.notify("Instance ID is required", severity="error")
            self.query_one("#input_attach_instance_id", Input).focus()
            return

        project_id = vol.get("_project_id", "")
        volume_id = vol.get("id", "")
        volume_name = vol.get("name") or volume_id

        async def _confirm_and_attach() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Attach volume",
                    description=with_bold_values(
                        "Attach volume {} to instance {}.",
                        self._display_name(volume_name), self._display_instance_id(instance_id),
                    ),
                    consequences=["The volume will be available as a block device on the instance"],
                    confirm_text=self._display_name(volume_name),
                    action_label="Attach",
                    severity="warning",
                )
            )
            if confirmed:
                audit = getattr(self.app, "ovh_audit", None)
                if audit:
                    audit.log_action(
                        "volume_attach",
                        volume_id,
                        with_account(self.app, "ovh", self._account, {
                            "name": volume_name,
                            "project_id": project_id,
                            "instance_id": instance_id,
                        }),
                        confirmed=True,
                    )
                await self._attach_volume(project_id, volume_id, instance_id, volume_name)

        self._hide_all_forms()
        self.run_worker(_confirm_and_attach(), exclusive=False)

    async def _attach_volume(
        self, project_id: str, volume_id: str, instance_id: str, volume_name: str
    ) -> None:
        svc = self._get_storage_service()
        if svc is None:
            self.app.notify("OVHStorageService not initialised", severity="error")
            return
        try:
            await svc.attach_volume(project_id, volume_id, instance_id)
            self.app.notify(f"Volume '{self._display_name(volume_name)}' attached", severity="information")
            await self._load_volumes()
        except Exception as exc:
            logger.error("attach_volume failed for %s: %s", volume_id, exc)
            self.app.notify(f"Failed to attach volume: {self._provider_error(exc)}", severity="error", markup=False)

    # ------------------------------------------------------------------
    # Detach volume
    # ------------------------------------------------------------------

    def _action_detach(self) -> None:
        vol = self._get_selected_volume()
        if vol is None:
            self.app.notify("No volume selected", severity="warning")
            return

        attachments = self._attachment_instance_ids(vol)
        if not attachments:
            self.app.notify("Volume is not attached to any instance", severity="warning")
            return

        project_id = vol.get("_project_id", "")
        volume_id = vol.get("id", "")
        volume_name = vol.get("name") or volume_id
        instance_id = attachments[0]

        async def _confirm_and_detach() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Detach volume",
                    description=with_bold_values(
                        "Detach volume {} from instance {}.",
                        self._display_name(volume_name), self._display_instance_id(instance_id),
                    ),
                    consequences=[
                        "The volume will no longer be accessible from the instance",
                        "Data is preserved — you can re-attach later",
                    ],
                    confirm_text=self._display_name(volume_name),
                    action_label="Detach",
                    severity="warning",
                )
            )
            if confirmed:
                audit = getattr(self.app, "ovh_audit", None)
                if audit:
                    audit.log_action(
                        "volume_detach",
                        volume_id,
                        with_account(self.app, "ovh", self._account, {
                            "name": volume_name,
                            "project_id": project_id,
                            "instance_id": instance_id,
                        }),
                        confirmed=True,
                    )
                await self._detach_volume(project_id, volume_id, instance_id, volume_name)

        self.run_worker(_confirm_and_detach(), exclusive=False)

    async def _detach_volume(
        self,
        project_id: str,
        volume_id: str,
        instance_id: str,
        volume_name: str,
    ) -> None:
        svc = self._get_storage_service()
        if svc is None:
            self.app.notify("OVHStorageService not initialised", severity="error")
            return
        try:
            await svc.detach_volume(project_id, volume_id, instance_id)
            self.app.notify(f"Volume '{self._display_name(volume_name)}' detached", severity="information")
            await self._load_volumes()
        except Exception as exc:
            logger.error("detach_volume failed for %s: %s", volume_id, exc)
            self.app.notify(f"Failed to detach volume: {self._provider_error(exc)}", severity="error", markup=False)

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def _action_snapshot(self) -> None:
        vol = self._get_selected_volume()
        if vol is None:
            self.app.notify("No volume selected", severity="warning")
            return
        self._show_snapshot_form()

    def _submit_snapshot(self) -> None:
        vol = self._get_selected_volume()
        if vol is None:
            self.app.notify("No volume selected", severity="warning")
            self._hide_all_forms()
            return

        snap_name = self.query_one("#input_snapshot_name", Input).value.strip()
        if not snap_name:
            self.app.notify("Snapshot name is required", severity="error")
            self.query_one("#input_snapshot_name", Input).focus()
            return

        project_id = vol.get("_project_id", "")
        volume_id = vol.get("id", "")
        volume_name = vol.get("name") or volume_id

        self._hide_all_forms()
        self.run_worker(
            self._create_snapshot(project_id, volume_id, snap_name, volume_name),
            exclusive=False,
        )

    async def _create_snapshot(
        self,
        project_id: str,
        volume_id: str,
        snap_name: str,
        volume_name: str,
    ) -> None:
        svc = self._get_storage_service()
        if svc is None:
            self.app.notify("OVHStorageService not initialised", severity="error")
            return
        try:
            await svc.create_volume_snapshot(project_id, volume_id, snap_name)
            self.app.notify(
                f"Snapshot '{self._display_name(snap_name)}' created from volume '{self._display_name(volume_name)}'",
                severity="information",
            )
        except Exception as exc:
            logger.error("create_volume_snapshot failed for %s: %s", volume_id, exc)
            self.app.notify(f"Failed to create snapshot: {self._provider_error(exc)}", severity="error", markup=False)

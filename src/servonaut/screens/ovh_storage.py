"""OVH block storage management screen for Servonaut."""

from __future__ import annotations

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


class OVHStorageScreen(Screen):
    """Manage OVH Public Cloud block storage volumes."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]OVH Block Storage[/bold cyan]",
                    id="storage_title",
                ),
                DataTable(id="volumes_table"),
                Horizontal(
                    Button("Create Volume", id="btn_create", variant="primary"),
                    Button("Attach", id="btn_attach", variant="default"),
                    Button("Detach", id="btn_detach", variant="default"),
                    Button("Delete", id="btn_delete", variant="error"),
                    Button("Snapshot", id="btn_snapshot", variant="default"),
                    Button("Refresh", id="btn_refresh", variant="default"),
                    Button("Back", id="btn_back", variant="default"),
                    id="storage_actions",
                ),
                # Create Volume form (hidden by default)
                Container(
                    Static("[bold]Create Volume[/bold]", classes="section_header"),
                    Label("Name:"),
                    Input(placeholder="my-volume", id="input_vol_name"),
                    Label("Size (GB):"),
                    Input(placeholder="50", id="input_vol_size"),
                    Label("Region:"),
                    Input(placeholder="GRA11", id="input_vol_region"),
                    Label("Type:"),
                    Input(placeholder="classic", id="input_vol_type"),
                    Horizontal(
                        Button("Save Volume", id="btn_save_vol", variant="primary"),
                        Button("Cancel", id="btn_cancel_form", variant="default"),
                        classes="add_row",
                    ),
                    id="create_vol_form",
                ),
                # Attach Volume form (hidden by default)
                Container(
                    Static("[bold]Attach Volume[/bold]", classes="section_header"),
                    Label("Instance ID:"),
                    Input(placeholder="instance-uuid", id="input_attach_instance_id"),
                    Horizontal(
                        Button("Attach", id="btn_confirm_attach", variant="primary"),
                        Button("Cancel", id="btn_cancel_attach", variant="default"),
                        classes="add_row",
                    ),
                    id="attach_vol_form",
                ),
                # Snapshot form (hidden by default)
                Container(
                    Static("[bold]Create Snapshot[/bold]", classes="section_header"),
                    Label("Snapshot Name:"),
                    Input(placeholder="snapshot-name", id="input_snapshot_name"),
                    Horizontal(
                        Button("Create Snapshot", id="btn_confirm_snapshot", variant="primary"),
                        Button("Cancel", id="btn_cancel_snapshot", variant="default"),
                        classes="add_row",
                    ),
                    id="snapshot_form",
                ),
                id="storage_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._setup_table()
        self._hide_all_forms()
        self.run_worker(self._load_volumes(), exclusive=True)

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
        return getattr(self.app, "ovh_storage_service", None)

    def _get_project_ids(self) -> List[str]:
        ovh_config = getattr(getattr(self.app, "config_manager", None), "config", None)
        if ovh_config is None:
            ovh_config = getattr(self.app, "config", None)
        ovh_cfg = getattr(ovh_config, "ovh", None) if ovh_config else None
        if ovh_cfg is None:
            return []
        return list(getattr(ovh_cfg, "cloud_project_ids", []))

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

        all_volumes: List[dict] = []
        for pid in project_ids:
            try:
                vols = await svc.list_volumes(pid)
                for v in vols:
                    v["_project_id"] = pid
                all_volumes.extend(vols)
            except Exception as exc:
                logger.error("list_volumes failed for project %s: %s", pid, exc)
                self.app.notify(f"Failed to load volumes for {pid}: {exc}", severity="error")

        self._volumes: List[dict] = all_volumes

        table = self.query_one("#volumes_table", DataTable)
        table.clear()
        for vol in all_volumes:
            name = vol.get("name") or vol.get("id", "—")
            size = str(vol.get("size", "—"))
            region = vol.get("region") or "—"
            status = vol.get("status") or "—"
            attachments = vol.get("attachments") or []
            if attachments:
                attached_to = ", ".join(
                    a.get("serverId") or a.get("id") or "unknown"
                    for a in attachments
                )
            else:
                attached_to = "—"
            table.add_row(name, size, region, status, attached_to)

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
        self.run_worker(self._load_volumes(), exclusive=True)

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
            self.app.notify(f"Volume '{name}' created", severity="information")
            await self._load_volumes()
        except Exception as exc:
            logger.error("create_volume failed: %s", exc)
            self.app.notify(f"Failed to create volume: {exc}", severity="error")

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
                    title="Delete Volume",
                    description=f"Permanently delete volume [bold]{volume_name}[/bold].",
                    consequences=[
                        "All data on this volume will be permanently lost",
                        "Any remaining snapshots may also be affected",
                    ],
                    confirm_text=volume_name,
                    action_label="Delete Volume",
                    severity="danger",
                )
            )
            if confirmed:
                audit = getattr(self.app, "ovh_audit", None)
                if audit:
                    audit.log_action(
                        "volume_delete",
                        volume_id,
                        {"name": volume_name, "project_id": project_id},
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
            self.app.notify(f"Volume '{volume_name}' deleted", severity="information")
            await self._load_volumes()
        except Exception as exc:
            logger.error("delete_volume failed for %s: %s", volume_id, exc)
            self.app.notify(f"Failed to delete volume: {exc}", severity="error")

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
                    title="Attach Volume",
                    description=(
                        f"Attach volume [bold]{volume_name}[/bold] to instance "
                        f"[bold]{instance_id}[/bold]."
                    ),
                    consequences=["The volume will be available as a block device on the instance"],
                    confirm_text=volume_name,
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
                        {
                            "name": volume_name,
                            "project_id": project_id,
                            "instance_id": instance_id,
                        },
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
            self.app.notify(f"Volume '{volume_name}' attached", severity="information")
            await self._load_volumes()
        except Exception as exc:
            logger.error("attach_volume failed for %s: %s", volume_id, exc)
            self.app.notify(f"Failed to attach volume: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Detach volume
    # ------------------------------------------------------------------

    def _action_detach(self) -> None:
        vol = self._get_selected_volume()
        if vol is None:
            self.app.notify("No volume selected", severity="warning")
            return

        attachments = vol.get("attachments") or []
        if not attachments:
            self.app.notify("Volume is not attached to any instance", severity="warning")
            return

        project_id = vol.get("_project_id", "")
        volume_id = vol.get("id", "")
        volume_name = vol.get("name") or volume_id
        instance_id = (
            attachments[0].get("serverId") or attachments[0].get("id") or ""
        )

        async def _confirm_and_detach() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Detach Volume",
                    description=(
                        f"Detach volume [bold]{volume_name}[/bold] from instance "
                        f"[bold]{instance_id}[/bold]."
                    ),
                    consequences=[
                        "The volume will no longer be accessible from the instance",
                        "Data is preserved — you can re-attach later",
                    ],
                    confirm_text=volume_name,
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
                        {
                            "name": volume_name,
                            "project_id": project_id,
                            "instance_id": instance_id,
                        },
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
            self.app.notify(f"Volume '{volume_name}' detached", severity="information")
            await self._load_volumes()
        except Exception as exc:
            logger.error("detach_volume failed for %s: %s", volume_id, exc)
            self.app.notify(f"Failed to detach volume: {exc}", severity="error")

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
                f"Snapshot '{snap_name}' created from volume '{volume_name}'",
                severity="information",
            )
        except Exception as exc:
            logger.error("create_volume_snapshot failed for %s: %s", volume_id, exc)
            self.app.notify(f"Failed to create snapshot: {exc}", severity="error")

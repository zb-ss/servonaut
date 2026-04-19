"""OVH snapshot and backup management screen."""

from __future__ import annotations

import logging
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class OVHSnapshotsScreen(Screen):
    """Screen for managing snapshots of a specific OVH instance.

    Supports VPS snapshots, VPS automated backups, and Public Cloud snapshots
    depending on the instance's provider_type.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        """Initialize the snapshots screen.

        Args:
            instance: Instance dictionary from the instance list.
        """
        super().__init__()
        self._instance = instance
        self._provider_type: str = instance.get("provider_type", "vps")
        self._snapshots: List[dict] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Compose the snapshots management UI."""
        instance_name = self._instance.get("name") or self._instance.get("id", "Unknown")
        is_vps = self._provider_type == "vps"

        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with ScrollableContainer(id="snapshots_container"):
                yield Static(
                    f"[bold cyan]Snapshots: {instance_name}[/bold cyan]",
                    id="snapshots_title",
                )
                yield DataTable(id="snapshots_table")
                with Horizontal(id="snapshots_actions"):
                    yield Button(
                        "Create Snapshot",
                        variant="primary",
                        id="btn_create",
                    )
                    yield Button(
                        "Restore Selected",
                        variant="error",
                        id="btn_restore",
                    )
                    yield Button(
                        "Delete Selected",
                        variant="error",
                        id="btn_delete",
                    )
                    yield Button("Back", variant="default", id="btn_back")
                if is_vps:
                    yield Static(
                        "[bold]Automated Backups[/bold]",
                        id="backup_section_title",
                    )
                    yield Static(
                        "[dim]Loading backup status...[/dim]",
                        id="backup_status",
                    )
                    yield Button(
                        "Configure Backup",
                        variant="default",
                        id="btn_configure_backup",
                    )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        """Set up table columns and load snapshots."""
        table = self.query_one("#snapshots_table", DataTable)
        table.add_columns("Name / ID", "Date", "Description / Status")
        table.cursor_type = "row"

        if self._provider_type == "vps":
            self.run_worker(self._load_vps_snapshots(), exclusive=True)
            self.run_worker(self._load_vps_backup_status(), exclusive=False)
        elif self._provider_type == "cloud":
            self.run_worker(self._load_cloud_snapshots(), exclusive=True)
        else:
            self.notify(
                f"Snapshots are not supported for provider_type: {self._provider_type!r}",
                severity="warning",
            )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id or ""

        if button_id == "btn_back":
            self.action_back()
        elif button_id == "btn_create":
            await self._on_create_snapshot()
        elif button_id == "btn_restore":
            await self._on_restore_snapshot()
        elif button_id == "btn_delete":
            await self._on_delete_snapshot()
        elif button_id == "btn_configure_backup":
            await self._on_configure_backup()

    def action_back(self) -> None:
        """Navigate back."""
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Data loading workers
    # ------------------------------------------------------------------

    async def _load_vps_snapshots(self) -> None:
        """Fetch VPS snapshots and populate the table."""
        svc = getattr(self.app, "ovh_snapshot_service", None)
        if svc is None:
            self.notify("OVH snapshot service is not available.", severity="error")
            return

        vps_name = self._instance.get("id", "")
        if not vps_name:
            self.notify("No VPS ID found in instance data.", severity="error")
            return

        try:
            self._snapshots = await svc.list_vps_snapshots(vps_name)
        except Exception as e:
            logger.error("Error loading VPS snapshots: %s", e)
            self.notify(f"Failed to load snapshots: {e}", severity="error")
            return

        self._populate_table()

    async def _load_cloud_snapshots(self) -> None:
        """Fetch Public Cloud snapshots and populate the table."""
        svc = getattr(self.app, "ovh_snapshot_service", None)
        if svc is None:
            self.notify("OVH snapshot service is not available.", severity="error")
            return

        # Cloud instance IDs are encoded as "{project_id}/{instance_id}"
        raw_id: str = self._instance.get("id", "")
        if "/" not in raw_id:
            self.notify(
                "Cloud instance ID must be 'project_id/instance_id'.",
                severity="error",
            )
            return

        project_id, _ = raw_id.split("/", 1)
        try:
            self._snapshots = await svc.list_cloud_snapshots(project_id)
        except Exception as e:
            logger.error("Error loading cloud snapshots: %s", e)
            self.notify(f"Failed to load snapshots: {e}", severity="error")
            return

        self._populate_table()

    async def _load_vps_backup_status(self) -> None:
        """Fetch and display VPS automated backup options."""
        svc = getattr(self.app, "ovh_snapshot_service", None)
        if svc is None:
            return

        vps_name = self._instance.get("id", "")
        if not vps_name:
            return

        try:
            backup_status_widget = self.query_one("#backup_status", Static)
        except Exception:
            return  # widget may not exist for non-VPS instances

        try:
            options = await svc.get_vps_backup_options(vps_name)
        except Exception as e:
            logger.error("Error fetching backup options: %s", e)
            backup_status_widget.update(f"[red]Error loading backup status: {e}[/red]")
            return

        if not options:
            backup_status_widget.update("[dim]No automated backup configured.[/dim]")
            return

        state = options.get("state") or options.get("status") or "unknown"
        schedule = options.get("schedule") or options.get("cron") or ""
        if schedule:
            backup_status_widget.update(
                f"[green]Enabled[/green] — Schedule: [bold]{schedule}[/bold] — State: {state}"
            )
        else:
            backup_status_widget.update(f"State: {state}")

    def _populate_table(self) -> None:
        """Populate the DataTable with the current snapshot list."""
        table = self.query_one("#snapshots_table", DataTable)
        table.clear()

        if not self._snapshots:
            self.notify("No snapshots found.", severity="information")
            return

        for snap in self._snapshots:
            name_or_id = snap.get("name") or snap.get("id") or "—"
            created_at = (
                snap.get("creationDate")
                or snap.get("createdAt")
                or snap.get("restore_point")
                or "—"
            )
            description = (
                snap.get("description")
                or snap.get("status")
                or snap.get("state")
                or "—"
            )
            table.add_row(str(name_or_id), str(created_at), str(description))

    # ------------------------------------------------------------------
    # Create snapshot
    # ------------------------------------------------------------------

    async def _on_create_snapshot(self) -> None:
        """Prompt for description and create a snapshot."""
        svc = getattr(self.app, "ovh_snapshot_service", None)
        if svc is None:
            self.notify("OVH snapshot service is not available.", severity="error")
            return

        instance_name = self._instance.get("name") or self._instance.get("id", "")

        if self._provider_type == "vps":
            vps_name = self._instance.get("id", "")
            if not vps_name:
                self.notify("No VPS ID found.", severity="error")
                return
            self.run_worker(
                self._do_create_vps_snapshot(svc, vps_name),
                exclusive=False,
            )

        elif self._provider_type == "cloud":
            raw_id: str = self._instance.get("id", "")
            if "/" not in raw_id:
                self.notify("Invalid cloud instance ID.", severity="error")
                return
            project_id, instance_id = raw_id.split("/", 1)
            snapshot_name = f"{instance_name}-snapshot"
            self.run_worker(
                self._do_create_cloud_snapshot(svc, project_id, instance_id, snapshot_name),
                exclusive=False,
            )
        else:
            self.notify("Snapshot creation not supported for this provider type.", severity="warning")

    async def _do_create_vps_snapshot(self, svc, vps_name: str) -> None:
        """Worker: create a VPS snapshot."""
        try:
            await svc.create_vps_snapshot(vps_name, description="")
            self.notify("Snapshot creation has been queued.", severity="information")
            await self._load_vps_snapshots()
        except Exception as e:
            logger.error("VPS snapshot creation failed: %s", e)
            self.notify(f"Snapshot creation failed: {e}", severity="error")

    async def _do_create_cloud_snapshot(
        self,
        svc,
        project_id: str,
        instance_id: str,
        snapshot_name: str,
    ) -> None:
        """Worker: create a Public Cloud snapshot."""
        try:
            await svc.create_cloud_snapshot(project_id, instance_id, snapshot_name)
            self.notify(
                f"Cloud snapshot '{snapshot_name}' creation has been queued.",
                severity="information",
            )
            await self._load_cloud_snapshots()
        except Exception as e:
            logger.error("Cloud snapshot creation failed: %s", e)
            self.notify(f"Snapshot creation failed: {e}", severity="error")

    # ------------------------------------------------------------------
    # Restore snapshot
    # ------------------------------------------------------------------

    async def _on_restore_snapshot(self) -> None:
        """Confirm and restore the selected snapshot."""
        table = self.query_one("#snapshots_table", DataTable)
        row_index = table.cursor_row

        if row_index < 0 or row_index >= len(self._snapshots):
            self.notify("Please select a snapshot to restore.", severity="warning")
            return

        snap = self._snapshots[row_index]
        snap_name = snap.get("name") or snap.get("id") or "snapshot"
        instance_name = self._instance.get("name") or self._instance.get("id", "")

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Restore Snapshot",
                description=(
                    f"Restore [bold]{instance_name}[/bold] from snapshot "
                    f"[bold]{snap_name}[/bold]."
                ),
                consequences=[
                    "The instance will be reverted to the snapshot state",
                    "All changes made after the snapshot was taken will be lost",
                ],
                confirm_text=instance_name,
                action_label="Restore Now",
                severity="danger",
            )
        )

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            from servonaut.services.ovh_audit import OVHAuditLogger
            ovh_audit.log_action(
                action="snapshot_restore",
                target=self._instance.get("id", ""),
                details={"snapshot_id": snap.get("id", ""), "snapshot_name": snap_name},
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        svc = getattr(self.app, "ovh_snapshot_service", None)
        if svc is None:
            self.notify("OVH snapshot service is not available.", severity="error")
            return

        if self._provider_type == "vps":
            snapshot_id = str(snap.get("id", ""))
            self.run_worker(
                self._do_restore_vps_snapshot(svc, snapshot_id),
                exclusive=False,
            )
        else:
            self.notify("Snapshot restore not supported for this provider type.", severity="warning")

    async def _do_restore_vps_snapshot(self, svc, snapshot_id: str) -> None:
        """Worker: restore a VPS snapshot."""
        vps_name = self._instance.get("id", "")
        try:
            await svc.restore_vps_snapshot(vps_name, snapshot_id)
            self.notify("Snapshot restore has been queued.", severity="information")
        except Exception as e:
            logger.error("VPS snapshot restore failed: %s", e)
            self.notify(f"Snapshot restore failed: {e}", severity="error")

    # ------------------------------------------------------------------
    # Delete snapshot
    # ------------------------------------------------------------------

    async def _on_delete_snapshot(self) -> None:
        """Confirm and delete the selected snapshot."""
        table = self.query_one("#snapshots_table", DataTable)
        row_index = table.cursor_row

        if row_index < 0 or row_index >= len(self._snapshots):
            self.notify("Please select a snapshot to delete.", severity="warning")
            return

        snap = self._snapshots[row_index]
        snap_name = snap.get("name") or snap.get("id") or "snapshot"

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete Snapshot",
                description=f"Delete snapshot [bold]{snap_name}[/bold].",
                consequences=[
                    "The snapshot will be permanently deleted",
                    "This cannot be undone",
                ],
                confirm_text=str(snap_name),
                action_label="Delete Snapshot",
                severity="warning",
            )
        )

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            from servonaut.services.ovh_audit import OVHAuditLogger
            ovh_audit.log_action(
                action="snapshot_delete",
                target=self._instance.get("id", ""),
                details={"snapshot_id": snap.get("id", ""), "snapshot_name": snap_name},
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        svc = getattr(self.app, "ovh_snapshot_service", None)
        if svc is None:
            self.notify("OVH snapshot service is not available.", severity="error")
            return

        if self._provider_type == "vps":
            self.run_worker(self._do_delete_vps_snapshot(svc), exclusive=False)
        elif self._provider_type == "cloud":
            raw_id: str = self._instance.get("id", "")
            project_id = raw_id.split("/", 1)[0] if "/" in raw_id else ""
            snapshot_id = str(snap.get("id", ""))
            self.run_worker(
                self._do_delete_cloud_snapshot(svc, project_id, snapshot_id),
                exclusive=False,
            )
        else:
            self.notify("Snapshot deletion not supported for this provider type.", severity="warning")

    async def _do_delete_vps_snapshot(self, svc) -> None:
        """Worker: delete the VPS snapshot."""
        vps_name = self._instance.get("id", "")
        try:
            await svc.delete_vps_snapshot(vps_name)
            self.notify("Snapshot deleted successfully.", severity="information")
            await self._load_vps_snapshots()
        except Exception as e:
            logger.error("VPS snapshot deletion failed: %s", e)
            self.notify(f"Snapshot deletion failed: {e}", severity="error")

    async def _do_delete_cloud_snapshot(self, svc, project_id: str, snapshot_id: str) -> None:
        """Worker: delete a Public Cloud snapshot."""
        try:
            await svc.delete_cloud_snapshot(project_id, snapshot_id)
            self.notify("Cloud snapshot deleted successfully.", severity="information")
            await self._load_cloud_snapshots()
        except Exception as e:
            logger.error("Cloud snapshot deletion failed: %s", e)
            self.notify(f"Cloud snapshot deletion failed: {e}", severity="error")

    # ------------------------------------------------------------------
    # Configure backup (VPS only)
    # ------------------------------------------------------------------

    async def _on_configure_backup(self) -> None:
        """Prompt and configure automated backup schedule (VPS only)."""
        svc = getattr(self.app, "ovh_snapshot_service", None)
        if svc is None:
            self.notify("OVH snapshot service is not available.", severity="error")
            return

        vps_name = self._instance.get("id", "")
        if not vps_name:
            self.notify("No VPS ID found.", severity="error")
            return

        # Use a default daily schedule as a starting point
        default_schedule = "0 3 * * *"
        self.run_worker(
            self._do_configure_backup(svc, vps_name, default_schedule),
            exclusive=False,
        )

    async def _do_configure_backup(self, svc, vps_name: str, schedule: str) -> None:
        """Worker: configure VPS automated backup."""
        try:
            await svc.configure_vps_backup(vps_name, schedule)
            self.notify(
                f"Automated backup configured with schedule: {schedule}",
                severity="information",
            )
            await self._load_vps_backup_status()
        except Exception as e:
            logger.error("VPS backup configuration failed: %s", e)
            self.notify(f"Backup configuration failed: {e}", severity="error")

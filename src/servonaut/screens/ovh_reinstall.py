"""OVH VPS reinstall screen — select a new OS image and trigger reinstall."""

from __future__ import annotations

import logging
from typing import List

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.widgets import Button, DataTable, Footer, Static

from servonaut.screens._busy_work import BusyWork
from servonaut.utils.markup import with_bold_values
from servonaut.screens._demo_resolve import real_instance_id
from servonaut.screens._provider_accounts import ServerAccountMixin, ServerAuditMixin
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

logger = logging.getLogger(__name__)


class OVHReinstallScreen(ServerAuditMixin, ServerAccountMixin, WorkspaceScreen):
    """Screen for reinstalling a VPS with a new OS image.

    Fetches available images from OVHcloud, shows them in a DataTable,
    and confirms the destructive operation via ConfirmActionScreen before
    calling OVHVPSService.reinstall().
    """

    DEFAULT_CSS = """
    OVHReinstallScreen .workspace-content > BusyIndicator.read-loading {
        dock: top;
        height: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    AUTO_FOCUS = "#reinstall_container"
    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 56
    CONTENT_NARROW_WIDTH = 84

    def __init__(self, instance: dict) -> None:
        """Initialize the reinstall screen.

        Args:
            instance: Instance dictionary from the instance list.
        """
        super().__init__()
        self._read_loading = BusyWork(self, "#read_loading")
        self._instance = instance
        self._images: List[dict] = []

    def compose(self) -> ComposeResult:
        """Compose the reinstall UI."""
        name = self._instance.get('name') or self._instance.get('id', 'VPS')
        yield SafeHeader()
        yield WorkspaceControls("Reinstall")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield ScrollableContainer(
                BusyIndicator(id="read_loading", classes="read-loading"),
                Vertical(
                    Static(
                        f"[bold $text-accent]Reinstall VPS: {escape(str(name))}[/bold $text-accent]",
                        id="reinstall_title",
                    ),
                    Static(
                        "Choose an OS image to install on this VPS. "
                        "All existing data will be permanently destroyed.",
                        id="reinstall_description",
                    ),
                    classes="provider-lifecycle-heading",
                ),
                Horizontal(
                    Container(
                        Static("[bold]Available OS images[/bold]", classes="provider_catalog_heading"),
                        DataTable(id="images_table"),
                        classes="provider_maintenance_catalog",
                    ),
                    Vertical(
                        Static(
                            "[bold]Current instance[/bold]\n" + "\n".join(
                                f"[dim]{label}:[/dim] {escape(str(self._instance[key]))}"
                                for key, label in (("id", "ID"), ("os", "OS"), ("type", "Plan"), ("region", "Region"), ("account", "Account"))
                                if self._instance.get(key)
                            ),
                            id="reinstall_context", classes="provider_instance_context",
                        ),
                        Static(
                            "[dim]Select an image and click Reinstall[/dim]",
                            id="reinstall_hint",
                        ),
                        Horizontal(
                            Button(
                                "Reinstall Selected",
                                variant="error",
                                id="btn_reinstall",
                            ),
                            Button("Back", variant="default", id="btn_back"),
                            id="reinstall_actions",
                        ),
                        classes="provider-lifecycle-operations",
                    ),
                    classes="provider-lifecycle-body",
                ),
                id="reinstall_container",
                classes="workspace-content provider-lifecycle-workspace",
            )
        yield Footer()

    def on_mount(self) -> None:
        """Set up the DataTable and start loading images."""
        table = self.query_one("#images_table", DataTable)
        table.add_columns("Name", "OS Type")
        table.cursor_type = "row"
        self.run_worker(self._load_images(), exclusive=True)

    async def _load_images(self) -> None:
        """Fetch available images and populate the DataTable."""
        vps_name = real_instance_id(self.app, self._instance.get('id', ''))
        if not vps_name:
            self.notify("No VPS ID found in instance data.", severity="error")
            return

        ovh_vps_service = self._ovh_service("vps")
        if ovh_vps_service is None:
            self.notify("OVH VPS service is not available.", severity="error")
            return

        try:
            with self._read_loading.running('Loading images…'):
                self._images = await ovh_vps_service.list_images(vps_name)
        except Exception as e:
            logger.error("Error loading VPS images: %s", e)
            self.notify(f"Failed to load images: {e}", severity="error", markup=False)
            return

        table = self.query_one("#images_table", DataTable)
        table.clear()
        if not self._images:
            self.notify("No images available for this VPS.", severity="warning")
            return

        for image in self._images:
            table.add_row(
                image.get('name', ''),
                image.get('os_type', ''),
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses.

        ``_on_reinstall`` awaits ``push_screen_wait`` for the confirmation,
        which Textual 8 only allows inside a worker, so it runs in one. Its
        own group keeps it from cancelling the image-loading worker.
        """
        if event.button.id == "btn_back":
            self.action_back()
        elif event.button.id == "btn_reinstall":
            # The reinstall request runs in a thread that cancelling the
            # worker cannot stop, so a second press must neither cancel this
            # attempt nor start another: the button stays off until it ends.
            event.button.disabled = True
            self.run_worker(
                self._on_reinstall(),
                group="ovh_reinstall",
                name="ovh_reinstall_submit",
            )

    async def _on_reinstall(self) -> None:
        """Run one reinstall attempt; offer the button again unless it was queued."""
        queued = False
        try:
            queued = await self._confirm_and_reinstall()
        finally:
            if not queued:
                self.query("#btn_reinstall").set(disabled=False)

    async def _confirm_and_reinstall(self) -> bool:
        """Confirm and execute the reinstall operation.

        Returns:
            True once OVH has queued the reinstall.
        """
        table = self.query_one("#images_table", DataTable)
        row_key = table.cursor_row

        if row_key < 0 or row_key >= len(self._images):
            self.notify("Please select an image from the list.", severity="warning")
            return False

        image = self._images[row_key]
        image_name = image.get('name', image.get('id', 'Unknown'))
        shown_id = self._instance.get('id', '')
        # The row may carry demo-mode fakes: show them, act on the real VPS.
        vps_name = real_instance_id(self.app, shown_id)
        instance_name = self._instance.get('name') or shown_id

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Reinstall VPS",
                description=with_bold_values(
                    "Reinstall {} with {}.", instance_name, image_name,
                ),
                consequences=[
                    "All data on the VPS will be permanently destroyed",
                    "A fresh OS will be installed",
                    "SSH keys will need to be re-applied",
                ],
                confirm_text=instance_name,
                action_label="Reinstall Now",
                severity="danger",
            )
        )

        ovh_audit = getattr(self.app, 'ovh_audit', None)
        if ovh_audit is not None:
            from servonaut.services.ovh_audit import OVHAuditLogger
            ovh_audit.log_action(
                action="vps_reinstall",
                target=vps_name,
                details=self._audit_details(
                    {"image_id": image.get('id', ''), "image_name": image_name},
                ),
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return False

        ovh_vps_service = self._ovh_service("vps")
        if ovh_vps_service is None:
            self.notify("OVH VPS service is not available.", severity="error")
            return False

        try:
            await ovh_vps_service.reinstall(vps_name, image.get('id', ''))
        except Exception as e:
            logger.error("VPS reinstall failed: %s", e)
            self.notify(f"Reinstall failed: {e}", severity="error", markup=False)
            return False
        self.notify(
            f"Reinstall of {instance_name} with {image_name} has been queued.",
            severity="information",
            markup=False,
        )
        return True

    def action_back(self) -> None:
        """Navigate back."""
        self.app.pop_screen()

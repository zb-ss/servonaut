"""OVH VPS reinstall screen — select a new OS image and trigger reinstall."""

from __future__ import annotations

import logging
from typing import List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class OVHReinstallScreen(Screen):
    """Screen for reinstalling a VPS with a new OS image.

    Fetches available images from OVHcloud, shows them in a DataTable,
    and confirms the destructive operation via ConfirmActionScreen before
    calling OVHVPSService.reinstall().
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        """Initialize the reinstall screen.

        Args:
            instance: Instance dictionary from the instance list.
        """
        super().__init__()
        self._instance = instance
        self._images: List[dict] = []

    def compose(self) -> ComposeResult:
        """Compose the reinstall UI."""
        name = self._instance.get('name') or self._instance.get('id', 'VPS')
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with ScrollableContainer(id="reinstall_container"):
                yield Static(
                    f"[bold cyan]Reinstall VPS: {name}[/bold cyan]",
                    id="reinstall_title",
                )
                yield Static(
                    "Choose an OS image to install on this VPS. "
                    "All existing data will be permanently destroyed.",
                    id="reinstall_description",
                )
                yield DataTable(id="images_table")
                yield Static(
                    "[dim]Select an image and click Reinstall[/dim]",
                    id="reinstall_hint",
                )
                with Horizontal(id="reinstall_actions"):
                    yield Button(
                        "Reinstall Selected",
                        variant="error",
                        id="btn_reinstall",
                    )
                    yield Button("Back", variant="default", id="btn_back")
        yield Footer()

    def on_mount(self) -> None:
        """Set up the DataTable and start loading images."""
        table = self.query_one("#images_table", DataTable)
        table.add_columns("Name", "OS Type")
        table.cursor_type = "row"
        self.run_worker(self._load_images(), exclusive=True)

    async def _load_images(self) -> None:
        """Fetch available images and populate the DataTable."""
        vps_name = self._instance.get('id', '')
        if not vps_name:
            self.notify("No VPS ID found in instance data.", severity="error")
            return

        ovh_vps_service = getattr(self.app, 'ovh_vps_service', None)
        if ovh_vps_service is None:
            self.notify("OVH VPS service is not available.", severity="error")
            return

        try:
            self._images = await ovh_vps_service.list_images(vps_name)
        except Exception as e:
            logger.error("Error loading VPS images: %s", e)
            self.notify(f"Failed to load images: {e}", severity="error")
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

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn_back":
            self.action_back()
        elif event.button.id == "btn_reinstall":
            await self._on_reinstall()

    async def _on_reinstall(self) -> None:
        """Confirm and execute the reinstall operation."""
        table = self.query_one("#images_table", DataTable)
        row_key = table.cursor_row

        if row_key < 0 or row_key >= len(self._images):
            self.notify("Please select an image from the list.", severity="warning")
            return

        image = self._images[row_key]
        image_name = image.get('name', image.get('id', 'Unknown'))
        vps_name = self._instance.get('id', '')
        instance_name = self._instance.get('name') or vps_name

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Reinstall VPS",
                description=(
                    f"Reinstall [bold]{instance_name}[/bold] with "
                    f"[bold]{image_name}[/bold]."
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
                details={"image_id": image.get('id', ''), "image_name": image_name},
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        ovh_vps_service = getattr(self.app, 'ovh_vps_service', None)
        if ovh_vps_service is None:
            self.notify("OVH VPS service is not available.", severity="error")
            return

        try:
            await ovh_vps_service.reinstall(vps_name, image.get('id', ''))
            self.notify(
                f"Reinstall of {instance_name} with {image_name} has been queued.",
                severity="information",
            )
        except Exception as e:
            logger.error("VPS reinstall failed: %s", e)
            self.notify(f"Reinstall failed: {e}", severity="error")

    def action_back(self) -> None:
        """Navigate back."""
        self.app.pop_screen()

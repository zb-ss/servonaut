"""Wizard screen for creating a new OVH Public Cloud instance."""

from __future__ import annotations

import logging
from typing import List, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class OVHCloudCreateScreen(Screen):
    """Wizard for creating a new OVH Public Cloud instance.

    Lets the user choose a flavor, OS image, and optional SSH key, then
    confirms before billing begins.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        super().__init__()
        self._project_id: str = ""
        self._flavors: List[dict] = []
        self._images: List[dict] = []
        self._keys: List[dict] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]Create Cloud Instance[/bold cyan]",
                    id="cloud_create_title",
                ),

                Input(placeholder="Instance Name", id="input_name"),
                Input(
                    placeholder="e.g. GRA11, SBG5",
                    id="input_region",
                ),

                Static("[bold]Select Flavor[/bold]", classes="section_header"),
                DataTable(id="flavors_table"),

                Static("[bold]Select Image[/bold]", classes="section_header"),
                DataTable(id="images_table"),

                Static("[bold]SSH Key (optional)[/bold]", classes="section_header"),
                DataTable(id="keys_table"),

                Horizontal(
                    Button("Create Instance", variant="primary", id="btn_create"),
                    Button("Back", variant="default", id="btn_back"),
                    id="cloud_create_actions",
                ),

                id="cloud_create_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._setup_tables()

        config = self.app.config_manager.get()
        project_ids: List[str] = getattr(config.ovh, "cloud_project_ids", [])

        if not project_ids:
            self.query_one("#cloud_create_container", ScrollableContainer).mount(
                Static(
                    "[red]No OVH cloud project IDs configured. "
                    "Add them in Settings under OVH.[/red]",
                    id="no_project_error",
                )
            )
            return

        # Use the first configured project for the wizard.
        self._project_id = project_ids[0]

        self.run_worker(self._load_flavors(), exclusive=False)
        self.run_worker(self._load_images(), exclusive=False)
        self.run_worker(self._load_keys(), exclusive=False)

    # ------------------------------------------------------------------
    # Table setup
    # ------------------------------------------------------------------

    def _setup_tables(self) -> None:
        flavors_tbl = self.query_one("#flavors_table", DataTable)
        flavors_tbl.add_columns("Name", "vCPUs", "RAM (GB)", "Disk (GB)")
        flavors_tbl.cursor_type = "row"

        images_tbl = self.query_one("#images_table", DataTable)
        images_tbl.add_columns("Name", "OS Type", "Min Disk")
        images_tbl.cursor_type = "row"

        keys_tbl = self.query_one("#keys_table", DataTable)
        keys_tbl.add_columns("Name", "ID")
        keys_tbl.cursor_type = "row"

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    async def _load_flavors(self) -> None:
        svc = getattr(self.app, "ovh_cloud_service", None)
        tbl = self.query_one("#flavors_table", DataTable)
        if svc is None:
            self.notify("OVH Cloud service not available.", severity="error")
            return
        try:
            self._flavors = await svc.list_flavors(self._project_id)
            for flavor in self._flavors:
                ram_gb = round(flavor.get("ram", 0) / 1024, 1) if flavor.get("ram") else 0
                tbl.add_row(
                    flavor.get("name", ""),
                    str(flavor.get("vcpus", "")),
                    str(ram_gb),
                    str(flavor.get("disk", "")),
                )
        except Exception as exc:
            logger.error("Failed to load flavors: %s", exc)
            self.notify(f"Error loading flavors: {exc}", severity="error")

    async def _load_images(self) -> None:
        svc = getattr(self.app, "ovh_cloud_service", None)
        tbl = self.query_one("#images_table", DataTable)
        if svc is None:
            return
        try:
            self._images = await svc.list_images(self._project_id)
            for image in self._images:
                tbl.add_row(
                    image.get("name", ""),
                    image.get("os_type", ""),
                    str(image.get("min_disk", "")),
                )
        except Exception as exc:
            logger.error("Failed to load images: %s", exc)
            self.notify(f"Error loading images: {exc}", severity="error")

    async def _load_keys(self) -> None:
        svc = getattr(self.app, "ovh_cloud_service", None)
        tbl = self.query_one("#keys_table", DataTable)
        if svc is None:
            return
        try:
            self._keys = await svc.list_ssh_keys(self._project_id)
            for key in self._keys:
                tbl.add_row(
                    key.get("name", ""),
                    key.get("id", ""),
                )
        except Exception as exc:
            logger.error("Failed to load SSH keys: %s", exc)
            self.notify(f"Error loading SSH keys: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.action_back()
        elif event.button.id == "btn_create":
            await self._on_create()

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Create flow
    # ------------------------------------------------------------------

    async def _on_create(self) -> None:
        """Validate selections, confirm, and call the Cloud service."""
        name = self.query_one("#input_name", Input).value.strip()
        if not name:
            self.notify("Please enter an instance name.", severity="warning")
            return

        flavors_tbl = self.query_one("#flavors_table", DataTable)
        flavor_row = flavors_tbl.cursor_row
        if flavor_row < 0 or flavor_row >= len(self._flavors):
            self.notify("Please select a flavor.", severity="warning")
            return

        images_tbl = self.query_one("#images_table", DataTable)
        image_row = images_tbl.cursor_row
        if image_row < 0 or image_row >= len(self._images):
            self.notify("Please select an OS image.", severity="warning")
            return

        region = self.query_one("#input_region", Input).value.strip()
        if not region:
            self.notify("Please enter a region (e.g. GRA11).", severity="warning")
            return

        flavor = self._flavors[flavor_row]
        image = self._images[image_row]

        keys_tbl = self.query_one("#keys_table", DataTable)
        key_row = keys_tbl.cursor_row
        ssh_key_id = ""
        if 0 <= key_row < len(self._keys):
            ssh_key_id = self._keys[key_row].get("id", "")

        flavor_name = flavor.get("name", flavor.get("id", ""))
        image_name = image.get("name", image.get("id", ""))

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Create Cloud Instance",
                description=(
                    f"Create instance [bold]{name}[/bold] in [bold]{region}[/bold] "
                    f"using [bold]{flavor_name}[/bold] / [bold]{image_name}[/bold]."
                ),
                consequences=[
                    "This will start billing for a new cloud instance immediately",
                    "Ongoing charges apply until the instance is deleted",
                ],
                confirm_text="create",
                action_label="Create Instance",
                severity="warning",
            )
        )

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            ovh_audit.log_action(
                action="cloud_create",
                target=self._project_id,
                details={
                    "name": name,
                    "flavor_id": flavor.get("id", ""),
                    "image_id": image.get("id", ""),
                    "region": region,
                    "ssh_key_id": ssh_key_id,
                },
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        svc = getattr(self.app, "ovh_cloud_service", None)
        if svc is None:
            self.notify("OVH Cloud service not available.", severity="error")
            return

        try:
            result = await svc.create_instance(
                project_id=self._project_id,
                name=name,
                flavor_id=flavor.get("id", ""),
                image_id=image.get("id", ""),
                region=region,
                ssh_key_id=ssh_key_id,
            )
            instance_id = result.get("id", "")
            self.notify(
                f"Instance '{name}' created successfully (ID: {instance_id}).",
                severity="information",
            )
            self.app.pop_screen()
        except Exception as exc:
            logger.error("Cloud instance creation failed: %s", exc)
            self.notify(f"Creation failed: {exc}", severity="error")

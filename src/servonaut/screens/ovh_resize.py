"""OVH VPS resize screen — select an upgrade model and trigger the resize."""

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


class OVHResizeScreen(Screen):
    """Screen for upgrading/resizing a VPS to a larger plan.

    Fetches available upgrade models from OVHcloud, shows them in a DataTable,
    and confirms the operation via ConfirmActionScreen before calling
    OVHVPSService.upgrade().
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        """Initialize the resize screen.

        Args:
            instance: Instance dictionary from the instance list.
        """
        super().__init__()
        self._instance = instance
        self._models: List[dict] = []

    def compose(self) -> ComposeResult:
        """Compose the resize UI."""
        name = self._instance.get('name') or self._instance.get('id', 'VPS')
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with ScrollableContainer(id="resize_container"):
                yield Static(
                    f"[bold cyan]Resize VPS: {name}[/bold cyan]",
                    id="resize_title",
                )
                yield Static(
                    "Choose an upgrade plan for this VPS. "
                    "Downgrades are not supported by OVHcloud.",
                    id="resize_description",
                )
                yield DataTable(id="models_table")
                yield Static(
                    "[dim]Select a plan and click Upgrade[/dim]",
                    id="resize_hint",
                )
                with Horizontal(id="resize_actions"):
                    yield Button(
                        "Upgrade Selected",
                        variant="warning",
                        id="btn_upgrade",
                    )
                    yield Button("Back", variant="default", id="btn_back")
        yield Footer()

    def on_mount(self) -> None:
        """Set up the DataTable and start loading upgrade models."""
        table = self.query_one("#models_table", DataTable)
        table.add_columns("Model", "vCPUs", "RAM", "Disk", "Price")
        table.cursor_type = "row"
        self.run_worker(self._load_models(), exclusive=True)

    async def _load_models(self) -> None:
        """Fetch available upgrade models and populate the DataTable."""
        vps_name = self._instance.get('id', '')
        if not vps_name:
            self.notify("No VPS ID found in instance data.", severity="error")
            return

        ovh_vps_service = getattr(self.app, 'ovh_vps_service', None)
        if ovh_vps_service is None:
            self.notify("OVH VPS service is not available.", severity="error")
            return

        try:
            self._models = await ovh_vps_service.list_upgrade_models(vps_name)
        except Exception as e:
            logger.error("Error loading VPS upgrade models: %s", e)
            self.notify(f"Failed to load upgrade models: {e}", severity="error")
            return

        table = self.query_one("#models_table", DataTable)
        table.clear()
        if not self._models:
            self.notify("No upgrade plans available for this VPS.", severity="warning")
            return

        for model in self._models:
            table.add_row(
                str(model.get('name', '')),
                str(model.get('vcpus', '-')),
                str(model.get('ram', '-')),
                str(model.get('disk', '-')),
                str(model.get('price', '-')),
            )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn_back":
            self.action_back()
        elif event.button.id == "btn_upgrade":
            await self._on_upgrade()

    async def _on_upgrade(self) -> None:
        """Confirm and execute the upgrade operation."""
        table = self.query_one("#models_table", DataTable)
        row_key = table.cursor_row

        if row_key < 0 or row_key >= len(self._models):
            self.notify("Please select a plan from the list.", severity="warning")
            return

        model = self._models[row_key]
        model_name = model.get('name', 'Unknown')
        vps_name = self._instance.get('id', '')
        instance_name = self._instance.get('name') or vps_name

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Resize VPS",
                description=(
                    f"Upgrade [bold]{instance_name}[/bold] to plan "
                    f"[bold]{model_name}[/bold]."
                ),
                consequences=[
                    "The VPS will be temporarily unavailable during the resize",
                    "Billing will change to the new plan immediately",
                    "Downgrades are not possible after this operation",
                ],
                confirm_text=instance_name,
                action_label="Upgrade Now",
                severity="warning",
            )
        )

        ovh_audit = getattr(self.app, 'ovh_audit', None)
        if ovh_audit is not None:
            from servonaut.services.ovh_audit import OVHAuditLogger
            ovh_audit.log_action(
                action="vps_upgrade",
                target=vps_name,
                details={"model": model_name},
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        ovh_vps_service = getattr(self.app, 'ovh_vps_service', None)
        if ovh_vps_service is None:
            self.notify("OVH VPS service is not available.", severity="error")
            return

        try:
            await ovh_vps_service.upgrade(vps_name, model_name)
            self.notify(
                f"Upgrade of {instance_name} to {model_name} has been queued.",
                severity="information",
            )
        except Exception as e:
            logger.error("VPS upgrade failed: %s", e)
            self.notify(f"Upgrade failed: {e}", severity="error")

    def action_back(self) -> None:
        """Navigate back."""
        self.app.pop_screen()

"""Wizard screen for creating a new OVH Public Cloud instance."""

from __future__ import annotations

import asyncio
import logging
from typing import List, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Select, Static,
)

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

                Static("[bold]Instance Name[/bold]", classes="section_header"),
                Static(
                    "[dim]Display name for the new instance — appears in the "
                    "OVH console and Servonaut's instance list.[/dim]",
                    classes="note",
                ),
                Input(placeholder="e.g. web-prod-1", id="input_name"),

                Static("[bold]Region[/bold]", classes="section_header"),
                Static(
                    "[dim]OVH datacenter code that hosts the instance. "
                    "Pick a region first — flavors and images load "
                    "filtered to it. Full datacenter list at "
                    "ovhcloud.com/en/about-us/data-centers/.[/dim]",
                    classes="note",
                ),
                Select(
                    options=[],
                    id="input_region",
                    prompt="Loading regions…",
                    allow_blank=True,
                ),

                Static("[bold]Select Flavor[/bold]", classes="section_header"),
                DataTable(id="flavors_table"),

                Static("[bold]Select Image[/bold]", classes="section_header"),
                DataTable(id="images_table"),

                Static("[bold]SSH Key (optional)[/bold]", classes="section_header"),
                # Empty-state hint shown by ``_load_keys`` when the
                # project has zero registered keys — otherwise hidden.
                Static("", id="keys_hint", classes="note hidden"),
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

        # Region first — once it resolves, the on_select_changed
        # handler kicks off the flavors / images loaders filtered to
        # the picked region. SSH keys are project-scoped (no region
        # binding) so they can load in parallel.
        self.run_worker(self._load_regions(), exclusive=False)
        self.run_worker(self._load_keys(), exclusive=False)

    # ------------------------------------------------------------------
    # Table setup
    # ------------------------------------------------------------------

    def _setup_tables(self) -> None:
        flavors_tbl = self.query_one("#flavors_table", DataTable)
        flavors_tbl.add_columns(
            "Name", "vCPUs", "RAM (GB)", "Disk (GB)",
            "Region", "Hourly", "Monthly",
        )
        flavors_tbl.cursor_type = "row"

        images_tbl = self.query_one("#images_table", DataTable)
        images_tbl.add_columns("Name", "OS Type", "Min Disk", "Region")
        images_tbl.cursor_type = "row"

        keys_tbl = self.query_one("#keys_table", DataTable)
        keys_tbl.add_columns("Name", "ID")
        keys_tbl.cursor_type = "row"

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    async def _load_regions(self) -> None:
        svc = getattr(self.app, "ovh_cloud_service", None)
        sel = self.query_one("#input_region", Select)
        if svc is None:
            self.notify("OVH Cloud service not available.", severity="error")
            return
        # Fetch the region list AND the project-wide flavor list in
        # parallel — the latter lets us hide regions with zero
        # deployable flavors so the user doesn't pick a dead zone and
        # see an empty table.
        try:
            regions, all_flavors = await asyncio.gather(
                svc.list_regions(self._project_id),
                svc.list_flavors(self._project_id),
                return_exceptions=False,
            )
        except Exception as exc:
            logger.error("Failed to load regions: %s", exc)
            self.notify(
                f"Error loading regions: {exc}",
                severity="error", markup=False,
            )
            return

        if not regions:
            sel.set_options([])
            sel.value = Select.NULL
            self.notify(
                "No regions returned for this project — check OVH "
                "credentials and that the project has Public Cloud "
                "enabled.",
                severity="warning", markup=False,
            )
            return

        # Set of regions that carry at least one deployable flavor.
        # OVH ``available=false`` flavors are catalogue placeholders
        # for capacity/withdrawn SKUs; filtering them out prevents
        # ghost regions from appearing in the picker.
        available_regions = {
            f.get("region") for f in (all_flavors or [])
            if f.get("region") and f.get("available", True)
        }
        filtered = [r for r in regions if r in available_regions]

        # Defensive fallback: if the flavor fetch returned an empty
        # set (older API or transient hiccup), don't filter at all —
        # better to show the raw region list than an empty picker.
        if not filtered:
            filtered = regions
            logger.warning(
                "OVH flavor fetch returned no regions; falling back "
                "to unfiltered region list."
            )

        # Render each option as ``GRA11 — Gravelines, France`` so the
        # user picks by location rather than by cryptic code; the value
        # stays as the raw code so the API call is unchanged.
        from servonaut.services.ovh_cloud_service import (
            format_ovh_region_label,
        )
        sel.set_options(
            [(format_ovh_region_label(r), r) for r in filtered]
        )
        # Default to the first region; on_select_changed picks it up
        # and loads the filtered flavors / images.
        sel.value = filtered[0]

    async def _load_flavors(self, region: str) -> None:
        svc = getattr(self.app, "ovh_cloud_service", None)
        tbl = self.query_one("#flavors_table", DataTable)
        tbl.clear()
        self._flavors = []
        if svc is None or not region:
            return
        try:
            raw_flavors = await svc.list_flavors(
                self._project_id, region=region,
            )
            # Hide ``available=false`` flavors — they're catalogue
            # placeholders the user can't deploy. ``True`` is the
            # default so older API responses without the flag aren't
            # accidentally filtered out.
            self._flavors = [
                f for f in raw_flavors if f.get("available", True)
            ]
            for flavor in self._flavors:
                ram_gb = (
                    round(flavor.get("ram", 0) / 1024, 1)
                    if flavor.get("ram") else 0
                )
                hourly = flavor.get("hourly_price") or ""
                monthly = flavor.get("monthly_price") or ""
                currency = flavor.get("currency") or ""
                # ``text`` from OVH is pre-formatted (e.g. "0.0086€");
                # bare numerics get a currency suffix here so the
                # column is unambiguous regardless of API shape.
                hourly_label = (
                    hourly if (hourly and not currency) or (
                        hourly and any(c in hourly for c in "€$£¥")
                    )
                    else (f"{hourly} {currency}" if hourly else "—")
                )
                monthly_label = (
                    monthly if (monthly and not currency) or (
                        monthly and any(c in monthly for c in "€$£¥")
                    )
                    else (f"{monthly} {currency}" if monthly else "—")
                )
                tbl.add_row(
                    flavor.get("name", ""),
                    str(flavor.get("vcpus", "")),
                    str(ram_gb),
                    str(flavor.get("disk", "")),
                    flavor.get("region", "") or "—",
                    hourly_label,
                    monthly_label,
                )
            # Default cursor on the first row so the user sees a
            # selection without having to click — a region change
            # otherwise leaves the table cursor stranded on a row
            # index that no longer exists in the new data set.
            if self._flavors:
                tbl.move_cursor(row=0)
        except Exception as exc:
            logger.error("Failed to load flavors: %s", exc)
            self.notify(f"Error loading flavors: {exc}", severity="error")

    async def _load_images(self, region: str) -> None:
        svc = getattr(self.app, "ovh_cloud_service", None)
        tbl = self.query_one("#images_table", DataTable)
        tbl.clear()
        self._images = []
        if svc is None or not region:
            return
        try:
            # Pull region-bound images AND any region-less ("shared")
            # ones — those are usable regardless of the picked region.
            region_images = await svc.list_images(
                self._project_id, region=region,
            )
            all_images = await svc.list_images(self._project_id)
            shared_images = [
                img for img in all_images
                if not (img.get("region") or "")
            ]
            self._images = list(region_images) + shared_images
            for image in self._images:
                tbl.add_row(
                    image.get("name", ""),
                    image.get("os_type", ""),
                    str(image.get("min_disk", "")),
                    image.get("region", "") or "any",
                )
            if self._images:
                tbl.move_cursor(row=0)
        except Exception as exc:
            logger.error("Failed to load images: %s", exc)
            self.notify(f"Error loading images: {exc}", severity="error")

    async def _load_keys(self) -> None:
        svc = getattr(self.app, "ovh_cloud_service", None)
        tbl = self.query_one("#keys_table", DataTable)
        hint = self.query_one("#keys_hint", Static)
        if svc is None:
            return
        try:
            self._keys = await svc.list_ssh_keys(self._project_id)

            def _s(x: str) -> str:
                if self.app.demo_mode and self.app.redaction_service:
                    return self.app.redaction_service.scrub_stream(x)
                return x

            for key in self._keys:
                tbl.add_row(
                    _s(key.get("name", "")),
                    key.get("id", ""),
                )
            if not self._keys:
                # Zero registered SSH keys — table renders as a 1-row
                # header strip, easy to miss on a small terminal.
                # Surface a hint pointing at the OVH SSH Keys screen
                # so the user knows where to add one.
                hint.update(
                    "[yellow]No SSH keys configured on this OVH "
                    "project. Add one via [b]OVH → SSH Keys[/b] "
                    "(sidebar) — without a key the new instance "
                    "boots without your public key in "
                    "authorized_keys.[/yellow]"
                )
                hint.display = True
            else:
                hint.display = False
        except Exception as exc:
            logger.error("Failed to load SSH keys: %s", exc)
            self.notify(f"Error loading SSH keys: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Region change → reload flavors + images filtered for that region.
    #
    # OVH flavors and images are region-bound (each has a unique ID
    # per region). Picking the region first and re-loading both
    # tables filtered for it prevents the ``Flavor X could not be
    # found`` error users hit when the wizard previously offered all
    # flavors across all regions next to a free-text region field.
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if (event.select.id != "input_region"
                or event.value is Select.NULL):
            return
        region = str(event.value)
        # ``group=`` scopes exclusivity per table so a fast
        # region-change cycle doesn't end up with an in-flight loader
        # for the OLD region clobbering the NEW region's table state
        # (resulting in "Please select an OS image" even when one
        # appears highlighted — the cursor pointed at a row index that
        # no longer existed in ``self._images``).
        self.run_worker(
            self._load_flavors(region),
            group="ovh_create_flavors", exclusive=True,
            name="ovh_create_load_flavors",
        )
        self.run_worker(
            self._load_images(region),
            group="ovh_create_images", exclusive=True,
            name="ovh_create_load_images",
        )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # ``_on_create`` calls ``push_screen_wait`` for the confirm
        # modal, which Textual 8.x requires to run inside a worker (not
        # just an async handler) — otherwise it raises NoActiveWorker.
        # Wrap the create flow in a worker rather than awaiting it
        # directly here.
        if event.button.id == "btn_back":
            self.action_back()
        elif event.button.id == "btn_create":
            self.run_worker(
                self._on_create(),
                exclusive=True,
                name="ovh_cloud_create_submit",
            )

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
            logger.warning(
                "Flavor selection out of bounds: cursor_row=%d, "
                "flavors_count=%d (table_rows=%d)",
                flavor_row, len(self._flavors), flavors_tbl.row_count,
            )
            self.notify(
                "Please select a flavor.",
                severity="warning", markup=False,
            )
            return

        images_tbl = self.query_one("#images_table", DataTable)
        image_row = images_tbl.cursor_row
        if image_row < 0 or image_row >= len(self._images):
            logger.warning(
                "Image selection out of bounds: cursor_row=%d, "
                "images_count=%d (table_rows=%d)",
                image_row, len(self._images), images_tbl.row_count,
            )
            self.notify(
                "Please select an OS image.",
                severity="warning", markup=False,
            )
            return

        region_sel = self.query_one("#input_region", Select)
        region_val = region_sel.value
        region = "" if region_val is Select.NULL else str(region_val)
        if not region:
            self.notify(
                "Please pick a region from the dropdown.",
                severity="warning", markup=False,
            )
            return

        flavor = self._flavors[flavor_row]
        image = self._images[image_row]

        # Defence-in-depth: the tables are now reloaded on every
        # region change so a mismatch shouldn't reach this point —
        # but a stale row reference (e.g. user clicked Create while
        # the reload was mid-flight) could still slip through. The
        # guard catches that and surfaces a clear message instead of
        # the API's "Flavor X could not be found" stack trace.
        flavor_region = (flavor.get("region") or "").strip()
        image_region = (image.get("region") or "").strip()
        if flavor_region and flavor_region != region:
            self.notify(
                f"Flavor '{flavor.get('name')}' belongs to region "
                f"'{flavor_region}', not '{region}'. Re-pick the "
                "flavor — the table refreshes on region change.",
                severity="error", markup=False,
            )
            return
        if image_region and image_region != region:
            self.notify(
                f"Image '{image.get('name')}' belongs to region "
                f"'{image_region}', not '{region}'. Re-pick the "
                "image — the table refreshes on region change.",
                severity="error", markup=False,
            )
            return

        keys_tbl = self.query_one("#keys_table", DataTable)
        key_row = keys_tbl.cursor_row
        ssh_key_id = ""
        if 0 <= key_row < len(self._keys):
            ssh_key_id = self._keys[key_row].get("id", "")

        flavor_name = flavor.get("name", flavor.get("id", ""))
        image_name = image.get("name", image.get("id", ""))
        # Surface the OVH-quoted monthly price in the confirm modal so
        # the cost reminder isn't tucked away in the table — matches
        # the Hetzner wizard's confirm-modal behaviour.
        monthly = (flavor.get("monthly_price") or "").strip()
        currency = (flavor.get("currency") or "").strip()
        if monthly:
            cost_line = (
                f"Billing starts immediately (~{monthly}"
                f"{(' ' + currency) if currency else ''}/month)"
            )
        else:
            cost_line = (
                "Billing starts immediately (price not returned by API "
                "— check the OVH console)"
            )

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Create Cloud Instance",
                description=(
                    f"Create instance [bold]{name}[/bold] in [bold]{region}[/bold] "
                    f"using [bold]{flavor_name}[/bold] / [bold]{image_name}[/bold]."
                ),
                consequences=[
                    cost_line,
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

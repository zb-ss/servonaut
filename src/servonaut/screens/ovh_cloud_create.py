"""Wizard screen for creating a new OVH Public Cloud instance.

With several OVH accounts configured, an account picker comes first: the
project, regions, flavors, images and SSH keys are the chosen account's,
and the instance is created there.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional, TYPE_CHECKING

from rich.markup import escape

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Input, Select, Static,
)

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._demo_resolve import replace_instances
from servonaut.screens._provider_accounts import (
    UnknownAccountError,
    account_settings,
    inventory,
    ovh_services,
    provider_accounts,
    registry_for,
)
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.safe_header import SafeHeader
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

    # Label of the chosen account; "" is the default account.
    _account: str = ""

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def __init__(self, account: Optional[str] = None) -> None:
        super().__init__()
        self._account = account or ""
        self._project_id: str = ""
        self._flavors: List[dict] = []
        self._images: List[dict] = []
        self._keys: List[dict] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]Create Cloud Instance[/bold cyan]",
                    id="cloud_create_title",
                ),
                # Hidden unless several OVH accounts are configured.
                AccountPicker.for_provider(
                    registry_for(self.app, "ovh"), "ovh",
                    value=self._account or None, id="cloud_create_account",
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
        self._account = self.query_one(
            "#cloud_create_account", AccountPicker,
        ).account
        self._load_account()

    def _load_account(self) -> None:
        """Load the chosen account's first project into the wizard."""
        try:
            settings = account_settings(self.app, "ovh", self._account)
        except UnknownAccountError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        project_ids: List[str] = getattr(settings, "cloud_project_ids", [])
        # Shown once, and gone when another account has a project.
        shown_errors = list(self.query("#no_project_error"))

        if not project_ids:
            if shown_errors:
                return
            self.query_one("#cloud_create_container", ScrollableContainer).mount(
                Static(
                    "[red]No OVH cloud project IDs configured. "
                    "Add them in Settings under OVH.[/red]",
                    id="no_project_error",
                )
            )
            return

        for error in shown_errors:
            error.remove()
        # Use the first configured project for the wizard.
        self._project_id = project_ids[0]

        # Region first — once it resolves, the on_select_changed
        # handler kicks off the flavors / images loaders filtered to
        # the picked region. SSH keys are project-scoped (no region
        # binding) so they can load in parallel. A group per loader lets
        # an account switch cancel the loads of the previous account.
        self.run_worker(self._load_regions(), group="ovh_create_regions", exclusive=True)
        self.run_worker(self._load_keys(), group="ovh_create_keys", exclusive=True)

    def on_account_picker_changed(self, event: AccountPicker.Changed) -> None:
        """Another account was picked: the wizard starts over in its project."""
        self._account = event.account
        self._project_id = ""
        for group in (
            "ovh_create_regions", "ovh_create_keys",
            "ovh_create_flavors", "ovh_create_images",
        ):
            self.workers.cancel_group(self, group)
        self._flavors, self._images, self._keys = [], [], []
        for selector in ("#flavors_table", "#images_table", "#keys_table"):
            self.query_one(selector, DataTable).clear()
        self.query_one("#keys_hint", Static).display = False
        region = self.query_one("#input_region", Select)
        region.set_options([])
        self._load_account()

    def _cloud_service(self):
        """The chosen account's Public Cloud service (None when unavailable)."""
        try:
            return ovh_services(self.app, self._account).cloud
        except UnknownAccountError:
            return None

    # ------------------------------------------------------------------
    # Table setup
    # ------------------------------------------------------------------

    def _setup_tables(self) -> None:
        flavors_tbl = self.query_one("#flavors_table", DataTable)
        flavors_tbl.add_columns(
            "Name", "vCPUs", "RAM (GiB)", "Disk (GB)",
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
        svc = self._cloud_service()
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
        svc = self._cloud_service()
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
                # OVH's flavor API supplies RAM in GiB, not MiB.
                ram_gib = flavor.get("ram", 0)
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
                    str(ram_gib),
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
            self.notify(f"Error loading flavors: {exc}", severity="error", markup=False)

    async def _load_images(self, region: str) -> None:
        svc = self._cloud_service()
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
            self.notify(f"Error loading images: {exc}", severity="error", markup=False)

    async def _load_keys(self) -> None:
        svc = self._cloud_service()
        tbl = self.query_one("#keys_table", DataTable)
        hint = self.query_one("#keys_hint", Static)
        if svc is None:
            return
        try:
            self._keys = await svc.list_ssh_keys(self._project_id)

            def _s(x: str) -> str:
                if self.app.demo_mode:
                    redactor = self.app.redaction_service
                    return redactor.redact_key_name(x) if redactor else "Hidden"
                return x

            for index, key in enumerate(self._keys, start=1):
                tbl.add_row(
                    _s(key.get("name", "")),
                    f"key-{index:03d}" if self.app.demo_mode else key.get("id", ""),
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
            self.notify(f"Error loading SSH keys: {exc}", severity="error", markup=False)

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

        # With several accounts, say which one is billed.
        account = (
            f" in account [bold]{escape(self._account)}[/bold]"
            if len(provider_accounts(self.app, "ovh")) > 1 else ""
        )
        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Create Cloud Instance",
                description=(
                    f"Create instance [bold]{name}[/bold] in [bold]{region}[/bold] "
                    f"using [bold]{flavor_name}[/bold] / [bold]{image_name}[/bold]"
                    f"{account}."
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

        svc = self._cloud_service()
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
            if self.app.demo_mode:
                redactor = self.app.redaction_service
                instance_id = redactor.redact_instance_id(instance_id) if redactor else "Hidden"
            self.notify(
                f"Instance '{name}' created successfully (ID: {instance_id}).",
                severity="information",
            )
        except Exception as exc:
            logger.error("Cloud instance creation failed: %s", exc)
            error = "Provider request failed. See logs for details." if self.app.demo_mode else str(exc)
            self.notify(f"Creation failed: {error}", severity="error", markup=False)
            return

        # List the new instance without the user having to refresh.
        # Best-effort: a failure here does not undo the create.
        try:
            await self._refresh_instances_after_create()
        except Exception as exc:
            logger.warning("Post-create instance refresh failed: %s", exc)
        # True tells the screen that opened the wizard (the OVH Manager)
        # that an instance was created, so it reloads its list.
        self.dismiss(True)

    async def _refresh_instances_after_create(self) -> None:
        """Replace the OVH slice of ``app.instances`` with a fresh fetch.

        Every account is fetched, so the new instance is listed under its
        own account and no other account's servers drop out.
        """
        svc = inventory(self.app, "ovh")
        if svc is None:
            return
        rows = await svc.fetch_instances_cached(force_refresh=True)
        # Keeps the real rows aside and lists them redacted in demo mode.
        replace_instances(self.app, "ovh", rows)

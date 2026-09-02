"""Wizard screen for creating a new Hetzner Cloud server.

Mirrors :class:`servonaut.screens.ovh_cloud_create.OVHCloudCreateScreen`
in shape — the two providers share the same conceptual flow (name,
type/flavor, image, location, SSH key, confirm, create) — but adapts
each step to Hetzner's API and config defaults.

Notable differences from the OVH wizard:

* Server-type rows show monthly EUR price (Hetzner bills in EUR
  globally; the API exposes per-location pricing that is identical
  within a region group).
* Architecture mismatch is enforced client-side at create time:
  Hetzner ARM server types only boot ARM images. Hard-rejecting the
  combination here matches what the API would do, but earlier and
  with a clearer message.
* The SSH-key table is single-select with a "use default" hint;
  leaving it unselected delegates to
  ``config.hetzner.default_hetzner_ssh_key`` and the service-side
  no-keys footgun guard.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

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


class HetznerCreateScreen(Screen):
    """Wizard for creating a new Hetzner Cloud server."""

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
        self._server_types: List[dict] = []
        self._images: List[dict] = []
        self._locations: List[dict] = []
        self._ssh_keys: List[dict] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]Create Hetzner Cloud Server[/bold cyan]",
                    id="hetzner_create_title",
                ),

                Static("[bold]Server Name[/bold]", classes="section_header"),
                Static(
                    "[dim]Display name for the server — appears in the "
                    "Hetzner console and Servonaut's instance list. "
                    "1-253 ASCII chars, must start with a letter or "
                    "digit.[/dim]",
                    classes="note",
                ),
                Input(placeholder="e.g. demo-web-01", id="hetzner_input_name"),

                Static("[bold]Select Server Type[/bold]",
                       classes="section_header"),
                Static(
                    "[dim]Hetzner server types vary by architecture (x86 vs "
                    "arm) and price. Pick a row — its [b]Arch[/b] column "
                    "must match the image you select below.[/dim]",
                    classes="note",
                ),
                DataTable(id="hetzner_types_table"),

                Static("[bold]Select Image[/bold]", classes="section_header"),
                Static(
                    "[dim]Stock OS images only (snapshots and backups are "
                    "managed elsewhere). [b]Arch[/b] must match the "
                    "selected server type.[/dim]",
                    classes="note",
                ),
                DataTable(id="hetzner_images_table"),

                Static("[bold]Select Location[/bold]",
                       classes="section_header"),
                DataTable(id="hetzner_locations_table"),

                Static(
                    "[bold]SSH Key (optional)[/bold]",
                    classes="section_header",
                ),
                Static(
                    "[dim]Leave unselected to use your configured default key "
                    "([b]config.hetzner.default_hetzner_ssh_key[/b]). "
                    "Hetzner refuses to create a server without keys to "
                    "avoid leaking root passwords on a billed but "
                    "unreachable box.[/dim]",
                    classes="note",
                ),
                DataTable(id="hetzner_keys_table"),

                Horizontal(
                    Button("Create Server", variant="primary",
                           id="btn_hetzner_create_submit"),
                    Button("Back", variant="default",
                           id="btn_hetzner_create_back"),
                    id="hetzner_create_actions",
                ),

                id="hetzner_create_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._setup_tables()

        svc = getattr(self.app, "hetzner_service", None)
        if svc is None:
            self.query_one(
                "#hetzner_create_container", ScrollableContainer,
            ).mount(
                Static(
                    "[red]Hetzner Cloud is not enabled. Configure a token "
                    "in Settings → Hetzner Cloud first.[/red]",
                    id="hetzner_not_configured_error",
                )
            )
            self.query_one(
                "#btn_hetzner_create_submit", Button,
            ).disabled = True
            return

        self.run_worker(self._load_server_types(), exclusive=False)
        self.run_worker(self._load_images(), exclusive=False)
        self.run_worker(self._load_locations(), exclusive=False)
        self.run_worker(self._load_ssh_keys(), exclusive=False)

    # ------------------------------------------------------------------
    # Table setup
    # ------------------------------------------------------------------

    def _setup_tables(self) -> None:
        types_tbl = self.query_one("#hetzner_types_table", DataTable)
        types_tbl.add_columns("Name", "vCPUs", "RAM", "Disk", "Arch",
                              "€/month")
        types_tbl.cursor_type = "row"

        images_tbl = self.query_one("#hetzner_images_table", DataTable)
        images_tbl.add_columns("Name", "Description", "Arch")
        images_tbl.cursor_type = "row"

        loc_tbl = self.query_one("#hetzner_locations_table", DataTable)
        loc_tbl.add_columns("Name", "City", "Country", "Description")
        loc_tbl.cursor_type = "row"

        keys_tbl = self.query_one("#hetzner_keys_table", DataTable)
        keys_tbl.add_columns("Name", "ID", "Fingerprint")
        keys_tbl.cursor_type = "row"

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    async def _load_server_types(self) -> None:
        svc = self.app.hetzner_service
        tbl = self.query_one("#hetzner_types_table", DataTable)
        try:
            self._server_types = await svc.list_server_types()
            for st in self._server_types:
                tbl.add_row(
                    st.get("name", ""),
                    str(st.get("cores", "")),
                    f"{st.get('memory_gb', 0)} GB",
                    f"{st.get('disk_gb', 0)} GB",
                    st.get("architecture", ""),
                    st.get("monthly_price_gross", "") or "-",
                )
            self._preselect_default(
                tbl, self._server_types, "name",
                getattr(self.app.config_manager.get().hetzner,
                        "default_server_type", ""),
            )
        except Exception as exc:
            logger.error("Failed to load Hetzner server types: %s", exc)
            self.notify(f"Could not load server types: {exc}",
                        severity="error", markup=False)

    async def _load_images(self) -> None:
        svc = self.app.hetzner_service
        tbl = self.query_one("#hetzner_images_table", DataTable)
        try:
            self._images = await svc.list_images()
            for img in self._images:
                tbl.add_row(
                    img.get("name", ""),
                    img.get("description", ""),
                    img.get("architecture", ""),
                )
            self._preselect_default(
                tbl, self._images, "name",
                getattr(self.app.config_manager.get().hetzner,
                        "default_image", ""),
            )
        except Exception as exc:
            logger.error("Failed to load Hetzner images: %s", exc)
            self.notify(f"Could not load images: {exc}",
                        severity="error", markup=False)

    async def _load_locations(self) -> None:
        svc = self.app.hetzner_service
        tbl = self.query_one("#hetzner_locations_table", DataTable)
        try:
            self._locations = await svc.list_locations()
            for loc in self._locations:
                tbl.add_row(
                    loc.get("name", ""),
                    loc.get("city", ""),
                    loc.get("country", ""),
                    loc.get("description", ""),
                )
            self._preselect_default(
                tbl, self._locations, "name",
                getattr(self.app.config_manager.get().hetzner,
                        "default_location", ""),
            )
        except Exception as exc:
            logger.error("Failed to load Hetzner locations: %s", exc)
            self.notify(f"Could not load locations: {exc}",
                        severity="error", markup=False)

    async def _load_ssh_keys(self) -> None:
        svc = self.app.hetzner_service
        tbl = self.query_one("#hetzner_keys_table", DataTable)
        try:
            self._ssh_keys = await svc.list_ssh_keys()
            for key in self._ssh_keys:
                name = str(key.get("name", ""))
                # Key labels are user-chosen (an email address is common) --
                # shown as a pool key name when demo mode is on.
                if self.app.demo_mode and self.app.redaction_service:
                    name = self.app.redaction_service.redact_key_name(name)
                tbl.add_row(
                    name,
                    key.get("id", ""),
                    key.get("fingerprint", "")[:32],
                )
            # Pre-select the row matching the configured default key so
            # the cursor lands on what the user expects without them
            # having to spot it. Without this the wizard would call
            # create_server with ssh_keys=None and rely on the silent
            # service-side fallback — which surfaces a confusing
            # "Refusing to create…without SSH keys" error if the
            # default_hetzner_ssh_key happens to be empty.
            self._preselect_default(
                tbl, self._ssh_keys, "name",
                getattr(self.app.config_manager.get().hetzner,
                        "default_hetzner_ssh_key", ""),
            )
        except Exception as exc:
            logger.error("Failed to load Hetzner SSH keys: %s", exc)
            self.notify(f"Could not load SSH keys: {exc}",
                        severity="error", markup=False)

    def _display_key_name(self, name: str) -> str:
        """Key label as shown on screen -- a pool key name in demo mode."""
        if name and self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_key_name(name)
        return name

    @staticmethod
    def _preselect_default(
        tbl: DataTable, rows: List[dict], key: str, default: str,
    ) -> None:
        """Move the cursor to the row whose ``key`` matches ``default``.

        No-op when the default is empty, the table is empty, or the
        default doesn't match any loaded row. The user can always move
        the cursor afterwards — this is purely a head-start.
        """
        if not default or not rows:
            return
        for idx, row in enumerate(rows):
            if row.get(key) == default:
                tbl.move_cursor(row=idx)
                return

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # ``_on_create`` calls ``push_screen_wait`` for the confirm
        # modal, which Textual 8.x requires to run inside a worker (not
        # just an async handler) — otherwise it raises NoActiveWorker.
        # Wrap the create flow in a worker rather than awaiting it
        # directly here.
        if event.button.id == "btn_hetzner_create_back":
            self.action_back()
        elif event.button.id == "btn_hetzner_create_submit":
            self.run_worker(
                self._on_create(),
                exclusive=True,
                name="hetzner_create_submit",
            )

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Create flow
    # ------------------------------------------------------------------

    async def _on_create(self) -> None:
        """Validate selections, confirm, call the Hetzner service."""
        name = self.query_one("#hetzner_input_name", Input).value.strip()
        if not name:
            self.notify("Please enter a server name.", severity="warning",
                        markup=False)
            return

        types_tbl = self.query_one("#hetzner_types_table", DataTable)
        type_row = types_tbl.cursor_row
        if type_row < 0 or type_row >= len(self._server_types):
            self.notify("Please select a server type.", severity="warning",
                        markup=False)
            return

        images_tbl = self.query_one("#hetzner_images_table", DataTable)
        image_row = images_tbl.cursor_row
        if image_row < 0 or image_row >= len(self._images):
            self.notify("Please select an OS image.", severity="warning",
                        markup=False)
            return

        loc_tbl = self.query_one("#hetzner_locations_table", DataTable)
        loc_row = loc_tbl.cursor_row
        if loc_row < 0 or loc_row >= len(self._locations):
            self.notify("Please select a location.", severity="warning",
                        markup=False)
            return

        server_type = self._server_types[type_row]
        image = self._images[image_row]
        location = self._locations[loc_row]

        type_arch = (server_type.get("architecture") or "").lower()
        image_arch = (image.get("architecture") or "").lower()
        if type_arch and image_arch and type_arch != image_arch:
            self.notify(
                f"Architecture mismatch: server type '{server_type.get('name')}' "
                f"is {type_arch} but image '{image.get('name')}' is {image_arch}. "
                "Pick an image whose Arch column matches the server type.",
                severity="error", markup=False,
            )
            return

        keys_tbl = self.query_one("#hetzner_keys_table", DataTable)
        key_row = keys_tbl.cursor_row
        ssh_keys: Optional[List[str]] = None
        ssh_key_label = ""
        if 0 <= key_row < len(self._ssh_keys):
            picked = self._ssh_keys[key_row]
            ssh_keys = [picked.get("name") or picked.get("id") or ""]
            ssh_key_label = self._display_key_name(picked.get("name", ""))

        # Pre-flight check: if the user didn't pick a row AND no default
        # is configured in Settings, surface a clear actionable message
        # here rather than let the service-layer footgun guard fire
        # with a generic "Refusing to create" stack trace. Mirrors the
        # service-side guard's intent but at a UX-friendly layer.
        config_default = (
            self.app.config_manager.get().hetzner.default_hetzner_ssh_key or ""
        ).strip()
        if not ssh_keys and not config_default:
            if not self._ssh_keys:
                self.notify(
                    "No SSH keys are registered with Hetzner Cloud yet. "
                    "Run `servonaut hetzner ssh-keys add <name> "
                    "--public-key-file ~/.ssh/id_ed25519.pub` first.",
                    severity="error", markup=False,
                )
            else:
                self.notify(
                    "Pick an SSH key from the table, or configure one as "
                    "the default in Settings → Hetzner Cloud → Hetzner "
                    "SSH Key. Hetzner refuses to create a server without "
                    "keys (it would emit a random root password we can't "
                    "recover).",
                    severity="error", markup=False,
                )
            return
        if not ssh_key_label:
            # Wizard is delegating to the configured default — show the
            # actual value in the confirm modal so the user sees what's
            # about to be injected, not just a generic "(default)".
            ssh_key_label = f"{self._display_key_name(config_default)} (config default)"

        type_name = server_type.get("name", "")
        image_name = image.get("name", "")
        location_name = location.get("name", "")
        monthly_price = server_type.get("monthly_price_gross", "") or "?"

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Create Hetzner Cloud Server",
                description=(
                    f"Create [bold]{name}[/bold] in [bold]{location_name}[/bold] "
                    f"as [bold]{type_name}[/bold] / [bold]{image_name}[/bold] "
                    f"with SSH key [bold]{ssh_key_label}[/bold]."
                ),
                consequences=[
                    f"Billing starts immediately (~€{monthly_price}/month gross)",
                    "Charges continue until the server is deleted",
                ],
                confirm_text="create",
                action_label="Create Server",
                severity="warning",
            )
        )

        if not confirmed:
            return

        svc = self.app.hetzner_service
        if svc is None:
            self.notify("Hetzner Cloud service is not available.",
                        severity="error", markup=False)
            return

        submit_btn = self.query_one(
            "#btn_hetzner_create_submit", Button,
        )
        submit_btn.disabled = True
        try:
            instance = await svc.create_server(
                name=name,
                server_type=type_name,
                image=image_name,
                location=location_name,
                ssh_keys=ssh_keys,
            )
        except Exception as exc:
            logger.error("Hetzner server creation failed: %s", exc)
            self.notify(
                f"Creation failed: {exc}", severity="error", markup=False,
            )
            submit_btn.disabled = False
            return

        instance_id = instance.get("id", "")
        self.notify(
            f"Server '{name}' created (ID: {instance_id}). "
            "Refreshing instance list…",
            severity="information", markup=False,
        )

        # Trigger an instance-list refresh so the new server shows up
        # without the user having to hit `r`. Best-effort: failures here
        # don't undo the create.
        try:
            await self._refresh_instances_after_create()
        except Exception as exc:
            logger.warning("Post-create instance refresh failed: %s", exc)

        self.app.pop_screen()

    async def _refresh_instances_after_create(self) -> None:
        """Re-merge Hetzner instances into ``app.instances`` after create.

        Mirrors the merge pattern used by ``InstanceListScreen`` and
        ``HetznerSetupScreen`` — non-Hetzner rows are preserved, the
        Hetzner slice is replaced with a fresh fetch.
        """
        svc = self.app.hetzner_service
        if svc is None:
            return
        new_hetzner = await svc.fetch_instances_cached(force_refresh=True)
        existing = list(getattr(self.app, "instances", []) or [])
        non_hetzner = [
            i for i in existing if not i.get("is_hetzner")
        ]
        self.app.instances = non_hetzner + list(new_hetzner)

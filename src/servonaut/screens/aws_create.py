"""Wizard screen for launching a new AWS EC2 instance.

Mirrors :class:`servonaut.screens.hetzner_create.HetznerCreateScreen`
in shape, but adapts to EC2's region-scoped API surface:

* Region selection is FIRST — all subsequent describe calls (AMIs,
  instance types, key pairs, subnets, security groups) are scoped to
  the picked region and reload automatically when the region row changes.
* AMI search is via a text ``Input`` above the AMI table; changing the
  input text re-runs ``list_amis(region, name_filter=…)`` in an
  exclusive worker so the table stays responsive.
* Each of the five dependent tables loads in its own exclusive named-group
  worker (``aws_create_amis``, ``aws_create_types``, ``aws_create_keys``,
  ``aws_create_subnets``, ``aws_create_sgs``) — cancelling the previous
  request when the region changes.

Design intent: the wizard collects all required EC2 ``RunInstances``
parameters up-front so the user can review everything before billing
starts. The confirm modal shows the selected AMI, type, key pair, subnet,
and SG so surprises are minimal.

Demo mode: this is a setup/launch wizard screen — outside demo-recording
scope. ``notify()`` is already auto-scrubbed by the app override; pass
``markup=False`` on every ``notify()`` with dynamic content.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

from rich.markup import escape as markup_escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.utils.formatting import escape_cell
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)

# Debounce delay (seconds) before re-running AMI search after the user
# stops typing in the search field.  Keeps describe-images calls bounded.
_AMI_SEARCH_DEBOUNCE_S = 0.4


class AWSCreateScreen(Screen):
    """Wizard for launching a new AWS EC2 instance."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        super().__init__()
        self._regions: List[str] = []
        self._amis: List[dict] = []
        self._instance_types: List[dict] = []
        self._key_pairs: List[dict] = []
        self._subnets: List[dict] = []
        self._security_groups: List[dict] = []
        # Timer handle for AMI search debounce (set_timer returns a Timer)
        self._ami_search_timer: Optional[object] = None

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]Launch EC2 Instance[/bold cyan]",
                    id="aws_create_title",
                ),

                Static("[bold]Instance Name[/bold]", classes="section_header"),
                Static(
                    "[dim]Display name for the new instance — stored as the "
                    "[b]Name[/b] tag and visible in the EC2 console and "
                    "Servonaut's instance list.[/dim]",
                    classes="note",
                ),
                Input(placeholder="e.g. web-prod-01", id="aws_input_name"),

                Static("[bold]Select Region[/bold]", classes="section_header"),
                Static(
                    "[dim]Pick a region first — AMI / instance-type / "
                    "key-pair / subnet / SG tables reload automatically "
                    "when the region row changes.[/dim]",
                    classes="note",
                ),
                DataTable(id="aws_regions_table"),

                Static("[bold]Search AMI[/bold]", classes="section_header"),
                Static(
                    "[dim]Filter by name substring (e.g. \"al2023\" or "
                    "\"ubuntu-22\"). Only public Amazon-owned AMIs are "
                    "shown by default. Leave blank to list the 50 most "
                    "recent.[/dim]",
                    classes="note",
                ),
                Input(placeholder="Filter by name…", id="aws_input_ami_search"),

                Static("[bold]Select AMI[/bold]", classes="section_header"),
                DataTable(id="aws_amis_table"),

                Static("[bold]Select Instance Type[/bold]",
                       classes="section_header"),
                DataTable(id="aws_types_table"),

                Static("[bold]Select Key Pair[/bold]", classes="section_header"),
                Static(
                    "[dim]EC2 key pair whose public key will be injected "
                    "into the instance. The private key must be on your "
                    "local machine (~/.ssh/).[/dim]",
                    classes="note",
                ),
                DataTable(id="aws_keys_table"),

                Static("[bold]Select Subnet[/bold]", classes="section_header"),
                Static(
                    "[dim]VPC subnet for network placement. Choose one in "
                    "the availability zone you want. A public subnet gives "
                    "the instance a public IP automatically (depending on "
                    "the subnet's auto-assign setting).[/dim]",
                    classes="note",
                ),
                DataTable(id="aws_subnets_table"),

                Static("[bold]Select Security Group[/bold]",
                       classes="section_header"),
                Static(
                    "[dim]The security group controls inbound/outbound "
                    "firewall rules. Only one group is supported here; "
                    "you can attach additional groups from the console "
                    "after launch.[/dim]",
                    classes="note",
                ),
                DataTable(id="aws_sg_table"),

                Horizontal(
                    Button("Launch Instance", variant="primary",
                           id="btn_aws_create_submit"),
                    Button("Back", variant="default",
                           id="btn_aws_create_back"),
                    id="aws_create_actions",
                ),

                id="aws_create_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._setup_tables()

        svc = getattr(self.app, "aws_service", None)
        if svc is None:
            try:
                self.query_one(
                    "#aws_create_container", ScrollableContainer,
                ).mount(
                    Static(
                        "[red]AWS is not configured. Ensure boto3 credentials "
                        "are available (env vars, ~/.aws/, or an IAM role) "
                        "and restart Servonaut.[/red]",
                        id="aws_not_configured_error",
                    )
                )
            except Exception:  # pragma: no cover - defensive
                pass
            try:
                self.query_one("#btn_aws_create_submit", Button).disabled = True
            except Exception:  # pragma: no cover - defensive
                pass
            return

        self.run_worker(
            self._load_regions(),
            exclusive=True,
            name="aws_create_load_regions",
        )

    # ------------------------------------------------------------------
    # Table setup
    # ------------------------------------------------------------------

    def _setup_tables(self) -> None:
        regions_tbl = self.query_one("#aws_regions_table", DataTable)
        regions_tbl.add_columns("Region")
        regions_tbl.cursor_type = "row"

        amis_tbl = self.query_one("#aws_amis_table", DataTable)
        amis_tbl.add_columns(
            "AMI ID", "Name", "Arch", "Virt", "Created",
        )
        amis_tbl.cursor_type = "row"

        types_tbl = self.query_one("#aws_types_table", DataTable)
        types_tbl.add_columns("Type", "vCPUs", "RAM (MiB)")
        types_tbl.cursor_type = "row"

        keys_tbl = self.query_one("#aws_keys_table", DataTable)
        keys_tbl.add_columns("Key Name", "ID", "Fingerprint")
        keys_tbl.cursor_type = "row"

        subnets_tbl = self.query_one("#aws_subnets_table", DataTable)
        subnets_tbl.add_columns(
            "Subnet ID", "VPC", "AZ", "CIDR", "Free IPs",
        )
        subnets_tbl.cursor_type = "row"

        sg_tbl = self.query_one("#aws_sg_table", DataTable)
        sg_tbl.add_columns("Group ID", "Name", "Description", "VPC")
        sg_tbl.cursor_type = "row"

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    async def _load_regions(self) -> None:
        svc = self.app.aws_service
        tbl = self.query_one("#aws_regions_table", DataTable)
        tbl.clear()
        self._regions = []
        # Resolve the configured default region first — it doubles as the
        # bootstrap region for the describe_regions client, so region listing
        # works even when no ambient AWS_DEFAULT_REGION is set.
        default_region = ""
        try:
            default_region = (
                self.app.config_manager.get().aws.default_region or ""
            )
        except Exception:
            pass
        try:
            self._regions = await svc.list_regions(
                bootstrap_region=default_region or "us-east-1"
            )
            for region in self._regions:
                tbl.add_row(region, key=region)
            # Pre-select default region from config
            self._preselect_default(tbl, self._regions, default_region)
            if self._regions:
                selected_region = self._regions[tbl.cursor_row]
                self._load_region_dependents(selected_region)
        except Exception as exc:
            logger.error("Failed to load AWS regions: %s", exc)
            exc_msg = str(exc)
            if self.app.demo_mode and self.app.redaction_service:
                exc_msg = self.app.redaction_service.scrub_stream(exc_msg)
            self.notify(
                f"Could not load regions: {exc_msg}",
                severity="error", markup=False,
            )

    def _load_region_dependents(self, region: str) -> None:
        """Fire all region-scoped loaders in exclusive named groups."""
        if not region:
            return
        ami_filter = ""
        try:
            ami_filter = self.query_one(
                "#aws_input_ami_search", Input,
            ).value.strip()
        except Exception:
            pass
        self.run_worker(
            self._load_amis(region, name_filter=ami_filter),
            group="aws_create_amis",
            exclusive=True,
            name="aws_create_load_amis",
        )
        self.run_worker(
            self._load_instance_types(region),
            group="aws_create_types",
            exclusive=True,
            name="aws_create_load_types",
        )
        self.run_worker(
            self._load_key_pairs(region),
            group="aws_create_keys",
            exclusive=True,
            name="aws_create_load_keys",
        )
        self.run_worker(
            self._load_subnets(region),
            group="aws_create_subnets",
            exclusive=True,
            name="aws_create_load_subnets",
        )
        self.run_worker(
            self._load_security_groups(region),
            group="aws_create_sgs",
            exclusive=True,
            name="aws_create_load_sgs",
        )

    async def _load_amis(self, region: str, name_filter: str = "") -> None:
        svc = self.app.aws_service
        tbl = self.query_one("#aws_amis_table", DataTable)
        tbl.clear()
        self._amis = []
        if not region:
            return
        try:
            self._amis = await svc.list_amis(region, name_filter=name_filter)
            for ami in self._amis:
                tbl.add_row(
                    escape_cell(ami.get("image_id", "")),
                    escape_cell(ami.get("name", "")),
                    escape_cell(ami.get("architecture", "")),
                    escape_cell(ami.get("virtualization_type", "")),
                    escape_cell((ami.get("creation_date", "") or "")[:10]),
                    key=ami.get("image_id", ""),
                )
            if self._amis:
                tbl.move_cursor(row=0)
        except Exception as exc:
            logger.error("Failed to load AMIs for %s: %s", region, exc)
            exc_msg = str(exc)
            if self.app.demo_mode and self.app.redaction_service:
                exc_msg = self.app.redaction_service.scrub_stream(exc_msg)
            self.notify(
                f"Could not load AMIs: {exc_msg}",
                severity="error", markup=False,
            )

    async def _load_instance_types(self, region: str) -> None:
        svc = self.app.aws_service
        tbl = self.query_one("#aws_types_table", DataTable)
        tbl.clear()
        self._instance_types = []
        if not region:
            return
        try:
            self._instance_types = await svc.list_instance_types(region)
            for it in self._instance_types:
                tbl.add_row(
                    escape_cell(it.get("instance_type", "")),
                    str(it.get("vcpus", "")),
                    str(it.get("memory_mib", "")),
                    key=it.get("instance_type", ""),
                )
            if self._instance_types:
                tbl.move_cursor(row=0)
        except Exception as exc:
            logger.error(
                "Failed to load instance types for %s: %s", region, exc,
            )
            exc_msg = str(exc)
            if self.app.demo_mode and self.app.redaction_service:
                exc_msg = self.app.redaction_service.scrub_stream(exc_msg)
            self.notify(
                f"Could not load instance types: {exc_msg}",
                severity="error", markup=False,
            )

    async def _load_key_pairs(self, region: str) -> None:
        svc = self.app.aws_service
        tbl = self.query_one("#aws_keys_table", DataTable)
        tbl.clear()
        self._key_pairs = []
        if not region:
            return
        try:
            self._key_pairs = await svc.list_key_pairs(region)
            for kp in self._key_pairs:
                tbl.add_row(
                    escape_cell(self._demo_key_name(kp.get("key_name", ""))),
                    escape_cell(kp.get("key_pair_id", "")),
                    escape_cell((kp.get("fingerprint", "") or "")[:32]),
                    key=kp.get("key_name", ""),
                )
            # Pre-select using the default SSH key config from general SSH
            # settings (heuristic: if only one key, auto-select it).
            if self._key_pairs:
                tbl.move_cursor(row=0)
        except Exception as exc:
            logger.error("Failed to load key pairs for %s: %s", region, exc)
            exc_msg = str(exc)
            if self.app.demo_mode and self.app.redaction_service:
                exc_msg = self.app.redaction_service.scrub_stream(exc_msg)
            self.notify(
                f"Could not load key pairs: {exc_msg}",
                severity="error", markup=False,
            )

    async def _load_subnets(self, region: str) -> None:
        svc = self.app.aws_service
        tbl = self.query_one("#aws_subnets_table", DataTable)
        tbl.clear()
        self._subnets = []
        if not region:
            return
        try:
            self._subnets = await svc.list_subnets(region)
            for sn in self._subnets:
                tbl.add_row(
                    escape_cell(sn.get("subnet_id", "")),
                    escape_cell(sn.get("vpc_id", "")),
                    escape_cell(sn.get("availability_zone", "")),
                    escape_cell(sn.get("cidr_block", "")),
                    str(sn.get("available_ip_count", "")),
                    key=sn.get("subnet_id", ""),
                )
            if self._subnets:
                tbl.move_cursor(row=0)
        except Exception as exc:
            logger.error("Failed to load subnets for %s: %s", region, exc)
            exc_msg = str(exc)
            if self.app.demo_mode and self.app.redaction_service:
                exc_msg = self.app.redaction_service.scrub_stream(exc_msg)
            self.notify(
                f"Could not load subnets: {exc_msg}",
                severity="error", markup=False,
            )

    async def _load_security_groups(self, region: str) -> None:
        svc = self.app.aws_service
        tbl = self.query_one("#aws_sg_table", DataTable)
        tbl.clear()
        self._security_groups = []
        if not region:
            return
        try:
            self._security_groups = await svc.list_security_groups(region)
            for sg in self._security_groups:
                tbl.add_row(
                    escape_cell(sg.get("group_id", "")),
                    escape_cell(self._demo_name(sg.get("group_name", ""))),
                    escape_cell(self._demo_text(sg.get("description", ""))[:60]),
                    escape_cell(sg.get("vpc_id", "")),
                    key=sg.get("group_id", ""),
                )
            if self._security_groups:
                tbl.move_cursor(row=0)
        except Exception as exc:
            logger.error(
                "Failed to load security groups for %s: %s", region, exc,
            )
            exc_msg = str(exc)
            if self.app.demo_mode and self.app.redaction_service:
                exc_msg = self.app.redaction_service.scrub_stream(exc_msg)
            self.notify(
                f"Could not load security groups: {exc_msg}",
                severity="error", markup=False,
            )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted,
    ) -> None:
        """Reload dependent tables when the region row changes."""
        if event.data_table.id == "aws_regions_table":
            row = event.data_table.cursor_row
            if 0 <= row < len(self._regions):
                self._load_region_dependents(self._regions[row])

    def on_input_changed(self, event: Input.Changed) -> None:
        """Debounce AMI search: fires ~400 ms after the user stops typing."""
        if event.input.id != "aws_input_ami_search":
            return
        # Cancel any pending timer so rapid keystrokes don't each trigger a call.
        if self._ami_search_timer is not None:
            try:
                self._ami_search_timer.stop()
            except Exception:
                pass
            self._ami_search_timer = None
        query = event.value.strip()
        region = self._current_region()
        if not region:
            return

        def _fire_search() -> None:
            self._ami_search_timer = None
            self.run_worker(
                self._load_amis(region, name_filter=query),
                group="aws_create_amis",
                exclusive=True,
                name="aws_create_ami_search",
            )

        self._ami_search_timer = self.set_timer(_AMI_SEARCH_DEBOUNCE_S, _fire_search)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # ``_on_create`` calls ``push_screen_wait`` for the confirm modal,
        # which Textual 8.x requires to run inside a worker — not just an
        # async handler — otherwise it raises ``NoActiveWorker``.
        if event.button.id == "btn_aws_create_back":
            self.action_back()
        elif event.button.id == "btn_aws_create_submit":
            self.run_worker(
                self._on_create(),
                exclusive=True,
                name="aws_create_submit",
            )

    # Demo mode: key-pair names, security-group names and their free-text
    # descriptions are operator-authored identifiers; the table keys stay
    # raw so a launch still targets the real resource.
    def _demo_key_name(self, value: str) -> str:
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_key_name(value)
        return value

    def _demo_name(self, value: str) -> str:
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_name(value)
        return value

    def _demo_text(self, value: str) -> str:
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.scrub_stream(value)
        return value

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Create flow
    # ------------------------------------------------------------------

    def _current_region(self) -> Optional[str]:
        """Return the currently selected region string, or None."""
        try:
            tbl = self.query_one("#aws_regions_table", DataTable)
            row = tbl.cursor_row
            if 0 <= row < len(self._regions):
                return self._regions[row]
        except Exception:
            pass
        return None

    async def _on_create(self) -> None:
        """Validate all selections, confirm, call AWSService.run_instances."""
        # ------ required text field ------
        name = self.query_one("#aws_input_name", Input).value.strip()
        if not name:
            self.notify(
                "Please enter an instance name.",
                severity="warning", markup=False,
            )
            return

        # ------ region ------
        region = self._current_region()
        if not region:
            self.notify(
                "Please select a region.",
                severity="warning", markup=False,
            )
            return

        # ------ AMI ------
        ami_row = self.query_one("#aws_amis_table", DataTable).cursor_row
        if ami_row < 0 or ami_row >= len(self._amis):
            self.notify(
                "Please select an AMI.", severity="warning", markup=False,
            )
            return

        # ------ instance type ------
        type_row = self.query_one("#aws_types_table", DataTable).cursor_row
        if type_row < 0 or type_row >= len(self._instance_types):
            self.notify(
                "Please select an instance type.",
                severity="warning", markup=False,
            )
            return

        # ------ key pair ------
        key_row = self.query_one("#aws_keys_table", DataTable).cursor_row
        if key_row < 0 or key_row >= len(self._key_pairs):
            self.notify(
                "Please select a key pair.",
                severity="warning", markup=False,
            )
            return

        # ------ subnet ------
        subnet_row = self.query_one("#aws_subnets_table", DataTable).cursor_row
        if subnet_row < 0 or subnet_row >= len(self._subnets):
            self.notify(
                "Please select a subnet.",
                severity="warning", markup=False,
            )
            return

        # ------ security group ------
        sg_row = self.query_one("#aws_sg_table", DataTable).cursor_row
        if sg_row < 0 or sg_row >= len(self._security_groups):
            self.notify(
                "Please select a security group.",
                severity="warning", markup=False,
            )
            return

        # ------ extract selected data ------
        ami = self._amis[ami_row]
        instance_type = self._instance_types[type_row]
        key_pair = self._key_pairs[key_row]
        subnet = self._subnets[subnet_row]
        sg = self._security_groups[sg_row]

        ami_id = ami.get("image_id", "")
        type_name = instance_type.get("instance_type", "")
        key_name = key_pair.get("key_name", "")
        subnet_id = subnet.get("subnet_id", "")
        sg_id = sg.get("group_id", "")

        # ------ confirm modal ------
        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Launch EC2 Instance",
                description=(
                    f"Launch [bold]{markup_escape(name)}[/bold] in [bold]{markup_escape(region)}[/bold] "
                    f"as [bold]{markup_escape(type_name)}[/bold] with AMI [bold]{markup_escape(ami_id)}[/bold], "
                    f"key [bold]{markup_escape(key_name)}[/bold], subnet [bold]{markup_escape(subnet_id)}[/bold], "
                    f"SG [bold]{markup_escape(sg_id)}[/bold]."
                ),
                consequences=[
                    "EC2 billing starts immediately once the instance reaches running state",
                    "Charges continue until the instance is stopped or terminated",
                    "Data on instance-store volumes is lost on stop/terminate",
                ],
                confirm_text="launch",
                action_label="Launch Instance",
                severity="warning",
            )
        )

        if not confirmed:
            return

        svc = self.app.aws_service
        if svc is None:
            self.notify(
                "AWS service is not available.",
                severity="error", markup=False,
            )
            return

        submit_btn: Optional[Button] = None
        try:
            submit_btn = self.query_one("#btn_aws_create_submit", Button)
            submit_btn.disabled = True
        except Exception:
            pass

        try:
            new_instances = await svc.run_instances(
                region=region,
                ami_id=ami_id,
                instance_type=type_name,
                key_name=key_name,
                subnet_id=subnet_id,
                security_group_ids=[sg_id],
                name_tag=name,
                count=1,
            )
        except Exception as exc:
            logger.error("EC2 launch failed: %s", exc)
            exc_msg = str(exc)
            if self.app.demo_mode and self.app.redaction_service:
                exc_msg = self.app.redaction_service.scrub_stream(exc_msg)
            self.notify(
                f"Launch failed: {exc_msg}",
                severity="error", markup=False,
            )
            if submit_btn is not None:
                submit_btn.disabled = False
            return

        # ------ audit ------
        audit = getattr(self.app, "aws_audit", None)
        if audit is not None:
            try:
                launched_ids = [i.get("id", "") for i in new_instances]
                audit.log_action(
                    action="run_instances",
                    target=",".join(launched_ids),
                    details={
                        "region": region,
                        "ami_id": ami_id,
                        "instance_type": type_name,
                        "key_name": key_name,
                        "subnet_id": subnet_id,
                        "security_group_ids": [sg_id],
                        "name_tag": name,
                    },
                    confirmed=True,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to write AWS audit row: %s", exc)

        launched_id = new_instances[0].get("id", "") if new_instances else ""
        self.notify(
            f"Instance '{name}' launching "
            f"{'(ID: ' + launched_id + ')' if launched_id else ''}. "
            "Refreshing instance list…",
            severity="information", markup=False,
        )

        # Refresh the manager's list so the new instance appears without
        # the user having to press R. Best-effort — failures here don't
        # undo the launch.
        try:
            await self._refresh_instances_after_create()
        except Exception as exc:
            logger.warning("Post-launch instance refresh failed: %s", exc)

        self.app.pop_screen()

    async def _refresh_instances_after_create(self) -> None:
        """Re-merge AWS instances into ``app.instances`` after launch.

        Mirrors the merge pattern used by ``HetznerCreateScreen`` —
        non-AWS rows are preserved, the AWS slice is replaced with a
        fresh fetch.
        """
        svc = self.app.aws_service
        if svc is None:
            return
        new_aws = await svc.fetch_instances_cached(force_refresh=True)
        existing = list(getattr(self.app, "instances", []) or [])
        # AWS instance dicts have no "provider" key, so .get() returns None —
        # keeping them in the exclusion set.  Custom servers always carry
        # is_custom=True and are kept regardless of the provider value.
        non_aws = [
            i for i in existing
            if i.get("provider") not in ("aws", None) or i.get("is_custom")
        ]
        self.app.instances = non_aws + list(new_aws)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _preselect_default(
        tbl: DataTable, rows: List[str], default: str,
    ) -> None:
        """Move the cursor to the row whose value matches *default*.

        No-op when the default is empty, the list is empty, or the default
        does not match any row.
        """
        if not default or not rows:
            return
        for idx, value in enumerate(rows):
            if value == default:
                tbl.move_cursor(row=idx)
                return

"""IP Ban Configurations settings panel.

Migrated from the legacy ``settings.py`` Section 6 (compose lines 145-294 and
helpers ``_handle_ipban_*`` / ``_discover_*``). Behaviour is identical to the
original: a DataTable lists configured :class:`~servonaut.config.schema.IPBanConfig`
entries; Add / Edit / Remove buttons toggle an inline CRUD form; a Discover
button queries AWS WAF / EC2 APIs asynchronously to populate the method-specific
dropdowns.

Panel-specific CSS lives in :attr:`DEFAULT_CSS` — never in ``app.css``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.config.schema import IPBanConfig
from servonaut.screens.settings.base import SettingsPanel

logger = logging.getLogger(__name__)

_AWS_REGIONS: List[tuple[str, str]] = [
    ("US East (N. Virginia)", "us-east-1"),
    ("US East (Ohio)", "us-east-2"),
    ("US West (N. California)", "us-west-1"),
    ("US West (Oregon)", "us-west-2"),
    ("EU (Ireland)", "eu-west-1"),
    ("EU (Frankfurt)", "eu-central-1"),
    ("EU (London)", "eu-west-2"),
    ("EU (Paris)", "eu-west-3"),
    ("EU (Stockholm)", "eu-north-1"),
    ("EU (Milan)", "eu-south-1"),
    ("Asia Pacific (Tokyo)", "ap-northeast-1"),
    ("Asia Pacific (Seoul)", "ap-northeast-2"),
    ("Asia Pacific (Singapore)", "ap-southeast-1"),
    ("Asia Pacific (Sydney)", "ap-southeast-2"),
    ("Asia Pacific (Mumbai)", "ap-south-1"),
    ("Asia Pacific (Hong Kong)", "ap-east-1"),
    ("Canada (Central)", "ca-central-1"),
    ("South America (Sao Paulo)", "sa-east-1"),
    ("Middle East (Bahrain)", "me-south-1"),
    ("Africa (Cape Town)", "af-south-1"),
]


class IpBanPanel(SettingsPanel):
    """CRUD editor for :class:`~servonaut.config.schema.IPBanConfig` entries.

    Provides a DataTable overview and an inline form for WAF IP sets, Security
    Groups, and Network ACLs.  AWS discovery is performed in a background worker
    so the TUI remains responsive.
    """

    PANEL_ID = "ip_ban"
    TITLE = "IP Ban Configurations"

    DEFAULT_CSS = """
    IpBanPanel .ipban-action-row {
        height: auto;
        margin-bottom: 1;
    }
    IpBanPanel #ipban-form-container {
        border: round $primary;
        background: $boost;
        padding: 1 2;
        margin-top: 1;
        height: auto;
    }
    IpBanPanel #ipban-form-container Select {
        height: 3;
        max-height: 3;
    }
    IpBanPanel .ipban-form-actions {
        height: auto;
        margin-top: 1;
    }
    IpBanPanel #ipban_waf_fields,
    IpBanPanel #ipban_sg_fields,
    IpBanPanel #ipban_nacl_fields {
        height: auto;
        padding: 0;
    }
    IpBanPanel .ipban-discover-row {
        height: auto;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        # Name of the config being edited; None when adding a new one.
        self._editing_ipban_name: Optional[str] = None
        # Raw discovery results kept so Select auto-fill can look up names.
        self._discovered_ip_sets: List[Dict[str, str]] = []
        self._discovered_sgs: List[Dict[str, str]] = []
        self._discovered_nacls: List[Dict[str, str]] = []

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the IP ban CRUD form rows."""
        yield Static(
            "Configure WAF IP sets, Security Groups, or NACLs for IP banning. "
            "WAF IP sets are the recommended method.",
            classes="note",
        )
        yield DataTable(id="ipban_table")
        yield Horizontal(
            Button("Add", id="btn_ipban_add", variant="primary"),
            Button("Edit", id="btn_ipban_edit"),
            Button("Remove", id="btn_ipban_remove", variant="error"),
            classes="ipban-action-row",
        )
        # Inline CRUD form — hidden until Add / Edit is pressed.
        yield Container(
            # Common fields
            Horizontal(
                Static("Name:", classes="label"),
                Input(
                    placeholder="e.g. production-waf-blocklist",
                    id="ipban_input_name",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Method:", classes="label"),
                Select(
                    options=[
                        ("WAF IP Set (recommended)", "waf"),
                        ("Security Group", "security_group"),
                        ("Network ACL", "nacl"),
                    ],
                    prompt="Select method...",
                    id="ipban_select_method",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Region:", classes="label"),
                Select(
                    [(f"{label} ({value})", value) for label, value in _AWS_REGIONS],
                    prompt="Select region...",
                    id="ipban_select_region",
                    allow_blank=True,
                ),
                classes="setting_row",
            ),
            # Discover button row
            Horizontal(
                Button("Discover from AWS", id="btn_ipban_discover", variant="default"),
                Static(
                    "Select a method and region first, then discover available resources",
                    id="ipban_discover_hint",
                    classes="note",
                ),
                classes="ipban-discover-row setting_row",
            ),
            # WAF-specific fields
            Container(
                Horizontal(
                    Static("WAF IP Set:", classes="label"),
                    Select(
                        [],
                        prompt="Discover or enter manually below",
                        id="ipban_select_ip_set",
                        allow_blank=True,
                    ),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("IP Set ID:", classes="label"),
                    Input(
                        placeholder="e.g. 12345678-abcd-1234-efgh-123456789012",
                        id="ipban_input_ip_set_id",
                    ),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("IP Set Name:", classes="label"),
                    Input(
                        placeholder="e.g. my-blocklist",
                        id="ipban_input_ip_set_name",
                    ),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("WAF Scope:", classes="label"),
                    Select(
                        options=[
                            ("Regional (ALB, API Gateway)", "REGIONAL"),
                            ("CloudFront (Global)", "CLOUDFRONT"),
                        ],
                        value="REGIONAL",
                        id="ipban_select_waf_scope",
                    ),
                    classes="setting_row",
                ),
                id="ipban_waf_fields",
            ),
            # Security Group fields
            Container(
                Horizontal(
                    Static("Security Group:", classes="label"),
                    Select(
                        [],
                        prompt="Discover or enter manually below",
                        id="ipban_select_sg",
                        allow_blank=True,
                    ),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("Security Group ID:", classes="label"),
                    Input(
                        placeholder="e.g. sg-0123456789abcdef0",
                        id="ipban_input_sg_id",
                    ),
                    classes="setting_row",
                ),
                id="ipban_sg_fields",
            ),
            # NACL fields
            Container(
                Horizontal(
                    Static("Network ACL:", classes="label"),
                    Select(
                        [],
                        prompt="Discover or enter manually below",
                        id="ipban_select_nacl",
                        allow_blank=True,
                    ),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("NACL ID:", classes="label"),
                    Input(
                        placeholder="e.g. acl-0123456789abcdef0",
                        id="ipban_input_nacl_id",
                    ),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("Rule Number Start:", classes="label"),
                    Input(placeholder="100", id="ipban_input_rule_number_start"),
                    classes="setting_row",
                ),
                id="ipban_nacl_fields",
            ),
            # Form action buttons
            Horizontal(
                Button("Save Entry", id="btn_ipban_save", variant="primary"),
                Button("Cancel", id="btn_ipban_cancel"),
                classes="ipban-form-actions",
            ),
            id="ipban-form-container",
        )

    # ------------------------------------------------------------------
    # SettingsPanel lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate the table from config and hide the inline form."""
        self._populate_ipban_table()
        self.query_one("#ipban-form-container").display = False
        self.query_one("#ipban_waf_fields").display = False
        self.query_one("#ipban_sg_fields").display = False
        self.query_one("#ipban_nacl_fields").display = False
        self._snapshot_now()

    def collect(self) -> Dict[str, Any]:
        """Not used for inline-CRUD panels; returns current config list as-is.

        The real save path goes through :meth:`_handle_ipban_save`.  The
        per-panel Save button in the dock calls :meth:`persist` which delegates
        here only so the base class bookkeeping (dirty-marker) works correctly.
        """
        config = self.app.config_manager.get()
        return {"ip_ban_configs": config.ip_ban_configs}

    def persist(self) -> None:
        """No-op at the panel level — individual entries are saved via the form.

        The base-class Save dock is not meaningfully useful for an inline-CRUD
        panel, but the method must exist so the contract is satisfied and the
        dirty-marker clears correctly after explicit form saves.
        """
        self._finish_save("IP ban configurations are saved per entry.")

    def is_dirty(self) -> bool:
        """Always False: dirty state is managed per entry via inline form."""
        return False

    def current_values(self) -> Dict[str, Any]:
        """Return empty dict — dirty tracking is not row-based for this panel."""
        return {}

    # ------------------------------------------------------------------
    # Table helpers
    # ------------------------------------------------------------------

    def _populate_ipban_table(self) -> None:
        """Rebuild the DataTable from current config."""
        config = self.app.config_manager.get()
        table = self.query_one("#ipban_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Name", "Method", "Region", "Details")
        table.cursor_type = "row"
        for cfg in config.ip_ban_configs:
            details = _entry_details(cfg)
            table.add_row(cfg.name, cfg.method, cfg.region or "N/A", details)

    def _get_selected_name(self) -> Optional[str]:
        """Return the name column from the currently-highlighted table row."""
        table = self.query_one("#ipban_table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_data = table.get_row_at(table.cursor_row)
            return str(row_data[0])
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Form visibility helpers
    # ------------------------------------------------------------------

    def _show_form(self) -> None:
        self.query_one("#ipban-form-container").display = True

    def _hide_form(self) -> None:
        self.query_one("#ipban-form-container").display = False
        self._editing_ipban_name = None

    def _clear_form(self) -> None:
        """Reset every form field to blank / default and hide method sub-panels."""
        self.query_one("#ipban_input_name", Input).value = ""
        self.query_one("#ipban_input_ip_set_id", Input).value = ""
        self.query_one("#ipban_input_ip_set_name", Input).value = ""
        self.query_one("#ipban_input_sg_id", Input).value = ""
        self.query_one("#ipban_input_nacl_id", Input).value = ""
        self.query_one("#ipban_input_rule_number_start", Input).value = ""
        self.query_one("#ipban_select_method", Select).clear()
        self.query_one("#ipban_select_region", Select).clear()
        self.query_one("#ipban_select_waf_scope", Select).value = "REGIONAL"
        self.query_one("#ipban_select_ip_set", Select).set_options([])
        self.query_one("#ipban_select_sg", Select).set_options([])
        self.query_one("#ipban_select_nacl", Select).set_options([])
        self._discovered_ip_sets = []
        self._discovered_sgs = []
        self._discovered_nacls = []
        self._set_method_fields_visible(None)

    def _set_method_fields_visible(self, method: Optional[str]) -> None:
        """Show only the sub-form container that matches *method*."""
        self.query_one("#ipban_waf_fields").display = (method == "waf")
        self.query_one("#ipban_sg_fields").display = (method == "security_group")
        self.query_one("#ipban_nacl_fields").display = (method == "nacl")

    # ------------------------------------------------------------------
    # CRUD actions
    # ------------------------------------------------------------------

    def _handle_ipban_add(self) -> None:
        """Open a blank form for a new entry."""
        self._editing_ipban_name = None
        self._clear_form()
        self._show_form()
        self.query_one("#ipban_input_name", Input).focus()

    def _handle_ipban_edit(self) -> None:
        """Populate the form with the selected entry for editing."""
        name = self._get_selected_name()
        if not name:
            self.app.notify("Select a configuration to edit", severity="warning", markup=False)
            return

        config = self.app.config_manager.get()
        cfg = next((c for c in config.ip_ban_configs if c.name == name), None)
        if not cfg:
            self.app.notify("Configuration not found", severity="error", markup=False)
            return

        self._editing_ipban_name = name
        self._clear_form()

        self.query_one("#ipban_input_name", Input).value = cfg.name
        self.query_one("#ipban_input_ip_set_id", Input).value = cfg.ip_set_id
        self.query_one("#ipban_input_ip_set_name", Input).value = cfg.ip_set_name
        self.query_one("#ipban_input_sg_id", Input).value = cfg.security_group_id
        self.query_one("#ipban_input_nacl_id", Input).value = cfg.nacl_id
        self.query_one("#ipban_input_rule_number_start", Input).value = str(
            cfg.rule_number_start
        )
        self.query_one("#ipban_select_method", Select).value = cfg.method
        if cfg.region:
            self.query_one("#ipban_select_region", Select).value = cfg.region
        self.query_one("#ipban_select_waf_scope", Select).value = cfg.waf_scope
        self._set_method_fields_visible(cfg.method)
        self._show_form()
        self.query_one("#ipban_input_name", Input).focus()

    def _handle_ipban_remove(self) -> None:
        """Remove the selected entry from config immediately."""
        name = self._get_selected_name()
        if not name:
            self.app.notify("Select a configuration to remove", severity="warning", markup=False)
            return

        config = self.app.config_manager.get()
        original_count = len(config.ip_ban_configs)
        config.ip_ban_configs = [c for c in config.ip_ban_configs if c.name != name]

        if len(config.ip_ban_configs) < original_count:
            self.app.config_manager.save(config)
            self._populate_ipban_table()
            self.app.notify(
                f"Removed IP ban config: {escape(name)}",
                severity="information",
                markup=False,
            )
        else:
            self.app.notify("Configuration not found", severity="error", markup=False)

    def _handle_ipban_save(self) -> None:
        """Validate the form and upsert the entry into config."""
        name = self.query_one("#ipban_input_name", Input).value.strip()
        method_value = self.query_one("#ipban_select_method", Select).value
        region_value = self.query_one("#ipban_select_region", Select).value

        if not name:
            self.app.notify("Name is required", severity="error", markup=False)
            self.query_one("#ipban_input_name", Input).focus()
            return

        if method_value is Select.BLANK or not method_value:
            self.app.notify("Method is required", severity="error", markup=False)
            self.query_one("#ipban_select_method", Select).focus()
            return

        method = str(method_value)
        region = str(region_value) if region_value is not Select.BLANK else ""

        # Method-specific required-field validation
        if method == "waf":
            if not self.query_one("#ipban_input_ip_set_id", Input).value.strip():
                self.app.notify(
                    "IP Set ID is required for WAF method",
                    severity="error",
                    markup=False,
                )
                self.query_one("#ipban_input_ip_set_id", Input).focus()
                return
            if not self.query_one("#ipban_input_ip_set_name", Input).value.strip():
                self.app.notify(
                    "IP Set Name is required for WAF method",
                    severity="error",
                    markup=False,
                )
                self.query_one("#ipban_input_ip_set_name", Input).focus()
                return
        elif method == "security_group":
            if not self.query_one("#ipban_input_sg_id", Input).value.strip():
                self.app.notify(
                    "Security Group ID is required",
                    severity="error",
                    markup=False,
                )
                self.query_one("#ipban_input_sg_id", Input).focus()
                return
        elif method == "nacl":
            if not self.query_one("#ipban_input_nacl_id", Input).value.strip():
                self.app.notify(
                    "NACL ID is required",
                    severity="error",
                    markup=False,
                )
                self.query_one("#ipban_input_nacl_id", Input).focus()
                return

        # Collect all form fields
        ip_set_id = self.query_one("#ipban_input_ip_set_id", Input).value.strip()
        ip_set_name = self.query_one("#ipban_input_ip_set_name", Input).value.strip()
        waf_scope_value = self.query_one("#ipban_select_waf_scope", Select).value
        waf_scope = (
            str(waf_scope_value) if waf_scope_value is not Select.BLANK else "REGIONAL"
        )
        sg_id = self.query_one("#ipban_input_sg_id", Input).value.strip()
        nacl_id = self.query_one("#ipban_input_nacl_id", Input).value.strip()
        rule_number_start_raw = self.query_one(
            "#ipban_input_rule_number_start", Input
        ).value.strip()
        try:
            rule_number_start = int(rule_number_start_raw) if rule_number_start_raw else 100
        except ValueError:
            rule_number_start = 100

        new_cfg = IPBanConfig(
            name=name,
            method=method,
            region=region,
            ip_set_id=ip_set_id,
            ip_set_name=ip_set_name,
            waf_scope=waf_scope,
            security_group_id=sg_id,
            nacl_id=nacl_id,
            rule_number_start=rule_number_start,
        )

        config = self.app.config_manager.get()

        if self._editing_ipban_name is not None:
            # Replace in-place; fall through to append if somehow missing.
            replaced = False
            for i, c in enumerate(config.ip_ban_configs):
                if c.name == self._editing_ipban_name:
                    config.ip_ban_configs[i] = new_cfg
                    replaced = True
                    break
            if not replaced:
                config.ip_ban_configs.append(new_cfg)
        else:
            if any(c.name == name for c in config.ip_ban_configs):
                self.app.notify(
                    f"A configuration named '{escape(name)}' already exists",
                    severity="error",
                    markup=False,
                )
                self.query_one("#ipban_input_name", Input).focus()
                return
            config.ip_ban_configs.append(new_cfg)

        self.app.config_manager.save(config)
        self._populate_ipban_table()
        self._hide_form()
        self.app.notify(
            f"Saved IP ban config: {escape(name)}",
            severity="information",
            markup=False,
        )
        logger.info("IP ban config saved: name=%s method=%s", name, method)

    # ------------------------------------------------------------------
    # AWS Discovery
    # ------------------------------------------------------------------

    def _handle_ipban_discover(self) -> None:
        """Validate selections and kick off the background discovery worker."""
        method_value = self.query_one("#ipban_select_method", Select).value
        region_value = self.query_one("#ipban_select_region", Select).value

        if method_value is Select.BLANK or not method_value:
            self.app.notify("Select a method first", severity="warning", markup=False)
            return
        if region_value is Select.BLANK or not region_value:
            self.app.notify("Select a region first", severity="warning", markup=False)
            return

        method = str(method_value)
        region = str(region_value)
        scope_value = self.query_one("#ipban_select_waf_scope", Select).value
        scope = (
            str(scope_value) if scope_value is not Select.BLANK else "REGIONAL"
        )

        self.query_one("#btn_ipban_discover", Button).disabled = True
        self.query_one("#ipban_discover_hint", Static).update("Discovering...")

        self.run_worker(
            self._discover_aws_resources(method, region, scope),
            name="ipban_discover",
            group="discover",
            exclusive=True,
        )

    async def _discover_aws_resources(
        self, method: str, region: str, scope: str
    ) -> None:
        """Dispatch the appropriate AWS discovery call by *method*."""
        try:
            if method == "waf":
                await self._discover_waf_ip_sets(region, scope)
            elif method == "security_group":
                await self._discover_security_groups(region)
            elif method == "nacl":
                await self._discover_nacls(region)
        except Exception as exc:
            self.app.notify(
                f"Discovery failed: {exc}",
                severity="error",
                markup=False,
            )
            logger.error("AWS discovery failed: %s", exc)
        finally:
            self.query_one("#btn_ipban_discover", Button).disabled = False
            self.query_one("#ipban_discover_hint", Static).update(
                "Select a method and region first, then discover available resources"
            )

    async def _discover_waf_ip_sets(self, region: str, scope: str) -> None:
        """Fetch WAF IP sets from *region* and populate the dropdown."""
        import asyncio

        def _fetch() -> List[Dict[str, str]]:
            import boto3  # optional dependency — only needed for discovery

            client = boto3.client("wafv2", region_name=region)
            ip_sets: List[Dict[str, str]] = []
            params: Dict[str, Any] = {"Scope": scope}
            while True:
                response = client.list_ip_sets(**params)
                for entry in response.get("IPSets", []):
                    ip_sets.append(
                        {
                            "id": entry["Id"],
                            "name": entry["Name"],
                            "arn": entry.get("ARN", ""),
                        }
                    )
                next_marker = response.get("NextMarker")
                if not next_marker:
                    break
                params["NextMarker"] = next_marker
            return ip_sets

        loop = asyncio.get_event_loop()
        ip_sets = await loop.run_in_executor(None, _fetch)
        self._discovered_ip_sets = ip_sets

        select = self.query_one("#ipban_select_ip_set", Select)
        if not ip_sets:
            select.set_options([])
            select.prompt = "No IP sets found"
            self.app.notify(
                f"No WAF IP sets found in {region} ({scope})",
                severity="warning",
                markup=False,
            )
        else:
            select.set_options(
                [
                    (f"{s['name']} ({s['id'][:8]}...)", f"{s['id']}|{s['name']}")
                    for s in ip_sets
                ]
            )
            select.prompt = f"Select from {len(ip_sets)} IP set(s)"
            self.app.notify(
                f"Found {len(ip_sets)} WAF IP set(s)",
                markup=False,
            )

    async def _discover_security_groups(self, region: str) -> None:
        """Fetch EC2 Security Groups from *region* and populate the dropdown."""
        import asyncio

        def _fetch() -> List[Dict[str, str]]:
            import boto3

            ec2 = boto3.client("ec2", region_name=region)
            sgs: List[Dict[str, str]] = []
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sgs.append(
                        {
                            "id": sg["GroupId"],
                            "name": sg.get("GroupName", ""),
                            "vpc": sg.get("VpcId", ""),
                        }
                    )
            return sgs

        loop = asyncio.get_event_loop()
        sgs = await loop.run_in_executor(None, _fetch)
        self._discovered_sgs = sgs

        select = self.query_one("#ipban_select_sg", Select)
        if not sgs:
            select.set_options([])
            select.prompt = "No security groups found"
            self.app.notify(
                f"No security groups found in {region}",
                severity="warning",
                markup=False,
            )
        else:
            select.set_options(
                [(f"{s['name']} ({s['id']})", s["id"]) for s in sgs]
            )
            select.prompt = f"Select from {len(sgs)} SG(s)"
            self.app.notify(
                f"Found {len(sgs)} security group(s)",
                markup=False,
            )

    async def _discover_nacls(self, region: str) -> None:
        """Fetch Network ACLs from *region* and populate the dropdown."""
        import asyncio

        def _fetch() -> List[Dict[str, str]]:
            import boto3

            ec2 = boto3.client("ec2", region_name=region)
            nacls: List[Dict[str, str]] = []
            response = ec2.describe_network_acls()
            for acl in response.get("NetworkAcls", []):
                acl_id: str = acl["NetworkAclId"]
                vpc: str = acl.get("VpcId", "")
                is_default: bool = acl.get("IsDefault", False)
                name = ""
                for tag in acl.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                        break
                label = name or ("default" if is_default else acl_id)
                nacls.append({"id": acl_id, "name": label, "vpc": vpc})
            return nacls

        loop = asyncio.get_event_loop()
        nacls = await loop.run_in_executor(None, _fetch)
        self._discovered_nacls = nacls

        select = self.query_one("#ipban_select_nacl", Select)
        if not nacls:
            select.set_options([])
            select.prompt = "No NACLs found"
            self.app.notify(
                f"No NACLs found in {region}",
                severity="warning",
                markup=False,
            )
        else:
            select.set_options(
                [(f"{n['name']} ({n['id']})", n["id"]) for n in nacls]
            )
            select.prompt = f"Select from {len(nacls)} NACL(s)"
            self.app.notify(
                f"Found {len(nacls)} NACL(s)",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle method switching and auto-fill from discovery dropdowns."""
        if event.select.id == "ipban_select_method":
            method = (
                str(event.value) if event.value is not Select.BLANK else None
            )
            self._set_method_fields_visible(method)

        elif event.select.id == "ipban_select_ip_set":
            # Auto-fill ID and Name from the composite value "id|name"
            if event.value is not Select.BLANK and event.value:
                parts = str(event.value).split("|", 1)
                if len(parts) == 2:
                    self.query_one("#ipban_input_ip_set_id", Input).value = parts[0]
                    self.query_one("#ipban_input_ip_set_name", Input).value = parts[1]

        elif event.select.id == "ipban_select_sg":
            if event.value is not Select.BLANK and event.value:
                self.query_one("#ipban_input_sg_id", Input).value = str(event.value)

        elif event.select.id == "ipban_select_nacl":
            if event.value is not Select.BLANK and event.value:
                self.query_one("#ipban_input_nacl_id", Input).value = str(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route form / table action buttons.

        Delegates the panel-level Save button to the base class, then handles
        the IP-ban-specific buttons itself.
        """
        button_id = event.button.id

        # Let the base class handle the per-panel Save dock button.
        if button_id == f"save_{self.PANEL_ID}":
            super().on_button_pressed(event)
            return

        event.stop()

        if button_id == "btn_ipban_add":
            self._handle_ipban_add()
        elif button_id == "btn_ipban_edit":
            self._handle_ipban_edit()
        elif button_id == "btn_ipban_remove":
            self._handle_ipban_remove()
        elif button_id == "btn_ipban_save":
            self._handle_ipban_save()
        elif button_id == "btn_ipban_cancel":
            self._hide_form()
        elif button_id == "btn_ipban_discover":
            self._handle_ipban_discover()


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _entry_details(cfg: IPBanConfig) -> str:
    """Return a short details string for a DataTable row."""
    if cfg.method == "waf":
        return f"IP Set: {cfg.ip_set_name or cfg.ip_set_id or 'N/A'}"
    if cfg.method == "security_group":
        return f"SG: {cfg.security_group_id or 'N/A'}"
    if cfg.method == "nacl":
        return f"NACL: {cfg.nacl_id or 'N/A'}"
    return ""

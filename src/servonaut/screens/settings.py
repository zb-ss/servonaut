"""Settings screen for Servonaut v2.0."""

from __future__ import annotations

import logging
from typing import List, Dict, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Input, Button, DataTable, Select

logger = logging.getLogger(__name__)

_AWS_REGIONS = [
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
    ("South America (São Paulo)", "sa-east-1"),
    ("Middle East (Bahrain)", "me-south-1"),
    ("Africa (Cape Town)", "af-south-1"),
]


class SettingsScreen(Screen):
    """Configuration editor screen for app settings."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+s", "save", "Save", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._editing_ipban_name: Optional[str] = None
        self._discovered_ip_sets: List[dict] = []
        self._discovered_sgs: List[dict] = []
        self._discovered_nacls: List[dict] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield ScrollableContainer(
            Static("[bold cyan]Settings[/bold cyan]", id="settings_header"),

            # Section 1: General Settings
            Static("[bold]General[/bold]", classes="section_header"),
            Horizontal(
                Static("Default Username:", classes="label"),
                Input(placeholder="ec2-user", id="input_username"),
                classes="setting_row"
            ),
            Horizontal(
                Static("Cache TTL (seconds):", classes="label"),
                Input(placeholder="300", id="input_cache_ttl"),
                classes="setting_row"
            ),
            Horizontal(
                Static("Terminal Emulator:", classes="label"),
                Input(placeholder="auto", id="input_terminal"),
                classes="setting_row"
            ),
            Horizontal(
                Static("Theme:", classes="label"),
                Input(placeholder="dark", id="input_theme"),
                classes="setting_row"
            ),

            # Section 2: Default Scan Paths
            Static("[bold]Default Scan Paths[/bold]", classes="section_header"),
            Container(
                Vertical(id="scan_paths_list"),
                Horizontal(
                    Input(placeholder="Enter new path...", id="input_new_path"),
                    Button("Add", id="btn_add_path", variant="primary"),
                    classes="add_row"
                ),
                id="scan_paths_section"
            ),

            # Section 3: Scan Rules (read-only)
            Static("[bold]Scan Rules[/bold]", classes="section_header"),
            Static("[dim]Edit scan rules in ~/.servonaut/config.json[/dim]", classes="note"),
            DataTable(id="scan_rules_table"),

            # Section 4: Connection Profiles (read-only)
            Static("[bold]Connection Profiles[/bold]", classes="section_header"),
            Static("[dim]Edit connection profiles in ~/.servonaut/config.json[/dim]", classes="note"),
            DataTable(id="profiles_table"),

            # Section 5: Connection Rules (read-only)
            Static("[bold]Connection Rules[/bold]", classes="section_header"),
            Static("[dim]Edit connection rules in ~/.servonaut/config.json[/dim]", classes="note"),
            DataTable(id="rules_table"),

            # Section 6: IP Ban Configurations
            Static("[bold]IP Ban Configurations[/bold]", classes="section_header"),
            Static(
                "[dim]Configure WAF IP sets, Security Groups, or NACLs for IP banning. "
                "WAF IP sets are the recommended method.[/dim]",
                classes="note",
            ),
            DataTable(id="ipban_table"),
            Horizontal(
                Button("Add", id="btn_ipban_add", variant="primary"),
                Button("Edit", id="btn_ipban_edit"),
                Button("Remove", id="btn_ipban_remove", variant="error"),
                classes="ipban_action_row",
            ),
            Container(
                # Common fields
                Horizontal(
                    Static("Name:", classes="label"),
                    Input(placeholder="e.g. production-waf-blocklist", id="ipban_input_name"),
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
                # Discover button
                Horizontal(
                    Button(
                        "Discover from AWS",
                        id="btn_ipban_discover",
                        variant="default",
                    ),
                    Static(
                        "[dim]Select a method and region first, then discover available resources[/dim]",
                        id="ipban_discover_hint",
                    ),
                    classes="setting_row",
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
                        Input(placeholder="e.g. 12345678-abcd-1234-efgh-123456789012", id="ipban_input_ip_set_id"),
                        classes="setting_row",
                    ),
                    Horizontal(
                        Static("IP Set Name:", classes="label"),
                        Input(placeholder="e.g. my-blocklist", id="ipban_input_ip_set_name"),
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
                    classes="ipban-waf-fields",
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
                        Input(placeholder="e.g. sg-0123456789abcdef0", id="ipban_input_sg_id"),
                        classes="setting_row",
                    ),
                    classes="ipban-sg-fields",
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
                        Input(placeholder="e.g. acl-0123456789abcdef0", id="ipban_input_nacl_id"),
                        classes="setting_row",
                    ),
                    Horizontal(
                        Static("Rule Number Start:", classes="label"),
                        Input(placeholder="100", id="ipban_input_rule_number_start"),
                        classes="setting_row",
                    ),
                    classes="ipban-nacl-fields",
                    id="ipban_nacl_fields",
                ),
                # Form action buttons
                Horizontal(
                    Button("Save", id="btn_ipban_save", variant="primary"),
                    Button("Cancel", id="btn_ipban_cancel"),
                    classes="ipban_form_actions",
                ),
                id="ipban-form-container",
            ),

            # Section 7: AI Provider
            Static("[bold]AI Provider[/bold]", classes="section_header"),
            Static("[dim]Configure AI provider for log analysis[/dim]", classes="note"),
            Horizontal(
                Static("Provider:", classes="label"),
                Input(placeholder="openai / anthropic / ollama / gemini", id="input_ai_provider"),
                classes="setting_row"
            ),
            Horizontal(
                Static("API Key:", classes="label"),
                Input(placeholder="sk-... or $ENV_VAR", id="input_ai_api_key"),
                classes="setting_row"
            ),
            Horizontal(
                Static("Model:", classes="label"),
                Input(placeholder="leave blank for default", id="input_ai_model"),
                classes="setting_row"
            ),
            Horizontal(
                Static("Base URL:", classes="label"),
                Input(placeholder="http://localhost:11434 (Ollama)", id="input_ai_base_url"),
                classes="setting_row"
            ),
            Horizontal(
                Static("Max Tokens:", classes="label"),
                Input(placeholder="2048", id="input_ai_max_tokens"),
                classes="setting_row"
            ),
            Horizontal(
                Static("Temperature:", classes="label"),
                Input(placeholder="0.3", id="input_ai_temperature"),
                classes="setting_row"
            ),

            # Section 8: IP Lookup
            Static("[bold]IP Lookup[/bold]", classes="section_header"),
            Static("[dim]Optional: AbuseIPDB API key for abuse reports (press 'i' on Top IPs in CloudWatch). "
                   "Free key at abuseipdb.com. Supports $ENV_VAR syntax.[/dim]", classes="note"),
            Horizontal(
                Static("AbuseIPDB Key:", classes="label"),
                Input(placeholder="your-api-key or $ABUSEIPDB_API_KEY", id="input_abuseipdb_key", password=True),
                classes="setting_row"
            ),

            id="settings_container"
        )
        yield Footer()

    def on_mount(self) -> None:
        self._load_settings()
        self._populate_scan_paths()
        self._populate_scan_rules()
        self._populate_connection_profiles()
        self._populate_connection_rules()
        self._populate_ipban_table()
        # Ensure form and method fields start hidden
        self.query_one("#ipban-form-container").display = False
        self.query_one("#ipban_waf_fields").display = False
        self.query_one("#ipban_sg_fields").display = False
        self.query_one("#ipban_nacl_fields").display = False

    def _load_settings(self) -> None:
        config = self.app.config_manager.get()
        self.query_one("#input_username", Input).value = config.default_username
        self.query_one("#input_cache_ttl", Input).value = str(config.cache_ttl_seconds)
        self.query_one("#input_terminal", Input).value = config.terminal_emulator
        self.query_one("#input_theme", Input).value = config.theme

        ai = config.ai_provider
        self.query_one("#input_ai_provider", Input).value = ai.provider
        self.query_one("#input_ai_api_key", Input).value = ai.api_key
        self.query_one("#input_ai_model", Input).value = ai.model
        self.query_one("#input_ai_base_url", Input).value = ai.base_url
        self.query_one("#input_ai_max_tokens", Input).value = str(ai.max_tokens)
        self.query_one("#input_ai_temperature", Input).value = str(ai.temperature)

        self.query_one("#input_abuseipdb_key", Input).value = config.abuseipdb_api_key

    # ------------------------------------------------------------------
    # Scan Paths
    # ------------------------------------------------------------------

    def _populate_scan_paths(self) -> None:
        config = self.app.config_manager.get()
        paths_container = self.query_one("#scan_paths_list", Vertical)
        paths_container.remove_children()
        for path in config.default_scan_paths:
            paths_container.mount(
                Horizontal(
                    Static(path, classes="path_item"),
                    Button("Remove", classes="btn_remove_path", variant="error"),
                    classes="path_row",
                )
            )

    def _populate_scan_rules(self) -> None:
        config = self.app.config_manager.get()
        table = self.query_one("#scan_rules_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Rule Name", "Match Conditions", "Scan Paths", "Scan Commands")
        for rule in config.scan_rules:
            conditions = ", ".join(f"{k}={v}" for k, v in rule.match_conditions.items())
            paths = ", ".join(rule.scan_paths) if rule.scan_paths else "None"
            commands = ", ".join(rule.scan_commands) if rule.scan_commands else "None"
            table.add_row(rule.name, conditions, paths, commands)

    def _populate_connection_profiles(self) -> None:
        config = self.app.config_manager.get()
        table = self.query_one("#profiles_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Profile Name", "Bastion Host", "Bastion User", "SSH Port")
        for profile in config.connection_profiles:
            table.add_row(
                profile.name,
                profile.bastion_host or "None",
                profile.bastion_user or "None",
                str(profile.ssh_port),
            )

    def _populate_connection_rules(self) -> None:
        config = self.app.config_manager.get()
        table = self.query_one("#rules_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Rule Name", "Match Conditions", "Profile")
        for rule in config.connection_rules:
            conditions = ", ".join(f"{k}={v}" for k, v in rule.match_conditions.items())
            table.add_row(rule.name, conditions, rule.profile_name)

    # ------------------------------------------------------------------
    # IP Ban Configurations
    # ------------------------------------------------------------------

    def _populate_ipban_table(self) -> None:
        config = self.app.config_manager.get()
        table = self.query_one("#ipban_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Name", "Method", "Region", "Details")
        table.cursor_type = "row"
        for cfg in config.ip_ban_configs:
            if cfg.method == "waf":
                details = f"IP Set: {cfg.ip_set_name or cfg.ip_set_id or 'N/A'}"
            elif cfg.method == "security_group":
                details = f"SG: {cfg.security_group_id or 'N/A'}"
            elif cfg.method == "nacl":
                details = f"NACL: {cfg.nacl_id or 'N/A'}"
            else:
                details = ""
            table.add_row(cfg.name, cfg.method, cfg.region or "N/A", details)

    def _show_ipban_form(self) -> None:
        self.query_one("#ipban-form-container").display = True

    def _hide_ipban_form(self) -> None:
        self.query_one("#ipban-form-container").display = False
        self._editing_ipban_name = None

    def _clear_ipban_form(self) -> None:
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
        self._set_ipban_method_fields_visible(None)

    def _set_ipban_method_fields_visible(self, method: Optional[str]) -> None:
        waf_fields = self.query_one("#ipban_waf_fields")
        sg_fields = self.query_one("#ipban_sg_fields")
        nacl_fields = self.query_one("#ipban_nacl_fields")

        waf_fields.display = method == "waf"
        sg_fields.display = method == "security_group"
        nacl_fields.display = method == "nacl"

    def _get_selected_ipban_name(self) -> Optional[str]:
        table = self.query_one("#ipban_table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_data = table.get_row_at(table.cursor_row)
            return str(row_data[0])
        except Exception:
            return None

    # ------------------------------------------------------------------
    # IP Ban form actions
    # ------------------------------------------------------------------

    def _handle_ipban_add(self) -> None:
        self._editing_ipban_name = None
        self._clear_ipban_form()
        self._show_ipban_form()
        self.query_one("#ipban_input_name", Input).focus()

    def _handle_ipban_edit(self) -> None:
        name = self._get_selected_ipban_name()
        if not name:
            self.notify("Select a configuration to edit", severity="warning")
            return

        config = self.app.config_manager.get()
        cfg = next((c for c in config.ip_ban_configs if c.name == name), None)
        if not cfg:
            self.notify("Configuration not found", severity="error")
            return

        self._editing_ipban_name = name
        self._clear_ipban_form()

        self.query_one("#ipban_input_name", Input).value = cfg.name
        self.query_one("#ipban_input_ip_set_id", Input).value = cfg.ip_set_id
        self.query_one("#ipban_input_ip_set_name", Input).value = cfg.ip_set_name
        self.query_one("#ipban_input_sg_id", Input).value = cfg.security_group_id
        self.query_one("#ipban_input_nacl_id", Input).value = cfg.nacl_id
        self.query_one("#ipban_input_rule_number_start", Input).value = str(cfg.rule_number_start)

        self.query_one("#ipban_select_method", Select).value = cfg.method
        if cfg.region:
            self.query_one("#ipban_select_region", Select).value = cfg.region
        self.query_one("#ipban_select_waf_scope", Select).value = cfg.waf_scope

        self._set_ipban_method_fields_visible(cfg.method)
        self._show_ipban_form()
        self.query_one("#ipban_input_name", Input).focus()

    def _handle_ipban_remove(self) -> None:
        name = self._get_selected_ipban_name()
        if not name:
            self.notify("Select a configuration to remove", severity="warning")
            return

        config = self.app.config_manager.get()
        original_count = len(config.ip_ban_configs)
        config.ip_ban_configs = [c for c in config.ip_ban_configs if c.name != name]

        if len(config.ip_ban_configs) < original_count:
            self.app.config_manager.save(config)
            self._populate_ipban_table()
            self.notify(f"Removed IP ban config: {name}", severity="information")
        else:
            self.notify("Configuration not found", severity="error")

    def _handle_ipban_save(self) -> None:
        from servonaut.config.schema import IPBanConfig

        name = self.query_one("#ipban_input_name", Input).value.strip()
        method_value = self.query_one("#ipban_select_method", Select).value
        region_value = self.query_one("#ipban_select_region", Select).value

        if not name:
            self.notify("Name is required", severity="error")
            self.query_one("#ipban_input_name", Input).focus()
            return

        if method_value is Select.NULL or not method_value:
            self.notify("Method is required", severity="error")
            self.query_one("#ipban_select_method", Select).focus()
            return

        method = str(method_value)
        region = str(region_value) if region_value is not Select.NULL else ""

        # Method-specific validation
        if method == "waf":
            ip_set_id = self.query_one("#ipban_input_ip_set_id", Input).value.strip()
            ip_set_name = self.query_one("#ipban_input_ip_set_name", Input).value.strip()
            if not ip_set_id:
                self.notify("IP Set ID is required for WAF method", severity="error")
                self.query_one("#ipban_input_ip_set_id", Input).focus()
                return
            if not ip_set_name:
                self.notify("IP Set Name is required for WAF method", severity="error")
                self.query_one("#ipban_input_ip_set_name", Input).focus()
                return
        elif method == "security_group":
            sg_id = self.query_one("#ipban_input_sg_id", Input).value.strip()
            if not sg_id:
                self.notify("Security Group ID is required", severity="error")
                self.query_one("#ipban_input_sg_id", Input).focus()
                return
        elif method == "nacl":
            nacl_id = self.query_one("#ipban_input_nacl_id", Input).value.strip()
            if not nacl_id:
                self.notify("NACL ID is required", severity="error")
                self.query_one("#ipban_input_nacl_id", Input).focus()
                return

        ip_set_id = self.query_one("#ipban_input_ip_set_id", Input).value.strip()
        ip_set_name = self.query_one("#ipban_input_ip_set_name", Input).value.strip()
        waf_scope_value = self.query_one("#ipban_select_waf_scope", Select).value
        waf_scope = str(waf_scope_value) if waf_scope_value is not Select.NULL else "REGIONAL"
        sg_id = self.query_one("#ipban_input_sg_id", Input).value.strip()
        nacl_id = self.query_one("#ipban_input_nacl_id", Input).value.strip()
        rule_number_start_str = self.query_one("#ipban_input_rule_number_start", Input).value.strip()

        try:
            rule_number_start = int(rule_number_start_str) if rule_number_start_str else 100
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
                self.notify(f"A configuration named '{name}' already exists", severity="error")
                self.query_one("#ipban_input_name", Input).focus()
                return
            config.ip_ban_configs.append(new_cfg)

        self.app.config_manager.save(config)
        self._populate_ipban_table()
        self._hide_ipban_form()
        self.notify(f"Saved IP ban config: {name}", severity="information")
        logger.info("IP ban config saved: name=%s, method=%s", name, method)

    # ------------------------------------------------------------------
    # AWS Discovery
    # ------------------------------------------------------------------

    def _handle_ipban_discover(self) -> None:
        method_value = self.query_one("#ipban_select_method", Select).value
        region_value = self.query_one("#ipban_select_region", Select).value

        if method_value is Select.NULL or not method_value:
            self.notify("Select a method first", severity="warning")
            return
        if region_value is Select.NULL or not region_value:
            self.notify("Select a region first", severity="warning")
            return

        method = str(method_value)
        region = str(region_value)
        scope = "REGIONAL"
        scope_value = self.query_one("#ipban_select_waf_scope", Select).value
        if scope_value is not Select.NULL:
            scope = str(scope_value)

        self.query_one("#btn_ipban_discover", Button).disabled = True
        self.query_one("#ipban_discover_hint", Static).update("[dim]Discovering...[/dim]")

        self.run_worker(
            self._discover_aws_resources(method, region, scope),
            name="ipban_discover",
            group="discover",
            exclusive=True,
        )

    async def _discover_aws_resources(
        self, method: str, region: str, scope: str
    ) -> None:
        import asyncio

        try:
            if method == "waf":
                await self._discover_waf_ip_sets(region, scope)
            elif method == "security_group":
                await self._discover_security_groups(region)
            elif method == "nacl":
                await self._discover_nacls(region)
        except Exception as exc:
            self.notify(f"Discovery failed: {exc}", severity="error")
            logger.error("AWS discovery failed: %s", exc)
        finally:
            self.query_one("#btn_ipban_discover", Button).disabled = False
            self.query_one("#ipban_discover_hint", Static).update(
                "[dim]Select a method and region first, then discover available resources[/dim]"
            )

    async def _discover_waf_ip_sets(self, region: str, scope: str) -> None:
        import asyncio

        loop = asyncio.get_event_loop()

        def _fetch():
            import boto3

            client = boto3.client("wafv2", region_name=region)
            ip_sets = []
            params = {"Scope": scope}
            while True:
                response = client.list_ip_sets(**params)
                for ip_set in response.get("IPSets", []):
                    ip_sets.append({
                        "id": ip_set["Id"],
                        "name": ip_set["Name"],
                        "arn": ip_set.get("ARN", ""),
                    })
                next_marker = response.get("NextMarker")
                if not next_marker:
                    break
                params["NextMarker"] = next_marker
            return ip_sets

        ip_sets = await loop.run_in_executor(None, _fetch)
        self._discovered_ip_sets = ip_sets

        select = self.query_one("#ipban_select_ip_set", Select)
        if not ip_sets:
            select.set_options([])
            select.prompt = "No IP sets found"
            self.notify(f"No WAF IP sets found in {region} ({scope})", severity="warning")
        else:
            select.set_options([
                (f"{s['name']} ({s['id'][:8]}...)", f"{s['id']}|{s['name']}")
                for s in ip_sets
            ])
            select.prompt = f"Select from {len(ip_sets)} IP set(s)"
            self.notify(f"Found {len(ip_sets)} WAF IP set(s)")

    async def _discover_security_groups(self, region: str) -> None:
        import asyncio

        loop = asyncio.get_event_loop()

        def _fetch():
            import boto3

            ec2 = boto3.client("ec2", region_name=region)
            sgs = []
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    name = sg.get("GroupName", "")
                    sg_id = sg["GroupId"]
                    vpc = sg.get("VpcId", "")
                    sgs.append({"id": sg_id, "name": name, "vpc": vpc})
            return sgs

        sgs = await loop.run_in_executor(None, _fetch)
        self._discovered_sgs = sgs

        select = self.query_one("#ipban_select_sg", Select)
        if not sgs:
            select.set_options([])
            select.prompt = "No security groups found"
            self.notify(f"No security groups found in {region}", severity="warning")
        else:
            select.set_options([
                (f"{s['name']} ({s['id']})", s["id"])
                for s in sgs
            ])
            select.prompt = f"Select from {len(sgs)} SG(s)"
            self.notify(f"Found {len(sgs)} security group(s)")

    async def _discover_nacls(self, region: str) -> None:
        import asyncio

        loop = asyncio.get_event_loop()

        def _fetch():
            import boto3

            ec2 = boto3.client("ec2", region_name=region)
            nacls = []
            response = ec2.describe_network_acls()
            for acl in response.get("NetworkAcls", []):
                acl_id = acl["NetworkAclId"]
                vpc = acl.get("VpcId", "")
                is_default = acl.get("IsDefault", False)
                name = ""
                for tag in acl.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                        break
                label = name or ("default" if is_default else acl_id)
                nacls.append({"id": acl_id, "name": label, "vpc": vpc})
            return nacls

        nacls = await loop.run_in_executor(None, _fetch)
        self._discovered_nacls = nacls

        select = self.query_one("#ipban_select_nacl", Select)
        if not nacls:
            select.set_options([])
            select.prompt = "No NACLs found"
            self.notify(f"No NACLs found in {region}", severity="warning")
        else:
            select.set_options([
                (f"{n['name']} ({n['id']})", n["id"])
                for n in nacls
            ])
            select.prompt = f"Select from {len(nacls)} NACL(s)"
            self.notify(f"Found {len(nacls)} NACL(s)")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "ipban_select_method":
            method = str(event.value) if event.value is not Select.NULL else None
            self._set_ipban_method_fields_visible(method)
        elif event.select.id == "ipban_select_ip_set":
            # Auto-fill ID and Name from selected IP set
            if event.value is not Select.NULL and event.value:
                parts = str(event.value).split("|", 1)
                if len(parts) == 2:
                    self.query_one("#ipban_input_ip_set_id", Input).value = parts[0]
                    self.query_one("#ipban_input_ip_set_name", Input).value = parts[1]
        elif event.select.id == "ipban_select_sg":
            if event.value is not Select.NULL and event.value:
                self.query_one("#ipban_input_sg_id", Input).value = str(event.value)
        elif event.select.id == "ipban_select_nacl":
            if event.value is not Select.NULL and event.value:
                self.query_one("#ipban_input_nacl_id", Input).value = str(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "btn_add_path":
            self._add_scan_path()
        elif "btn_remove_path" in str(event.button.classes):
            self._remove_scan_path(event.button)
        elif button_id == "btn_ipban_add":
            self._handle_ipban_add()
        elif button_id == "btn_ipban_edit":
            self._handle_ipban_edit()
        elif button_id == "btn_ipban_remove":
            self._handle_ipban_remove()
        elif button_id == "btn_ipban_save":
            self._handle_ipban_save()
        elif button_id == "btn_ipban_cancel":
            self._hide_ipban_form()
        elif button_id == "btn_ipban_discover":
            self._handle_ipban_discover()

    def _add_scan_path(self) -> None:
        input_field = self.query_one("#input_new_path", Input)
        new_path = input_field.value.strip()

        if not new_path:
            self.notify("Please enter a path", severity="warning")
            return

        config = self.app.config_manager.get()
        if new_path in config.default_scan_paths:
            self.notify("Path already exists", severity="warning")
            return

        config.default_scan_paths.append(new_path)
        self.app.config_manager.save(config)
        self._populate_scan_paths()
        input_field.value = ""
        self.notify(f"Added path: {new_path}", severity="information")

    def _remove_scan_path(self, button: Button) -> None:
        path_row = button.parent
        if path_row:
            path_label = path_row.query_one(".path_item", Static)
            path_to_remove = str(path_label.content).strip()
            config = self.app.config_manager.get()
            if path_to_remove in config.default_scan_paths:
                config.default_scan_paths.remove(path_to_remove)
                self.app.config_manager.save(config)
                self._populate_scan_paths()
                self.notify(f"Removed path: {path_to_remove}", severity="information")

    def action_save(self) -> None:
        try:
            username = self.query_one("#input_username", Input).value.strip()
            cache_ttl_str = self.query_one("#input_cache_ttl", Input).value.strip()
            terminal = self.query_one("#input_terminal", Input).value.strip()
            theme = self.query_one("#input_theme", Input).value.strip()

            if not username:
                self.app.notify("Username cannot be empty", severity="error")
                self.query_one("#input_username", Input).focus()
                return

            if not cache_ttl_str:
                self.app.notify("Cache TTL is required", severity="error")
                self.query_one("#input_cache_ttl", Input).focus()
                return

            try:
                cache_ttl = int(cache_ttl_str)
                if cache_ttl < 0:
                    self.app.notify("Cache TTL must be a positive number", severity="error")
                    self.query_one("#input_cache_ttl", Input).focus()
                    return
            except ValueError:
                self.app.notify("Cache TTL must be a valid integer", severity="error")
                self.query_one("#input_cache_ttl", Input).focus()
                return

            if theme not in ["dark", "light"]:
                self.app.notify("Theme must be 'dark' or 'light'. Using 'dark'.", severity="warning")
                theme = "dark"

            ai_provider = self.query_one("#input_ai_provider", Input).value.strip() or "openai"
            ai_api_key = self.query_one("#input_ai_api_key", Input).value.strip()
            ai_model = self.query_one("#input_ai_model", Input).value.strip()
            ai_base_url = self.query_one("#input_ai_base_url", Input).value.strip()
            ai_max_tokens_str = self.query_one("#input_ai_max_tokens", Input).value.strip() or "2048"
            ai_temperature_str = self.query_one("#input_ai_temperature", Input).value.strip() or "0.3"

            try:
                ai_max_tokens = int(ai_max_tokens_str)
            except ValueError:
                ai_max_tokens = 2048

            try:
                ai_temperature = float(ai_temperature_str)
            except ValueError:
                ai_temperature = 0.3

            from servonaut.config.schema import AIProviderConfig

            ai_config = AIProviderConfig(
                provider=ai_provider,
                api_key=ai_api_key,
                model=ai_model,
                base_url=ai_base_url,
                max_tokens=ai_max_tokens,
                temperature=ai_temperature,
            )

            abuseipdb_key = self.query_one("#input_abuseipdb_key", Input).value.strip()

            self.app.config_manager.update(
                default_username=username,
                cache_ttl_seconds=cache_ttl,
                terminal_emulator=terminal,
                theme=theme,
                ai_provider=ai_config,
                abuseipdb_api_key=abuseipdb_key,
            )

            self.app.notify("Settings saved successfully", severity="information")
            logger.info("Settings saved: username=%s, cache_ttl=%d, terminal=%s, theme=%s",
                       username, cache_ttl, terminal, theme)

        except Exception as e:
            logger.error("Error saving settings: %s", e)
            self.app.notify(f"Error saving settings: {e}", severity="error")

    def action_back(self) -> None:
        self.app.pop_screen()

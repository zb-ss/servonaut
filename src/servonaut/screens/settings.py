"""Settings screen for Servonaut v2.0."""

from __future__ import annotations
from typing import List, Dict, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Input, Button, DataTable, Select


class SettingsScreen(Screen):
    """Configuration editor screen for app settings."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+s", "save", "Save", show=True),
    ]

    def __init__(self) -> None:
        """Initialize settings screen with edit state tracking."""
        super().__init__()
        self._editing_ipban_name: Optional[str] = None

    def compose(self) -> ComposeResult:
        """Compose the settings UI."""
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
                    Input(placeholder="my-waf-config", id="ipban_input_name"),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("Method:", classes="label"),
                    Select(
                        options=[
                            ("WAF", "waf"),
                            ("Security Group", "security_group"),
                            ("NACL", "nacl"),
                        ],
                        prompt="Select method...",
                        id="ipban_select_method",
                    ),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("Region:", classes="label"),
                    Input(placeholder="us-east-1", id="ipban_input_region"),
                    classes="setting_row",
                ),
                # WAF-specific fields
                Container(
                    Horizontal(
                        Static("IP Set ID:", classes="label"),
                        Input(placeholder="abc123...", id="ipban_input_ip_set_id"),
                        classes="setting_row",
                    ),
                    Horizontal(
                        Static("IP Set Name:", classes="label"),
                        Input(placeholder="my-blocklist", id="ipban_input_ip_set_name"),
                        classes="setting_row",
                    ),
                    Horizontal(
                        Static("WAF Scope:", classes="label"),
                        Select(
                            options=[
                                ("Regional", "REGIONAL"),
                                ("CloudFront", "CLOUDFRONT"),
                            ],
                            prompt="Select scope...",
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
                        Static("Security Group ID:", classes="label"),
                        Input(placeholder="sg-abc123", id="ipban_input_sg_id"),
                        classes="setting_row",
                    ),
                    classes="ipban-sg-fields",
                    id="ipban_sg_fields",
                ),
                # NACL fields
                Container(
                    Horizontal(
                        Static("NACL ID:", classes="label"),
                        Input(placeholder="acl-abc123", id="ipban_input_nacl_id"),
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

            id="settings_container"
        )
        yield Footer()

    def on_mount(self) -> None:
        """Load current settings when screen mounts."""
        self._load_settings()
        self._populate_scan_paths()
        self._populate_scan_rules()
        self._populate_connection_profiles()
        self._populate_connection_rules()
        self._populate_ipban_table()

    def _load_settings(self) -> None:
        """Load current config values into input fields."""
        config = self.app.config_manager.get()

        # Populate general settings
        self.query_one("#input_username", Input).value = config.default_username
        self.query_one("#input_cache_ttl", Input).value = str(config.cache_ttl_seconds)
        self.query_one("#input_terminal", Input).value = config.terminal_emulator
        self.query_one("#input_theme", Input).value = config.theme

        # Populate AI provider settings
        ai = config.ai_provider
        self.query_one("#input_ai_provider", Input).value = ai.provider
        self.query_one("#input_ai_api_key", Input).value = ai.api_key
        self.query_one("#input_ai_model", Input).value = ai.model
        self.query_one("#input_ai_base_url", Input).value = ai.base_url
        self.query_one("#input_ai_max_tokens", Input).value = str(ai.max_tokens)
        self.query_one("#input_ai_temperature", Input).value = str(ai.temperature)

    def _populate_scan_paths(self) -> None:
        """Populate the scan paths list."""
        config = self.app.config_manager.get()
        paths_container = self.query_one("#scan_paths_list", Vertical)

        # Clear existing paths
        paths_container.remove_children()

        # Add each path with remove button
        for path in config.default_scan_paths:
            paths_container.mount(
                Horizontal(
                    Static(path, classes="path_item"),
                    Button("Remove", classes="btn_remove_path", variant="error"),
                    classes="path_row",
                )
            )

    def _populate_scan_rules(self) -> None:
        """Populate scan rules table (read-only)."""
        config = self.app.config_manager.get()
        table = self.query_one("#scan_rules_table", DataTable)

        # Clear and setup table
        table.clear(columns=True)
        table.add_columns("Rule Name", "Match Conditions", "Scan Paths", "Scan Commands")

        # Add rules
        for rule in config.scan_rules:
            conditions = ", ".join(f"{k}={v}" for k, v in rule.match_conditions.items())
            paths = ", ".join(rule.scan_paths) if rule.scan_paths else "None"
            commands = ", ".join(rule.scan_commands) if rule.scan_commands else "None"
            table.add_row(rule.name, conditions, paths, commands)

    def _populate_connection_profiles(self) -> None:
        """Populate connection profiles table (read-only)."""
        config = self.app.config_manager.get()
        table = self.query_one("#profiles_table", DataTable)

        # Clear and setup table
        table.clear(columns=True)
        table.add_columns("Profile Name", "Bastion Host", "Bastion User", "SSH Port")

        # Add profiles
        for profile in config.connection_profiles:
            bastion_host = profile.bastion_host or "None"
            bastion_user = profile.bastion_user or "None"
            table.add_row(
                profile.name,
                bastion_host,
                bastion_user,
                str(profile.ssh_port)
            )

    def _populate_connection_rules(self) -> None:
        """Populate connection rules table (read-only)."""
        config = self.app.config_manager.get()
        table = self.query_one("#rules_table", DataTable)

        # Clear and setup table
        table.clear(columns=True)
        table.add_columns("Rule Name", "Match Conditions", "Profile")

        # Add rules
        for rule in config.connection_rules:
            conditions = ", ".join(f"{k}={v}" for k, v in rule.match_conditions.items())
            table.add_row(rule.name, conditions, rule.profile_name)

    def _populate_ipban_table(self) -> None:
        """Populate IP ban configurations table."""
        config = self.app.config_manager.get()
        table = self.query_one("#ipban_table", DataTable)

        table.clear(columns=True)
        table.add_columns("Name", "Method", "Region", "Details")

        for cfg in config.ip_ban_configs:
            if cfg.method == "waf":
                details = f"IP Set: {cfg.ip_set_id or 'N/A'}"
            elif cfg.method == "security_group":
                details = f"SG: {cfg.security_group_id or 'N/A'}"
            elif cfg.method == "nacl":
                details = f"NACL: {cfg.nacl_id or 'N/A'}"
            else:
                details = ""
            table.add_row(cfg.name, cfg.method, cfg.region or "N/A", details)

    def _show_ipban_form(self) -> None:
        """Show the IP ban edit form."""
        self.query_one("#ipban-form-container").add_class("--visible")

    def _hide_ipban_form(self) -> None:
        """Hide the IP ban edit form and clear all fields."""
        self.query_one("#ipban-form-container").remove_class("--visible")
        self._editing_ipban_name = None

    def _clear_ipban_form(self) -> None:
        """Reset all IP ban form fields to empty/defaults."""
        self.query_one("#ipban_input_name", Input).value = ""
        self.query_one("#ipban_input_region", Input).value = ""
        self.query_one("#ipban_input_ip_set_id", Input).value = ""
        self.query_one("#ipban_input_ip_set_name", Input).value = ""
        self.query_one("#ipban_input_sg_id", Input).value = ""
        self.query_one("#ipban_input_nacl_id", Input).value = ""
        self.query_one("#ipban_input_rule_number_start", Input).value = ""
        self.query_one("#ipban_select_method", Select).clear()
        self.query_one("#ipban_select_waf_scope", Select).clear()
        self._set_ipban_method_fields_visible(None)

    def _set_ipban_method_fields_visible(self, method: Optional[str]) -> None:
        """Toggle visibility of method-specific field containers.

        Args:
            method: Active method ('waf', 'security_group', 'nacl') or None to hide all.
        """
        waf_fields = self.query_one("#ipban_waf_fields")
        sg_fields = self.query_one("#ipban_sg_fields")
        nacl_fields = self.query_one("#ipban_nacl_fields")

        if method == "waf":
            waf_fields.add_class("--visible")
            sg_fields.remove_class("--visible")
            nacl_fields.remove_class("--visible")
        elif method == "security_group":
            waf_fields.remove_class("--visible")
            sg_fields.add_class("--visible")
            nacl_fields.remove_class("--visible")
        elif method == "nacl":
            waf_fields.remove_class("--visible")
            sg_fields.remove_class("--visible")
            nacl_fields.add_class("--visible")
        else:
            waf_fields.remove_class("--visible")
            sg_fields.remove_class("--visible")
            nacl_fields.remove_class("--visible")

    def _get_selected_ipban_name(self) -> Optional[str]:
        """Return the name of the currently cursor-selected IP ban config, or None."""
        table = self.query_one("#ipban_table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key = table.cursor_row
            row_data = table.get_row_at(row_key)
            return str(row_data[0])
        except Exception:
            return None

    def _handle_ipban_add(self) -> None:
        """Open the form in add mode."""
        self._editing_ipban_name = None
        self._clear_ipban_form()
        self._show_ipban_form()
        self.query_one("#ipban_input_name", Input).focus()

    def _handle_ipban_edit(self) -> None:
        """Open the form in edit mode for the selected config."""
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

        # Populate form with existing values
        self.query_one("#ipban_input_name", Input).value = cfg.name
        self.query_one("#ipban_input_region", Input).value = cfg.region
        self.query_one("#ipban_input_ip_set_id", Input).value = cfg.ip_set_id
        self.query_one("#ipban_input_ip_set_name", Input).value = cfg.ip_set_name
        self.query_one("#ipban_input_sg_id", Input).value = cfg.security_group_id
        self.query_one("#ipban_input_nacl_id", Input).value = cfg.nacl_id
        self.query_one("#ipban_input_rule_number_start", Input).value = str(cfg.rule_number_start)

        select_method = self.query_one("#ipban_select_method", Select)
        select_method.value = cfg.method

        select_scope = self.query_one("#ipban_select_waf_scope", Select)
        select_scope.value = cfg.waf_scope

        self._set_ipban_method_fields_visible(cfg.method)
        self._show_ipban_form()
        self.query_one("#ipban_input_name", Input).focus()

    def _handle_ipban_remove(self) -> None:
        """Remove the selected IP ban config."""
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
        """Validate form and save IP ban config."""
        import logging
        logger = logging.getLogger(__name__)

        from servonaut.config.schema import IPBanConfig

        name = self.query_one("#ipban_input_name", Input).value.strip()
        method_value = self.query_one("#ipban_select_method", Select).value
        region = self.query_one("#ipban_input_region", Input).value.strip()

        if not name:
            self.notify("Name is required", severity="error")
            self.query_one("#ipban_input_name", Input).focus()
            return

        # Select.BLANK is returned when nothing selected
        if method_value is Select.BLANK or not method_value:
            self.notify("Method is required", severity="error")
            self.query_one("#ipban_select_method", Select).focus()
            return

        method = str(method_value)

        # Method-specific validation
        if method == "waf":
            ip_set_id = self.query_one("#ipban_input_ip_set_id", Input).value.strip()
            if not ip_set_id:
                self.notify("IP Set ID is required for WAF method", severity="error")
                self.query_one("#ipban_input_ip_set_id", Input).focus()
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

        # Collect all field values
        ip_set_id = self.query_one("#ipban_input_ip_set_id", Input).value.strip()
        ip_set_name = self.query_one("#ipban_input_ip_set_name", Input).value.strip()
        waf_scope_value = self.query_one("#ipban_select_waf_scope", Select).value
        waf_scope = str(waf_scope_value) if waf_scope_value is not Select.BLANK else "REGIONAL"
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
            # Edit mode: replace existing entry (by original name)
            replaced = False
            for i, c in enumerate(config.ip_ban_configs):
                if c.name == self._editing_ipban_name:
                    config.ip_ban_configs[i] = new_cfg
                    replaced = True
                    break
            if not replaced:
                config.ip_ban_configs.append(new_cfg)
        else:
            # Add mode: check for duplicate name
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

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle Select widget value changes to toggle method-specific fields.

        Args:
            event: Select changed event.
        """
        if event.select.id == "ipban_select_method":
            method = str(event.value) if event.value is not Select.BLANK else None
            self._set_ipban_method_fields_visible(method)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events.

        Args:
            event: Button pressed event.
        """
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

    def _add_scan_path(self) -> None:
        """Add a new scan path to the list."""
        input_field = self.query_one("#input_new_path", Input)
        new_path = input_field.value.strip()

        if not new_path:
            self.notify("Please enter a path", severity="warning")
            return

        config = self.app.config_manager.get()

        # Check for duplicates
        if new_path in config.default_scan_paths:
            self.notify("Path already exists", severity="warning")
            return

        # Add to config
        config.default_scan_paths.append(new_path)
        self.app.config_manager.save(config)

        # Refresh display
        self._populate_scan_paths()

        # Clear input
        input_field.value = ""

        self.notify(f"Added path: {new_path}", severity="information")

    def _remove_scan_path(self, button: Button) -> None:
        """Remove a scan path from the list.

        Args:
            button: The remove button that was pressed.
        """
        # Get the path text from the sibling Static widget
        path_row = button.parent
        if path_row:
            path_label = path_row.query_one(".path_item", Static)
            path_to_remove = str(path_label.renderable).strip()

            config = self.app.config_manager.get()

            if path_to_remove in config.default_scan_paths:
                config.default_scan_paths.remove(path_to_remove)
                self.app.config_manager.save(config)
                self._populate_scan_paths()
                self.notify(f"Removed path: {path_to_remove}", severity="information")

    def action_save(self) -> None:
        """Save all settings changes."""
        import logging
        logger = logging.getLogger(__name__)

        try:
            # Read input values
            username = self.query_one("#input_username", Input).value.strip()
            cache_ttl_str = self.query_one("#input_cache_ttl", Input).value.strip()
            terminal = self.query_one("#input_terminal", Input).value.strip()
            theme = self.query_one("#input_theme", Input).value.strip()

            # Validate username
            if not username:
                self.app.notify("Username cannot be empty", severity="error")
                self.query_one("#input_username", Input).focus()
                return

            # Validate cache TTL
            if not cache_ttl_str:
                self.app.notify("Cache TTL is required", severity="error")
                self.query_one("#input_cache_ttl", Input).focus()
                return

            try:
                cache_ttl = int(cache_ttl_str)
                if cache_ttl < 0:
                    self.app.notify("Cache TTL must be a positive number (0 or greater)", severity="error")
                    self.query_one("#input_cache_ttl", Input).focus()
                    return
            except ValueError:
                self.app.notify("Cache TTL must be a valid integer", severity="error")
                self.query_one("#input_cache_ttl", Input).focus()
                return

            # Validate theme
            if theme not in ["dark", "light"]:
                self.app.notify("Theme must be 'dark' or 'light'. Using 'dark' as default.", severity="warning")
                theme = "dark"

            # Read AI provider fields
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

            # Build updated AI config
            from servonaut.config.schema import AIProviderConfig
            ai_config = AIProviderConfig(
                provider=ai_provider,
                api_key=ai_api_key,
                model=ai_model,
                base_url=ai_base_url,
                max_tokens=ai_max_tokens,
                temperature=ai_temperature,
            )

            # Update config
            self.app.config_manager.update(
                default_username=username,
                cache_ttl_seconds=cache_ttl,
                terminal_emulator=terminal,
                theme=theme,
                ai_provider=ai_config,
            )

            self.app.notify("Settings saved successfully", severity="information")
            logger.info("Settings saved: username=%s, cache_ttl=%d, terminal=%s, theme=%s",
                       username, cache_ttl, terminal, theme)

        except Exception as e:
            logger.error("Error saving settings: %s", e)
            self.app.notify(f"Error saving settings: {e}", severity="error")

    def action_back(self) -> None:
        """Navigate back to main menu."""
        self.app.pop_screen()

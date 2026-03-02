"""Settings screen for Servonaut v2.0."""

from __future__ import annotations
from typing import List, Dict

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Input, Button, DataTable


class SettingsScreen(Screen):
    """Configuration editor screen for app settings."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("s", "save", "Save", show=True),
    ]

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

            # Section 6: AI Provider
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

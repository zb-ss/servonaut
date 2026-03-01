"""Main menu screen for Servonaut v2.0."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Static, Button, Header, Footer

from servonaut.widgets.progress_indicator import ProgressIndicator


class MainMenuScreen(Screen):
    """Main menu screen with option selection."""

    BINDINGS = [
        Binding("1", "option_1", "List Instances", show=True),
        Binding("2", "option_2", "SSH Keys", show=True),
        Binding("3", "option_3", "Scan Servers", show=True),
        Binding("4", "option_4", "Settings", show=True),
        Binding("5", "option_5", "Custom Servers", show=True),
        Binding("6", "option_6", "CloudTrail Logs", show=True),
        Binding("7", "option_7", "IP Ban Manager", show=True),
        Binding("8", "quit", "Quit", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("l", "option_1", "List", show=False),
        Binding("k", "option_2", "Keys", show=False),
        Binding("c", "option_3", "Scan", show=False),
        Binding("t", "option_4", "Settings", show=False),
        Binding("q", "quit", "Quit", show=False),
        Binding("h", "show_help", "Help", show=False),
    ]

    def on_mount(self) -> None:
        """Focus the first menu button on mount."""
        self.query_one("#btn_list", Button).focus()


    def on_key(self, event) -> None:
        """Handle arrow key navigation between buttons.

        Args:
            event: Key event.
        """
        if event.key in ("up", "down"):
            buttons = list(self.query("Button"))
            if not buttons:
                return
            # Find currently focused button
            focused = self.focused
            if focused not in buttons:
                buttons[0].focus()
                return
            idx = buttons.index(focused)
            if event.key == "down":
                next_idx = (idx + 1) % len(buttons)
            else:
                next_idx = (idx - 1) % len(buttons)
            buttons[next_idx].focus()

    def compose(self) -> ComposeResult:
        """Compose the main menu UI."""
        yield Header()
        yield Container(
            Static(
                "[bold cyan]Servonaut v2.0[/bold cyan]\n\n"
                "[dim]AWS EC2 Instance Manager with SSH, SCP, and more.[/dim]\n"
                "[dim]Use arrow keys or number keys to navigate. Press Enter to select.[/dim]",
                id="banner"
            ),
            Vertical(
                Button("1. List Instances", id="btn_list", variant="primary"),
                Static("[dim]  View and connect to your EC2 instances across all regions[/dim]", classes="help_text"),
                Button("2. Manage SSH Keys", id="btn_keys"),
                Static("[dim]  Configure SSH keys, auto-discovery, and agent settings[/dim]", classes="help_text"),
                Button("3. Scan Servers", id="btn_scan"),
                Static("[dim]  Scan running instances for configured paths and commands[/dim]", classes="help_text"),
                Button("4. Settings", id="btn_settings"),
                Static("[dim]  Configure scan paths, profiles, and application settings[/dim]", classes="help_text"),
                Button("5. Custom Servers", id="btn_custom_servers"),
                Static("[dim]  Manage non-AWS servers (DigitalOcean, Hetzner, bare-metal)[/dim]", classes="help_text"),
                Button("6. CloudTrail Logs", id="btn_cloudtrail"),
                Static("[dim]  Browse and filter AWS CloudTrail events[/dim]", classes="help_text"),
                Button("7. IP Ban Manager", id="btn_ip_ban"),
                Static("[dim]  Ban/unban IPs via WAF, Security Groups, or NACLs[/dim]", classes="help_text"),
                Button("8. Quit", id="btn_quit", variant="error"),
                id="menu_buttons"
            ),
            ProgressIndicator(),
            id="menu_container"
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events.

        Args:
            event: Button pressed event.
        """
        button_id = event.button.id

        if button_id == "btn_list":
            self.action_option_1()
        elif button_id == "btn_keys":
            self.action_option_2()
        elif button_id == "btn_scan":
            self.action_option_3()
        elif button_id == "btn_settings":
            self.action_option_4()
        elif button_id == "btn_custom_servers":
            self.action_option_5()
        elif button_id == "btn_cloudtrail":
            self.action_option_6()
        elif button_id == "btn_ip_ban":
            self.action_option_7()
        elif button_id == "btn_quit":
            self.action_quit()

    def action_option_1(self) -> None:
        """Navigate to List Instances screen."""
        from servonaut.screens.instance_list import InstanceListScreen
        self.app.push_screen(InstanceListScreen())

    def action_option_2(self) -> None:
        """Navigate to SSH Keys management."""
        from servonaut.screens.key_management import KeyManagementScreen
        self.app.push_screen(KeyManagementScreen())

    def action_option_3(self) -> None:
        """Scan Servers — scan all running instances."""
        progress = self.query_one(ProgressIndicator)
        progress.start("Preparing scan...")
        self.query_one("#btn_scan", Button).disabled = True
        self.run_worker(self._scan_all_servers(), name="scan_all", exclusive=True)

    async def _scan_all_servers(self) -> None:
        """Worker function to scan all running instances."""
        progress = self.query_one(ProgressIndicator)

        instances = self.app.instances
        if not instances:
            progress.start("Loading instances from AWS...")
            instances = await self.app.aws_service.fetch_instances_cached()
            self.app.instances = instances

        running = [i for i in instances if i.get('state') == 'running']
        if not running:
            progress.stop()
            self.query_one("#btn_scan", Button).disabled = False
            self.app.notify("No running instances to scan", severity="warning")
            return

        total = len(running)
        scanned = 0
        for idx, instance in enumerate(running, 1):
            name = instance.get('name') or instance.get('id', 'unknown')
            progress.start(f"Scanning {idx}/{total}: {name}...")
            try:
                results = await self.app.scan_service.scan_server(
                    instance, self.app.ssh_service, self.app.connection_service
                )
                if results:
                    self.app.keyword_store.save_results(instance['id'], results)
                    scanned += 1
            except Exception as e:
                self.app.notify(f"Scan failed for {name}: {e}", severity="error")

        progress.stop()
        self.query_one("#btn_scan", Button).disabled = False
        self.app.notify(f"Scan complete. {scanned}/{total} servers scanned.")

    def action_option_4(self) -> None:
        """Navigate to Settings."""
        from servonaut.screens.settings import SettingsScreen
        self.app.push_screen(SettingsScreen())

    def action_option_5(self) -> None:
        """Navigate to Custom Servers management."""
        from servonaut.screens.custom_servers import CustomServersScreen
        self.app.push_screen(CustomServersScreen())

    def action_option_6(self) -> None:
        """Navigate to CloudTrail Log Browser."""
        from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
        self.app.push_screen(CloudTrailBrowserScreen())

    def action_option_7(self) -> None:
        """Navigate to IP Ban Manager."""
        from servonaut.screens.ip_ban import IPBanScreen
        self.app.push_screen(IPBanScreen())

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()

    def action_show_help(self) -> None:
        """Show help screen."""
        from servonaut.screens.help import HelpScreen
        self.app.push_screen(HelpScreen())

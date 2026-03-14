"""Main menu screen for Servonaut v2.0."""

from __future__ import annotations

from importlib.metadata import version as pkg_version

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
        Binding("8", "option_8", "CloudWatch Logs", show=True),
        Binding("0", "quit", "Quit", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("a", "account", "Account", show=False),
        Binding("l", "option_1", "List", show=False),
        Binding("k", "option_2", "Keys", show=False),
        Binding("c", "option_3", "Scan", show=False),
        Binding("t", "option_4", "Settings", show=False),
        Binding("u", "update", "Update", show=False),
        Binding("q", "quit", "Quit", show=False),
        Binding("h", "show_help", "Help", show=False),
    ]

    def on_mount(self) -> None:
        """Focus the first menu button on mount and check for updates."""
        self.query_one("#btn_list", Button).focus()
        self.run_worker(self._check_update(), name="version_check", exclusive=True)
        self._update_account_status()

    def on_key(self, event) -> None:
        """Handle arrow key navigation between buttons."""
        if event.key in ("up", "down"):
            buttons = list(self.query("Button"))
            if not buttons:
                return
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

    BUTTON_DESCRIPTIONS: dict[str, str] = {
        "btn_list": "View and connect to your EC2 instances across all regions",
        "btn_keys": "Configure SSH keys, auto-discovery, and agent settings",
        "btn_scan": "Scan running instances for configured paths and commands",
        "btn_settings": "Configure scan paths, profiles, AI provider, and application settings",
        "btn_custom_servers": "Manage non-AWS servers (DigitalOcean, Hetzner, bare-metal)",
        "btn_cloudtrail": "Browse and filter AWS CloudTrail events",
        "btn_ip_ban": "Ban/unban IPs via WAF, Security Groups, or NACLs",
        "btn_cloudwatch": "Browse AWS CloudWatch log groups with Top IPs analysis",
        "btn_account": "Log in, view plan, manage your servonaut.dev account",
        "btn_team": "Manage team workspaces, shared servers, and members",
        "btn_update": "Download and install the latest version of Servonaut",
        "btn_quit": "Exit Servonaut",
    }

    def compose(self) -> ComposeResult:
        """Compose the main menu UI."""
        yield Header()
        yield Container(
            Static(
                f"[bold cyan]Servonaut v{pkg_version('servonaut')}[/bold cyan]\n\n"
                "[dim]Server Manager with SSH, SCP, AI Analysis, and more.[/dim]\n"
                "[dim]Use arrow keys or number keys to navigate. Press Enter to select.[/dim]",
                id="banner"
            ),
            Static("", id="account_status"),
            Vertical(
                Button("1. List Instances", id="btn_list", variant="primary"),
                Button("2. Manage SSH Keys", id="btn_keys"),
                Button("3. Scan Servers", id="btn_scan"),
                Button("4. Settings", id="btn_settings"),
                Button("5. Custom Servers", id="btn_custom_servers"),
                Button("6. CloudTrail Logs", id="btn_cloudtrail"),
                Button("7. IP Ban Manager", id="btn_ip_ban"),
                Button("8. CloudWatch Logs", id="btn_cloudwatch"),
                Button("A. Account", id="btn_account"),
                Button("T. Team", id="btn_team", classes="hidden"),
                Button("9. Update Servonaut", id="btn_update", classes="hidden", disabled=True),
                Button("0. Quit", id="btn_quit", variant="error"),
                id="menu_buttons"
            ),
            Static("", id="menu_hint"),
            ProgressIndicator(),
            id="menu_container"
        )
        yield Footer()

    async def _check_update(self) -> None:
        """Check for updates in the background."""
        import asyncio
        latest = await asyncio.to_thread(self.app.update_service.check_for_update)
        if latest:
            btn = self.query_one("#btn_update", Button)
            btn.label = f"9. Update to v{latest}"
            btn.remove_class("hidden")
            btn.disabled = False
            self.app.notify(
                f"Update available: v{latest} (you have v{self.app.update_service.current_version})",
                severity="information",
                timeout=8,
            )

    def on_descendant_focus(self, event) -> None:
        """Update hint text when a button receives focus."""
        hint = self.query_one("#menu_hint", Static)
        if isinstance(event.widget, Button) and event.widget.id:
            description = self.BUTTON_DESCRIPTIONS.get(event.widget.id, "")
            hint.update(f"[dim italic]{description}[/dim italic]")
        else:
            hint.update("")

    def _update_account_status(self) -> None:
        """Update the account status display on the main menu."""
        status_widget = self.query_one("#account_status", Static)
        auth = self.app.auth_service
        if auth and auth.is_authenticated:
            plan = auth.plan.capitalize()
            status_widget.update(f"[dim]Logged in — [cyan]{plan}[/cyan] plan[/dim]")
            # Show team button for teams plan
            if auth.plan == "teams":
                team_btn = self.query_one("#btn_team", Button)
                team_btn.remove_class("hidden")
        else:
            status_widget.update("[dim]Not logged in — [yellow]Free[/yellow] tier[/dim]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
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
        elif button_id == "btn_cloudwatch":
            self.action_option_8()
        elif button_id == "btn_account":
            self.action_account()
        elif button_id == "btn_team":
            self.action_team()
        elif button_id == "btn_update":
            self.action_update()
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

    def action_option_8(self) -> None:
        """Navigate to CloudWatch Logs Browser."""
        from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
        self.app.push_screen(CloudWatchBrowserScreen())

    def action_account(self) -> None:
        """Navigate to Account / Login screen."""
        if self.app.auth_service and self.app.auth_service.is_authenticated:
            # Already logged in — show status or offer logout
            plan = self.app.auth_service.plan
            self.app.notify(
                f"Logged in ({plan} plan). Use 'servonaut --logout' to sign out.",
                severity="information",
            )
        else:
            from servonaut.screens.login import LoginScreen
            self.app.push_screen(LoginScreen(on_complete=self._on_login_complete))

    def _on_login_complete(self, success: bool) -> None:
        """Callback after login flow completes."""
        if success:
            self._update_account_status()

    def action_team(self) -> None:
        """Navigate to Team Management screen."""
        allowed, reason = self.app.entitlement_guard.check("team_workspace")
        if not allowed:
            self.app.notify(reason, severity="warning")
            return
        from servonaut.screens.team_management import TeamManagementScreen
        self.app.push_screen(TeamManagementScreen())

    def action_update(self) -> None:
        """Run the update process."""
        btn = self.query_one("#btn_update", Button)
        if btn.has_class("hidden"):
            self.app.notify("Already up to date!", severity="information")
            return
        btn.disabled = True
        progress = self.query_one(ProgressIndicator)
        progress.start("Updating Servonaut...")
        self.run_worker(self._run_update(), name="update", exclusive=True)

    async def _run_update(self) -> None:
        """Run upgrade in background."""
        progress = self.query_one(ProgressIndicator)
        success, message = await self.app.update_service.run_upgrade()
        progress.stop()
        self.query_one("#btn_update", Button).disabled = False
        severity = "information" if success else "error"
        self.app.notify(message, severity=severity, timeout=10)

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()

    def action_show_help(self) -> None:
        """Show help screen."""
        from servonaut.screens.help import HelpScreen
        self.app.push_screen(HelpScreen())

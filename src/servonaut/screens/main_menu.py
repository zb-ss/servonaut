"""Main menu screen for Servonaut v2.0."""

from __future__ import annotations

from importlib.metadata import version as pkg_version

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal, Grid
from textual.screen import Screen
from textual.widgets import Static, Button, Header, Footer

from servonaut.widgets.progress_indicator import ProgressIndicator
from servonaut.widgets.sidebar import Sidebar


class MainMenuScreen(Screen):
    """Modern Dashboard screen with sidebar navigation."""

    BINDINGS = [
        Binding("1", "option_1", "List Instances", show=False),
        Binding("2", "option_2", "SSH Keys", show=False),
        Binding("3", "option_3", "Scan Servers", show=False),
        Binding("4", "option_4", "Settings", show=False),
        Binding("5", "option_5", "Custom Servers", show=False),
        Binding("6", "option_6", "CloudTrail", show=False),
        Binding("7", "option_7", "IP Ban Manager", show=False),
        Binding("8", "option_8", "CloudWatch", show=False),
        Binding("0", "quit", "Quit", show=False),
        Binding("q", "quit", "Quit", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
    ]

    def on_mount(self) -> None:
        """Initialize the dashboard and check for updates."""
        self.run_worker(self._update_stats(), name="update_stats")
        self.run_worker(self._check_update(), name="version_check", exclusive=True)
        # Focus the list instances button in the main area by default
        try:
            self.query_one("#card_list", Button).focus()
        except:
            pass

    async def _update_stats(self) -> None:
        """Update dashboard statistics."""
        instances = self.app.instances
        
        # If no instances loaded yet, try to load from cache
        if not instances and self.app.cache_service:
            cached = self.app.cache_service.load_any()
            if cached:
                instances = cached
                self.app.instances = cached
                
        total = len(instances)
        running = sum(1 for i in instances if i.get("state") == "running")
        stopped = sum(1 for i in instances if i.get("state") == "stopped")
        
        # Update UI safely
        try:
            self.query_one("#stat-total", Static).update(f"[bold cyan]{total}[/bold cyan]\nTotal Servers")
            self.query_one("#stat-running", Static).update(f"[bold green]{running}[/bold green]\nRunning")
            self.query_one("#stat-stopped", Static).update(f"[bold yellow]{stopped}[/bold yellow]\nStopped")
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        """Compose the dashboard UI."""
        yield Header()
        
        with Horizontal(id="main-layout"):
            # Left Navigation Sidebar
            yield Sidebar()
            
            # Right Content Area (Dashboard)
            with Vertical(id="dashboard-content"):
                with Container(id="dashboard-header"):
                    yield Static(f"Welcome to [bold cyan]Servonaut[/bold cyan]", id="dashboard-title")
                    yield Static("Select a tool or view to get started.", id="dashboard-subtitle")
                
                # Stats Row
                with Horizontal(id="stats-row"):
                    yield Static("...\nTotal Servers", id="stat-total", classes="stat-card")
                    yield Static("...\nRunning", id="stat-running", classes="stat-card")
                    yield Static("...\nStopped", id="stat-stopped", classes="stat-card")
                
                # Main Actions Grid
                with Grid(id="actions-grid"):
                    yield Button("📋  Instances Explorer\n[dim]View, connect, and manage servers[/dim]", id="card_list", classes="action-card")
                    yield Button("💻 Custom Servers\n[dim]Manage external bare-metal/VPS[/dim]", id="card_custom_servers", classes="action-card")
                    yield Button("📊  CloudWatch Logs\n[dim]Analyze logs and top IPs[/dim]", id="card_cloudwatch", classes="action-card")
                    yield Button("🔒 IP Ban Manager\n[dim]Block malicious traffic[/dim]", id="card_ip_ban", classes="action-card")
                    yield Button("🔍  CloudTrail Events\n[dim]Audit AWS API activity[/dim]", id="card_cloudtrail", classes="action-card")
                    yield Button("🎯  Security Scanner\n[dim]Scan fleet for vulnerabilities[/dim]", id="card_scan", classes="action-card")

                yield ProgressIndicator()
                
        yield Footer()

    async def _check_update(self) -> None:
        """Check for updates in the background."""
        import asyncio
        latest = await asyncio.to_thread(self.app.update_service.check_for_update)
        if latest:
            # Update sidebar button
            try:
                btn = self.query_one("#nav_update", Button)
                btn.label = f"⬇️ Update to v{latest}"
                btn.remove_class("hidden")
            except:
                pass
            
            self.app.notify(
                f"Update available: v{latest} (you have v{self.app.update_service.current_version})",
                severity="information",
                timeout=8,
            )

    def on_sidebar_navigation_requested(self, message: Sidebar.NavigationRequested) -> None:
        """Handle navigation events from the sidebar."""
        self._route_navigation(message.target_id)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle dashboard card button presses."""
        # Convert card IDs to match routing logic
        card_id = event.button.id
        if card_id and card_id.startswith("card_"):
            nav_id = card_id.replace("card_", "nav_")
            self._route_navigation(nav_id)
            
    def _route_navigation(self, target_id: str | None) -> None:
        """Route to the appropriate screen based on button ID."""
        if not target_id:
            return
            
        if target_id == "nav_list":
            self.action_option_1()
        elif target_id == "nav_keys":
            self.action_option_2()
        elif target_id == "nav_scan":
            self.action_option_3()
        elif target_id == "nav_settings":
            self.action_option_4()
        elif target_id == "nav_custom_servers":
            self.action_option_5()
        elif target_id == "nav_cloudtrail":
            self.action_option_6()
        elif target_id == "nav_ip_ban":
            self.action_option_7()
        elif target_id == "nav_cloudwatch":
            self.action_option_8()
        elif target_id == "nav_update":
            self.action_update()
        elif target_id == "nav_quit":
            self.action_quit()

    # --- Actions (Same as before, just triggered differently) ---

    def action_option_1(self) -> None:
        from servonaut.screens.instance_list import InstanceListScreen
        self.app.push_screen(InstanceListScreen())

    def action_option_2(self) -> None:
        from servonaut.screens.key_management import KeyManagementScreen
        self.app.push_screen(KeyManagementScreen())

    def action_option_3(self) -> None:
        progress = self.query_one(ProgressIndicator)
        progress.start("Preparing scan...")
        # Disable scan buttons
        for btn in self.query("Button"):
            if "scan" in str(btn.id):
                btn.disabled = True
        self.run_worker(self._scan_all_servers(), name="scan_all", exclusive=True)

    async def _scan_all_servers(self) -> None:
        progress = self.query_one(ProgressIndicator)
        instances = self.app.instances
        if not instances:
            progress.start("Loading instances from AWS...")
            instances = await self.app.aws_service.fetch_instances_cached()
            self.app.instances = instances

        running = [i for i in instances if i.get('state') == 'running']
        if not running:
            progress.stop()
            for btn in self.query("Button"):
                if "scan" in str(btn.id):
                    btn.disabled = False
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
        for btn in self.query("Button"):
            if "scan" in str(btn.id):
                btn.disabled = False
        self.app.notify(f"Scan complete. {scanned}/{total} servers scanned.")

    def action_option_4(self) -> None:
        from servonaut.screens.settings import SettingsScreen
        self.app.push_screen(SettingsScreen())

    def action_option_5(self) -> None:
        from servonaut.screens.custom_servers import CustomServersScreen
        self.app.push_screen(CustomServersScreen())

    def action_option_6(self) -> None:
        from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
        self.app.push_screen(CloudTrailBrowserScreen())

    def action_option_7(self) -> None:
        from servonaut.screens.ip_ban import IPBanScreen
        self.app.push_screen(IPBanScreen())

    def action_option_8(self) -> None:
        from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
        self.app.push_screen(CloudWatchBrowserScreen())

    def action_update(self) -> None:
        btn = self.query_one("#nav_update", Button)
        if btn.has_class("hidden"):
            self.app.notify("Already up to date!", severity="information")
            return
        btn.disabled = True
        progress = self.query_one(ProgressIndicator)
        progress.start("Updating Servonaut...")
        self.run_worker(self._run_update(), name="update", exclusive=True)

    async def _run_update(self) -> None:
        progress = self.query_one(ProgressIndicator)
        success, message = await self.app.update_service.run_upgrade()
        progress.stop()
        self.query_one("#nav_update", Button).disabled = False
        severity = "information" if success else "error"
        self.app.notify(message, severity=severity, timeout=10)

    def action_quit(self) -> None:
        self.app.exit()

    def action_show_help(self) -> None:
        from servonaut.screens.help import HelpScreen
        self.app.push_screen(HelpScreen())

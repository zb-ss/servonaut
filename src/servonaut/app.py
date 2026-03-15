"""Main Textual application for Servonaut v2.0."""

from __future__ import annotations
from typing import Optional, List

from textual.app import App
from textual.binding import Binding


class ServonautApp(App):
    """Servonaut TUI application."""

    CSS_PATH = "app.css"
    TITLE = "Servonaut"
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("f2", "toggle_chat", "Chat", show=True),
    ]

    # Service instances - created in on_mount
    config_manager = None
    aws_service = None
    cache_service = None
    ssh_service = None
    connection_service = None
    scan_service = None
    keyword_store = None
    terminal_service = None
    scp_service = None
    command_history = None
    custom_server_service = None
    log_viewer_service = None
    cloudtrail_service = None
    cloudwatch_service = None
    ip_ban_service = None
    ai_analysis_service = None
    chat_service = None
    update_service = None

    # Shared state
    instances: List[dict] = []  # all fetched instances

    # Latest version found by the background update check (None = not checked yet)
    _latest_version: Optional[str] = None

    def on_mount(self) -> None:
        """Initialize services and push main menu."""
        from servonaut.screens.instance_list import InstanceListScreen

        self._init_services()
        # Eagerly load cached instances so all screens have data
        cached = self.cache_service.load_any()
        if cached:
            self.instances = cached
        # Merge custom servers into instance list
        self.instances.extend(self.custom_server_service.list_as_instances())
        self.push_screen(InstanceListScreen())
        # Check for updates in background
        self.run_worker(self._check_for_update(), name="version_check", exclusive=True)

    def _init_services(self) -> None:
        """Create all service instances."""
        from servonaut.config.manager import ConfigManager
        from servonaut.services.cache_service import CacheService
        from servonaut.services.aws_service import AWSService
        from servonaut.services.ssh_service import SSHService
        from servonaut.services.connection_service import ConnectionService
        from servonaut.services.scan_service import ScanService
        from servonaut.services.keyword_store import KeywordStore
        from servonaut.services.terminal_service import TerminalService
        from servonaut.services.scp_service import SCPService
        from servonaut.services.command_history import CommandHistoryService
        from servonaut.services.custom_server_service import CustomServerService
        from servonaut.services.log_viewer_service import LogViewerService
        from servonaut.services.cloudtrail_service import CloudTrailService
        from servonaut.services.cloudwatch_service import CloudWatchService
        from servonaut.services.ip_ban_service import IPBanService
        from servonaut.services.ai_analysis_service import AIAnalysisService
        from servonaut.services.chat_service import ChatService
        from servonaut.services.chat_tools import ChatToolExecutor

        from servonaut.services.update_service import UpdateService
        self.update_service = UpdateService()
        self.config_manager = ConfigManager()
        config = self.config_manager.get()
        self.cache_service = CacheService(ttl_seconds=config.cache_ttl_seconds)
        self.aws_service = AWSService(self.cache_service)
        self.ssh_service = SSHService(self.config_manager)
        self.connection_service = ConnectionService(self.config_manager)
        self.scan_service = ScanService(self.config_manager)
        self.keyword_store = KeywordStore(config.keyword_store_path)
        self.terminal_service = TerminalService(preferred=config.terminal_emulator)
        self.scp_service = SCPService()
        self.command_history = CommandHistoryService(config.command_history_path)
        self.custom_server_service = CustomServerService(self.config_manager)
        self.log_viewer_service = LogViewerService(self.config_manager)
        self.cloudtrail_service = CloudTrailService(self.config_manager)
        self.cloudwatch_service = CloudWatchService()
        self.ip_ban_service = IPBanService(self.config_manager)
        self.ai_analysis_service = AIAnalysisService(self.config_manager)
        tool_executor = ChatToolExecutor(
            config_manager=self.config_manager,
            aws_service=self.aws_service,
            cache_service=self.cache_service,
            ssh_service=self.ssh_service,
            connection_service=self.connection_service,
            guard_level=config.chat_tool_guard_level,
        )
        self.chat_service = ChatService(
            self.config_manager, self.ai_analysis_service, tool_executor
        )

    def on_text_selected(self) -> None:
        """Auto-copy selected text to clipboard when user highlights with mouse."""
        text = self.screen.get_selected_text()
        if not text:
            return

        from servonaut.utils.platform_utils import copy_to_clipboard
        if copy_to_clipboard(text):
            self.notify(f"Copied to clipboard", severity="information")
        else:
            # Fallback: use Textual's OSC 52 clipboard
            self.copy_to_clipboard(text)
            self.notify(f"Copied to clipboard", severity="information")

    def action_show_help(self) -> None:
        """Show help screen from any context."""
        from servonaut.screens.help import HelpScreen
        self.push_screen(HelpScreen())

    def action_toggle_chat(self) -> None:
        """Toggle the chat panel on the current screen."""
        from textual.css.query import NoMatches
        from servonaut.widgets.chat_panel import ChatPanel
        try:
            panel = self.screen.query_one("#chat-panel", ChatPanel)
            panel.remove()
        except NoMatches:
            panel = ChatPanel()
            self.screen.mount(panel)
            panel.focus_input()


    def on_sidebar_navigation_requested(self, message) -> None:
        """Handle navigation events from the sidebar."""
        target_id = message.target_id
        if not target_id:
            return
            
        if target_id == "nav_list":
            from servonaut.screens.instance_list import InstanceListScreen
            self.switch_screen(InstanceListScreen())
        elif target_id == "nav_keys":
            from servonaut.screens.key_management import KeyManagementScreen
            self.switch_screen(KeyManagementScreen())
        elif target_id == "nav_scan":
            self._run_global_scan()
        elif target_id == "nav_settings":
            from servonaut.screens.settings import SettingsScreen
            self.switch_screen(SettingsScreen())
        elif target_id == "nav_custom_servers":
            from servonaut.screens.custom_servers import CustomServersScreen
            self.switch_screen(CustomServersScreen())
        elif target_id == "nav_cloudtrail":
            from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
            self.switch_screen(CloudTrailBrowserScreen())
        elif target_id == "nav_ip_ban":
            from servonaut.screens.ip_ban import IPBanScreen
            self.switch_screen(IPBanScreen())
        elif target_id == "nav_cloudwatch":
            from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
            self.switch_screen(CloudWatchBrowserScreen())
        elif target_id == "nav_update":
            self._run_update()
        elif target_id == "nav_quit":
            self.exit()

    def _run_global_scan(self) -> None:
        """Run keyword scan across all running instances."""
        self.notify("Starting scan of all running servers...", severity="information")
        self.run_worker(self._do_global_scan(), name="global_scan", exclusive=True)

    async def _do_global_scan(self) -> None:
        """Worker: scan all running instances for keywords."""
        instances = self.instances
        if not instances:
            self.notify("No instances loaded. Load instances first.", severity="warning")
            return

        running = [i for i in instances if i.get('state') == 'running']
        if not running:
            self.notify("No running instances to scan.", severity="warning")
            return

        total = len(running)
        scanned = 0
        for idx, instance in enumerate(running, 1):
            name = instance.get('name') or instance.get('id', 'unknown')
            self.notify(f"Scanning {idx}/{total}: {name}...", severity="information")
            try:
                results = await self.scan_service.scan_server(
                    instance, self.ssh_service, self.connection_service
                )
                if results:
                    self.keyword_store.save_results(instance['id'], results)
                    scanned += 1
            except Exception as e:
                self.notify(f"Scan failed for {name}: {e}", severity="error")

        self.notify(f"Scan complete. {scanned}/{total} servers scanned.")

    async def _check_for_update(self) -> None:
        """Check PyPI for a newer version in the background."""
        import asyncio
        latest = await asyncio.to_thread(self.update_service.check_for_update)
        if latest:
            self._latest_version = latest
            self._show_update_button(latest)
            self.notify(
                f"Update available: v{latest} (you have v{self.update_service.current_version})",
                severity="information",
                timeout=8,
            )

    def _show_update_button(self, version: str) -> None:
        """Reveal the update button on the current screen's sidebar."""
        from textual.widgets import Button
        try:
            btn = self.screen.query_one("#nav_update", Button)
            btn.label = f"⬇️ Update to v{version}"
            btn.remove_class("hidden")
        except Exception:
            pass

    def _run_update(self) -> None:
        """Run the upgrade via pipx/pip."""
        if not self._latest_version:
            self.notify("Already up to date!", severity="information")
            return
        self.notify("Updating Servonaut...", severity="information")
        self.run_worker(self._do_update(), name="update", exclusive=True)

    async def _do_update(self) -> None:
        """Worker: run the upgrade."""
        success, message = await self.update_service.run_upgrade()
        severity = "information" if success else "error"
        self.notify(message, severity=severity, timeout=10)

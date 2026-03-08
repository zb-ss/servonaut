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

    def on_mount(self) -> None:
        """Initialize services and push main menu."""
        from servonaut.screens.main_menu import MainMenuScreen

        self._init_services()
        # Eagerly load cached instances so all screens have data
        cached = self.cache_service.load_any()
        if cached:
            self.instances = cached
        # Merge custom servers into instance list
        self.instances.extend(self.custom_server_service.list_as_instances())
        self.push_screen(MainMenuScreen())

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


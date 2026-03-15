from __future__ import annotations

from importlib.metadata import version as pkg_version

from textual.app import ComposeResult
from textual.containers import Vertical, Container
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, Static, Label


# Map screen class names to their sidebar nav button IDs.
_SCREEN_TO_NAV: dict[str, str] = {
    "InstanceListScreen": "nav_list",
    "CustomServersScreen": "nav_custom_servers",
    "KeyManagementScreen": "nav_keys",
    "CloudWatchBrowserScreen": "nav_cloudwatch",
    "IPBanScreen": "nav_ip_ban",
    "CloudTrailBrowserScreen": "nav_cloudtrail",
    "SettingsScreen": "nav_settings",
    "HelpScreen": "nav_help",
}


class Sidebar(Widget):
    """A persistent sidebar navigation widget."""

    class NavigationRequested(Message):
        """Message sent when a sidebar navigation button is pressed."""
        def __init__(self, target_id: str | None) -> None:
            self.target_id = target_id
            super().__init__()

    def compose(self) -> ComposeResult:
        with Vertical(id="sidebar-container"):
            with Container(id="sidebar-header"):
                yield Static(f"[bold cyan]Servonaut[/bold cyan] [dim]v{pkg_version('servonaut')}[/dim]", id="sidebar-logo")
                yield Static("[dim italic]Server Manager[/dim italic]", id="sidebar-subtitle")

            with Vertical(id="sidebar-nav"):
                yield Label("Core", classes="sidebar-section-title")
                yield Button("📋 Instances", id="nav_list", classes="nav-button")
                yield Button("🖥️  Custom Servers", id="nav_custom_servers", classes="nav-button")
                yield Button("🔑 SSH Keys", id="nav_keys", classes="nav-button")

                yield Label("Logs & Security", classes="sidebar-section-title")
                yield Button("📊 CloudWatch", id="nav_cloudwatch", classes="nav-button")
                yield Button("🛡️  IP Ban Manager", id="nav_ip_ban", classes="nav-button")
                yield Button("🔍 CloudTrail", id="nav_cloudtrail", classes="nav-button")

                yield Label("Tools", classes="sidebar-section-title")
                yield Button("🎯 Scan Servers", id="nav_scan", classes="nav-button")
                yield Button("⚙️  Settings", id="nav_settings", classes="nav-button")

            with Vertical(id="sidebar-footer"):
                yield Button("⬇️  Update Available", id="nav_update", classes="nav-button hidden")
                yield Button("👋 Quit", id="nav_quit", classes="nav-button error-button")

    def on_mount(self) -> None:
        """Highlight the button matching the current screen and sync update state."""
        self._update_active()
        self._sync_update_button()

    def _update_active(self) -> None:
        """Set the --active class on the button that matches the current screen."""
        screen_name = type(self.screen).__name__
        active_id = _SCREEN_TO_NAV.get(screen_name)
        for btn in self.query(".nav-button"):
            btn.remove_class("--active")
        if active_id:
            try:
                self.query_one(f"#{active_id}", Button).add_class("--active")
            except Exception:
                pass

    def _sync_update_button(self) -> None:
        """Show the update button if the app already found a newer version."""
        latest = getattr(self.app, "_latest_version", None)
        if latest:
            try:
                btn = self.query_one("#nav_update", Button)
                btn.label = f"⬇️ Update to v{latest}"
                btn.remove_class("hidden")
            except Exception:
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Propagate button presses to the parent screen."""
        event.stop()
        self.post_message(self.NavigationRequested(event.button.id))

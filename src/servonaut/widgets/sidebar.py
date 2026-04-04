from __future__ import annotations

from importlib.metadata import version as pkg_version

from textual.app import ComposeResult
from textual.css.query import NoMatches
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
    "OVHDNSScreen": "nav_ovh_dns",
    "OVHIPManagementScreen": "nav_ovh_ips",
    "OVHStorageScreen": "nav_ovh_storage",
    "OVHBillingScreen": "nav_ovh_billing",
    "OVHCloudCreateScreen": "nav_ovh_cloud_new",
    "OVHSSHKeysScreen": "nav_ovh_ssh_keys",
    "LoginScreen": "nav_login",
    "TeamManagementScreen": "nav_teams",
}


class Sidebar(Widget):
    """A persistent sidebar navigation widget.

    Flat structure — no nested Vertical/Container wrappers — to avoid
    scrollbar-gutter artifacts at the widget boundary.
    """

    DEFAULT_CSS = """
    Sidebar {
        width: 25;
        height: 100%;
        background: $panel;
        overflow: hidden;
        layout: vertical;
        padding: 1 0 2 0;
    }
    """

    class NavigationRequested(Message):
        """Message sent when a sidebar navigation button is pressed."""
        def __init__(self, target_id: str | None) -> None:
            self.target_id = target_id
            super().__init__()

    def compose(self) -> ComposeResult:
        yield Static(
            f"  [bold cyan]Servonaut[/bold cyan] [dim]v{pkg_version('servonaut')}[/dim]",
            id="sidebar-logo",
        )
        yield Static("  [dim italic]Server Manager[/dim italic]", id="sidebar-subtitle")
        yield Label("Core", classes="sidebar-section-title")
        btn = Button("📋 Instances", id="nav_list", classes="nav-button")
        btn.tooltip = "View, connect, and manage all servers"
        yield btn
        btn = Button("💻 Custom Servers", id="nav_custom_servers", classes="nav-button")
        btn.tooltip = "Manage non-AWS servers (DigitalOcean, Hetzner, etc.)"
        yield btn
        btn = Button("🔑 SSH Keys", id="nav_keys", classes="nav-button")
        btn.tooltip = "Configure SSH keys and agent"
        yield btn
        yield Label("Logs & Security", classes="sidebar-section-title")
        btn = Button("📊 CloudWatch", id="nav_cloudwatch", classes="nav-button")
        btn.tooltip = "Browse CloudWatch log groups and events"
        yield btn
        btn = Button("🔒 IP Ban Manager", id="nav_ip_ban", classes="nav-button")
        btn.tooltip = "Ban/unban IPs via WAF, Security Groups, or NACLs"
        yield btn
        btn = Button("🔍 CloudTrail", id="nav_cloudtrail", classes="nav-button")
        btn.tooltip = "Audit AWS API activity and events"
        yield btn
        yield Label("Tools", classes="sidebar-section-title")
        btn = Button("🔧 Settings", id="nav_settings", classes="nav-button")
        btn.tooltip = "Edit configuration, scan rules, and AI provider"
        yield btn
        yield Label("OVH", id="ovh_section_label", classes="sidebar-section-title")
        btn = Button("DNS Zones", id="nav_ovh_dns", classes="nav-button")
        btn.tooltip = "Manage OVH DNS zones and records"
        yield btn
        btn = Button("IP Management", id="nav_ovh_ips", classes="nav-button")
        btn.tooltip = "Manage OVH IP blocks and failover IPs"
        yield btn
        btn = Button("Block Storage", id="nav_ovh_storage", classes="nav-button")
        btn.tooltip = "Manage OVH block storage volumes"
        yield btn
        btn = Button("Billing", id="nav_ovh_billing", classes="nav-button")
        btn.tooltip = "View OVH invoices and consumption"
        yield btn
        btn = Button("SSH Keys", id="nav_ovh_ssh_keys", classes="nav-button")
        btn.tooltip = "Manage SSH keys on OVH cloud projects"
        yield btn
        btn = Button("New Cloud Instance", id="nav_ovh_cloud_new", classes="nav-button")
        btn.tooltip = "Create a new OVH Public Cloud instance"
        yield btn
        yield Label("Account", classes="sidebar-section-title")
        btn = Button("Login / Account", id="nav_login", classes="nav-button")
        btn.tooltip = "Sign in to your Servonaut account"
        yield btn
        btn = Button("Teams", id="nav_teams", classes="nav-button")
        btn.tooltip = "Manage team members and shared access"
        yield btn
        yield Static("", id="sidebar-spacer")
        yield Button("📥  Update Available", id="nav_update", classes="nav-button hidden")
        yield Button("👋 Quit", id="nav_quit", classes="nav-button error-button")

    can_focus = False

    def on_mount(self) -> None:
        """Highlight the button matching the current screen and sync update state."""
        self._update_active()
        self._sync_update_button()
        # Prevent sidebar nav buttons from stealing keyboard focus.
        for btn in self.query(".nav-button"):
            btn.can_focus = False
        # Hide OVH section if OVH is not enabled
        if getattr(self.app, 'ovh_service', None) is None:
            for widget_id in [
                "nav_ovh_dns", "nav_ovh_ips", "nav_ovh_storage",
                "nav_ovh_billing", "nav_ovh_ssh_keys", "nav_ovh_cloud_new",
                "ovh_section_label",
            ]:
                try:
                    self.query_one(f"#{widget_id}").display = False
                except Exception:
                    pass

    def _update_active(self) -> None:
        """Set the --active class on the button that matches the current screen."""
        screen_name = type(self.screen).__name__
        active_id = _SCREEN_TO_NAV.get(screen_name)
        for btn in self.query(".nav-button"):
            btn.remove_class("--active")
        if active_id:
            try:
                self.query_one(f"#{active_id}", Button).add_class("--active")
            except NoMatches:
                pass

    def _sync_update_button(self) -> None:
        """Show the update button if the app already found a newer version."""
        latest = getattr(self.app, "_latest_version", None)
        if latest:
            try:
                btn = self.query_one("#nav_update", Button)
                btn.label = f"📥 Update to v{latest}"
                btn.remove_class("hidden")
            except NoMatches:
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Propagate button presses to the parent screen."""
        event.stop()
        self.post_message(self.NavigationRequested(event.button.id))

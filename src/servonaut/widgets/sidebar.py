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
    "FleetMemoryScreen": "nav_memory",
    "MemorySyncSetupScreen": "nav_memory_sync",
    "MemoryDriftScreen": "nav_drift",
    "MemoryExportScreen": "nav_memory_export",
    "SnapshotManagerScreen": "nav_sync_config",
    "OVHDNSScreen": "nav_ovh_dns",
    "OVHIPManagementScreen": "nav_ovh_ips",
    "OVHStorageScreen": "nav_ovh_storage",
    "OVHBillingScreen": "nav_ovh_billing",
    "OVHCloudCreateScreen": "nav_ovh_cloud_new",
    "OVHSSHKeysScreen": "nav_ovh_ssh_keys",
    "LoginScreen": "nav_login",
    "TeamManagementScreen": "nav_teams",
    "BugReportScreen": "nav_bug_report",
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
        btn = Button("🧠 Fleet Memory", id="nav_memory", classes="nav-button")
        btn.tooltip = (
            "Fleet-wide server memory — scan, refresh, and inspect the "
            "AI-queryable fact cache for every server"
        )
        yield btn
        btn = Button("🔄 Sync Config", id="nav_sync_config", classes="nav-button")
        btn.tooltip = (
            "Push or pull your servonaut config (scan rules, custom servers, "
            "AI provider) across devices via the cloud — encrypted with your passphrase"
        )
        yield btn
        btn = Button("☁ Memory Sync", id="nav_memory_sync", classes="nav-button")
        btn.tooltip = (
            "Set up encrypted Memory Sync — back up server memory across "
            "devices, with drift detection and AI-queryable history"
        )
        yield btn
        btn = Button("Drift Events", id="nav_drift", classes="nav-button")
        btn.tooltip = "View configuration drift and anomaly events across the fleet"
        yield btn
        btn = Button("Memory Export", id="nav_memory_export", classes="nav-button")
        btn.tooltip = "Export a compliance-grade signed archive of server memory"
        yield btn
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
        btn = Button("👤 Account / Login", id="nav_login", classes="nav-button")
        btn.tooltip = "Sign in to your Servonaut account"
        yield btn
        btn = Button("Teams", id="nav_teams", classes="nav-button")
        btn.tooltip = "Manage team members and shared access"
        yield btn
        btn = Button("🐛 Report a bug", id="nav_bug_report", classes="nav-button")
        btn.tooltip = "Send a bug report — review exactly what's included before anything leaves your machine"
        yield btn
        yield Static("", id="sidebar-spacer")
        from servonaut.widgets.relay_indicator import RelayIndicator
        yield RelayIndicator(id="relay_indicator")
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
        # Hide Teams button unless the plan includes team_workspaces
        auth = getattr(self.app, 'auth_service', None)
        if not auth or not auth.has_feature("team_workspaces"):
            try:
                self.query_one("#nav_teams").display = False
            except Exception:
                pass
        # Memory cloud nav gating:
        # - "Memory Sync" (nav_memory_sync) is visible to ALL users — it's
        #   the central setup/explainer/upsell hub. The screen itself adapts
        #   to the user's tier.
        # - The action-specific entries (Drift / Settings / Export) only
        #   appear once the user has BOTH the entitlement AND has finished
        #   one-time setup — otherwise they'd be empty and confusing.
        # Sync Config — only for logged-in subscribers (config_sync entitlement).
        # Free / logged-out users don't see it.
        if not auth or not auth.is_authenticated or not auth.has_feature("config_sync"):
            try:
                self.query_one("#nav_sync_config").display = False
            except Exception:
                pass
        sync_svc = getattr(self.app, "memory_sync_service", None)
        is_configured = bool(sync_svc and getattr(sync_svc, "is_configured", False))
        _memory_feature_gates = {
            "nav_drift": "memory_drift",
            "nav_memory_export": "memory_compliance_export",
        }
        for nav_id, feature_slug in _memory_feature_gates.items():
            entitled = bool(auth and auth.has_feature(feature_slug))
            if not (entitled and is_configured):
                try:
                    self.query_one(f"#{nav_id}").display = False
                except Exception:
                    pass
        # Sync initial relay indicator from the app's reactive.
        try:
            indicator = self.query_one("#relay_indicator")
            indicator.state = getattr(self.app, "relay_state", None)
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

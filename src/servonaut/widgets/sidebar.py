"""Persistent left-rail navigation for every Servonaut screen.

Layout:

* Top (fixed): logo + subtitle.
* Middle (scrollable): a stack of :class:`SidebarSection` collapsibles
  grouping nav buttons by purpose. Sections auto-expand when the
  active screen lives inside them, and collapse otherwise. The middle
  region scrolls if content exceeds the available height.
* Bottom (docked): the relay indicator, optional update prompt, and
  the always-visible ``Quit`` button. Docking guarantees these stay
  on screen even on a 24-row terminal — small terminals were
  silently clipping these buttons before this redesign.

Provider sections follow a single pattern: render only when the
corresponding ``app.<provider>_service`` is non-``None``. Each
provider owns its section title and button set; adding a new
provider means adding one ``SidebarSection`` block here plus the
screens it points at. OVH ships today; GCP, Azure, Hetzner can
follow the same shape.
"""

from __future__ import annotations

from importlib.metadata import version as pkg_version

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, Static

from servonaut.widgets.sidebar_section import SidebarSection


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
}


class Sidebar(Widget):
    """Top-level navigation widget mounted on every screen."""

    DEFAULT_CSS = """
    Sidebar {
        width: 25;
        height: 100%;
        background: $panel;
        layout: vertical;
        padding: 1 0 0 0;
    }
    Sidebar > #sidebar-scroll {
        height: 1fr;
        overflow-y: auto;
        overflow-x: hidden;
        scrollbar-size: 0 1;
        scrollbar-background: $panel;
        scrollbar-color: $panel;
    }
    Sidebar > #sidebar-bottom {
        dock: bottom;
        height: auto;
        layout: vertical;
        padding: 1 0 1 0;
        background: $panel;
    }
    """

    class NavigationRequested(Message):
        """Message sent when a sidebar navigation button is pressed."""

        def __init__(self, target_id: str | None) -> None:
            self.target_id = target_id
            super().__init__()

    def compose(self) -> ComposeResult:
        # ----- top: logo, subtitle -----
        yield Static(
            f"  [bold cyan]Servonaut[/bold cyan] [dim]v{pkg_version('servonaut')}[/dim]",
            id="sidebar-logo",
        )
        yield Static(
            "  [dim italic]Server Manager[/dim italic]",
            id="sidebar-subtitle",
        )

        # ----- middle: scrollable sections -----
        with VerticalScroll(id="sidebar-scroll"):
            yield SidebarSection(
                "Core",
                self._nav("📋 Instances", "nav_list",
                          tooltip="View, connect, and manage all servers"),
                self._nav("💻 Custom Servers", "nav_custom_servers",
                          tooltip="Manage non-AWS servers (DigitalOcean, Hetzner, etc.)"),
                self._nav("🔑 SSH Keys", "nav_keys",
                          tooltip="Configure SSH keys and agent"),
                section_id="section_core",
            )
            yield SidebarSection(
                "Logs & Security",
                self._nav("📊 CloudWatch", "nav_cloudwatch",
                          tooltip="Browse CloudWatch log groups and events"),
                self._nav("🔒 IP Ban Manager", "nav_ip_ban",
                          tooltip="Ban/unban IPs via WAF, Security Groups, or NACLs"),
                self._nav("🔍 CloudTrail", "nav_cloudtrail",
                          tooltip="Audit AWS API activity and events"),
                section_id="section_logs",
                collapsed=True,
            )
            yield SidebarSection(
                "Tools",
                self._nav("🧠 Fleet Memory", "nav_memory",
                          tooltip="Fleet-wide server memory — scan, refresh, and inspect "
                                  "the AI-queryable fact cache for every server"),
                self._nav("🔄 Sync Config", "nav_sync_config",
                          tooltip="Push or pull your servonaut config across devices via "
                                  "the cloud — encrypted with your passphrase"),
                self._nav("☁ Memory Sync", "nav_memory_sync",
                          tooltip="Set up encrypted Memory Sync — back up server memory "
                                  "across devices, with drift detection and AI-queryable history"),
                self._nav("Drift Events", "nav_drift",
                          tooltip="View configuration drift and anomaly events across the fleet"),
                self._nav("Memory Export", "nav_memory_export",
                          tooltip="Export a compliance-grade signed archive of server memory"),
                self._nav("🔧 Settings", "nav_settings",
                          tooltip="Edit configuration, scan rules, and AI provider"),
                section_id="section_tools",
                collapsed=True,
            )
            yield SidebarSection(
                "OVH",
                self._nav("DNS Zones", "nav_ovh_dns",
                          tooltip="Manage OVH DNS zones and records"),
                self._nav("IP Management", "nav_ovh_ips",
                          tooltip="Manage OVH IP blocks and failover IPs"),
                self._nav("Block Storage", "nav_ovh_storage",
                          tooltip="Manage OVH block storage volumes"),
                self._nav("Billing", "nav_ovh_billing",
                          tooltip="View OVH invoices and consumption"),
                self._nav("SSH Keys", "nav_ovh_ssh_keys",
                          tooltip="Manage SSH keys on OVH cloud projects"),
                self._nav("New Cloud Instance", "nav_ovh_cloud_new",
                          tooltip="Create a new OVH Public Cloud instance"),
                section_id="section_ovh",
                collapsed=True,
            )
            yield SidebarSection(
                "Hetzner",
                self._nav("☁ Hetzner Servers", "nav_hetzner_list",
                          tooltip="Filter the instance table to Hetzner Cloud servers"),
                self._nav("Test Connection", "nav_hetzner_test",
                          tooltip="Verify the Hetzner API token can reach Hetzner Cloud"),
                self._nav("SSH Keys", "nav_hetzner_ssh_keys",
                          tooltip="Manage Hetzner-side SSH keys (use `servonaut hetzner "
                                  "ssh-keys` CLI for now)"),
                self._nav("Server Types", "nav_hetzner_types",
                          tooltip="Browse available Hetzner server types (use `servonaut "
                                  "hetzner server-types` CLI for now)"),
                self._nav("New Cloud Instance", "nav_hetzner_create",
                          tooltip="Provision a new Hetzner Cloud server (use `servonaut "
                                  "hetzner create` CLI for now)"),
                section_id="section_hetzner",
                collapsed=True,
            )
            yield SidebarSection(
                "Account",
                self._nav("👤 Account / Login", "nav_login",
                          tooltip="Sign in to your Servonaut account"),
                self._nav("Teams", "nav_teams",
                          tooltip="Manage team members and shared access"),
                section_id="section_account",
                collapsed=True,
            )

        # ----- bottom: docked, always visible -----
        with Vertical(id="sidebar-bottom"):
            from servonaut.widgets.relay_indicator import RelayIndicator
            yield RelayIndicator(id="relay_indicator")
            yield Button(
                "📥  Update Available",
                id="nav_update",
                classes="nav-button hidden",
            )
            yield Button("👋 Quit", id="nav_quit", classes="nav-button error-button")

    can_focus = False

    def _nav(self, label: str, button_id: str, *, tooltip: str) -> Button:
        """Helper — build a nav button with the standard class + tooltip."""
        btn = Button(label, id=button_id, classes="nav-button")
        btn.tooltip = tooltip
        return btn

    def on_mount(self) -> None:
        """Apply gating, sync update + relay state, then expand the active section."""
        # Buttons in nav-button class never steal focus.
        for btn in self.query(".nav-button"):
            btn.can_focus = False
        # The wrapping VerticalScroll defaults to focusable — without
        # this the sidebar would steal initial focus from the screen's
        # search input on every mount (regression in the redesign).
        try:
            self.query_one("#sidebar-scroll").can_focus = False
        except NoMatches:
            pass

        # ----- Provider section gating -----
        # Hide whole sections when the corresponding provider isn't enabled.
        # (If an entire section disappears, its sibling sections renumber
        # cleanly because the layout is a flexible scroll container.)
        if getattr(self.app, "ovh_service", None) is None:
            self._hide_section("section_ovh")
        if getattr(self.app, "hetzner_service", None) is None:
            self._hide_section("section_hetzner")

        # ----- Per-button entitlement gating (inside still-visible sections) -----
        auth = getattr(self.app, "auth_service", None)
        if not auth or not auth.has_feature("team_workspaces"):
            self._hide_button("nav_teams")

        # Sync Config — only for logged-in subscribers (config_sync entitlement).
        if not auth or not auth.is_authenticated or not auth.has_feature("config_sync"):
            self._hide_button("nav_sync_config")

        # Memory cloud nav gating:
        # - "Memory Sync" (nav_memory_sync) is visible to ALL users — central
        #   setup hub, the screen adapts to tier.
        # - Drift / Export only appear once entitled AND configured, otherwise
        #   they'd be empty and confusing.
        sync_svc = getattr(self.app, "memory_sync_service", None)
        is_configured = bool(sync_svc and getattr(sync_svc, "is_configured", False))
        memory_feature_gates = {
            "nav_drift": "memory_drift",
            "nav_memory_export": "memory_compliance_export",
        }
        for nav_id, feature_slug in memory_feature_gates.items():
            entitled = bool(auth and auth.has_feature(feature_slug))
            if not (entitled and is_configured):
                self._hide_button(nav_id)

        # ----- Initial active highlight + auto-expand -----
        self._update_active()
        self._sync_update_button()

        # ----- Sync relay indicator -----
        try:
            indicator = self.query_one("#relay_indicator")
            indicator.state = getattr(self.app, "relay_state", None)
        except NoMatches:
            pass

    def _hide_section(self, section_id: str) -> None:
        try:
            self.query_one(f"#{section_id}", SidebarSection).display = False
        except NoMatches:
            pass

    def _hide_button(self, button_id: str) -> None:
        try:
            self.query_one(f"#{button_id}", Button).display = False
        except NoMatches:
            pass

    def _update_active(self) -> None:
        """Highlight the active nav button and auto-expand its section.

        Sections without the active button collapse (default-tight UX).
        If the active screen has no nav button (e.g. a modal) the
        previously expanded section stays expanded — feels less jumpy
        than collapsing everything.
        """
        screen_name = type(self.screen).__name__
        active_id = _SCREEN_TO_NAV.get(screen_name)

        # Highlight ring
        for btn in self.query(".nav-button"):
            btn.remove_class("--active")
        if active_id:
            try:
                self.query_one(f"#{active_id}", Button).add_class("--active")
            except NoMatches:
                pass

        # Auto-expand: only the section containing the active button stays open.
        if active_id:
            for section in self.query(SidebarSection):
                section.collapsed = not section.contains_button(active_id)

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
        """Propagate nav button presses to the parent screen.

        Section-header presses are consumed by ``SidebarSection`` itself
        and never reach this handler. Only nav buttons (with ids in
        ``_SCREEN_TO_NAV`` plus ``nav_quit`` / ``nav_update`` / the
        Hetzner stub ids) reach here.
        """
        event.stop()
        self.post_message(self.NavigationRequested(event.button.id))

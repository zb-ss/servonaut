"""Persistent left-rail navigation for every Servonaut screen.

Layout:

* A rounded Navigate panel contains :class:`SidebarSection` collapsibles
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

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.content import Content
from textual.css.query import NoMatches
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button

from servonaut.widgets.link_button import LinkButton
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
    "SecretsScreen": "nav_secrets",
    "VaultScreen": "nav_vault",
    "CaScreen": "nav_ca",
    "BwVaultManagerScreen": "nav_bw_vault",
    "FindingsScreen": "nav_findings",
    "FindingDetailScreen": "nav_findings",
    "MemoryDriftScreen": "nav_drift",
    "MemoryExportScreen": "nav_memory_export",
    "SnapshotManagerScreen": "nav_sync_config",
    "OVHDNSScreen": "nav_ovh_dns",
    "OVHIPManagementScreen": "nav_ovh_ips",
    "OVHStorageScreen": "nav_ovh_storage",
    "OVHBillingScreen": "nav_ovh_billing",
    "OVHSSHKeysScreen": "nav_ovh_ssh_keys",
    "AWSManagerScreen": "nav_aws_manage",
    "ObjectStorageScreen": "nav_aws_s3",
    "OVHManagerScreen": "nav_ovh_manage",
    "HetznerManagerScreen": "nav_hetzner_manage",
    "HetznerSSHKeysScreen": "nav_hetzner_ssh_keys",
    "LoginScreen": "nav_login",
    "TeamManagementScreen": "nav_teams",
    "BugReportScreen": "nav_bug_report",
}


def _provider_available(app, provider: str) -> bool:
    """Whether *provider* has a usable account (any account, not only the
    primary one). Hosts without the check fall back to the default service."""
    check = getattr(app, "provider_available", None)
    if callable(check):
        return bool(check(provider))
    return getattr(app, f"{provider}_service", None) is not None


def _aws_switched_on(app) -> bool:
    """Whether AWS is switched on in Settings; hosts without a config count as on."""
    from servonaut.config.accounts import aws_enabled

    manager = getattr(app, "config_manager", None)
    try:
        return aws_enabled(manager.get()) if manager is not None else True
    except Exception:  # noqa: BLE001 — a stand-in host must never hide AWS
        return True


class _NavigationButton(Button):
    """Extend native active styling through the row's trailing cells."""

    def render(self) -> Content:
        label = self.label
        if self.has_class("--active"):
            return label.pad_right(max(0, self.content_size.width - label.cell_length))
        return label


class Sidebar(Widget):
    """Top-level navigation widget mounted on every screen."""

    BINDINGS = [Binding("escape", "leave_navigation", "Return to content", show=False)]

    DEFAULT_CSS = """
    Sidebar {
        width: 25;
        height: 100%;
        background: transparent;
        layout: vertical;
        padding: 1 0 0 0;
    }
    Sidebar > #sidebar-scroll {
        height: 1fr;
        background: transparent;
        overflow-y: auto;
        overflow-x: hidden;
        scrollbar-size: 0 1;
        scrollbar-background: transparent;
        scrollbar-color: $panel;
    }
    Sidebar > #sidebar-bottom {
        dock: bottom;
        height: auto;
        layout: vertical;
        padding: 1 0 1 0;
        background: transparent;
    }
    """

    class NavigationRequested(Message):
        """Message sent when a sidebar navigation button is pressed."""

        def __init__(self, target_id: str | None) -> None:
            self.target_id = target_id
            super().__init__()

    def compose(self) -> ComposeResult:
        # ----- middle: scrollable sections -----
        # Start outside the tab order so content keeps initial focus.
        # Explicit navigation mode enables the visible buttons temporarily.
        with VerticalScroll(id="sidebar-scroll", can_focus=False):
            yield SidebarSection(
                "Core",
                self._nav("Instances", "nav_list",
                          tooltip="View, connect, and manage all servers"),
                self._nav("Custom servers", "nav_custom_servers",
                          tooltip="Manage non-AWS servers (DigitalOcean, Hetzner, etc.)"),
                self._nav("SSH keys", "nav_keys",
                          tooltip="Configure SSH keys and agent"),
                section_id="section_core",
            )
            yield SidebarSection(
                "Tools",
                self._nav("Fleet memory", "nav_memory",
                          tooltip="Fleet-wide server memory — scan, refresh, and inspect "
                                  "the AI-queryable fact cache for every server"),
                self._nav("Sync config", "nav_sync_config",
                          tooltip="Push or pull your servonaut config across devices via "
                                  "the cloud — encrypted with your passphrase"),
                self._nav("Memory Sync", "nav_memory_sync",
                          tooltip="Set up encrypted Memory Sync — back up server memory "
                                  "across devices, with drift detection and AI-queryable history"),
                self._nav("Secrets", "nav_secrets",
                          tooltip="Manage secrets-management backend — Bitwarden / "
                                  "local store / install bws / refresh team config"),
                self._nav("Vault", "nav_vault",
                          tooltip="Encrypted vault identities, SSH keys and secrets"),
                self._nav("SSH certificates", "nav_ca",
                          tooltip="Team SSH certificate authority and audit"),
                self._nav("BW SSH vault", "nav_bw_vault",
                          tooltip="Browse your Bitwarden SSH-key items joined with the "
                                  "servers that reference them (local-only; Solo/Teams)"),
                self._nav("Findings", "nav_findings",
                          tooltip="Proactive monitoring findings across your fleet — "
                                  "scan, review, and triage server-detected issues"),
                self._nav("Drift events", "nav_drift",
                          tooltip="View configuration drift and anomaly events across the fleet"),
                self._nav("Memory export", "nav_memory_export",
                          tooltip="Export a compliance-grade signed archive of server memory"),
                self._nav("Settings", "nav_settings",
                          tooltip="Edit configuration, scan rules, and AI provider"),
                section_id="section_tools",
                collapsed=True,
            )
            yield SidebarSection(
                "AWS",
                self._nav("Manage", "nav_aws_manage",
                          tooltip="Per-provider manager: create, start/stop, reboot, terminate EC2 instances"),
                self._nav("Object storage", "nav_aws_s3",
                          tooltip="Browse and manage S3 buckets and objects"),
                self._nav("CloudWatch", "nav_cloudwatch",
                          tooltip="Browse CloudWatch log groups and events"),
                self._nav("IP ban manager", "nav_ip_ban",
                          tooltip="Ban/unban IPs via WAF, Security Groups, or NACLs"),
                self._nav("CloudTrail", "nav_cloudtrail",
                          tooltip="Audit AWS API activity and events"),
                section_id="section_aws",
                collapsed=True,
            )
            yield SidebarSection(
                "OVH",
                self._nav("Manage", "nav_ovh_manage",
                          tooltip="Per-provider manager: create, start/stop, reboot, delete OVH instances"),
                self._nav("DNS zones", "nav_ovh_dns",
                          tooltip="Manage OVH DNS zones and records"),
                self._nav("IP management", "nav_ovh_ips",
                          tooltip="Manage OVH IP blocks and failover IPs"),
                self._nav("Block storage", "nav_ovh_storage",
                          tooltip="Manage OVH block storage volumes"),
                self._nav("Billing", "nav_ovh_billing",
                          tooltip="View OVH invoices and consumption"),
                self._nav("SSH keys", "nav_ovh_ssh_keys",
                          tooltip="Manage SSH keys on OVH cloud projects"),
                self._nav("Object storage", "nav_ovh_s3",
                          tooltip="Browse and manage OVH Object Storage (S3-compatible) buckets"),
                section_id="section_ovh",
                collapsed=True,
            )
            yield SidebarSection(
                "Hetzner",
                self._nav("Manage", "nav_hetzner_manage",
                          tooltip="Per-provider manager: create, start/stop, reboot, delete Hetzner servers"),
                self._nav("SSH keys", "nav_hetzner_ssh_keys",
                          tooltip="Manage Hetzner project SSH keys (the registry the create wizard injects from)"),
                self._nav("Object storage", "nav_hetzner_s3",
                          tooltip="Browse and manage Hetzner Object Storage (S3-compatible) buckets"),
                section_id="section_hetzner",
                collapsed=True,
            )
            yield SidebarSection(
                "Account",
                self._nav("Account / login", "nav_login",
                          tooltip="Sign in to your Servonaut account"),
                self._nav("Teams", "nav_teams",
                          tooltip="Manage team members and shared access"),
                self._nav("Report a bug", "nav_bug_report",
                          tooltip="Send a bug report — review exactly what's "
                                  "included before anything leaves your machine"),
                section_id="section_account",
                collapsed=True,
            )

        # ----- bottom: docked, always visible -----
        with Vertical(id="sidebar-bottom"):
            from servonaut.widgets.relay_indicator import RelayIndicator
            yield RelayIndicator(id="relay_indicator")
            update = LinkButton(
                "Update available",
                id="nav_update",
                classes="hidden",
            )
            update.can_focus = False
            yield update
            quit_button = Button("Quit", id="nav_quit", classes="nav-button error-button")
            quit_button.can_focus = False
            yield quit_button

    can_focus = False

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.navigation_mode = False
        self._navigation_previous_focus: Widget | None = None
        self._navigation_previous_display = True

    def enter_navigation_mode(self) -> None:
        """Temporarily make the visible rail usable from the keyboard."""
        if self.navigation_mode:
            return
        self._navigation_previous_focus = self.screen.focused
        self._navigation_previous_display = self.display
        self.navigation_mode = True
        self.display = True
        self.add_class("--navigation-mode")
        self.call_after_refresh(self._focus_navigation)

    def _focus_navigation(self) -> None:
        if not self.navigation_mode or self.screen is not self.app.screen:
            return
        self._sync_navigation_focusable()
        buttons = [button for button in self.query(Button) if button.can_focus]
        target = next((button for button in buttons if button.has_class("--active")), None)
        if target is None:
            target = next(iter(buttons), None)
        if target is not None:
            target.focus()
            target.scroll_visible(animate=False)
        self.screen.refresh_bindings()

    @staticmethod
    def _in_layout(widget: Widget) -> bool:
        return widget.visible and widget.display and all(node.display for node in widget.ancestors)

    def _sync_navigation_focusable(self) -> None:
        for button in self.query(Button):
            button.can_focus = self.navigation_mode and self._in_layout(button)

    def exit_navigation_mode(self, *, restore_focus: bool = True) -> None:
        """Restore content focus and the visibility chosen before entering."""
        if not self.navigation_mode:
            return
        previous = self._navigation_previous_focus
        self._navigation_previous_focus = None
        self.navigation_mode = False
        self.remove_class("--navigation-mode")
        self._sync_navigation_focusable()
        self.display = self._navigation_previous_display
        # The terminal may have changed width class while the rail was open.
        apply_workspace_state = getattr(self.screen, "apply_workspace_state", None)
        if apply_workspace_state is not None:
            apply_workspace_state()
        if restore_focus:
            restore = getattr(self.screen, "restore_navigation_focus", None)
            if restore is not None and restore(previous):
                pass  # The reflow shell restores focus after its layout settles.
            elif (previous is not None and previous.is_attached
                    and previous.screen is self.screen and previous.focusable
                    and self._in_layout(previous)):
                previous.focus()
            else:
                self._focus_primary_content()
        self.screen.refresh_bindings()

    def _focus_primary_content(self) -> None:
        """A removed origin falls back to the screen's initial content target."""
        selector = self.screen.AUTO_FOCUS
        if selector:
            for widget in self.screen.query(selector):
                if widget.focusable and self._in_layout(widget):
                    widget.focus()
                    return
        self.screen.focus_next()

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "leave_navigation":
            return self.navigation_mode
        return super().check_action(action, parameters)

    def action_leave_navigation(self) -> None:
        self.exit_navigation_mode()

    def on_descendant_blur(self) -> None:
        self.call_after_refresh(self._leave_if_focus_outside)

    def _leave_if_focus_outside(self) -> None:
        if self.is_attached and self.navigation_mode and not self.has_focus_within:
            self.exit_navigation_mode(restore_focus=False)

    def on_sidebar_section_section_toggled(self) -> None:
        self.call_after_refresh(self._sync_navigation_focusable)

    def _nav(self, label: str, button_id: str, *, tooltip: str) -> Button:
        """Helper — build a nav button with the standard class + tooltip."""
        btn = _NavigationButton(label, id=button_id, classes="nav-button")
        btn.tooltip = tooltip
        btn.can_focus = False
        return btn

    def on_mount(self) -> None:
        """Apply gating, sync update + relay state, then expand the active section."""
        self.border_title = "Navigate"
        # ----- Provider section gating -----
        # OVH and Hetzner sections have TWO independent auth surfaces:
        # compute (API token / app+consumer keys) and S3 object storage
        # (S3-compatible access/secret keys). A user can configure either
        # alone, both, or neither. Show the section whenever at least one
        # is configured; hide individual buttons inside the section based
        # on which surface is configured.
        #
        # AWS is always visible (D6); only its S3 button may be hidden if
        # boto3 default-chain fails to produce a usable client.
        ovh_compute = _provider_available(self.app, "ovh")
        ovh_s3 = (
            getattr(self.app, "ovh_object_storage_service", None) is not None
        )
        if not (ovh_compute or ovh_s3):
            self._hide_section("section_ovh")
        else:
            if not ovh_compute:
                # S3-only OVH user: hide compute-only buttons but keep
                # the section visible so they can reach Object Storage.
                for nav_id in (
                    "nav_ovh_manage",
                    "nav_ovh_dns",
                    "nav_ovh_ips",
                    "nav_ovh_storage",
                    "nav_ovh_billing",
                    "nav_ovh_ssh_keys",
                ):
                    self._hide_button(nav_id)
            if not ovh_s3:
                self._hide_button("nav_ovh_s3")

        hetzner_compute = _provider_available(self.app, "hetzner")
        hetzner_s3 = (
            getattr(self.app, "hetzner_object_storage_service", None) is not None
        )
        if not (hetzner_compute or hetzner_s3):
            self._hide_section("section_hetzner")
        else:
            if not hetzner_compute:
                for nav_id in (
                    "nav_hetzner_manage",
                    "nav_hetzner_ssh_keys",
                ):
                    self._hide_button(nav_id)
            if not hetzner_s3:
                self._hide_button("nav_hetzner_s3")

        # AWS — visible unless switched off in Settings → AWS; its S3 button
        # is gated independently.
        if not _aws_switched_on(self.app):
            self._hide_section("section_aws")
        elif getattr(self.app, "aws_object_storage_service", None) is None:
            self._hide_button("nav_aws_s3")

        # ----- Per-button entitlement gating (inside still-visible sections) -----
        auth = getattr(self.app, "auth_service", None)
        # Vault discovery usually answers after this sidebar is up, so follow
        # the app's flag instead of reading it once.
        self.watch(self.app, "vault_available", self._show_vault_navigation)
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

    def _show_vault_navigation(self, available: object) -> None:
        for button_id in ("nav_vault", "nav_ca"):
            try:
                self.query_one(f"#{button_id}", Button).display = bool(available)
            except NoMatches:
                pass
        self.call_after_refresh(self._sync_navigation_focusable)

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

        # ObjectStorageScreen is shared across three providers; pick the
        # correct provider's nav button so the right section expands.
        if screen_name == "ObjectStorageScreen":
            provider = getattr(self.screen, "_provider", "aws")
            active_id = f"nav_{provider}_s3"

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
            # On a short terminal the active entry can sit below the fold.
            # Scroll to it once the expanded section has been laid out.
            self.call_after_refresh(self._scroll_to_button, active_id)

    def _scroll_to_button(self, button_id: str) -> None:
        """Scroll the sidebar so the nav button *button_id* is in view."""
        try:
            button = self.query_one(f"#{button_id}", Button)
        except NoMatches:
            return
        if button.display:
            button.scroll_visible(animate=False, immediate=True)

    def _sync_update_button(self) -> None:
        """Show the update button if the app already found a newer version."""
        latest = getattr(self.app, "_latest_version", None)
        if latest:
            try:
                btn = self.query_one("#nav_update", Button)
                btn.label = f"Update to v{latest}"
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

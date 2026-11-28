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
    "MemorySyncSetupScreen": "nav_memory",
    "SecretsScreen": "nav_secrets",
    "VaultScreen": "nav_vault",
    "CaScreen": "nav_ca",
    "BwVaultManagerScreen": "nav_secrets",
    "FindingsScreen": "nav_findings",
    "FindingDetailScreen": "nav_findings",
    "MemoryDriftScreen": "nav_memory",
    "MemoryExportScreen": "nav_memory",
    "SnapshotManagerScreen": "nav_login",
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


def provider_ready(app, provider: str) -> bool:
    """Whether *provider* has an enabled, usable account for creating servers."""
    if provider == "aws":
        return is_nav_route_visible(app, "nav_aws_manage") and _provider_available(app, "aws")
    if provider == "hetzner":
        return is_nav_route_visible(app, "nav_hetzner_manage")
    if provider == "ovh":
        return is_nav_route_visible(app, "nav_ovh_manage")
    return _provider_available(app, provider)


def is_nav_route_visible(app, target_id: str) -> bool:
    """Single source of truth for Sidebar and Command Palette route visibility."""
    auth = getattr(app, "auth_service", None)
    is_auth = bool(auth and getattr(auth, "is_authenticated", False))
    sync_svc = getattr(app, "memory_sync_service", None)
    sync_configured = bool(sync_svc and getattr(sync_svc, "is_configured", False))
    aws_on = _aws_switched_on(app)

    if target_id == "nav_aws_s3":
        return bool(aws_on and getattr(app, "aws_object_storage_service", None) is not None)
    if target_id.startswith(("nav_aws", "nav_cloudwatch", "nav_ip_ban", "nav_cloudtrail")):
        return aws_on
    if target_id == "nav_ovh_s3":
        return getattr(app, "ovh_object_storage_service", None) is not None
    if target_id.startswith("nav_ovh"):
        return _provider_available(app, "ovh")
    if target_id == "nav_hetzner_s3":
        return getattr(app, "hetzner_object_storage_service", None) is not None
    if target_id.startswith("nav_hetzner"):
        return _provider_available(app, "hetzner")
    if target_id == "nav_vault":
        return bool(
            getattr(app, "vault_available", False)
            or getattr(app, "vault_update_required", False)
        )
    if target_id == "nav_ca":
        return bool(
            getattr(app, "vault_available", False)
            and auth
            and auth.has_feature("ssh_ca")
        )
    if target_id == "nav_teams":
        return bool(auth and auth.has_feature("team_workspaces"))
    if target_id == "nav_sync_config":
        return bool(is_auth and auth.has_feature("config_sync"))
    if target_id == "nav_bw_vault":
        return bool(is_auth and auth.has_feature("secrets_management"))
    if target_id == "nav_drift":
        return bool(auth and auth.has_feature("memory_drift") and sync_configured)
    if target_id == "nav_memory_export":
        return bool(
            auth and auth.has_feature("memory_compliance_export") and sync_configured
        )
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
                "Fleet",
                self._nav("Instances", "nav_list",
                          tooltip="View, connect, and manage all servers"),
                self._nav("Custom servers", "nav_custom_servers",
                          tooltip="Add, edit, and organize non-cloud SSH servers"),
                section_id="section_fleet",
            )
            yield SidebarSection(
                "Access & secrets",
                self._nav("Vault", "nav_vault",
                          tooltip="Encrypted vault identities, SSH keys and secrets"),
                self._nav("Local SSH keys", "nav_keys",
                          tooltip="Configure local ~/.ssh keys, overrides, and SSH agent"),
                self._nav("SSH certificates", "nav_ca",
                          tooltip="Team SSH certificate authority and audit"),
                self._nav("Secrets", "nav_secrets",
                          tooltip="Manage secrets backends, DB coverage, and Bitwarden SSH items"),
                section_id="section_access",
                collapsed=True,
            )
            yield SidebarSection(
                "Monitor",
                self._nav("Findings", "nav_findings",
                          tooltip="Proactive monitoring findings across your fleet — "
                                  "scan, review, and triage server-detected issues"),
                self._nav("Fleet memory", "nav_memory",
                          tooltip="Fleet-wide server memory, Memory Sync, drift events, and exports"),
                section_id="section_monitor",
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
                          tooltip="Ban/unban IPs via WAF, security groups or NACLs"),
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
                "Team",
                self._nav("Teams", "nav_teams",
                          tooltip="Manage team members, shared servers, and shared configs"),
                section_id="section_team",
                collapsed=True,
            )
            yield SidebarSection(
                "Account",
                self._nav("Account / login", "nav_login",
                          tooltip="Sign in to your Servonaut account and manage plan / snapshots"),
                self._nav("Report a bug", "nav_bug_report",
                          tooltip="Send a bug report — review exactly what's "
                                  "included before anything leaves your machine"),
                section_id="section_account",
                collapsed=True,
            )

        # ----- bottom: docked, always visible -----
        with Vertical(id="sidebar-bottom"):
            yield self._nav(
                "Settings",
                "nav_settings",
                tooltip="Edit configuration, scan rules, cloud providers, and AI",
            )
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
        # Vault discovery usually answers after this sidebar is up, so follow
        # the app's flag instead of reading it once.
        self.watch(self.app, "vault_available", self._show_vault_navigation)
        if hasattr(self.app, "vault_update_required"):
            self.watch(self.app, "vault_update_required", self._show_vault_navigation)
        self.refresh_auth_gates()

        # ----- Initial active highlight + auto-expand -----
        self._update_active()
        self._sync_update_button()
        if hasattr(self.app, "apt_upgrade_state"):
            self.watch(self.app, "apt_upgrade_state", self._sync_update_button, init=False)

        # ----- Sync relay indicator -----
        try:
            indicator = self.query_one("#relay_indicator")
            indicator.state = getattr(self.app, "relay_state", None)
        except NoMatches:
            pass

    def refresh_auth_gates(self) -> None:
        """Re-apply auth/entitlement gating (Team section and Vault/CA items)."""
        has_teams = is_nav_route_visible(self.app, "nav_teams")
        try:
            self.query_one("#section_team", SidebarSection).display = has_teams
        except NoMatches:
            pass
        try:
            self.query_one("#nav_teams", Button).display = has_teams
        except NoMatches:
            pass
        self._show_vault_navigation(None)

    def _hide_section(self, section_id: str) -> None:
        try:
            self.query_one(f"#{section_id}", SidebarSection).display = False
        except NoMatches:
            pass

    def _show_vault_navigation(self, _changed: object) -> None:
        visibility = {
            "nav_vault": is_nav_route_visible(self.app, "nav_vault"),
            "nav_ca": is_nav_route_visible(self.app, "nav_ca"),
        }
        for button_id, visible in visibility.items():
            try:
                self.query_one(f"#{button_id}", Button).display = visible
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
        # Settings sits in #sidebar-bottom outside any section, so keep Fleet
        # expanded to leave Instances one click away.
        if active_id == "nav_settings":
            for section in self.query(SidebarSection):
                section.collapsed = section.id != "section_fleet"
        elif active_id:
            for section in self.query(SidebarSection):
                section.collapsed = not section.contains_button(active_id)
            # On a short terminal an active entry inside #sidebar-scroll can
            # sit below the fold; pinned #sidebar-bottom buttons need no scroll.
            try:
                scroll = self.query_one("#sidebar-scroll", VerticalScroll)
                btn = self.query_one(f"#{active_id}", Button)
                if scroll in btn.ancestors:
                    self.call_after_refresh(self._scroll_to_button, active_id)
            except NoMatches:
                pass

    def _scroll_to_button(self, button_id: str) -> None:
        """Scroll the sidebar so the nav button *button_id* is in view."""
        try:
            button = self.query_one(f"#{button_id}", Button)
        except NoMatches:
            return
        if button.display:
            button.scroll_visible(animate=False, immediate=True)

    def _sync_update_button(self, _state: object = None) -> None:
        """Keep an installed package's restart notice available across screens."""
        from servonaut.services.apt_runtime import AptChange

        state = getattr(self.app, "apt_upgrade_state", None)
        latest = getattr(self.app, "_latest_version", None)
        try:
            btn = self.query_one("#nav_update", Button)
            if state is not None and state.restart_version:
                btn.label = "Restart to update"
                btn.remove_class("hidden")
            elif latest and (state is None or state.change is AptChange.UNCHANGED):
                btn.label = f"Update to v{latest}"
                btn.remove_class("hidden")
            else:
                btn.add_class("hidden")
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

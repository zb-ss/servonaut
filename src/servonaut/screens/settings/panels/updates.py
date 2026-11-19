"""Updates settings panel — version status, release channel, and update schedule."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime
import logging
import sys
import time
from typing import Any, Dict, Optional, Sequence

from textual import events, on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, RadioButton, RadioSet, Static

from servonaut import get_version
from servonaut.runtime import DistributionKind, RuntimeLayout
from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.services.client_identity import (
    configure_client_identity,
    install_update_step,
    is_apt_managed_install,
)
from servonaut.services.update_service import UpdateCheckResult, UpdateService
from servonaut.services.version_policy import (
    DEFAULT_UPDATE_URL,
    VersionPolicy,
    VersionPolicyClient,
    _terminal_safe,
    normalize_public_version,
    safe_update_url,
)
from servonaut.updates import status as updates_status
from servonaut.updates.status import (
    Channel,
    UpdateStatus,
    postpone_update,
    read_update_status,
    set_update_channel,
)
from servonaut.utils.package_version import PackageVersion
from servonaut.widgets._layout_refit import LayoutRefitMixin
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.link_button import LinkButton

logger = logging.getLogger(__name__)

# Matches SettingsScreen.CONTENT_NARROW_WIDTH so standalone mounts stack at
# the same width as SettingsScreen.-content-narrow.
STACK_BREAKPOINT_WIDTH = 95

_RELEASES_TAG_BASE = "https://github.com/zb-ss/servonaut/releases/tag/v"
_APT_UPGRADE_COMMAND = "sudo apt update && sudo apt install --only-upgrade servonaut"

_CHECK_ERROR_RESULTS = frozenset({
    UpdateCheckResult.OFFLINE,
    UpdateCheckResult.INVALID_MANIFEST,
    UpdateCheckResult.VERIFICATION_FAILED,
    UpdateCheckResult.VERSION_UNCOMPARABLE,
    UpdateCheckResult.NO_COMPATIBLE_ARTIFACT,
    UpdateCheckResult.OS_TOO_OLD,
})

_CHECK_OUTCOME_NOTIFICATIONS: dict[str, tuple[str, str]] = {
    "busy": ("An update check is already running.", "information"),
    "skipped": ("Automatic updates are turned off for this session.", "information"),
    "failed": ("Couldn't start an update check.", "error"),
}


def _is_apt_install(
    install_kind: str,
    *,
    platform_name: Optional[str] = None,
    apt_managed: Optional[bool] = None,
) -> bool:
    """Return True when *install_kind* is managed by the Servonaut APT repository."""
    if install_kind == "apt":
        return True
    if install_kind != DistributionKind.PACKAGED_DESKTOP.value:
        return False
    plat = (platform_name if platform_name is not None else sys.platform).lower()
    if not plat.startswith("linux"):
        return False
    if apt_managed is not None:
        return apt_managed
    return is_apt_managed_install(platform_name=plat)


def describe_install_kind(
    install_kind: str,
    *,
    platform_name: Optional[str] = None,
    apt_managed: Optional[bool] = None,
) -> str:
    """Human-readable label describing how Servonaut was installed."""
    if install_kind == DistributionKind.PIPX.value:
        return "installed with pipx"
    if _is_apt_install(
        install_kind, platform_name=platform_name, apt_managed=apt_managed,
    ):
        return "installed from the Servonaut APT repository"
    if install_kind == DistributionKind.PIP.value:
        return "installed with pip"
    if install_kind == DistributionKind.SOURCE.value:
        return "source checkout"
    if install_kind == DistributionKind.FROZEN_CLI.value:
        return "standalone build"
    if install_kind == DistributionKind.PACKAGED_DESKTOP.value:
        plat = (platform_name if platform_name is not None else sys.platform).lower()
        if plat == "darwin":
            return "macOS app"
        if plat.startswith("linux"):
            return "Linux desktop app"
        return "desktop app"
    cleaned = _terminal_safe(install_kind).strip()
    return f"installed ({cleaned})" if cleaned else "unknown installation"


def format_checked_ago(checked_at: float, *, now: Optional[float] = None) -> str:
    """Format a relative elapsed timestamp for the last interactive update check."""
    current = time.time() if now is None else now
    elapsed = max(0, int(current - checked_at))
    if elapsed < 60:
        return "just now"
    minutes = elapsed // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hr ago" if hours == 1 else f"{hours} hrs ago"
    days = hours // 24
    return f"{days} day ago" if days == 1 else f"{days} days ago"


def format_postponed_until(timestamp: float) -> str:
    """Format a Unix UTC timestamp in local time, e.g. ``Fri 20 Nov, 18:40``."""
    dt = datetime.fromtimestamp(timestamp).astimezone()
    return f"{dt:%a} {dt.day} {dt:%b}, {dt:%H:%M}"


def format_old_sessions(roles: Sequence[str], installed_version: str) -> str:
    """Describe running sessions still pinned to an older version."""
    cleaned = [_terminal_safe(role).strip().lower() for role in roles if str(role).strip()]
    if not cleaned:
        return ""
    ver = _terminal_safe(installed_version).strip() or "the previous version"
    counts = Counter(cleaned)
    total = sum(counts.values())

    if len(counts) == 1:
        role, count = next(iter(counts.items()))
        if role == "mcp":
            if count == 1:
                return f"1 MCP server keeps {ver} until your agent restarts it"
            return f"{count} MCP servers keep {ver} until your agents restart them"
        if role == "relay":
            if count == 1:
                return f"1 relay listener keeps {ver} until it restarts"
            return f"{count} relay listeners keep {ver} until they restart"
        if role in {"cli", "tui"}:
            if count == 1:
                return f"1 other session keeps {ver} until it restarts"
            return f"{count} other sessions keep {ver} until they restart"
        if count == 1:
            return f"1 {role} session keeps {ver} until it restarts"
        return f"{count} {role} sessions keep {ver} until they restart"

    parts = []
    for role in sorted(counts):
        count = counts[role]
        if role == "mcp":
            label = "MCP server" if count == 1 else "MCP servers"
        elif role == "relay":
            label = "relay listener" if count == 1 else "relay listeners"
        elif role == "cli":
            label = "CLI session" if count == 1 else "CLI sessions"
        else:
            label = f"{role} session" if count == 1 else f"{role} sessions"
        parts.append(f"{count} {label}")
    joined = ", ".join(parts)
    return f"{total} sessions ({joined}) keep {ver} until they restart"


def format_server_minimum_hint(
    install_kind: str,
    *,
    platform_name: Optional[str] = None,
    apt_managed: Optional[bool] = None,
    policy: Optional[VersionPolicy] = None,
) -> str:
    """Format the ``Update:`` step for a server minimum version requirement."""
    is_apt = _is_apt_install(
        install_kind, platform_name=platform_name, apt_managed=apt_managed,
    )
    hint_key: Optional[str]
    if install_kind == DistributionKind.PIPX.value:
        hint_key = "pipx"
    elif is_apt:
        hint_key = "apt"
    elif install_kind in {
        DistributionKind.PACKAGED_DESKTOP.value,
        DistributionKind.FROZEN_CLI.value,
    }:
        hint_key = "desktop"
    elif install_kind == DistributionKind.PIP.value:
        hint_key = "pip"
    elif install_kind == DistributionKind.SOURCE.value:
        hint_key = "source"
    else:
        hint_key = None

    if policy is not None and hint_key is not None:
        server_hint = policy.update_hints.get(hint_key)
        if isinstance(server_hint, str) and server_hint.strip():
            return _terminal_safe(server_hint.strip())

    raw_step = install_update_step(
        "apt" if is_apt else install_kind,
        platform_name=platform_name,
        update_url=policy.update_url if policy is not None else DEFAULT_UPDATE_URL,
        apt_managed=is_apt,
    )
    if raw_step.startswith("run: "):
        return raw_step[5:]
    if raw_step.startswith("download: "):
        return raw_step[10:]
    return raw_step


def release_notes_url(version: str) -> Optional[str]:
    """Return the GitHub release URL for a normalized public version."""
    normalized = normalize_public_version(version)
    if not normalized:
        return None
    return f"{_RELEASES_TAG_BASE}{normalized}"


def _is_prerelease_version(version: str) -> bool:
    parsed = PackageVersion.parse_installed(version)
    return parsed is not None and parsed.is_prerelease


def _can_run_in_app_update(
    install_kind: str,
    *,
    platform_name: Optional[str] = None,
    apt_managed: Optional[bool] = None,
) -> bool:
    """True when Servonaut can initiate an upgrade or verified download in-app."""
    if _is_apt_install(
        install_kind, platform_name=platform_name, apt_managed=apt_managed,
    ):
        return False
    return install_kind in {
        DistributionKind.PIPX.value,
        DistributionKind.PIP.value,
        DistributionKind.PACKAGED_DESKTOP.value,
        DistributionKind.FROZEN_CLI.value,
    }


def _supports_download_link(
    install_kind: str,
    *,
    platform_name: Optional[str] = None,
    apt_managed: Optional[bool] = None,
) -> bool:
    """True for packaged/standalone builds updated via installer downloads."""
    if _is_apt_install(
        install_kind, platform_name=platform_name, apt_managed=apt_managed,
    ):
        return False
    return install_kind in {
        DistributionKind.PACKAGED_DESKTOP.value,
        DistributionKind.FROZEN_CLI.value,
    }


class UpdatesPanel(LayoutRefitMixin, SettingsPanel):
    """Settings panel for update status, release channel, and update schedule."""

    PANEL_ID = "updates"
    TITLE = "Updates"
    DESCRIPTION = "Automatic update status, release channel, and version requirements."
    # Nothing sensitive here; versions and install kind stay visible in demo mode.
    DEMO_REDACTED_FIELDS: Dict[str, Any] = {}

    def __init__(self) -> None:
        super().__init__()
        self._status: Optional[UpdateStatus] = None
        self._policy: Optional[VersionPolicy] = None
        self._last_checked_at: Optional[float] = None
        self._discovered_version: Optional[str] = None
        self._check_error: Optional[str] = None
        self._details_expanded: bool = False
        self._busy: bool = False
        self._release_notes_target: Optional[str] = None
        self._loading_controls: bool = False
        self._presented_versions: set[str] = set()

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield version summary, live update status, and release channel."""
        with Vertical(id="updates_summary_section", classes="settings-form-section"):
            with Horizontal(id="updates_installed_row", classes="updates-row"):
                yield Static("Installed", classes="updates-label", markup=False)
                yield Static(
                    "",
                    id="updates_installed_value",
                    classes="updates-value",
                    markup=False,
                )
            with Horizontal(id="updates_status_row", classes="updates-row"):
                yield Static("Status", classes="updates-label", markup=False)
                with Vertical(id="updates_status_body"):
                    yield Static(
                        "",
                        id="updates_status_primary",
                        classes="updates-status-text",
                        markup=False,
                    )
                    yield Static(
                        "",
                        id="updates_status_secondary",
                        classes="updates-status-detail",
                        markup=False,
                    )
                    with Horizontal(id="updates_status_links"):
                        yield LinkButton(
                            "What's new →",
                            id="updates_link_release_notes",
                        )
                        yield LinkButton(
                            "Details →",
                            id="updates_link_details",
                        )
                        yield LinkButton(
                            "Download and install →",
                            id="updates_link_download",
                        )
                    yield Static(
                        "",
                        id="updates_failure_details",
                        classes="updates-failure-details",
                        markup=False,
                    )
                    yield BusyIndicator(id="updates_busy")
                with Vertical(id="updates_status_actions"):
                    yield Button("Check now", id="updates_btn_check", variant="default")
                    yield Button("Postpone 24 h", id="updates_btn_postpone", variant="default")
                    yield Button("Try now", id="updates_btn_try", variant="primary")
                    yield Button("Update now", id="updates_btn_update", variant="primary")

        with Vertical(id="updates_channel_section", classes="settings-form-section"):
            yield Static("Release channel", id="updates_channel_title", classes="settings-group-title", markup=False)
            yield RadioSet(
                RadioButton(
                    "Stable — recommended",
                    id="updates_channel_stable",
                    value=True,
                ),
                RadioButton(
                    "Release candidates — early access to the next version; may have rough edges",
                    id="updates_channel_rc",
                ),
                id="updates_channel_radio",
            )
            yield Static(
                "",
                id="updates_channel_note",
                classes="updates-note",
                markup=False,
            )
            yield Static(
                "Updates install automatically in the background and take effect "
                "the next time Servonaut starts. Sessions already running (other "
                "windows, MCP servers) keep their version until they restart.",
                id="updates_auto_note",
                classes="updates-note",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Responsive layout
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        super().on_mount()
        self.call_after_refresh(self._apply_layout_to_size)

    def on_show(self) -> None:
        self.call_after_refresh(self._apply_layout_to_size)

    def on_resize(self, event: events.Resize) -> None:
        self._apply_layout(event.size.width)

    def _refit_for_layout(self) -> None:
        self._apply_layout_to_size()

    def _apply_layout_to_size(self) -> None:
        if self.size.width > 0:
            self._apply_layout(self.size.width)

    def _apply_layout(self, width: int) -> None:
        self._mark_layout_fitted()
        self.set_class(width < STACK_BREAKPOINT_WIDTH, "-narrow")

    # ------------------------------------------------------------------
    # Lifecycle: load / dirty / collect / persist
    # ------------------------------------------------------------------

    def _runtime(self) -> Optional[RuntimeLayout]:
        runtime = getattr(self.app, "runtime_layout", None)
        if runtime is not None:
            return runtime
        service = getattr(self.app, "update_service", None)
        return getattr(service, "runtime", None)

    def _load_cached_policy(self) -> Optional[VersionPolicy]:
        auth = getattr(self.app, "auth_service", None)
        getter = getattr(auth, "cached_version_policy", None)
        if callable(getter):
            try:
                cached = getter()
                if isinstance(cached, VersionPolicy):
                    return cached
            except Exception:  # noqa: BLE001 — fail open
                pass
        client = getattr(self.app, "version_policy_client", None)
        if client is not None:
            try:
                cached = client.cached()
                if isinstance(cached, VersionPolicy):
                    return cached
            except Exception:  # noqa: BLE001 — fail open
                pass
        return None

    def load(self) -> None:
        """Read local update status without network I/O and populate controls."""
        self._status = read_update_status(self._runtime())
        if self._policy is None:
            self._policy = self._load_cached_policy()
        self._details_expanded = False
        self._set_radio_channel(self._status.channel)
        self._render_status()
        self._snapshot_now()

    def refresh_external_state(self) -> None:
        """Refresh local status when returning from another screen without clobbering edits."""
        dirty_before = self.is_dirty()
        selected = self._selected_channel()
        self._status = read_update_status(self._runtime())
        if not dirty_before:
            self._set_radio_channel(self._status.channel)
            self._snapshot_now()
        else:
            self._set_radio_channel(selected)
        self._render_status()

    def _selected_channel(self) -> Channel:
        try:
            rc_btn = self.query_one("#updates_channel_rc", RadioButton)
            return "rc" if rc_btn.value else "stable"
        except NoMatches:
            return "stable"

    def _set_radio_channel(self, channel: Channel) -> None:
        self._loading_controls = True
        try:
            radio = self.query_one("#updates_channel_radio", RadioSet)
            stable_btn = self.query_one("#updates_channel_stable", RadioButton)
            rc_btn = self.query_one("#updates_channel_rc", RadioButton)
            target = rc_btn if channel == "rc" else stable_btn
            other = stable_btn if channel == "rc" else rc_btn
            with (
                radio.prevent(RadioButton.Changed, RadioSet.Changed),
                target.prevent(RadioButton.Changed),
                other.prevent(RadioButton.Changed),
            ):
                other.value = False
                target.value = True
            radio._pressed_button = target
            radio._selected = 1 if channel == "rc" else 0
        finally:
            self._loading_controls = False

    def current_values(self) -> Dict[str, Any]:
        return {"channel": self._selected_channel()}

    def collect(self) -> Dict[str, Any]:
        channel = self._selected_channel()
        if channel not in ("stable", "rc"):
            raise ValidationError("updates_channel_radio", "Choose Stable or Release candidates.")
        return {"channel": channel}

    def persist(self) -> None:
        fields = self.collect()
        channel: Channel = fields["channel"]
        if self._status is not None and self._status.state == "managed_elsewhere":
            self._finish_save("No changes to save.")
            return
        if not set_update_channel(channel, runtime=self._runtime()):
            raise ValidationError(
                "updates_channel_radio",
                "Could not save release channel for this installation.",
            )
        configure_client_identity(channel=channel)
        self._status = read_update_status(self._runtime())
        self._set_radio_channel(self._status.channel)
        self._render_status()
        self._finish_save("Release channel saved.")

    @on(RadioSet.Changed, "#updates_channel_radio")
    def _on_channel_changed(self, _event: RadioSet.Changed) -> None:
        if self._loading_controls:
            return
        self._sync_channel_notes()
        self._dirty_watch()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _effective_required_minimum(self, installed: str) -> Optional[str]:
        if self._status is not None and self._status.required_minimum:
            cleaned = normalize_public_version(self._status.required_minimum)
            return cleaned or _terminal_safe(self._status.required_minimum).strip()
        if (
            self._policy is not None
            and self._policy.minimum_version
            and self._policy.is_enforced_below_floor(installed)
        ):
            return self._policy.minimum_version
        return None

    def _render_status(self) -> None:
        status = self._status
        if status is None:
            return

        installed = _terminal_safe(status.installed_version or get_version()).strip() or "unknown"
        install_kind = status.install_kind or ""
        install_label = describe_install_kind(install_kind)

        self.query_one("#updates_installed_value", Static).update(
            f"{installed}  ·  {install_label}"
        )

        primary_widget = self.query_one("#updates_status_primary", Static)
        secondary_widget = self.query_one("#updates_status_secondary", Static)
        details_widget = self.query_one("#updates_failure_details", Static)
        links_row = self.query_one("#updates_status_links", Horizontal)
        link_notes = self.query_one("#updates_link_release_notes", LinkButton)
        link_details = self.query_one("#updates_link_details", LinkButton)
        link_download = self.query_one("#updates_link_download", LinkButton)

        btn_check = self.query_one("#updates_btn_check", Button)
        btn_postpone = self.query_one("#updates_btn_postpone", Button)
        btn_try = self.query_one("#updates_btn_try", Button)
        btn_update = self.query_one("#updates_btn_update", Button)
        actions_box = self.query_one("#updates_status_actions", Vertical)

        # Reset visibility and state classes cleanly.
        for cls in ("-warning", "-error", "-accent", "-success"):
            primary_widget.remove_class(cls)
        for btn in (btn_check, btn_postpone, btn_try, btn_update):
            btn.display = False
        link_notes.display = False
        link_details.display = False
        link_download.display = False
        details_widget.display = False
        self._release_notes_target = None

        primary_text = ""
        secondary_text = ""
        required_min = self._effective_required_minimum(installed)
        pinned_version = _terminal_safe(
            getattr(status, "pinned_version", None) or ""
        ).strip()
        pinned_until_newer_than = _terminal_safe(
            getattr(status, "pinned_until_newer_than", None) or ""
        ).strip()

        if required_min:
            # State 4 — service requires a newer version (server minimum).
            hint = format_server_minimum_hint(install_kind, policy=self._policy)
            primary_text = (
                f"servonaut.dev needs {required_min} or later for team, "
                "vault and AI features."
            )
            secondary_text = f"Local features keep working.  Update: {hint}"
            primary_widget.add_class("-warning")
            if _can_run_in_app_update(install_kind):
                btn_update.display = True
            if _supports_download_link(install_kind):
                link_download.display = True
        elif status.state == "managed_elsewhere":
            # State 5 — managed elsewhere.
            primary_text, secondary_text, show_check, show_download, notes_ver = (
                self._managed_elsewhere_view(status)
            )
            if show_check:
                btn_check.display = True
            if show_download:
                link_download.display = True
                primary_widget.add_class("-accent")
            if notes_ver:
                self._configure_release_notes_link(link_notes, notes_ver)
        elif pinned_version:
            # Manual install pinned to a specific version; not an error state
            # and never offers Postpone.
            if pinned_until_newer_than:
                resume = (
                    f"automatic updates resume when a release newer than "
                    f"{pinned_until_newer_than} is out"
                )
            else:
                resume = "automatic updates resume when a newer release is out"
            primary_text = f"Pinned to {pinned_version} by a manual install  ·  {resume}"
            if self._check_error:
                secondary_text = _terminal_safe(self._check_error).strip()
            btn_check.display = True
        elif status.state in ("failed", "rolled_back"):
            # State 3 — update failed / rolled back.
            target = _terminal_safe(status.target_version or "").strip()
            if target:
                primary_text = (
                    f"The update to {target} did not start correctly, "
                    f"so Servonaut kept {installed}."
                )
            else:
                primary_text = (
                    "The last update did not start correctly, "
                    f"so Servonaut kept {installed}."
                )
            secondary_text = "It will try again at a later start."
            primary_widget.add_class("-error")
            btn_try.display = True
            failure_text = _terminal_safe(status.last_failure or "").strip()
            if failure_text:
                link_details.label = "Hide details" if self._details_expanded else "Details →"
                link_details.display = True
                details_widget.update(failure_text)
                details_widget.display = self._details_expanded
        elif status.state in ("ready", "offered", "building"):
            # State 2 — update ready / offered / building.
            target = _terminal_safe(status.target_version or self._discovered_version or "").strip()
            if status.state == "ready":
                primary_text = (
                    f"{target} is ready  ·  starts the next time you open Servonaut"
                    if target
                    else "An update is ready  ·  starts the next time you open Servonaut"
                )
            elif status.state == "building":
                primary_text = (
                    f"Preparing {target} in the background…"
                    if target
                    else "Preparing an update in the background…"
                )
            else:
                primary_text = (
                    f"{target} is available  ·  will install in the background"
                    if target
                    else "An update is available  ·  will install in the background"
                )
            primary_widget.add_class("-accent")

            detail_lines = []
            if status.postponed_until is not None:
                when = format_postponed_until(status.postponed_until)
                detail_lines.append(
                    f"Postponed until {when} — installs at the next start after that"
                )
            if status.old_sessions:
                sessions_line = format_old_sessions(status.old_sessions, installed)
                if sessions_line:
                    detail_lines.append(sessions_line)
            secondary_text = "\n".join(detail_lines)

            if status.can_postpone and status.target_version:
                btn_postpone.display = True
            if target:
                self._configure_release_notes_link(link_notes, target)
            if status.state in ("offered", "ready") and status.target_version:
                self._notify_update_presented(status.target_version)
        else:
            # State 1 — up to date (or interactive check found a newer release).
            discovered = _terminal_safe(self._discovered_version or "").strip()
            if discovered and self._is_newer(discovered, installed):
                suffix = (
                    f"  ·  checked {format_checked_ago(self._last_checked_at)}"
                    if self._last_checked_at is not None
                    else ""
                )
                primary_text = f"{discovered} is available{suffix}"
                secondary_text = "Automatic background update will install it, or update now."
                primary_widget.add_class("-accent")
                btn_update.display = True
                self._configure_release_notes_link(link_notes, discovered)
            else:
                if self._last_checked_at is not None:
                    ago = format_checked_ago(self._last_checked_at)
                    primary_text = f"Up to date  ·  checked {ago}"
                else:
                    primary_text = "Up to date"
                primary_widget.add_class("-success")
                if self._check_error:
                    secondary_text = _terminal_safe(self._check_error).strip()
                btn_check.display = True

        primary_widget.update(primary_text)
        secondary_widget.update(secondary_text)
        secondary_widget.display = bool(secondary_text)
        links_row.display = bool(
            link_notes.display or link_details.display or link_download.display
        )
        actions_box.display = any(
            btn.display for btn in (btn_check, btn_postpone, btn_try, btn_update)
        )

        self._sync_channel_controls(status)
        self._sync_channel_notes()
        self._sync_action_busy()

    def _managed_elsewhere_view(
        self, status: UpdateStatus,
    ) -> tuple[str, str, bool, bool, Optional[str]]:
        """Return ``(primary, secondary, show_check, show_download, notes_ver)``."""
        install_kind = status.install_kind or ""
        if _is_apt_install(install_kind):
            return (
                "Updates are installed by apt (your system's package updates).",
                f"To update now: {_APT_UPGRADE_COMMAND}",
                False,
                False,
                None,
            )
        if install_kind == DistributionKind.SOURCE.value:
            return (
                "Running from a source checkout — automatic updates are off.",
                "Update your checkout to get newer versions.",
                False,
                False,
                None,
            )
        if install_kind == DistributionKind.PIP.value:
            return (
                "Updates are installed with pip.",
                "To update now: pip install --upgrade servonaut",
                False,
                False,
                None,
            )
        if install_kind == DistributionKind.PIPX.value:
            return (
                "Updates are managed by pipx.",
                "To update now: pipx upgrade servonaut",
                False,
                False,
                None,
            )
        if _supports_download_link(install_kind):
            available = _terminal_safe(
                status.target_version or self._discovered_version or ""
            ).strip()
            if available and self._is_newer(available, status.installed_version):
                return (
                    f"{available} is available",
                    "",
                    False,
                    True,
                    available,
                )
            if self._last_checked_at is not None:
                ago = format_checked_ago(self._last_checked_at)
                primary = f"Up to date  ·  checked {ago}"
            else:
                primary = "Up to date"
            secondary = (
                _terminal_safe(self._check_error).strip()
                if self._check_error
                else "New releases are available from servonaut.dev/download."
            )
            return (primary, secondary, True, False, None)

        return (
            "Updates are managed outside Servonaut.",
            f"Download newer versions from {DEFAULT_UPDATE_URL}.",
            False,
            False,
            None,
        )

    def _configure_release_notes_link(self, link: LinkButton, version: str) -> None:
        if release_notes_url(version) is None:
            return
        self._release_notes_target = version
        link.label = f"What's new in {version} →"
        link.display = True

    def _sync_channel_controls(self, status: UpdateStatus) -> None:
        managed = status.state == "managed_elsewhere"
        radio = self.query_one("#updates_channel_radio", RadioSet)
        radio.disabled = managed
        try:
            save_btn = self.query_one(f"#save_{self.PANEL_ID}", Button)
            save_btn.disabled = managed
        except NoMatches:
            pass
        self.query_one("#updates_auto_note", Static).display = not managed

    def _sync_channel_notes(self) -> None:
        note = self.query_one("#updates_channel_note", Static)
        status = self._status
        if status is None:
            note.update("")
            note.display = False
            return
        if status.state == "managed_elsewhere":
            note.update(
                "Release channel selection applies to pipx installations "
                "with automatic background updates."
            )
            note.display = True
            return
        if self._selected_channel() == "stable" and _is_prerelease_version(
            status.installed_version
        ):
            note.update(
                "You are running a release candidate. Switching back to Stable "
                "waits for the next stable release (no downgrade)."
            )
            note.display = True
            return
        note.update("")
        note.display = False

    def _sync_action_busy(self) -> None:
        for selector in (
            "#updates_btn_check",
            "#updates_btn_postpone",
            "#updates_btn_try",
            "#updates_btn_update",
            "#updates_link_download",
        ):
            try:
                self.query_one(selector, Button).disabled = self._busy
            except NoMatches:
                pass

    def _notify_update_presented(self, version: str) -> None:
        """Record that *version* was shown to the user once per rendered version."""
        cleaned = version.strip()
        if not cleaned or cleaned in self._presented_versions:
            return
        marker = getattr(updates_status, "mark_update_presented", None)
        if not callable(marker):
            return
        self._presented_versions.add(cleaned)
        self.run_worker(
            self._run_mark_presented(marker, cleaned),
            name=f"updates_mark_presented_{cleaned}",
            group="updates_present",
            exit_on_error=False,
        )

    @staticmethod
    async def _run_mark_presented(marker: Any, version: str) -> None:
        try:
            await asyncio.to_thread(marker, version)
        except Exception as exc:  # noqa: BLE001 — bookkeeping must never break the panel
            logger.debug("Could not record presented update %s: %s", version, exc)

    @staticmethod
    def _is_newer(candidate: str, current: str) -> bool:
        left = PackageVersion.parse_installed(candidate)
        right = PackageVersion.parse_installed(current)
        if left is None or right is None:
            return bool(candidate and candidate != current)
        return left > right

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#updates_btn_check")
    def _on_check_now_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if self._busy:
            return
        self.run_worker(
            self._run_check_now(),
            name="updates_check_now",
            group="updates_action",
            exclusive=True,
        )

    @on(Button.Pressed, "#updates_btn_postpone")
    def _on_postpone_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if (
            self._busy
            or self._status is None
            or not self._status.can_postpone
            or not self._status.target_version
        ):
            return
        target = self._status.target_version
        self.run_worker(
            self._run_postpone(target),
            name="updates_postpone",
            group="updates_action",
            exclusive=True,
        )

    @on(Button.Pressed, "#updates_btn_try")
    @on(Button.Pressed, "#updates_btn_update")
    def _on_run_upgrade_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if self._busy:
            return
        self.run_worker(
            self._run_upgrade(),
            name="updates_run_upgrade",
            group="updates_action",
            exclusive=True,
        )

    @on(Button.Pressed, "#updates_link_details")
    def _on_toggle_details(self, event: Button.Pressed) -> None:
        event.stop()
        self._details_expanded = not self._details_expanded
        self._render_status()

    @on(Button.Pressed, "#updates_link_release_notes")
    def _on_release_notes_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if not self._release_notes_target:
            return
        url = release_notes_url(self._release_notes_target)
        if url:
            self._open_web_url(url)

    @on(Button.Pressed, "#updates_link_download")
    def _on_download_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if self._busy:
            return
        service = self._update_service()
        if service is not None and service.runtime.is_frozen and service.target_artifact is not None:
            self.run_worker(
                self._run_upgrade(),
                name="updates_download_installer",
                group="updates_action",
                exclusive=True,
            )
            return
        url = safe_update_url(
            self._policy.update_url if self._policy is not None else DEFAULT_UPDATE_URL
        )
        self._open_web_url(url)

    def _open_web_url(self, url: str) -> None:
        opener = getattr(self.app, "open_url", None)
        if callable(opener):
            opener(url)
            return
        self.app.notify(f"Open: {url}", severity="information", markup=False)

    def _update_service(self) -> Optional[UpdateService]:
        existing = getattr(self.app, "update_service", None)
        if existing is not None:
            return existing
        try:
            return UpdateService(runtime=self._runtime())
        except Exception as exc:  # noqa: BLE001 — defensive
            logger.debug("Could not initialize UpdateService: %s", exc)
            return None

    def _version_policy_client(self) -> VersionPolicyClient:
        existing = getattr(self.app, "version_policy_client", None)
        if existing is not None:
            return existing
        return VersionPolicyClient()

    async def _run_check_now(self) -> None:
        """Worker: run update + version-policy checks off the UI thread."""
        busy = self.query_one("#updates_busy", BusyIndicator)
        self._busy = True
        self._sync_action_busy()
        busy.start("Checking for updates…")
        try:
            service = self._update_service()
            requester = getattr(self.app, "request_update_check", None)
            outcome: Any = None
            latest: Optional[str] = None
            check_error: Optional[str] = None
            if callable(requester):
                outcome = await requester()
                if outcome in (None, "queued"):
                    for worker in list(getattr(self.app, "workers", ())):
                        if worker.group == "update_check_requested" and not worker.is_finished:
                            try:
                                await worker.wait()
                            except Exception as exc:  # noqa: BLE001 — surface via status/log
                                logger.debug("Update check worker failed: %s", exc)
            elif service is not None:
                latest = await asyncio.to_thread(service.check_for_update)
                if (
                    latest is None
                    and service.last_check_result in _CHECK_ERROR_RESULTS
                    and service.update_status
                ):
                    check_error = service.update_status

            policy_client = self._version_policy_client()
            policy: Optional[VersionPolicy] = None
            try:
                policy = await policy_client.fetch(force_refresh=True)
            except Exception as exc:  # noqa: BLE001 — fail open
                logger.debug("Version policy refresh failed: %s", exc)

            status = await asyncio.to_thread(read_update_status, self._runtime())
            if not self.is_attached:
                return
            if callable(requester) and outcome in (None, "queued") and status.state == "managed_elsewhere" and service is not None:
                last_result = getattr(service, "last_check_result", None)
                if last_result in _CHECK_ERROR_RESULTS:
                    if getattr(service, "update_status", None):
                        check_error = service.update_status
                elif last_result != UpdateCheckResult.UP_TO_DATE:
                    latest = getattr(service, "latest_version", None) or getattr(
                        self.app, "_latest_version", None
                    )
            self._status = status
            if policy is not None:
                self._policy = policy
            # For managed-by-updater pipx installs, status.json is authoritative;
            # only surface a legacy UpdateService offer when managed elsewhere or
            # when no app-level generation requester is present.
            if status.state == "managed_elsewhere" or not callable(requester):
                self._discovered_version = latest
            else:
                self._discovered_version = None
            self._check_error = check_error
            if callable(requester) and outcome not in (None, "queued"):
                toast_msg, toast_severity = _CHECK_OUTCOME_NOTIFICATIONS.get(
                    str(outcome),
                    ("Couldn't start an update check.", "error"),
                )
                self._render_status()
                self.app.notify(toast_msg, severity=toast_severity, markup=False)
            else:
                self._last_checked_at = time.time()
                self._render_status()
        finally:
            self._busy = False
            if self.is_attached:
                busy.stop()
                self._sync_action_busy()

    async def _run_postpone(self, version: str) -> None:
        """Worker: postpone an offered update by up to 24 hours."""
        busy = self.query_one("#updates_busy", BusyIndicator)
        self._busy = True
        self._sync_action_busy()
        busy.start("Postponing update…")
        try:
            ok = await asyncio.to_thread(postpone_update, version, self._runtime())
            status = await asyncio.to_thread(read_update_status, self._runtime())
            if not self.is_attached:
                return
            self._status = status
            self._render_status()
            if ok:
                self.app.notify(
                    f"Postponed {version} for 24 hours.",
                    severity="information",
                    markup=False,
                )
            else:
                self.app.notify(
                    "This update could not be postponed.",
                    severity="warning",
                    markup=False,
                )
        finally:
            self._busy = False
            if self.is_attached:
                busy.stop()
                self._sync_action_busy()

    async def _run_upgrade(self) -> None:
        """Worker: run an upgrade via the app's owning-install hook (or frozen downloader)."""
        busy = self.query_one("#updates_busy", BusyIndicator)
        self._busy = True
        self._sync_action_busy()
        service = self._update_service()
        is_frozen = bool(service is not None and service.runtime.is_frozen)
        busy.start("Downloading verified update…" if is_frozen else "Updating Servonaut…")
        try:
            runner = getattr(self.app, "run_requested_upgrade", None)
            if is_frozen:
                if service is None:
                    if self.is_attached:
                        self.app.notify(
                            "Updater is unavailable for this installation.",
                            severity="error",
                            markup=False,
                        )
                    return
                success, message = await service.run_upgrade()
            elif callable(runner):
                success, message = await runner()
            elif service is not None:
                success, message = await service.run_upgrade()
            else:
                if self.is_attached:
                    self.app.notify(
                        "Updater is unavailable for this installation.",
                        severity="error",
                        markup=False,
                    )
                return
            status = await asyncio.to_thread(read_update_status, self._runtime())
            if not self.is_attached:
                return
            self._status = status
            self._render_status()
            self.app.notify(
                _terminal_safe(message),
                severity="information" if success else "error",
                timeout=10,
                markup=False,
            )
        finally:
            self._busy = False
            if self.is_attached:
                busy.stop()
                self._sync_action_busy()

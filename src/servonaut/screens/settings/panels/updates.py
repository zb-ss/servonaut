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
from textual.timer import Timer
from textual.worker import Worker
from textual.widgets import Button, RadioButton, RadioSet, Static

from servonaut import get_version
from servonaut.runtime import DistributionKind, RuntimeLayout
from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.services.client_identity import (
    configure_client_identity,
    install_update_step,
    is_apt_managed_install,
)
from servonaut.services.apt_runtime import AptChange, package_update_notice
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
from servonaut.updates.apt import (
    APT_UPGRADE_COMMAND,
    AptInstallStatus,
    get_cached_apt_status,
    is_apt_probe_candidate,
    refresh_apt_status,
)
from servonaut.updates.status import (
    Channel,
    STATUS_POLL_SECONDS,
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
_APT_UPGRADE_COMMAND = APT_UPGRADE_COMMAND

_CHECK_ERROR_RESULTS = frozenset({
    UpdateCheckResult.OFFLINE,
    UpdateCheckResult.INVALID_MANIFEST,
    UpdateCheckResult.VERIFICATION_FAILED,
    UpdateCheckResult.VERSION_UNCOMPARABLE,
    UpdateCheckResult.NO_COMPATIBLE_ARTIFACT,
    UpdateCheckResult.OS_TOO_OLD,
})

# Shown when a failed check left no reason of its own.
_STATUS_FALLBACK_FAILURE = "The last update check did not complete. Try again."

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
    try:
        dt = datetime.fromtimestamp(timestamp).astimezone()
    except (OverflowError, OSError, TypeError, ValueError):
        return ""
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
        self._presentations_in_progress: set[str] = set()
        self._status_worker: Worker[None] | None = None
        self._status_timer: Timer | None = None
        self._poll_seconds = STATUS_POLL_SECONDS
        self._saving_channel = False
        self._check_baseline: UpdateStatus | None = None
        self._apt_status: Optional[AptInstallStatus] = None
        # The app's own check outcome the status was last drawn from, so a
        # background check that finishes later redraws the panel.
        self._drawn_app_check: tuple[Optional[UpdateCheckResult], Optional[str], Optional[str]] | None = None
        self._showing_check_failure = False
        self._checking_apt: bool = False

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield version summary, live update status, and release channel."""
        with Vertical(id="updates_summary_section", classes="settings-form-section"):
            with Horizontal(id="updates_installed_row", classes="updates-row"):
                yield Static("Installed", id="updates_installed_label", classes="updates-label", markup=False)
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
                    yield Static(
                        "",
                        id="updates_status_command",
                        classes="updates-command",
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
                    yield Button("Install on quit", id="updates_btn_macos_install", variant="primary", classes="hidden")
                    yield Button("Restart Servonaut", id="updates_btn_restart", variant="primary", classes="hidden")

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
                id="updates_channel_apt_summary",
                classes="updates-apt-channel",
                markup=False,
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
        self.query_one("#updates_status_command", Static).display = False
        self.query_one("#updates_channel_apt_summary", Static).display = False
        if self._status is None:
            self.query_one("#updates_channel_radio", RadioSet).disabled = True
            self.query_one("#save_updates", Button).disabled = True
        if hasattr(self.app, "_update_in_progress"):
            self.watch(self.app, "_update_in_progress", self._sync_action_busy, init=False)
        if hasattr(self.app, "apt_upgrade_state"):
            self.watch(self.app, "apt_upgrade_state", self._render_status, init=False)
        self._status_timer = self.set_interval(self._poll_seconds, self._queue_status_refresh)
        self._sync_action_busy()
        self.call_after_refresh(self._apply_layout_to_size)

    def on_show(self) -> None:
        self.call_after_refresh(self._apply_layout_to_size)
        self._queue_status_refresh(redraw=True)

    def on_unmount(self) -> None:
        if self._status_timer is not None:
            self._status_timer.stop()

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

    def _needs_apt_probe(self, runtime: Optional[RuntimeLayout]) -> bool:
        return is_apt_probe_candidate(runtime, platform_name=sys.platform)

    def _effective_apt_managed(self, install_kind: str) -> Optional[bool]:
        if install_kind == "apt":
            return True
        if self._apt_status is not None and self._apt_status.checked:
            return self._apt_status.managed
        cached = get_cached_apt_status(self._runtime())
        if cached is not None and cached.checked:
            return cached.managed
        return None

    def _effective_apt_suite(self) -> tuple[Optional[str], int]:
        apt_status = (
            self._apt_status
            if self._apt_status is not None and self._apt_status.checked
            else get_cached_apt_status(self._runtime())
        )
        if apt_status is None or not apt_status.managed:
            return None, 0
        display = apt_status.suite_display
        if not display:
            return None, 0
        cleaned = _terminal_safe(display).strip()
        if not cleaned:
            return None, 0
        count = len(apt_status.suites) if apt_status.suites else 1
        return cleaned, count

    def load(self) -> None:
        """Restore saved controls and refresh local state off the UI thread."""
        self._details_expanded = False
        cached_apt = get_cached_apt_status(self._runtime())
        if cached_apt is not None:
            self._apt_status = cached_apt
        if self._status is not None:
            self._set_radio_channel(self._status.channel)
            self._snapshot_now()
            self._render_status()
        self._queue_status_refresh()

    def refresh_external_state(self) -> None:
        """Refresh local status when returning from another screen without clobbering edits."""
        self._queue_status_refresh()

    def refresh_after_demo_toggle(self) -> None:
        if self._status is not None and self.is_attached:
            self._render_status()

    def _queue_status_refresh(self, *, redraw: bool = False) -> None:
        if (not self.is_attached or not self.display or self.screen is not self.app.screen
                or self._saving_channel):
            return
        if self._status_worker is not None and not self._status_worker.is_finished:
            return
        self._status_worker = self.run_worker(
            self._refresh_local_status(redraw=redraw), group="updates_status", exit_on_error=False,
        )

    async def _refresh_local_status(self, *, redraw: bool) -> None:
        runtime = self._runtime()
        snapshot = await asyncio.to_thread(read_update_status, runtime)
        policy = self._policy or await asyncio.to_thread(self._load_cached_policy)
        if not self.is_attached or not self.display or self.screen is not self.app.screen:
            return
        changed = policy != self._policy
        self._policy = policy
        if not self._needs_apt_probe(runtime):
            cached_apt = get_cached_apt_status(runtime)
            apt_changed = cached_apt != self._apt_status
            self._apt_status = cached_apt
            self._accept_snapshot(snapshot, redraw=redraw or changed or apt_changed)
            return

        # Render the last cached APT classification immediately alongside a
        # loading indicator while dpkg-query and /etc/apt run off the UI thread.
        cached_apt = get_cached_apt_status(runtime)
        if cached_apt is not None and self._apt_status is None:
            self._apt_status = cached_apt
            changed = True
        self._checking_apt = True
        self._accept_snapshot(snapshot, redraw=redraw or changed)
        try:
            fresh_apt = await asyncio.to_thread(refresh_apt_status, runtime)
        except Exception as exc:  # noqa: BLE001 — incomplete evidence falls back
            logger.debug("APT installation check failed: %s", exc)
            fresh_apt = AptInstallStatus(managed=False, checked=False)
        finally:
            self._checking_apt = False
        if not self.is_attached or not self.display or self.screen is not self.app.screen:
            return
        if not fresh_apt.checked:
            last_good = (
                self._apt_status
                if self._apt_status is not None and self._apt_status.checked
                else get_cached_apt_status(runtime)
            )
            if last_good is not None and last_good.checked:
                fresh_apt = last_good
        apt_changed = fresh_apt != self._apt_status
        self._apt_status = fresh_apt
        if apt_changed:
            self._render_status()
        else:
            self._sync_action_busy()

    def _accept_snapshot(self, snapshot: UpdateStatus, *, redraw: bool = False) -> None:
        previous = self._status
        self._status = snapshot
        if previous is None or (not self.is_dirty() and self._selected_channel() != snapshot.channel):
            self._set_radio_channel(snapshot.channel)
            self._snapshot_now()
            self._refresh_dirty_marker()
        if snapshot.poll_seconds != self._poll_seconds:
            if self._status_timer is not None:
                self._status_timer.stop()
            self._poll_seconds = snapshot.poll_seconds
            self._status_timer = self.set_interval(self._poll_seconds, self._queue_status_refresh)
        baseline = self._check_baseline
        if baseline is not None and not snapshot.checking and (
            snapshot.checked_at != baseline.checked_at
            or snapshot.state != baseline.state
            or snapshot.target_version != baseline.target_version
        ):
            self._check_baseline = None
            self._last_checked_at = time.time()
            redraw = True
        if redraw or snapshot != previous or self._app_check_state() != self._drawn_app_check:
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
        if self._status is None or self._saving_channel:
            return
        fields = self.collect()
        channel: Channel = fields["channel"]
        if self._status.state == "managed_elsewhere" and not self._status.channel_selectable:
            self._finish_save("No changes to save.")
            return
        self._saving_channel = True
        if self._status_worker is not None:
            self._status_worker.cancel()
        self._sync_channel_controls(self._status)
        self.run_worker(self._save_channel(channel), group="updates_save", exit_on_error=False)

    @staticmethod
    def _persist_channel(channel: Channel, runtime: RuntimeLayout | None) -> UpdateStatus | None:
        if not set_update_channel(channel, runtime=runtime):
            return None
        configure_client_identity(channel=channel)
        return read_update_status(runtime)

    async def _save_channel(self, channel: Channel) -> None:
        try:
            snapshot = await asyncio.to_thread(self._persist_channel, channel, self._runtime())
            if not self.is_attached:
                return
            if snapshot is None:
                message = "Couldn't save the update channel right now. Try again."
                self.mark_field_error("updates_channel_radio", message)
                self.app.notify(message, severity="warning", markup=False)
                return
            self._set_radio_channel(snapshot.channel)
            self._finish_save("Release channel saved.")
            self._accept_snapshot(snapshot, redraw=True)
            if snapshot.state == "managed_elsewhere":
                # The packaged app has no background updater to notice the
                # switch, so look at the new channel straight away.
                self._start_check()
        finally:
            self._saving_channel = False
            if self.is_attached and self._status is not None:
                self._sync_channel_controls(self._status)

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
        self._drawn_app_check = self._app_check_state()
        self._showing_check_failure = False

        installed = _terminal_safe(status.installed_version or get_version()).strip() or "unknown"
        install_kind = status.install_kind or ""
        apt_managed = self._effective_apt_managed(install_kind)
        install_label = describe_install_kind(install_kind, apt_managed=apt_managed)
        apt_state = getattr(self.app, "apt_upgrade_state", None)

        self.query_one("#updates_installed_label", Static).update("Running" if apt_state is not None else "Installed")
        self.query_one("#updates_installed_value", Static).update(
            f"{installed}  ·  {install_label}"
        )

        primary_widget = self.query_one("#updates_status_primary", Static)
        secondary_widget = self.query_one("#updates_status_secondary", Static)
        command_widget = self.query_one("#updates_status_command", Static)
        details_widget = self.query_one("#updates_failure_details", Static)
        links_row = self.query_one("#updates_status_links", Horizontal)
        link_notes = self.query_one("#updates_link_release_notes", LinkButton)
        link_details = self.query_one("#updates_link_details", LinkButton)
        link_download = self.query_one("#updates_link_download", LinkButton)

        btn_check = self.query_one("#updates_btn_check", Button)
        btn_postpone = self.query_one("#updates_btn_postpone", Button)
        btn_try = self.query_one("#updates_btn_try", Button)
        btn_update = self.query_one("#updates_btn_update", Button)
        btn_restart = self.query_one("#updates_btn_restart", Button)
        btn_macos_install = self.query_one("#updates_btn_macos_install", Button)
        can_install = getattr(self.app, "can_install_macos_update", None)
        macos_update = callable(can_install) and can_install()
        actions_box = self.query_one("#updates_status_actions", Vertical)

        # Reset visibility and state classes cleanly.
        for cls in ("-warning", "-error", "-accent", "-success"):
            primary_widget.remove_class(cls)
        for btn in (btn_check, btn_postpone, btn_try, btn_update, btn_restart, btn_macos_install):
            btn.display = False
        btn_restart.remove_class("hidden")
        link_notes.display = False
        link_details.display = False
        link_download.display = False
        details_widget.display = False
        self._release_notes_target = None

        primary_text = ""
        secondary_text = ""
        command_text = ""
        required_min = self._effective_required_minimum(installed)
        pinned_version = _terminal_safe(
            getattr(status, "pinned_version", None) or ""
        ).strip()
        pinned_until_newer_than = _terminal_safe(
            getattr(status, "pinned_until_newer_than", None) or ""
        ).strip()

        if apt_state is not None and apt_state.restart_version:
            primary_text = package_update_notice(installed, apt_state.restart_version, managed_by_apt=apt_managed)
            btn_restart.display = True
            primary_widget.add_class("-accent")
        elif apt_state is not None and apt_state.change is AptChange.REMOVED:
            primary_text = "The Servonaut package was removed."
            secondary_text = "This running window remains available until you close it."
            primary_widget.add_class("-warning")
        elif apt_state is not None and apt_state.change is AptChange.DEFERRED:
            primary_text = "Waiting for the Servonaut package to finish configuring."
            primary_widget.add_class("-warning")
        elif required_min:
            # State 4 — service requires a newer version (server minimum).
            hint = format_server_minimum_hint(
                install_kind, apt_managed=apt_managed, policy=self._policy,
            )
            primary_text = (
                f"servonaut.dev needs {required_min} or later for team, "
                "vault and AI features."
            )
            if _is_apt_install(install_kind, apt_managed=apt_managed):
                secondary_text = "Local features keep working. To update now, run:"
                command_text = hint
            else:
                secondary_text = f"Local features keep working.  Update: {hint}"
            primary_widget.add_class("-warning")
            if _can_run_in_app_update(install_kind, apt_managed=apt_managed):
                btn_update.display = True
            if _supports_download_link(install_kind, apt_managed=apt_managed):
                link_download.display = True
        elif status.state == "managed_elsewhere":
            # State 5 — managed elsewhere.
            primary_text, secondary_text, command_text, show_check, show_download, notes_ver = (
                self._managed_elsewhere_view(status, apt_managed=apt_managed, macos_update=macos_update)
            )
            if show_check:
                btn_check.display = True
            if self._showing_check_failure and show_check and not show_download:
                primary_widget.add_class("-warning")
            if show_download:
                link_download.display = True
                primary_widget.add_class("-accent")
            if notes_ver:
                self._configure_release_notes_link(link_notes, notes_ver)
        elif status.ready_for_other_channel and status.target_version:
            target = _terminal_safe(status.target_version).strip()
            primary_text = (
                f"{target} was prepared for Release candidates and won't be used "
                "on the Stable channel. You'll get the next stable release."
            )
            btn_check.display = True
        elif pinned_version and not status.ready_for_offer:
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
                redactor = getattr(self.app, "redact_display_text", None)
                if callable(redactor):
                    failure_text = redactor(failure_text)
                link_details.label = "Hide details" if self._details_expanded else "Details →"
                link_details.display = True
                details_widget.update(failure_text)
                details_widget.display = self._details_expanded
        elif status.state in ("ready", "offered", "building"):
            # State 2 — update ready / offered / building.
            target = _terminal_safe(status.target_version or self._discovered_version or "").strip()
            when = (
                format_postponed_until(status.postponed_until)
                if status.postponed_until is not None else ""
            )
            if status.state == "ready":
                primary_text = f"{target or 'An update'} is ready"
                if not when:
                    primary_text += "  ·  starts the next time you open Servonaut"
            elif status.state == "building":
                primary_text = (
                    f"Preparing {target} in the background…"
                    if target
                    else "Preparing an update in the background…"
                )
            else:
                primary_text = f"{target or 'An update'} is available"
                if not when:
                    primary_text += "  ·  will install in the background"
            primary_widget.add_class("-accent")

            detail_lines = []
            if when:
                detail_lines.append(
                    f"Postponed until {when}, installs at the next start after that"
                )
            if status.old_sessions:
                sessions_line = format_old_sessions(status.old_sessions, status.old_session_version or "")
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
            if self._check_baseline is not None or status.checking:
                primary_text = "Checking for updates…"
                btn_check.display = True
            elif discovered and self._is_newer(discovered, installed):
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
                primary_text, secondary_text, failed = self._up_to_date_lines("")
                primary_widget.add_class("-warning" if failed else "-success")
                btn_check.display = True

        primary_widget.update(primary_text)
        secondary_widget.update(secondary_text)
        secondary_widget.display = bool(secondary_text)
        command_widget.update(command_text)
        command_widget.display = bool(command_text)
        links_row.display = bool(
            link_notes.display or link_details.display or link_download.display
        )
        if link_download.display and macos_update:
            btn_macos_install.remove_class("hidden")
            btn_macos_install.display = True
        actions_box.display = any(
            btn.display for btn in (btn_check, btn_postpone, btn_try, btn_update, btn_restart, btn_macos_install)
        )

        self._sync_channel_controls(status)
        self._sync_channel_notes()
        self._sync_action_busy()

    def _app_check_state(self) -> tuple[Optional[UpdateCheckResult], Optional[str], Optional[str]]:
        """``(result, latest, reason)`` of the app's own last update check.

        The app checks at start, before this panel exists; until a check runs
        here, its outcome is the only evidence of what is available.
        """
        service = getattr(self.app, "update_service", None)
        result = getattr(service, "last_check_result", None)
        latest = getattr(service, "latest_version", None)
        reason = getattr(service, "update_status", None)
        return (
            result if isinstance(result, UpdateCheckResult) else None,
            latest if isinstance(latest, str) else None,
            reason if isinstance(reason, str) else None,
        )

    def _up_to_date_lines(
        self, idle_secondary: str, *, app_check: bool = False,
    ) -> tuple[str, str, bool]:
        """Headline and detail for a check that found nothing newer.

        Returns ``(primary, secondary, failed)``. "Up to date" is only claimed
        after a check that succeeded; a failed one says so, with its reason.
        With *app_check*, the app's own last check stands in until a check
        runs here, and no check at all is reported as such.
        """
        ago = format_checked_ago(self._last_checked_at) if self._last_checked_at is not None else ""
        error = self._check_error
        unchecked = False
        if app_check and not error and self._last_checked_at is None:
            result, _latest, reason = self._app_check_state()
            if result in _CHECK_ERROR_RESULTS:
                error = reason or _STATUS_FALLBACK_FAILURE
            unchecked = result is None
        if error:
            self._showing_check_failure = True
            tried = f"  ·  tried {ago}" if ago else ""
            return (
                f"Couldn't check for updates{tried}",
                _terminal_safe(error).strip(),
                True,
            )
        if unchecked:
            return "Not checked yet", "Check now looks for a newer version.", False
        primary = f"Up to date  ·  checked {ago}" if ago else "Up to date"
        return primary, idle_secondary, False

    def _managed_elsewhere_view(
        self,
        status: UpdateStatus,
        *,
        apt_managed: Optional[bool] = None,
        macos_update: bool = False,
    ) -> tuple[str, str, str, bool, bool, Optional[str]]:
        """Return ``(primary, secondary, command, show_check, show_download, notes_ver)``."""
        install_kind = status.install_kind or ""
        if _is_apt_install(install_kind, apt_managed=apt_managed):
            return (
                "Updates are managed by apt.",
                "To update now, run:",
                _APT_UPGRADE_COMMAND,
                False,
                False,
                None,
            )
        if install_kind == DistributionKind.SOURCE.value:
            return (
                "Running from a source checkout — automatic updates are off.",
                "Update your checkout to get newer versions.",
                "",
                False,
                False,
                None,
            )
        if install_kind == DistributionKind.PIP.value:
            return (
                "Updates are installed with pip.",
                "To update now: pip install --upgrade servonaut",
                "",
                False,
                False,
                None,
            )
        if install_kind == DistributionKind.PIPX.value:
            return (
                "Updates are managed by pipx.",
                "To update now: pipx upgrade servonaut",
                "",
                False,
                False,
                None,
            )
        if _supports_download_link(install_kind, apt_managed=apt_managed):
            discovered = self._discovered_version
            if discovered is None and self._last_checked_at is None:
                result, latest, _reason = self._app_check_state()
                if result is UpdateCheckResult.UPDATE_AVAILABLE:
                    discovered = latest
            available = _terminal_safe(
                status.target_version or discovered or ""
            ).strip()
            if available and (macos_update or self._is_newer(available, status.installed_version)):
                return (
                    f"{available} is available",
                    "",
                    "",
                    False,
                    True,
                    available,
                )
            primary, secondary, _ = self._up_to_date_lines(
                "New releases are available from servonaut.dev/download.", app_check=True,
            )
            return (primary, secondary, "", True, False, None)

        return (
            "Updates are managed outside Servonaut.",
            f"Download newer versions from {DEFAULT_UPDATE_URL}.",
            "",
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
        install_kind = status.install_kind or ""
        apt_managed = self._effective_apt_managed(install_kind)
        is_apt = _is_apt_install(install_kind, apt_managed=apt_managed)
        selectable = status.channel_selectable and not is_apt
        managed = (status.state == "managed_elsewhere" and not selectable) or is_apt
        # A control that cannot act on this install is hidden, never shown locked.
        self.query_one("#updates_channel_section").display = (
            is_apt or selectable or status.state != "managed_elsewhere"
        )
        title = self.query_one("#updates_channel_title", Static)
        radio = self.query_one("#updates_channel_radio", RadioSet)
        apt_summary = self.query_one("#updates_channel_apt_summary", Static)
        title.display = not is_apt
        radio.display = not is_apt
        radio.disabled = managed or self._saving_channel
        if is_apt:
            suite_display, _ = self._effective_apt_suite()
            if suite_display:
                apt_summary.update(
                    f"Release channel: {suite_display} (set in your APT source)"
                )
            else:
                apt_summary.update("Release channel: set in your APT source")
            apt_summary.display = True
        else:
            apt_summary.update("")
            apt_summary.display = False
        try:
            save_btn = self.query_one(f"#save_{self.PANEL_ID}", Button)
            save_btn.disabled = managed or self._saving_channel
        except NoMatches:
            pass
        self.query_one("#updates_auto_note", Static).display = (
            not managed and status.state != "managed_elsewhere"
        )

    def _sync_channel_notes(self) -> None:
        note = self.query_one("#updates_channel_note", Static)
        status = self._status
        if status is None:
            note.update("")
            note.display = False
            return
        install_kind = status.install_kind or ""
        apt_managed = self._effective_apt_managed(install_kind)
        if _is_apt_install(install_kind, apt_managed=apt_managed):
            note.update("Servonaut does not modify APT configuration.")
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
        if not self.is_attached:
            return
        updating = bool(getattr(self.app, "_update_in_progress", False))
        checking = self._check_baseline is not None or bool(self._status and self._status.checking)
        locked = updating or self._busy or self._checking_apt or self._status is None
        for selector in (
            "#updates_btn_check",
            "#updates_btn_postpone",
            "#updates_btn_try",
            "#updates_btn_update",
            "#updates_btn_restart",
            "#updates_btn_macos_install",
            "#updates_link_download",
        ):
            try:
                self.query_one(selector, Button).disabled = locked or (
                    selector == "#updates_btn_check" and checking
                )
            except NoMatches:
                pass
        if self._busy:
            return
        busy = self.query_one("#updates_busy", BusyIndicator)
        if updating:
            busy.start("Updating Servonaut…")
        elif self._status is None:
            busy.start("Reading update status…")
        elif self._checking_apt:
            busy.start("Checking installation status…")
        elif checking:
            busy.start("Checking for updates…")
        elif busy.is_active:
            busy.stop()

    def _notify_update_presented(self, version: str) -> None:
        """Record that *version* was shown to the user once per rendered version."""
        cleaned = version.strip()
        if (
            not cleaned or cleaned in self._presented_versions
            or cleaned in self._presentations_in_progress
            or not self.is_attached or not self.display or self.screen is not self.app.screen
        ):
            return
        marker = getattr(updates_status, "mark_update_presented", None)
        if not callable(marker):
            return
        self._presentations_in_progress.add(cleaned)
        self.run_worker(
            self._run_mark_presented(marker, cleaned),
            name=f"updates_mark_presented_{cleaned}",
            group="updates_present",
            exit_on_error=False,
        )

    async def _run_mark_presented(self, marker: Any, version: str) -> None:
        try:
            if await asyncio.to_thread(marker, version):
                self._presented_versions.add(version)
        except Exception as exc:  # noqa: BLE001 — bookkeeping must never break the panel
            logger.debug("Could not record presented update %s: %s", version, exc)
        finally:
            self._presentations_in_progress.discard(version)

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

    @on(Button.Pressed, "#updates_btn_macos_install")
    def _on_macos_install_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.app.request_macos_install(self._show_macos_download)

    def _show_macos_download(self, downloading: bool) -> None:
        if not self.is_attached:
            return
        self._busy = downloading
        busy = self.query_one("#updates_busy", BusyIndicator)
        if downloading:
            busy.start("Downloading verified update…")
        else:
            busy.stop()
            self._render_status()
        self._sync_action_busy()

    @on(Button.Pressed, "#updates_btn_restart")
    def _on_restart_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.app.request_apt_restart()

    @on(Button.Pressed, "#updates_btn_check")
    def _on_check_now_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self._start_check()

    def _start_check(self) -> None:
        if self._busy or self._check_baseline is not None:
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
            generation_check = False
            if callable(requester):
                baseline = self._status
                outcome = await requester()
                if not self.is_attached:
                    return
                if (
                    outcome == "queued" and baseline is not None
                    and baseline.state != "managed_elsewhere"
                ):
                    generation_check = True
                    self._check_baseline = baseline
                    self._render_status()
                elif outcome in (None, "queued"):
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
                self._accept_snapshot(status, redraw=True)
                self.app.notify(toast_msg, severity=toast_severity, markup=False)
            else:
                if not generation_check:
                    self._last_checked_at = time.time()
                self._accept_snapshot(status, redraw=True)
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
            self._accept_snapshot(status, redraw=True)
            if ok:
                when = (
                    format_postponed_until(status.postponed_until)
                    if status.postponed_until is not None else ""
                )
                self.app.notify(
                    f"Postponed {_terminal_safe(version)} until {when}." if when
                    else f"Postponed {_terminal_safe(version)}.",
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
                downloader = getattr(self.app, "run_requested_download", None)
                success, message = await (downloader() if callable(downloader) else service.run_upgrade())
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
            self._accept_snapshot(status, redraw=True)
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

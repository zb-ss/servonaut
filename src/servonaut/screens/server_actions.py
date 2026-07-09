"""Server actions screen for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from typing import TYPE_CHECKING, Optional

from rich.markup import escape
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Static, Button, Header, Footer

from servonaut.utils.live_stats import LIVE_STATS_COMMAND, LiveStats, parse_live_stats
from servonaut.utils.memory_panel import render_memory_panel
from servonaut.widgets.sidebar import Sidebar

#: Seconds between live-stats polls while the panel is active.
_LIVE_STATS_INTERVAL = 3.0

#: Per-action one-line help shown in the detail pane on focus.
_ACTION_HELP: dict[str, str] = {
    "btn_browse": "Browse the remote filesystem in a tree view (over SSH).",
    "btn_command": "Run a one-off command on this server in an overlay panel.",
    "btn_ssh": "Open a full SSH session in a new terminal window.",
    "btn_memory": "Build / view the AI-queryable fact cache for this server.",
    "btn_logs": "Stream live log files via SSH (tail -f).",
    "btn_scan": "View keyword scan results collected from this server.",
    "btn_db_creds": "Scan this server for DB credentials and store them in your secret vault.",
    "btn_ai_analysis": "Analyze log text with AI (OpenAI, Anthropic, or Ollama).",
    "btn_scp": "Upload or download files via SCP.",
    "btn_ban_ip": "Ban this server's public IP via WAF, Security Group, or NACL.",
    "btn_manage_ssh_ref": "Add, edit, or remove the Bitwarden SSH item ref.",
    "btn_verify_ssh": "Run a local SSH probe and report the result.",
    "btn_ovh_reinstall": "Reinstall this OVH server with a new OS image.",
    "btn_ovh_resize": "Change the VPS model or Cloud flavor.",
    "btn_ovh_monitoring": "View CPU, RAM, and network metrics.",
    "btn_ovh_snapshots": "Create, restore, or delete snapshots.",
    "btn_ovh_firewall": "Manage VPS firewall rules.",
    "btn_back": "Return to the instance list.",
}

if TYPE_CHECKING:
    from servonaut.screens.file_browser import FileBrowserScreen
    from servonaut.screens.command_overlay import CommandOverlay

logger = logging.getLogger(__name__)


class ConfirmSshVerifyModal(ModalScreen[bool]):
    """Brief blocking confirmation for the SSH probe action.

    Returns True on Confirm, False on Cancel (including Escape).
    Per the project convention: ModalScreen for brief blocking prompts.
    Per style constraints: round $accent border, fixed height, Cancel button.
    """

    BINDINGS = [
        Binding("escape", "action_cancel", "Cancel", show=False),
    ]

    def __init__(self, host: str, has_ref: bool) -> None:
        """Initialize the modal.

        Args:
            host: Target host name / IP (cloud-origin — must be escaped).
            has_ref: True if a BW SSH ref is stored for this instance. When
                False the modal offers "Add SSH ref" instead of the probe prompt.
        """
        super().__init__()
        self._host = host
        self._has_ref = has_ref

    def compose(self) -> ComposeResult:
        """Compose the confirm modal."""
        safe_host = escape(self._host)
        if self._has_ref:
            body_text = (
                f"About to run a local SSH probe against [bold]{safe_host}[/bold].\n\n"
                "This will:\n"
                "  (1) resolve the Bitwarden item ref\n"
                "  (2) run ssh -o BatchMode=yes to test connectivity\n"
                "  (3) report the result to the server audit log"
            )
            confirm_label = "Verify"
        else:
            body_text = (
                f"No SSH ref is stored for [bold]{safe_host}[/bold].\n\n"
                "Would you like to add one so Servonaut can verify "
                "SSH connectivity via Bitwarden?"
            )
            confirm_label = "Add SSH Ref"

        yield Container(
            Static("[bold]Verify SSH[/bold]", id="ssh_verify_modal_title"),
            Static(body_text, id="ssh_verify_modal_body"),
            Horizontal(
                Button("Cancel", variant="default", id="btn_ssh_verify_cancel"),
                Button(confirm_label, variant="primary", id="btn_ssh_verify_confirm"),
                classes="ssh_verify_actions_row",
            ),
            id="ssh_verify_modal_container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with the appropriate result."""
        if event.button.id == "btn_ssh_verify_confirm":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_action_cancel(self) -> None:
        """Escape — dismiss False."""
        self.dismiss(False)


class ServerActionsScreen(Screen):
    """Screen displaying available actions for a selected EC2 instance.

    Shows server information and action buttons:
    1. Browse Files - File browser with RemoteTree
    2. Run Command - Command execution overlay
    3. SSH Connect - Launch external SSH terminal
    4. SCP Transfer - File transfer
    5. View Scan Results - Show keyword scan results
    6. View Logs - Real-time remote log viewer
    7. AI Analysis - AI-powered log analysis
    8. Ban IP - Ban this instance's public IP
    9. Back - Return to instance list
    """

    BINDINGS = [
        Binding("1", "action_1", "Browse Files", show=True),
        Binding("2", "action_2", "Run Command", show=True),
        Binding("3", "action_3", "SSH Connect", show=True),
        Binding("4", "action_4", "SCP Transfer", show=True),
        Binding("5", "action_5", "Scan Results", show=True),
        Binding("6", "action_6", "View Logs", show=True),
        Binding("7", "action_7", "AI Analysis", show=True),
        Binding("8", "action_8", "Ban IP", show=True),
        Binding("m", "open_memory", "Memory", show=True),
        Binding("d", "scan_db_creds", "Scan DB", show=True),
        Binding("l", "toggle_live", "Live", show=True),
        Binding("r", "manage_ssh_ref", "SSH Ref", show=True),
        Binding("v", "verify_ssh", "Verify SSH", show=True),
        Binding("9", "back", "Back", show=True),
        Binding("escape", "back", "Back", show=False),
    ]

    def __init__(self, instance: dict) -> None:
        """Initialize server actions screen.

        Args:
            instance: Instance dictionary with connection details.
        """
        super().__init__()
        self._instance = instance
        self._live_on = False
        # Id of the action button the focus-help line currently describes, so a
        # click on that (otherwise passive) line can re-dispatch to the button.
        self._focused_action_id: Optional[str] = None
        # Which read-only view is mounted inline in the detail pane, if any:
        # None | "browse" | "logs".
        self._inline_view: Optional[str] = None

    def on_mount(self) -> None:
        """Focus the first action button and populate the detail pane."""
        self.query_one("#btn_browse", Button).focus()
        # Fetch reverse DNS for OVH VPS instances
        if self._instance.get('is_ovh') and self._instance.get('provider_type') == 'vps':
            public_ip = self._instance.get('public_ip')
            if public_ip:
                self.run_worker(self._fetch_rdns(public_ip), exclusive=False)
        # Dynamically add OVH action buttons for OVH instances
        if self._instance.get('is_ovh'):
            action_buttons = self.query_one("#action_buttons")
            action_buttons.mount(
                Static("OVH", classes="section_label"),
                Button("Reinstall OS", id="btn_ovh_reinstall", variant="error"),
                Button("Resize / Upgrade", id="btn_ovh_resize"),
                Button("Monitoring", id="btn_ovh_monitoring"),
                Button("Snapshots", id="btn_ovh_snapshots"),
                Button("Firewall", id="btn_ovh_firewall"),
                before=self.query_one("#btn_back"),
            )
        # Populate the cached-memory snapshot pane.
        self._render_memory_panel()

    def on_key(self, event) -> None:
        """Handle arrow key navigation between buttons.

        Args:
            event: Key event.
        """
        if event.key in ("up", "down"):
            # Only cycle the action rail when a rail button already has focus.
            # When focus is inside the inline view (file tree) or elsewhere,
            # leave arrow keys alone so that widget can handle them.
            buttons = list(self.query("#action_buttons Button"))
            if not buttons:
                return
            focused = self.focused
            if focused not in buttons:
                return
            idx = buttons.index(focused)
            if event.key == "down":
                next_idx = (idx + 1) % len(buttons)
            else:
                next_idx = (idx - 1) % len(buttons)
            buttons[next_idx].focus()

    def compose(self) -> ComposeResult:
        """Compose the server actions UI (narrow action rail + detail pane)."""
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Horizontal(id="sa-body"):
                # --- Left: narrow, sectioned action rail ---
                yield Vertical(
                    Static("CONNECT", classes="section_label"),
                    Button("1. Browse Files", id="btn_browse", variant="primary"),
                    Button("2. Run Command", id="btn_command"),
                    Button("3. SSH Connect", id="btn_ssh"),
                    Static("INSPECT", classes="section_label"),
                    # Memory promoted to the top of INSPECT — highest-leverage
                    # feature for AI / MCP workflows.
                    Button("M. Memory", id="btn_memory"),
                    Button("6. View Logs", id="btn_logs"),
                    Button("5. Scan Results", id="btn_scan"),
                    Button("D. Scan DB Creds", id="btn_db_creds"),
                    Button("7. AI Analysis", id="btn_ai_analysis"),
                    Static("OPERATE", classes="section_label"),
                    Button("4. SCP Transfer", id="btn_scp"),
                    Button("8. Ban IP", id="btn_ban_ip"),
                    Static("MANAGE", classes="section_label"),
                    Button("R. Manage SSH Ref", id="btn_manage_ssh_ref"),
                    Button("V. Verify SSH", id="btn_verify_ssh"),
                    Button("9. Back", id="btn_back", variant="error"),
                    id="action_buttons",
                )
                # --- Right: identity + live + memory + focus help + inline view ---
                yield Vertical(
                    Static(self._build_server_info(), id="server_info"),
                    Static(self._live_stats_idle_text(), id="live_stats"),
                    Static("", id="memory_panel"),
                    Static("", id="action_help"),
                    # Mount target for inline read-only views (Browse / Logs).
                    # Hidden until an action opens it (see _open_inline).
                    Vertical(id="sa-inline"),
                    id="sa-detail",
                )
        yield Footer()

    def _build_server_info(self) -> str:
        """Build server information display string.

        Returns:
            Rich-formatted string with server details.
        """
        name = self._instance.get('name') or 'Unnamed'
        public_ip = self._instance.get('public_ip') or 'N/A'

        if self._instance.get('is_ovh'):
            provider_type = self._instance.get('provider_type', 'unknown')
            region = self._instance.get('region') or '-'
            state = self._instance.get('state', 'unknown')
            instance_id = self._instance.get('id', 'unknown')
            private_ip = self._instance.get('private_ip') or 'N/A'
            server_type = self._instance.get('type') or '-'
            os_label = self._instance.get('os') or '-'
            ram = self._instance.get('ram_gb') or '-'
            return (
                f"[bold cyan]OVH Server: {name}[/bold cyan]\n\n"
                f"[dim]ID:[/dim] {instance_id}\n"
                f"[dim]Type:[/dim] {provider_type.upper()} — {server_type}\n"
                f"[dim]Public IP:[/dim] {public_ip}\n"
                f"[dim]Private IP:[/dim] {private_ip}\n"
                f"[dim]Region:[/dim] {region}\n"
                f"[dim]State:[/dim] {self._colorize_state(state)}\n"
                f"[dim]OS:[/dim] {os_label}\n"
                f"[dim]RAM:[/dim] {ram} GB\n\n"
                f"[cyan]Direct Connection[/cyan]\n"
                f"[dim]Target:[/dim] {public_ip}"
            )

        if self._instance.get('is_custom'):
            provider = self._instance.get('provider') or 'custom'
            group = self._instance.get('group') or '-'
            port = self._instance.get('port', 22)
            username = self._instance.get('username') or 'root'
            return (
                f"[bold cyan]Server: {name}[/bold cyan]\n\n"
                f"[dim]Host:[/dim] {public_ip}\n"
                f"[dim]Port:[/dim] {port}\n"
                f"[dim]Username:[/dim] {username}\n"
                f"[dim]Provider:[/dim] {provider}\n"
                f"[dim]Group:[/dim] {group}\n"
                f"[dim]State:[/dim] [dim]N/A (custom server)[/dim]\n\n"
                f"[cyan]Direct Connection[/cyan]\n"
                f"[dim]Target:[/dim] {public_ip}"
            )

        instance_id = self._instance.get('id', 'unknown')
        private_ip = self._instance.get('private_ip') or 'N/A'
        region = self._instance.get('region', 'unknown')
        state = self._instance.get('state', 'unknown')

        # Resolve connection method for AWS instances
        profile = self.app.connection_service.resolve_profile(self._instance)
        if profile and profile.bastion_host:
            connection_info = f"[cyan]via Bastion:[/cyan] {profile.bastion_host}"
            target_ip = private_ip
        else:
            connection_info = "[cyan]Direct Connection[/cyan]"
            target_ip = public_ip

        return (
            f"[bold cyan]Server: {name}[/bold cyan]\n\n"
            f"[dim]Instance ID:[/dim] {instance_id}\n"
            f"[dim]Public IP:[/dim] {public_ip}\n"
            f"[dim]Private IP:[/dim] {private_ip}\n"
            f"[dim]Region:[/dim] {region}\n"
            f"[dim]State:[/dim] {self._colorize_state(state)}\n\n"
            f"{connection_info}\n"
            f"[dim]Target:[/dim] {target_ip}"
        )

    def _colorize_state(self, state: str) -> str:
        """Add color markup to instance state.

        Args:
            state: Instance state string.

        Returns:
            Colorized state string with markup.
        """
        state_colors = {
            'running': '[green]running[/green]',
            'stopped': '[red]stopped[/red]',
            'stopping': '[yellow]stopping[/yellow]',
            'pending': '[cyan]pending[/cyan]',
            'terminated': '[dim]terminated[/dim]',
        }
        return state_colors.get(state, state)

    async def _fetch_rdns(self, public_ip: str) -> None:
        """Fetch reverse DNS for a VPS IP and update the server info display."""
        vps_service = getattr(self.app, "ovh_vps_service", None)
        if vps_service is None:
            return
        vps_name = self._instance.get('id', '')
        if not vps_name:
            return
        reverse = await vps_service.get_reverse_dns(vps_name, public_ip)
        if reverse:
            if self.app.demo_mode and self.app.redaction_service:
                reverse = self.app.redaction_service.redact_hostname(reverse)
            info_widget = self.query_one("#server_info", Static)
            current = str(info_widget.renderable)
            # Insert rDNS line after Public IP line
            current = current.replace(
                f"[dim]Public IP:[/dim] {public_ip}",
                f"[dim]Public IP:[/dim] {public_ip}\n[dim]Reverse DNS:[/dim] {reverse}",
            )
            info_widget.update(current)

    # ------------------------------------------------------------------
    # Detail pane: focus help, cached memory snapshot, live stats
    # ------------------------------------------------------------------

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        """Update the focus-driven help line when an action button gains focus.

        The line is also a clickable proxy for the focused button (see
        :meth:`on_click`), so it reads as actionable rather than a dead label.
        """
        widget_id = getattr(event.widget, "id", None)
        if not widget_id:
            return
        help_text = _ACTION_HELP.get(widget_id)
        if help_text is None:
            return
        self._focused_action_id = widget_id
        try:
            self.query_one("#action_help", Static).update(
                f"[dim]▸[/dim] [u]{escape(help_text)}[/u]  [dim]· click to run[/dim]"
            )
        except Exception:  # noqa: BLE001 — pane may not be mounted yet
            pass

    def on_click(self, event: events.Click) -> None:
        """Treat a click on the focus-help line as activating the focused action."""
        widget = getattr(event, "widget", None)
        if widget is None or getattr(widget, "id", None) != "action_help":
            return
        btn_id = self._focused_action_id
        if not btn_id:
            return
        try:
            self.query_one(f"#{btn_id}", Button).press()
        except Exception:  # noqa: BLE001
            pass

    def _provider_for_memory(self) -> str:
        """Best-effort provider slug for memory lookups.

        Passing an empty string makes ``get_all_modules`` scan every provider
        sub-directory, so the snapshot is found regardless of which slug it was
        stored under (custom / aws / ovh / hetzner).
        """
        return ""

    def _render_memory_panel(self) -> None:
        """Render the cached server-memory snapshot into the detail pane."""
        try:
            panel = self.query_one("#memory_panel", Static)
        except Exception:  # noqa: BLE001
            return

        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            panel.update("[dim]Server memory is unavailable.[/dim]")
            return

        instance_id = str(self._instance.get("id") or "")
        instance_name = self._instance.get("name") or ""
        try:
            if memory_service.is_memory_disabled(instance_id, instance_name):
                panel.update("[dim]Memory is disabled for this server.[/dim]")
                return
        except Exception:  # noqa: BLE001
            pass

        try:
            modules = memory_service.get_all_modules(instance_id, self._provider_for_memory())
        except Exception as exc:  # noqa: BLE001
            logger.debug("get_all_modules failed for %s: %s", instance_id, exc)
            modules = {}

        text = render_memory_panel(modules)
        # Demo mode: the snapshot can embed paths / hostnames / versions from
        # the probed server — scrub before rendering, same posture as the
        # Memory screen and log viewer.
        if self.app.demo_mode and getattr(self.app, "redaction_service", None):
            text = self.app.redaction_service.scrub_stream(text)
        panel.update(text)

    # ------------------------------------------------------------------
    # Inline read-only views (Browse / Logs) — mounted in #sa-inline
    # ------------------------------------------------------------------

    def _safe_focus(self, selector: str) -> None:
        """Focus the widget matching *selector*, swallowing query failures."""
        try:
            self.query_one(selector).focus()
        except Exception:  # noqa: BLE001
            pass

    def _clear_inline(self) -> None:
        """Tear down whatever is mounted in the inline region and hide it."""
        try:
            inline = self.query_one("#sa-inline", Vertical)
        except Exception:  # noqa: BLE001
            self._inline_view = None
            return
        inline.remove_children()
        inline.remove_class("visible")
        self._inline_view = None

    def _open_inline_browse(self) -> None:
        """Mount the remote file tree inline in the detail pane."""
        from servonaut.screens.file_browser import build_remote_tree

        if self._inline_view == "browse":
            self._safe_focus("#remote_tree")
            return
        self._clear_inline()

        try:
            inline = self.query_one("#sa-inline", Vertical)
        except Exception:  # noqa: BLE001
            return

        try:
            tree = build_remote_tree(self.app, self._instance, tree_id="remote_tree")
        except Exception as exc:  # noqa: BLE001
            logger.error("Could not build inline file tree: %s", exc, exc_info=True)
            self.app.notify("Could not open file browser.", severity="error", markup=False)
            return

        self._inline_view = "browse"
        inline.mount(
            Static(
                "[b]📁 Files[/b]  [dim]· Esc to close[/dim]",
                classes="inline_title",
            ),
            tree,
            Static(
                "[dim]Root folders come from [b]Settings → Default Scan Paths[/b] "
                "(plus any matching Scan Rule).[/dim]",
                classes="inline_note",
            ),
        )
        inline.add_class("visible")
        self.call_after_refresh(lambda: self._safe_focus("#remote_tree"))

    # ------------------------------------------------------------------
    # Live stats (opt-in, SSH-polled)
    # ------------------------------------------------------------------

    def _live_stats_idle_text(self) -> str:
        """Text shown in the live-stats pane while polling is off."""
        return "[dim]Live stats: off — press [b]L[/b] to start (SSH-polled).[/dim]"

    def action_toggle_live(self) -> None:
        """Toggle the live resource-stats poller on/off."""
        if self._live_on:
            self._stop_live_stats()
            return

        if getattr(self.app, "memory_service", None) is None:
            self.app.notify(
                "Live stats need the memory service (SSH runner) — unavailable.",
                severity="warning",
                markup=False,
            )
            return
        if not self._validate_instance_connection():
            return

        self._live_on = True
        try:
            self.query_one("#live_stats", Static).update("[cyan]Live stats: connecting…[/cyan]")
        except Exception:  # noqa: BLE001
            pass
        self.run_worker(
            self._live_stats_worker(),
            group="live_stats",
            exclusive=True,
        )

    def _stop_live_stats(self) -> None:
        """Stop the poller and reset the pane to its idle text."""
        self._live_on = False
        self.workers.cancel_group(self, "live_stats")
        try:
            self.query_one("#live_stats", Static).update(self._live_stats_idle_text())
        except Exception:  # noqa: BLE001
            pass

    async def _live_stats_worker(self) -> None:
        """Poll live resource stats over SSH until toggled off or screen left."""
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        try:
            runner = memory_service.make_ssh_runner(self._instance)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not build SSH runner for live stats: %s", exc)
            self._set_live_text("[red]Live stats: SSH unavailable.[/red]")
            self._live_on = False
            return

        while self._live_on:
            try:
                stdout, _stderr, _rc = await runner(LIVE_STATS_COMMAND)
                stats = parse_live_stats(stdout)
                self._set_live_text(self._format_live_stats(stats))
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                self._set_live_text("[yellow]Live stats: timed out — retrying…[/yellow]")
            except Exception as exc:  # noqa: BLE001
                logger.debug("Live stats poll failed: %s", exc)
                self._set_live_text("[red]Live stats: poll failed — retrying…[/red]")

            try:
                await asyncio.sleep(_LIVE_STATS_INTERVAL)
            except asyncio.CancelledError:
                raise

    def _set_live_text(self, markup: str) -> None:
        """Update the live-stats pane defensively (screen may be torn down)."""
        try:
            self.query_one("#live_stats", Static).update(markup)
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _bar(pct: Optional[float], width: int = 12) -> str:
        """Return a simple text gauge for *pct* (0–100), color-coded."""
        if pct is None:
            return "[dim]" + "·" * width + "[/dim]"
        filled = max(0, min(width, round(pct / 100 * width)))
        color = "green" if pct < 70 else ("yellow" if pct < 90 else "red")
        return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * (width - filled)}[/dim]"

    def _format_live_stats(self, s: LiveStats) -> str:
        """Format a :class:`LiveStats` into a compact htop-like panel."""
        cpu = f"{s.cpu_pct:.0f}%" if s.cpu_pct is not None else "?"
        if s.mem_pct is not None and s.mem_total_mb:
            mem = f"{s.mem_pct:.0f}% [dim]({s.mem_used_mb}/{s.mem_total_mb} MB)[/dim]"
        else:
            mem = "?"
        if s.load_1m is not None:
            load = f"{s.load_1m:.2f} {s.load_5m:.2f} {s.load_15m:.2f}"
        else:
            load = "?"
        if s.disk_pct is not None:
            disk = f"{s.disk_pct}% [dim]({s.disk_used_gb}/{s.disk_total_gb} GB)[/dim]"
        else:
            disk = "?"
        uptime = escape(s.uptime) if s.uptime else "?"

        return (
            "[bold]Live[/bold]  [dim]· press [b]L[/b] to stop[/dim]\n\n"
            f"  [dim]CPU [/dim] {self._bar(s.cpu_pct)} {cpu}\n"
            f"  [dim]RAM [/dim] {self._bar(s.mem_pct)} {mem}\n"
            f"  [dim]Load[/dim] {load}    [dim]Disk[/dim] {self._bar(float(s.disk_pct) if s.disk_pct is not None else None)} {disk}\n"
            f"  [dim]Up  [/dim] {uptime}"
        )

    def on_screen_suspend(self) -> None:
        """Stop live polling when navigating away (no background SSH traffic)."""
        if self._live_on:
            self._stop_live_stats()

    def on_unmount(self) -> None:
        """Ensure the poller is cancelled and inline views torn down on teardown."""
        self._live_on = False
        try:
            self.workers.cancel_group(self, "live_stats")
        except Exception:  # noqa: BLE001
            pass
        if self._inline_view is not None:
            self._clear_inline()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events.

        Args:
            event: Button pressed event.
        """
        button_id = event.button.id

        if button_id == "btn_browse":
            self.action_action_1()
        elif button_id == "btn_command":
            self.action_action_2()
        elif button_id == "btn_ssh":
            self.action_action_3()
        elif button_id == "btn_scp":
            self.action_action_4()
        elif button_id == "btn_scan":
            self.action_action_5()
        elif button_id == "btn_logs":
            self.action_action_6()
        elif button_id == "btn_ai_analysis":
            self.action_action_7()
        elif button_id == "btn_ban_ip":
            self.action_action_8()
        elif button_id == "btn_memory":
            self.action_open_memory()
        elif button_id == "btn_db_creds":
            self.action_scan_db_creds()
        elif button_id == "btn_ovh_reinstall":
            from servonaut.screens.ovh_reinstall import OVHReinstallScreen
            self.app.push_screen(OVHReinstallScreen(self._instance))
        elif button_id == "btn_ovh_resize":
            from servonaut.screens.ovh_resize import OVHResizeScreen
            self.app.push_screen(OVHResizeScreen(self._instance))
        elif button_id == "btn_ovh_monitoring":
            from servonaut.screens.ovh_monitoring import OVHMonitoringScreen
            self.app.push_screen(OVHMonitoringScreen(self._instance))
        elif button_id == "btn_ovh_snapshots":
            from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
            self.app.push_screen(OVHSnapshotsScreen(self._instance))
        elif button_id == "btn_ovh_firewall":
            from servonaut.screens.ovh_firewall import OVHFirewallScreen
            self.app.push_screen(OVHFirewallScreen(self._instance))
        elif button_id == "btn_manage_ssh_ref":
            self.action_manage_ssh_ref()
        elif button_id == "btn_verify_ssh":
            self.action_verify_ssh()
        elif button_id == "btn_back":
            self.action_back()

    def _validate_instance_connection(self) -> bool:
        """Validate instance has required data for connection.

        Returns:
            True if instance can be connected to, False otherwise.
        """
        import logging
        logger = logging.getLogger(__name__)

        # Custom servers, OVH and Hetzner instances don't require running state for connection
        if (not self._instance.get('is_custom')
                and not self._instance.get('is_ovh')
                and not self._instance.get('is_hetzner')):
            state = self._instance.get('state', 'unknown')
            if state != 'running':
                self.app.notify(
                    f"Instance is {state}. Only running instances can be connected to.",
                    severity="warning"
                )
                logger.warning("Attempted connection to non-running instance: %s", state)
                return False

        # Check if we have a target IP
        public_ip = self._instance.get('public_ip')
        private_ip = self._instance.get('private_ip')
        if not public_ip and not private_ip:
            self.app.notify(
                "Instance has no IP address available.",
                severity="error"
            )
            logger.error("Instance missing both public and private IP")
            return False

        return True

    def action_action_1(self) -> None:
        """Browse Files — open the remote file tree inline in the detail pane."""
        if not self._validate_instance_connection():
            return
        self._open_inline_browse()

    def action_action_2(self) -> None:
        """Open Command Overlay as modal."""
        if not self._validate_instance_connection():
            return
        from servonaut.screens.command_overlay import CommandOverlay
        self.app.push_screen(CommandOverlay(self._instance))

    def action_action_3(self) -> None:
        """SSH Connect — walk SshRefResolver chain then launch in external terminal.

        Dispatches to a worker so a double-click or rapid key press cannot
        double-launch.  The 'ssh_connect' group is distinct from 'ssh_verify'
        so the two flows don't cancel each other.
        """
        if not self._validate_instance_connection():
            return

        self.run_worker(
            self._ssh_connect_flow(),
            group="ssh_connect",
            exclusive=True,
        )

    async def _ssh_connect_flow(self) -> None:
        """Async SSH connect: resolve credentials via three-tier chain, launch.

        Resolution order (mirrors the CLI ``servonaut ssh <id>`` surface):
          1. Personal Bitwarden ref  (requires Servonaut account)
          2. Team Bitwarden ref      (requires Servonaut Teams plan)
          3. Local ~/.ssh discovery  (existing TUI behaviour)
          4. None → notify user, stop

        BW tiers (source == 'personal' | 'team')
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        ``launch_ssh_in_terminal`` spawns a detached external window — the
        ephemeral key context manager would exit before SSH finishes reading
        the key.  We therefore use ``persistent_bw_ssh_key()`` (Option A):
        the file is written to ``~/.servonaut/tmp/bw-<random>.key`` with 0600
        perms and an ``atexit`` cleanup so normal TUI exit removes it.
        ``cleanup_stale_bw_keys()`` is called by ``ServonautApp`` on startup to
        catch crash-left files older than 24 h.
        """
        from rich.markup import escape as rich_escape

        from servonaut.services.ssh_ref_resolver import SshRefResolver
        from servonaut.services.bw_resolver import (
            BwResolver,
            BwCliMissingError,
            BwSessionMissingError,
            BwItemNotFoundError,
            BwItemShapeError,
        )
        from servonaut.utils.ephemeral_key import persistent_bw_ssh_key

        instance = self._instance
        name = instance.get("name") or instance.get("id", "instance")

        # ------------------------------------------------------------------
        # Build teams_supplier (mirrors cli/ssh.py _handle_ssh_async)
        # ------------------------------------------------------------------
        teams_supplier = None
        team_service = getattr(self.app, "team_service", None)
        if team_service is not None:
            _teams: list = []
            try:
                _teams = await team_service.list_teams()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not load teams list for SSH connect: %s", exc)

            def _teams_supplier_fn() -> list:
                return _teams

            teams_supplier = _teams_supplier_fn

        # ------------------------------------------------------------------
        # Build resolver — use Null stubs when services are unavailable
        # ------------------------------------------------------------------
        bw_ssh_config_service = getattr(self.app, "bw_ssh_config_service", None)
        if bw_ssh_config_service is None:
            bw_ssh_config_service = _NullBwService()
        if team_service is None:
            team_service = _NullTeamService()

        resolver = SshRefResolver(
            bw_ssh_config_service=bw_ssh_config_service,
            team_service=team_service,
            ssh_service=self.app.ssh_service,
            teams_supplier=teams_supplier,
        )

        resolved = await resolver.resolve(instance)

        if resolved is None:
            self.app.notify(
                "No SSH key configured for this instance.",
                severity="warning",
                markup=False,
            )
            return

        # ------------------------------------------------------------------
        # Build the SSH command depending on the resolution source
        # ------------------------------------------------------------------
        source = resolved.source

        if source in ("personal", "team"):
            # BW path — resolve key body via bw CLI, write persistent tmpfile
            if not resolved.item_id:
                self.app.notify(
                    "Bitwarden ref is missing item_id — re-register via Settings.",
                    severity="error",
                    markup=False,
                )
                return

            bw_session = getattr(self.app, "bw_session_service", None)
            bw_resolver = BwResolver(
                session_getter=bw_session.session if bw_session is not None else None
            )
            try:
                import asyncio
                key_body = await asyncio.to_thread(
                    bw_resolver.resolve_ssh_key, resolved.item_id
                )
            except BwCliMissingError:
                self.app.notify(
                    "Bitwarden CLI (bw) not found. Install it and ensure it is on your PATH.",
                    severity="error",
                    markup=False,
                )
                return
            except BwSessionMissingError:
                self.app.notify(
                    "Bitwarden vault is locked. Run 'bw unlock' and export BW_SESSION, then retry.",
                    severity="error",
                    markup=False,
                )
                return
            except BwItemNotFoundError:
                self.app.notify(
                    "Bitwarden item not found. Verify the item UUID or re-register via Settings.",
                    severity="error",
                    markup=False,
                )
                return
            except BwItemShapeError:
                self.app.notify(
                    "Bitwarden item shape unexpected — ensure it is a native SSH item (BW 2023.10+).",
                    severity="error",
                    markup=False,
                )
                return
            except Exception as exc:  # noqa: BLE001
                logger.error("BW key resolution failed: %s", exc, exc_info=True)
                self.app.notify(
                    "Bitwarden key resolution failed. See logs for details.",
                    severity="error",
                    markup=False,
                )
                return

            # Write a long-lived tmpfile (see docstring for rationale).
            key_path = persistent_bw_ssh_key(key_body)
            logger.debug(
                "Persistent BW SSH key written to %s for instance %s",
                key_path,
                instance.get("id"),
            )

            host = (
                instance.get("public_ip")
                or instance.get("private_ip")
                or instance.get("host")
                or instance.get("id", "")
            )
            username = (
                instance.get("username")
                or self.app.config_manager.get().default_username
                or "ubuntu"
            )
            port = instance.get("port")

            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=host,
                username=username,
                key_path=key_path,
                port=port,
            )

            tier_label = "personal" if source == "personal" else "team"
            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                self.app.notify(
                    f"Connected via BW ({tier_label}): {rich_escape(name)}",
                    markup=True,
                )
                logger.info(
                    "SSH connect (BW %s): host=%s, user=%s, item=%s",
                    tier_label, host, username, resolved.item_id,
                )
            else:
                self.app.notify(
                    "Could not detect terminal emulator. Set 'terminal_emulator' in settings.",
                    severity="error",
                    markup=False,
                )

        else:
            # source == "local" — existing per-provider logic
            try:
                if instance.get("is_ovh"):
                    host = instance.get("public_ip") or instance.get("private_ip")
                    provider_type = instance.get("provider_type", "")
                    instance_id = instance.get("id", "")
                    config = self.app.config_manager.get()

                    username = (
                        config.ovh.default_username
                        or self._ovh_default_username(provider_type)
                    )
                    key_path = (
                        config.instance_keys.get(instance_id)
                        or config.ovh.default_ssh_key
                        or config.default_key
                        or resolved.local_key_path
                        or None
                    )
                    proxy_args: list = []
                    extra_options = self.app.connection_service.get_extra_options(instance, None)
                    ssh_cmd = self.app.ssh_service.build_ssh_command(
                        host=host, username=username, key_path=key_path,
                        proxy_args=proxy_args, port=None, extra_options=extra_options,
                    )
                    logger.info(
                        "SSH connect (OVH %s): host=%s, user=%s, key=%s",
                        provider_type, host, username, key_path,
                    )

                elif instance.get("is_custom"):
                    host = instance.get("public_ip") or instance.get("private_ip")
                    username = instance.get("username") or "root"
                    port = instance.get("port", 22)
                    key_path = resolved.local_key_path or instance.get("ssh_key") or None
                    proxy_args = []
                    extra_options = self.app.connection_service.get_extra_options(instance, None)
                    ssh_cmd = self.app.ssh_service.build_ssh_command(
                        host=host, username=username, key_path=key_path,
                        proxy_args=proxy_args, port=port, extra_options=extra_options,
                    )
                    logger.info(
                        "SSH connect (custom): host=%s, user=%s, port=%s", host, username, port,
                    )

                elif instance.get("is_hetzner"):
                    host = instance.get("public_ip") or instance.get("private_ip")
                    username = instance.get("username") or "root"
                    config = self.app.config_manager.get()
                    key_path = (
                        resolved.local_key_path
                        or instance.get("ssh_key")
                        or config.default_key
                        or None
                    )
                    proxy_args = []
                    extra_options = self.app.connection_service.get_extra_options(instance, None)
                    ssh_cmd = self.app.ssh_service.build_ssh_command(
                        host=host, username=username, key_path=key_path,
                        proxy_args=proxy_args, port=None, extra_options=extra_options,
                    )
                    logger.info(
                        "SSH connect (hetzner): host=%s, user=%s, key=%s",
                        host, username, key_path,
                    )

                else:
                    # AWS / generic — resolve bastion profile
                    profile = self.app.connection_service.resolve_profile(instance)
                    host = self.app.connection_service.get_target_host(instance, profile)

                    if not host:
                        self.app.notify(
                            "No IP address available for this instance.", severity="error",
                        )
                        return

                    proxy_args = []
                    if profile:
                        proxy_args = self.app.connection_service.get_proxy_args(profile)

                    username = (
                        (profile.username if profile else None)
                        or self.app.config_manager.get().default_username
                    )
                    key_path = resolved.local_key_path

                    extra_options = self.app.connection_service.get_extra_options(instance, profile)
                    ssh_cmd = self.app.ssh_service.build_ssh_command(
                        host=host, username=username, key_path=key_path,
                        proxy_args=proxy_args, extra_options=extra_options,
                    )
                    via = f" via {profile.bastion_host}" if profile and profile.bastion_host else ""
                    logger.info(
                        "SSH connect: host=%s, user=%s, key=%s, proxy=%s, profile=%s",
                        host, username, key_path,
                        "yes" if proxy_args else "no",
                        profile.name if profile else "direct",
                    )

                if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                    if (instance.get("is_ovh")
                            or instance.get("is_custom")
                            or instance.get("is_hetzner")):
                        self.app.notify(
                            f"Connected via local ~/.ssh: {rich_escape(name)}",
                            markup=True,
                        )
                    else:
                        via_str = via if not instance.get("is_ovh") and not instance.get("is_custom") and not instance.get("is_hetzner") else ""  # noqa: E501
                        self.app.notify(
                            f"Connected via local ~/.ssh: {rich_escape(name)}{via_str}",
                            markup=True,
                        )
                else:
                    self.app.notify(
                        "Could not detect terminal emulator. Set 'terminal_emulator' in settings.",
                        severity="error",
                        markup=False,
                    )

            except Exception as exc:
                logger.error("Error launching SSH terminal: %s", exc, exc_info=True)
                self.app.notify(
                    f"Error launching SSH: {rich_escape(str(exc))}",
                    markup=True,
                    severity="error",
                )

    def action_action_4(self) -> None:
        """SCP Transfer."""
        if not self._validate_instance_connection():
            return
        from servonaut.screens.scp_transfer import SCPTransferScreen
        self.app.push_screen(SCPTransferScreen(self._instance))

    def action_action_5(self) -> None:
        """View Scan Results."""
        from servonaut.screens.scan_results import ScanResultsScreen
        self.app.push_screen(ScanResultsScreen(self._instance))

    def action_action_6(self) -> None:
        """View Logs — open real-time log viewer with tail -f."""
        if not self._validate_instance_connection():
            return
        from servonaut.screens.log_viewer import LogViewerScreen
        self.app.push_screen(LogViewerScreen(self._instance))

    def action_action_7(self) -> None:
        """AI Analysis — open AI log analysis screen."""
        from servonaut.screens.ai_analysis import AIAnalysisScreen
        self.app.push_screen(AIAnalysisScreen(text="", instance=self._instance))

    def action_action_8(self) -> None:
        """Ban IP — open IP ban manager pre-filled with this instance's public IP."""
        from servonaut.screens.ip_ban import IPBanScreen
        public_ip = self._instance.get('public_ip') or ""
        self.app.push_screen(IPBanScreen(prefill_ip=public_ip))

    @staticmethod
    def _ovh_default_username(provider_type: str) -> str:
        """Return the default SSH username for an OVH provider type.

        Args:
            provider_type: One of "dedicated", "vps", "cloud".

        Returns:
            Default SSH username string.
        """
        from servonaut.services.ovh_service import OVHService
        return OVHService.default_username(provider_type)

    def action_open_memory(self) -> None:
        """Open MemoryScreen for this instance."""
        from servonaut.screens.memory import MemoryScreen
        self.app.push_screen(MemoryScreen(self._instance))

    def action_scan_db_creds(self) -> None:
        """Open the DB-credential scan → review → store surface (B2)."""
        from servonaut.screens.db_credential_scan import DbCredentialScanScreen
        self.app.push_screen(DbCredentialScanScreen(self._instance))

    def action_manage_ssh_ref(self) -> None:
        """Push SshRefEditorModal directly to add/edit/delete the BW SSH ref."""
        self.run_worker(
            self._manage_ssh_ref_flow(),
            group="ssh_verify",
            exclusive=True,
        )

    async def _manage_ssh_ref_flow(self) -> None:
        """Fetch existing ref then open SshRefEditorModal in add or edit mode."""
        if not getattr(self.app, "bw_ssh_config_service", None):
            self.app.notify(
                "BW SSH service not available (sign in required)",
                severity="warning",
                markup=False,
            )
            return

        provider = self._instance.get("provider", "aws").lower()
        instance_id = self._instance.get("id")

        try:
            existing = await self.app.bw_ssh_config_service.get_personal_instance_ref(
                provider, instance_id
            )
        except Exception as exc:
            logger.debug("Failed to load existing SSH ref: %s", exc)
            existing = None

        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        saved = await self.app.push_screen_wait(
            SshRefEditorModal(self._instance, existing_ref=existing)
        )
        if saved:
            # Refresh SSH verify column in instance list if possible.
            if hasattr(self.app, "_refresh_ssh_verify_status"):
                self.app.run_worker(
                    self.app._refresh_ssh_verify_status(),
                    group="memory_io",
                )

    def action_verify_ssh(self) -> None:
        """Launch the Verify SSH flow: show confirm modal, then run worker."""
        self.run_worker(
            self._verify_ssh_flow(),
            group="ssh_verify",
            exclusive=True,
        )

    async def _verify_ssh_flow(self) -> None:
        """Async flow: modal → BW resolve → probe → report → refresh."""
        bw_service = getattr(self.app, "bw_ssh_config_service", None)
        if bw_service is None:
            self.app.notify(
                "SSH verify requires a Servonaut account. Sign in via Settings → Login.",
                severity="warning",
                markup=False,
            )
            return

        provider = self._instance.get("provider", "aws").lower()
        instance_id = self._instance.get("id", "")
        host = (
            self._instance.get("public_ip")
            or self._instance.get("private_ip")
            or instance_id
        )

        # Check if a BW ref is stored for this instance.
        try:
            ref_row = await bw_service.get_personal_instance_ref(provider, instance_id)
        except Exception as exc:
            logger.debug("SSH verify ref lookup failed: %s", exc)
            ref_row = None

        has_ref = ref_row is not None

        # Push the confirm modal and await user's choice.
        confirmed = await self.app.push_screen_wait(
            ConfirmSshVerifyModal(host=host, has_ref=has_ref)
        )
        if not confirmed:
            return

        # No ref stored → open SshRefEditorModal so the user can add one.
        if not has_ref:
            from servonaut.screens.ssh_ref_editor import SshRefEditorModal
            await self.app.push_screen_wait(
                SshRefEditorModal(self._instance, existing_ref=None)
            )
            return

        # Resolve BW item and run the SSH probe.
        ssh_credential_ref = ref_row.get("ssh_credential_ref", {})
        item_id: Optional[str] = ssh_credential_ref.get("item_id") if isinstance(ssh_credential_ref, dict) else None
        if item_id is None:
            # Partial row: the server confirmed a ref exists but this device
            # holds no local copy of the item id (see get_personal_instance_ref
            # fallbacks). Probe still runs with local keys; say so.
            self.app.notify(
                "A stored SSH ref exists but its vault item isn't available on "
                "this device — probing with local keys instead. Re-save the ref "
                "here to enable Bitwarden-backed verify.",
                severity="warning",
                markup=False,
            )

        status = await self._run_ssh_probe(item_id, host)

        # Report the result to the server.
        try:
            import servonaut as _sn_pkg
            client_version = f"servonaut-cli/{getattr(_sn_pkg, '__version__', 'unknown')}"
            await bw_service.report_personal_instance_verify(
                provider=provider,
                instance_id=instance_id,
                status=status,
                checked_by_client=client_version,
            )
        except Exception as exc:
            from servonaut.services.api_client import APIError
            if isinstance(exc, APIError) and exc.status == 402:
                self.app.notify(
                    "SSH verify reporting requires a paid Servonaut plan.",
                    severity="warning",
                    markup=False,
                )
            else:
                logger.warning("SSH verify report POST failed: %s", exc)
            # Don't abort — update local state anyway.

        # Update the instance dict in memory and re-render the table.
        from datetime import datetime, timezone
        self._instance["ssh_verify_status"] = status
        if status == "verified":
            self._instance["ssh_verified_at"] = (
                datetime.now(timezone.utc).isoformat()
            )
        else:
            self._instance.pop("ssh_verified_at", None)

        # Propagate into app.instances so the table refresh picks it up.
        for inst in self.app.instances:
            if inst.get("id") == instance_id:
                inst["ssh_verify_status"] = status
                if status == "verified":
                    inst["ssh_verified_at"] = self._instance.get("ssh_verified_at")
                else:
                    inst.pop("ssh_verified_at", None)
                break

        # Surface the result.
        _status_labels = {
            "verified": "SSH verified successfully.",
            "not_found": "SSH probe: host not found or unreachable.",
            "auth_failed": "SSH probe: authentication failed.",
        }
        label = _status_labels.get(status, f"SSH probe status: {status}")
        self.app.notify(label, markup=False)

        # Refresh the instance list table if it's behind this screen.
        try:
            from servonaut.screens.instance_list import InstanceListScreen
            for screen in self.app.screen_stack:
                if isinstance(screen, InstanceListScreen):
                    screen._update_table()
                    break
        except Exception:
            pass

    async def _run_ssh_probe(self, item_id: Optional[str], host: str) -> str:
        """Resolve BW item and run BatchMode SSH probe. Returns status string."""
        import asyncio

        # Resolve the private key from Bitwarden (synchronous CLI call — run in thread).
        private_key_body: Optional[str] = None
        if item_id:
            try:
                from servonaut.services.bw_resolver import (
                    BwResolver,
                    BwResolverError,
                )
                bw_session = getattr(self.app, "bw_session_service", None)
                resolver = BwResolver(
                    session_getter=bw_session.session if bw_session is not None else None
                )
                private_key_body = await asyncio.to_thread(
                    resolver.resolve_ssh_key, item_id
                )
            except Exception as exc:
                logger.debug("BW item resolution failed for %s: %s", item_id, exc)
                return "not_found"

        # Write the key to a temp file so ssh can use it.
        import tempfile, os, stat
        if private_key_body:
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=".pem",
                    delete=False,
                    prefix="servonaut_sshverify_",
                ) as tf:
                    tf.write(private_key_body)
                    tmp_key_path: Optional[str] = tf.name
                os.chmod(tmp_key_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as exc:
                logger.debug("Temp key write failed: %s", exc)
                return "not_found"
        else:
            tmp_key_path = None

        try:
            cmd = [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no",
            ]
            if tmp_key_path:
                cmd += ["-i", tmp_key_path, "-o", "IdentitiesOnly=yes"]
            # Use the configured username or default.
            username = (
                self._instance.get("username")
                or self.app.config_manager.get().default_username
                or "root"
            )
            cmd += [f"{username}@{host}", "true"]

            proc = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                timeout=15,
            )
            rc = proc.returncode
            if rc == 0:
                return "verified"
            # Exit code 255: SSH layer failure (host unreachable, key mismatch)
            # Exit code 1–254: auth issues or remote command failure
            return "auth_failed" if rc != 255 else "not_found"
        except subprocess.TimeoutExpired:
            return "not_found"
        except FileNotFoundError:
            # ssh binary not on PATH
            self.app.notify(
                "ssh binary not found on PATH — cannot run probe.",
                severity="error",
                markup=False,
            )
            return "not_found"
        except Exception as exc:
            logger.debug("SSH probe subprocess error: %s", exc)
            return "not_found"
        finally:
            if tmp_key_path:
                try:
                    os.unlink(tmp_key_path)
                except OSError:
                    pass

    def action_back(self) -> None:
        """Close an open inline view, or navigate back to the instance list.

        When a file tree / log view is open inline, Esc (and "9") first closes
        it and returns focus to the rail; a second press leaves the screen.
        """
        if self._inline_view is not None:
            self._clear_inline()
            self._safe_focus("#btn_browse")
            return
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Null-object stubs used by _ssh_connect_flow when API services are absent
# ---------------------------------------------------------------------------

class _NullBwService:
    """Drop-in for BwSshConfigService when the user is not logged in.

    Every method the resolver calls returns ``None`` immediately so the
    personal tier silently passes through to the local fallback.
    """

    async def get_personal_instance_ref(
        self, provider: str, instance_id: str
    ) -> None:
        return None


class _NullTeamService:
    """Drop-in for TeamService when the user is not logged in."""

    async def get_team_server_ssh_ref(
        self, slug: str, server_id: str
    ) -> None:
        return None

    async def list_teams(self) -> list:
        return []

"""Server actions screen for Servonaut v2.0."""

from __future__ import annotations

import logging
import subprocess
from typing import TYPE_CHECKING, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Static, Button, Header, Footer

from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.screens.file_browser import FileBrowserScreen
    from servonaut.screens.command_overlay import CommandOverlay

logger = logging.getLogger(__name__)


class ConfirmSshVerifyModal(ModalScreen[bool]):
    """Brief blocking confirmation for the SSH probe action.

    Returns True on Confirm, False on Cancel (including Escape).
    Per CLAUDE.md: ModalScreen for brief blocking prompts.
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

    def on_mount(self) -> None:
        """Focus the first action button on mount."""
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
                Button("Reinstall OS", id="btn_ovh_reinstall", variant="error"),
                Static("[dim]  Reinstall with a new OS image[/dim]", classes="help_text"),
                Button("Resize / Upgrade", id="btn_ovh_resize"),
                Static("[dim]  Change VPS model or Cloud flavor[/dim]", classes="help_text"),
                Button("Monitoring", id="btn_ovh_monitoring"),
                Static("[dim]  View CPU, RAM, and network metrics[/dim]", classes="help_text"),
                Button("Snapshots", id="btn_ovh_snapshots"),
                Static("[dim]  Create, restore, or delete snapshots[/dim]", classes="help_text"),
                Button("Firewall", id="btn_ovh_firewall"),
                Static("[dim]  Manage VPS firewall rules[/dim]", classes="help_text"),
                before=self.query_one("#btn_back"),
            )

    def on_key(self, event) -> None:
        """Handle arrow key navigation between buttons.

        Args:
            event: Key event.
        """
        if event.key in ("up", "down"):
            buttons = list(self.query("Button"))
            if not buttons:
                return
            # Find currently focused button
            focused = self.focused
            if focused not in buttons:
                buttons[0].focus()
                return
            idx = buttons.index(focused)
            if event.key == "down":
                next_idx = (idx + 1) % len(buttons)
            else:
                next_idx = (idx - 1) % len(buttons)
            buttons[next_idx].focus()

    def compose(self) -> ComposeResult:
        """Compose the server actions UI."""
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(self._build_server_info(), id="server_info"),
                Vertical(
                    Button("1. Browse Files", id="btn_browse", variant="primary"),
                    Static("[dim]  Browse remote filesystem via SSH (tree view)[/dim]", classes="help_text"),
                    Button("2. Run Command", id="btn_command"),
                    Static("[dim]  Execute commands on this server in an overlay panel[/dim]", classes="help_text"),
                    Button("3. SSH Connect", id="btn_ssh"),
                    Static("[dim]  Open a new terminal window with SSH session[/dim]", classes="help_text"),
                    # Promoted above SCP — memory is the highest-leverage
                    # feature on this screen for AI / MCP workflows, so it
                    # earns a prominent slot in the action stack.
                    Button("M. Memory", id="btn_memory"),
                    Static(
                        "[dim]  🧠 Build an AI-queryable fact cache (OS, "
                        "runtimes, services, web stack, logs) so the chat "
                        "panel and MCP agents answer instantly — no SSH "
                        "round-trip needed.[/dim]",
                        classes="help_text",
                    ),
                    Button("4. SCP Transfer", id="btn_scp"),
                    Static("[dim]  Upload or download files via SCP[/dim]", classes="help_text"),
                    Button("5. View Scan Results", id="btn_scan"),
                    Static("[dim]  View keyword scan data collected from this server[/dim]", classes="help_text"),
                    Button("6. View Logs", id="btn_logs"),
                    Static("[dim]  Stream live log files via SSH tail -f[/dim]", classes="help_text"),
                    Button("7. AI Analysis", id="btn_ai_analysis"),
                    Static("[dim]  Analyze log text with AI (OpenAI, Anthropic, or Ollama)[/dim]", classes="help_text"),
                    Button("8. Ban IP", id="btn_ban_ip"),
                    Static("[dim]  Ban this server's public IP via WAF, Security Group, or NACL[/dim]", classes="help_text"),
                    Button("V. Verify SSH", id="btn_verify_ssh"),
                    Static("[dim]  Run a local BW SSH probe and report the result[/dim]", classes="help_text"),
                    Button("9. Back", id="btn_back", variant="error"),
                    id="action_buttons"
                ),
                id="actions_container"
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
        """Navigate to File Browser screen."""
        if not self._validate_instance_connection():
            return
        from servonaut.screens.file_browser import FileBrowserScreen
        self.app.push_screen(FileBrowserScreen(self._instance))

    def action_action_2(self) -> None:
        """Open Command Overlay as modal."""
        if not self._validate_instance_connection():
            return
        from servonaut.screens.command_overlay import CommandOverlay
        self.app.push_screen(CommandOverlay(self._instance))

    def action_action_3(self) -> None:
        """SSH Connect — launch SSH in external terminal."""
        import logging
        logger = logging.getLogger(__name__)

        if not self._validate_instance_connection():
            return

        try:
            if self._instance.get('is_ovh'):
                host = self._instance.get('public_ip') or self._instance.get('private_ip')
                provider_type = self._instance.get('provider_type', '')
                instance_id = self._instance.get('id', '')
                config = self.app.config_manager.get()

                # Username: OVH config override > auto by provider type
                if config.ovh.default_username:
                    username = config.ovh.default_username
                else:
                    username = self._ovh_default_username(provider_type)

                # SSH key: instance_keys mapping > OVH default > global default > auto-discover
                key_path = (
                    config.instance_keys.get(instance_id)
                    or config.ovh.default_ssh_key
                    or config.default_key
                    or self.app.ssh_service.discover_key(instance_id)
                    or None
                )
                proxy_args = []
                extra_options = self.app.connection_service.get_extra_options(self._instance, None)

                ssh_cmd = self.app.ssh_service.build_ssh_command(
                    host=host,
                    username=username,
                    key_path=key_path,
                    proxy_args=proxy_args,
                    port=None,
                    extra_options=extra_options,
                )
                name = self._instance.get('name', host)
                logger.info(
                    "SSH connect (OVH %s): host=%s, user=%s, key=%s",
                    provider_type, host, username, key_path
                )
            elif self._instance.get('is_custom'):
                host = self._instance.get('public_ip') or self._instance.get('private_ip')
                username = self._instance.get('username') or 'root'
                port = self._instance.get('port', 22)
                key_path = self._instance.get('ssh_key') or self._instance.get('key_name') or None
                proxy_args = []
                extra_options = self.app.connection_service.get_extra_options(self._instance, None)

                ssh_cmd = self.app.ssh_service.build_ssh_command(
                    host=host,
                    username=username,
                    key_path=key_path,
                    proxy_args=proxy_args,
                    port=port,
                    extra_options=extra_options,
                )
                name = self._instance.get('name', host)
                logger.info("SSH connect (custom): host=%s, user=%s, port=%s", host, username, port)
            elif self._instance.get('is_hetzner'):
                host = self._instance.get('public_ip') or self._instance.get('private_ip')
                username = self._instance.get('username') or 'root'
                config = self.app.config_manager.get()
                key_path = (
                    self._instance.get('ssh_key')
                    or config.default_key
                    or None
                )
                proxy_args = []
                extra_options = self.app.connection_service.get_extra_options(self._instance, None)

                ssh_cmd = self.app.ssh_service.build_ssh_command(
                    host=host,
                    username=username,
                    key_path=key_path,
                    proxy_args=proxy_args,
                    port=None,
                    extra_options=extra_options,
                )
                name = self._instance.get('name', host)
                logger.info(
                    "SSH connect (hetzner): host=%s, user=%s, key=%s",
                    host, username, key_path,
                )
            else:
                # Resolve connection profile (bastion, proxy, etc.)
                profile = self.app.connection_service.resolve_profile(self._instance)
                host = self.app.connection_service.get_target_host(self._instance, profile)

                if not host:
                    self.app.notify("No IP address available for this instance.", severity="error")
                    return

                proxy_args = []
                if profile:
                    proxy_args = self.app.connection_service.get_proxy_args(profile)

                username = (
                    (profile.username if profile else None)
                    or self.app.config_manager.get().default_username
                )
                key_path = self.app.ssh_service.get_key_path(self._instance['id'])

                if not key_path and self._instance.get('key_name'):
                    key_path = self.app.ssh_service.discover_key(self._instance['key_name'])

                extra_options = self.app.connection_service.get_extra_options(self._instance, profile)

                ssh_cmd = self.app.ssh_service.build_ssh_command(
                    host=host,
                    username=username,
                    key_path=key_path,
                    proxy_args=proxy_args,
                    extra_options=extra_options,
                )
                name = self._instance.get('name') or self._instance.get('id', 'instance')
                via = f" via {profile.bastion_host}" if profile and profile.bastion_host else ""

                logger.info(
                    "SSH connect: host=%s, user=%s, key=%s, proxy=%s, profile=%s",
                    host, username, key_path,
                    'yes' if proxy_args else 'no',
                    profile.name if profile else 'direct',
                )

            # Launch in terminal
            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                if (self._instance.get('is_ovh')
                        or self._instance.get('is_custom')
                        or self._instance.get('is_hetzner')):
                    self.app.notify(f"SSH session launched for {name}")
                else:
                    self.app.notify(f"SSH session launched for {name}{via}")
            else:
                self.app.notify(
                    "Could not detect terminal emulator. Set 'terminal_emulator' in settings.",
                    severity="error"
                )
        except Exception as e:
            logger.error("Error launching SSH terminal: %s", e, exc_info=True)
            self.app.notify(f"Error launching SSH: {e}", severity="error")

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

        # No ref stored → stub "Add SSH ref" path (UI not yet implemented).
        if not has_ref:
            self.app.notify(
                "Add SSH ref UI not yet implemented.",
                severity="information",
                markup=False,
            )
            return

        # Resolve BW item and run the SSH probe.
        ssh_credential_ref = ref_row.get("ssh_credential_ref", {})
        item_id: Optional[str] = ssh_credential_ref.get("item_id") if isinstance(ssh_credential_ref, dict) else None

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
                resolver = BwResolver()
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
        """Navigate back to instance list."""
        self.app.pop_screen()

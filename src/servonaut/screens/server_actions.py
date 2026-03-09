"""Server actions screen for Servonaut v2.0."""

from __future__ import annotations
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Static, Button, Header, Footer

if TYPE_CHECKING:
    from servonaut.screens.file_browser import FileBrowserScreen
    from servonaut.screens.command_overlay import CommandOverlay


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
        yield Container(
            Static(self._build_server_info(), id="server_info"),
            Vertical(
                Button("1. Browse Files", id="btn_browse", variant="primary"),
                Static("[dim]  Browse remote filesystem via SSH (tree view)[/dim]", classes="help_text"),
                Button("2. Run Command", id="btn_command"),
                Static("[dim]  Execute commands on this server in an overlay panel[/dim]", classes="help_text"),
                Button("3. SSH Connect", id="btn_ssh"),
                Static("[dim]  Open a new terminal window with SSH session[/dim]", classes="help_text"),
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
        elif button_id == "btn_back":
            self.action_back()

    def _validate_instance_connection(self) -> bool:
        """Validate instance has required data for connection.

        Returns:
            True if instance can be connected to, False otherwise.
        """
        import logging
        logger = logging.getLogger(__name__)

        # Custom servers don't have an AWS state — skip state check
        if not self._instance.get('is_custom'):
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
            if self._instance.get('is_custom'):
                host = self._instance.get('public_ip') or self._instance.get('private_ip')
                username = self._instance.get('username') or 'root'
                port = self._instance.get('port', 22)
                key_path = self._instance.get('ssh_key') or self._instance.get('key_name') or None
                proxy_args = []

                ssh_cmd = self.app.ssh_service.build_ssh_command(
                    host=host,
                    username=username,
                    key_path=key_path,
                    proxy_args=proxy_args,
                    port=port,
                )
                name = self._instance.get('name', host)
                logger.info("SSH connect (custom): host=%s, user=%s, port=%s", host, username, port)
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

                ssh_cmd = self.app.ssh_service.build_ssh_command(
                    host=host,
                    username=username,
                    key_path=key_path,
                    proxy_args=proxy_args,
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
                if self._instance.get('is_custom'):
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

    def action_back(self) -> None:
        """Navigate back to instance list."""
        self.app.pop_screen()

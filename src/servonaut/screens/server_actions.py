"""Server actions screen for Servonaut v2.0."""

from __future__ import annotations

import logging
import subprocess
from typing import Any, Dict, Optional

from rich.markup import escape
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Static, Button, Checkbox, Footer, Input, Label, Select

from servonaut.services.ssh_host_keys import (
    OFF_OPTIONS_KEEP_KNOWN_HOSTS,
    HostKeyPolicy,
    HostKeyTarget,
    detect_host_key_problem,
    host_key_alias_options,
    identity_file_args,
    trusted_host_keys,
)
from servonaut.utils.ssh_utils import run_ssh
from servonaut.services.live_stats_service import LiveStatsError
from servonaut.utils.live_stats_panel import format_live_stats
from servonaut.utils.memory_panel import render_memory_panel
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar
from servonaut.screens._demo_resolve import connection_instance, refuse_unresolved
from servonaut.screens._provider_accounts import ServerAccountMixin
from servonaut.utils.instance_resolver import display_name

#: Per-action one-line help shown in the detail pane on focus.
_ACTION_HELP: dict[str, str] = {
    "btn_browse": "Browse the remote filesystem in a tree view (over SSH).",
    "btn_command": "Run a one-off command on this server in an overlay panel.",
    "btn_ssh": "Open a full SSH session in a new terminal window.",
    "btn_memory": "Build / view the AI-queryable fact cache for this server.",
    "btn_findings": "View proactive monitoring findings for this server and trigger a scan.",
    "btn_logs": "Stream live log files via SSH (tail -f).",
    "btn_scan": "View keyword scan results collected from this server.",
    "btn_db_creds": "Scan this server for DB credentials and store them in your secret vault.",
    "btn_ai_analysis": "Analyze log text with AI (OpenAI, Anthropic, or Ollama).",
    "btn_scp": "Upload or download files via SCP.",
    "btn_ban_ip": "Ban this server's public IP via WAF, Security Group, or NACL.",
    "btn_manage_ssh_ref": "Add, edit, or remove the Bitwarden SSH item ref.",
    "btn_use_vault_key": "Bind a verified native-vault SSH key to this server.",
    "btn_verify_ssh": "Run a local SSH probe and report the result.",
    "btn_ovh_reinstall": "Reinstall this OVH server with a new OS image.",
    "btn_ovh_resize": "Change the VPS model or Cloud flavor.",
    "btn_ovh_snapshots": "Create, restore, or delete snapshots.",
    "btn_ovh_firewall": "Manage VPS firewall rules.",
    "btn_back": "Return to the instance list.",
}

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


class VaultBindingModal(ModalScreen[Optional[dict]]):
    """Pick the vault SSH key for this server from what the user can read.

    A shared server belongs to its team, so only that team's vault is offered;
    any other server is bound for the user alone. Nothing secret is shown: keys
    are listed by name and fingerprint, and the result carries identifiers only.
    """

    DEFAULT_CSS = """
    #vault_bind_scope { color: $text-muted; }
    #vault_bind_trusted { margin: 1 0 0 0; }
    #vault_bind_use_trusted { margin: 0 0 1 0; }
    #vault_bind_message { color: $warning; margin: 1 0 0 0; }
    #vault_bind_modal > Horizontal { height: auto; margin-top: 1; }
    #vault_bind_use_trusted.-hidden { display: none; }
    #vault_bind_message { display: none; }
    """
    AUTO_FOCUS = ""
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, service: Any, instance: Dict[str, Any]) -> None:
        super().__init__()
        self._service = service
        self._instance = instance
        self._team = instance.get("team_slug") if instance.get("is_shared") is True else None
        self._trusted_keys: list[str] = []
        # What is on screen, kept raw so a demo-mode toggle can redraw it.
        self._vault_choices: list[dict[str, str]] = []
        self._key_choices: list[dict[str, str]] = []
        self._keys_for: str | None = None
        self._message = ""
        self._trusted_text = ""

    def compose(self) -> ComposeResult:
        login = str(self._instance.get("login_user") or self._instance.get("username") or "")
        rows: list[Any] = [
            Static("[bold]Use vault key[/bold]"),
            Static(escape(self.scrub_for_display(self._scope_text())), id="vault_bind_scope"),
            Label("Vault"),
            Select([], prompt="Loading vaults…", id="vault_bind_vault", disabled=True),
            Label("SSH key"),
            Select([], prompt="Choose a vault first", id="vault_bind_item", disabled=True),
            Label("Login user"),
            Input(value=login, placeholder="Login user", id="vault_bind_login"),
        ]
        if self._team:
            rows.append(Input(placeholder="Verified OpenSSH host keys, comma separated (optional)", id="vault_bind_host_keys"))
        else:
            rows.extend((
                Static("Checking the host keys this machine trusts…", id="vault_bind_trusted"),
                Checkbox("I checked these fingerprints: pin them", value=False, id="vault_bind_use_trusted",
                         disabled=True, classes="-hidden"),
                Input(placeholder="Or paste verified OpenSSH host keys, comma separated", id="vault_bind_host_keys"),
            ))
        rows.extend((
            Static("", id="vault_bind_message"),
            Horizontal(Button("Cancel", id="vault_bind_cancel"), Button("Bind", variant="primary", id="vault_bind_confirm")),
        ))
        yield Container(*rows, id="vault_bind_modal")

    def on_mount(self) -> None:
        self.run_worker(self._load_vaults(), group="vault_bind_choices", exclusive=True)
        if not self._team:
            self.run_worker(self._load_trusted_host_keys(), group="vault_bind_host_keys")

    def _scope_text(self) -> str:
        if self._team:
            return f"Shared server in team {self._team}: everyone in the team uses this key."
        return "Your server: the key is used only by you."

    def action_cancel(self) -> None:
        self.dismiss(None)

    def scrub_for_display(self, value: object) -> str:
        """Demo-safe text: vault, key and host names are hidden in demo mode."""
        text = str(value)
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            return str(redactor.scrub_stream(text))
        return text

    def refresh_after_demo_toggle(self) -> None:
        """Redraw names and messages under the current demo mode, keeping the choices."""
        self._show_options("#vault_bind_vault", self._vault_choices, "vault_id")
        self._show_options("#vault_bind_item", self._key_choices, "item_id")
        self.query_one("#vault_bind_scope", Static).update(escape(self.scrub_for_display(self._scope_text())))
        self._say(self._message)
        if not self._team:
            self._show_trusted(self._trusted_text)

    def _show_options(self, selector: str, choices: list[dict[str, str]], key: str) -> None:
        select = self.query_one(selector, Select)
        kept = select.value
        # Names come from other team members: inert text, never parsed as markup.
        select.set_options([(Text(self.scrub_for_display(choice["label"])), choice[key]) for choice in choices])
        if any(choice[key] == kept for choice in choices):
            select.value = kept

    def _show_trusted(self, text: str) -> None:
        self._trusted_text = text
        self.query_one("#vault_bind_trusted", Static).update(escape(self.scrub_for_display(text)))

    def _say(self, text: str) -> None:
        self._message = text
        message = self.query_one("#vault_bind_message", Static)
        message.update(escape(self.scrub_for_display(text)))
        message.display = bool(text)

    async def _load_vaults(self) -> None:
        select = self.query_one("#vault_bind_vault", Select)
        try:
            choices = await self._service.vault_choices(team=self._team)
        except Exception as exc:
            from servonaut.services.vault.errors import vault_failure_reason

            select.set_options([])
            select.prompt = "Vaults could not be loaded"
            self._say(f"Could not load your vaults ({vault_failure_reason(exc)}).")
            return
        if not choices:
            select.prompt = "No vault available"
            self._say(
                f"Team {self._team} has no vault you can read yet: an owner or admin creates it, "
                "or grants your access, on the Vault screen."
                if self._team else "You have no vault yet: create one on the Vault screen first."
            )
            return
        self._vault_choices = choices
        self._show_options("#vault_bind_vault", choices, "vault_id")
        select.prompt = "Choose a vault"
        select.disabled = False
        personal = [choice for choice in choices if choice.get("kind") == "personal"]
        obvious = choices[0] if self._team and len(choices) == 1 else (personal[0] if not self._team and personal else None)
        if obvious is not None:
            select.value = obvious["vault_id"]
        else:
            select.focus()

    async def _load_keys(self, vault_id: str) -> None:
        self._keys_for = vault_id
        self._key_choices = []
        select = self.query_one("#vault_bind_item", Select)
        select.set_options([])
        select.prompt = "Loading SSH keys…"
        select.disabled = True
        try:
            choices = await self._service.ssh_key_choices(vault_id=vault_id)
        except Exception as exc:
            from servonaut.services.vault.errors import vault_failure_reason

            select.prompt = "SSH keys could not be loaded"
            self._keys_for = None
            # Clear the vault so choosing it again (even the only one) retries.
            self.query_one("#vault_bind_vault", Select).clear()
            self._say(f"Could not load the SSH keys ({vault_failure_reason(exc)}). Choose the vault again to retry.")
            return
        if not choices:
            select.prompt = "No SSH key in this vault"
            self._say("This vault has no SSH key yet: import one with Import SSH on the Vault screen.")
            return
        self._say("")
        self._key_choices = choices
        self._show_options("#vault_bind_item", choices, "item_id")
        select.prompt = "Choose an SSH key"
        select.disabled = False
        if len(choices) == 1:
            select.value = choices[0]["item_id"]
        select.focus()

    async def _load_trusted_host_keys(self) -> None:
        import asyncio

        from servonaut.services.vault import crypto

        host = str(self._instance.get("hostname") or self._instance.get("host") or self._instance.get("public_ip") or "")
        port = self._instance.get("port") if isinstance(self._instance.get("port"), int) else None
        try:
            keys = await asyncio.to_thread(trusted_host_keys, self._instance, host, port) if host else []
        except Exception:
            keys = []
        box = self.query_one("#vault_bind_use_trusted", Checkbox)
        if not keys:
            self._show_trusted("This machine does not trust a host key for this server yet: connect once "
                               "with SSH and check its fingerprint, or paste verified host keys below.")
            box.value = False
            return
        self._trusted_keys = list(keys)
        self._show_trusted(f"Host keys this machine trusts for {host}:\n" + "\n".join(
            f"  {crypto.ssh_public_fingerprint(key)}" for key in keys
        ))
        box.disabled = False
        box.remove_class("-hidden")

    def on_select_changed(self, event: Select.Changed) -> None:
        # A redraw that restores the same vault is not a new choice.
        if event.select.id == "vault_bind_vault" and isinstance(event.value, str) and event.value != self._keys_for:
            self.run_worker(self._load_keys(event.value), group="vault_bind_choices", exclusive=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "vault_bind_confirm":
            self.dismiss(None)
            return
        vault_id = self.query_one("#vault_bind_vault", Select).value
        item_id = self.query_one("#vault_bind_item", Select).value
        offered_vaults = {choice["vault_id"] for choice in self._vault_choices}
        offered_keys = {choice["item_id"] for choice in self._key_choices}
        if (
            not isinstance(vault_id, str) or not isinstance(item_id, str)
            or vault_id not in offered_vaults or vault_id != self._keys_for or item_id not in offered_keys
        ):
            self._say("Choose a vault and an SSH key first.")
            return
        login = self.query_one("#vault_bind_login", Input).value.strip()
        if not self._team and not login:
            self._say("A server of your own needs the login user the key is for.")
            return
        port = self._instance.get("port", 22)
        if not self._team and (isinstance(port, bool) or not isinstance(port, int)):
            self._say("This server's SSH port is not a number: fix it in Custom Servers first.")
            return
        typed = [key.strip() for key in self.query_one("#vault_bind_host_keys", Input).value.split(",") if key.strip()]
        use_trusted = not self._team and self.query_one("#vault_bind_use_trusted", Checkbox).value
        host_keys = [*(self._trusted_keys if use_trusted else []), *typed]
        if not self._team and not host_keys:
            self._say("A server of your own needs its host keys pinned: tick the trusted keys or paste them.")
            return
        self.dismiss({
            "team": self._team or "",
            "vault_id": vault_id,
            "item_id": item_id,
            "login": login or None,
            "host_keys": ",".join(host_keys),
        })


class ServerActionsScreen(ServerAccountMixin, Screen):
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
        Binding("f", "open_findings", "Findings", show=True),
        Binding("l", "toggle_live", "Live", show=True),
        Binding("L", "toggle_live", "Live", show=False),
        Binding("r", "manage_ssh_ref", "SSH Ref", show=True),
        Binding("v", "verify_ssh", "Verify SSH", show=True),
        Binding("9", "back", "Back", show=True),
        Binding("escape", "back", "Back", show=False),
    ]

    # The screen gets -narrow / -wide and -short / -tall classes by terminal
    # size; the stylesheet lays the action rail out two to a row only when
    # there is room for it and the detail pane beside it.
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (130, "-wide")]
    VERTICAL_BREAKPOINTS = [(0, "-short"), (44, "-tall")]

    def __init__(self, instance: dict) -> None:
        """Initialize server actions screen.

        Args:
            instance: Instance dictionary with connection details.
        """
        super().__init__()
        # The row as displayed: demo-mode stand-ins when demo mode is on (the
        # app redacts and restores it in place). Anything that reaches a
        # provider, SSH or a store resolves the real record through
        # ``connection_instance`` first.
        self._instance = instance
        self._reverse_dns = ""
        self._live_on = False
        # Id of the action button the focus-help line currently describes, so a
        # click on that (otherwise passive) line can re-dispatch to the button.
        self._focused_action_id: Optional[str] = None
        # Which read-only view is mounted inline in the detail pane, if any:
        # None | "browse" | "logs".
        self._inline_view: Optional[str] = None
        # Markup source of #server_info, so later additions (reverse DNS)
        # edit the text we wrote instead of reading it back from the widget.
        self._server_info_text: str = ""

    def on_mount(self) -> None:
        """Focus the first action button and populate the detail pane."""
        self.query_one("#btn_browse", Button).focus()
        # Fetch reverse DNS for OVH VPS instances
        if self._instance.get('is_ovh') and self._instance.get('provider_type') == 'vps':
            if self._instance.get('public_ip'):
                self.run_worker(self._fetch_rdns(), exclusive=False)
        # Dynamically add OVH action buttons for OVH instances
        if self._instance.get('is_ovh'):
            action_buttons = self.query_one("#action_buttons")
            action_buttons.mount(
                Static("OVH", classes="section_label"),
                Button("Reinstall OS", id="btn_ovh_reinstall", variant="error"),
                Button("Resize / Upgrade", id="btn_ovh_resize"),
                Button("Snapshots", id="btn_ovh_snapshots"),
                Button("Firewall", id="btn_ovh_firewall"),
                before=self.query_one("#btn_back"),
            )
        # Populate the cached-memory snapshot pane.
        self._render_memory_panel()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the identity and memory panes for the new demo-mode state."""
        self._render_server_info()
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
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Horizontal(id="sa-body"):
                # --- Left: sectioned action rail ---
                yield Vertical(
                    Static("CONNECT", classes="section_label"),
                    Button("1. Browse Files", id="btn_browse", variant="primary"),
                    Button("2. Run Command", id="btn_command"),
                    Button("3. SSH Connect", id="btn_ssh"),
                    Static("INSPECT", classes="section_label"),
                    # Memory promoted to the top of INSPECT — highest-leverage
                    # feature for AI / MCP workflows.
                    Button("M. Memory", id="btn_memory"),
                    Button("F. Findings", id="btn_findings"),
                    Button("6. View Logs", id="btn_logs"),
                    Button("5. Scan Results", id="btn_scan"),
                    Button("D. Scan DB Creds", id="btn_db_creds"),
                    Button("7. AI Analysis", id="btn_ai_analysis"),
                    Static("OPERATE", classes="section_label"),
                    Button("4. SCP Transfer", id="btn_scp"),
                    Button("8. Ban IP", id="btn_ban_ip"),
                    Static("MANAGE", classes="section_label"),
                    Button("Use Vault Key", id="btn_use_vault_key"),
                    Button("R. Manage SSH Ref", id="btn_manage_ssh_ref"),
                    Button("V. Verify SSH", id="btn_verify_ssh"),
                    Button("9. Back", id="btn_back", variant="error"),
                    id="action_buttons",
                )
                # --- Right: identity + live + memory + focus help + inline view ---
                self._server_info_text = self._build_server_info()
                yield Vertical(
                    Static(self._server_info_text, id="server_info"),
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

        Every value comes from a provider or from the user's server list, so
        each is markup-escaped: a name like ``web-[b]1`` shows as typed.

        Returns:
            Rich-formatted string with server details.
        """
        def field(key: str, default: str) -> str:
            return escape(str(self._instance.get(key) or default))

        name = escape(display_name(self._instance) or 'Unnamed')
        public_ip = field('public_ip', 'N/A')
        # With several accounts of this provider, say which one it is in.
        account_line = (
            f"[dim]Account:[/dim] {field('account', '-')}\n"
            if self._instance.get('account_qualified') else ""
        )
        credential_line = self._credential_source_line()

        if self._instance.get('is_ovh'):
            provider_type = escape(str(self._instance.get('provider_type', 'unknown')))
            region = field('region', '-')
            state = self._instance.get('state', 'unknown')
            instance_id = field('id', 'unknown')
            private_ip = field('private_ip', 'N/A')
            server_type = field('type', '-')
            os_label = field('os', '-')
            ram = field('ram_gb', '-')
            reverse_dns = self._display_reverse_dns()
            rdns_line = (
                f"[dim]Reverse DNS:[/dim] {escape(reverse_dns)}\n" if reverse_dns else ""
            )
            return (
                f"[bold $text-accent]OVH Server: {name}[/bold $text-accent]\n\n"
                f"{account_line}"
                f"[dim]ID:[/dim] {instance_id}\n"
                f"[dim]Type:[/dim] {provider_type.upper()} — {server_type}\n"
                f"[dim]Public IP:[/dim] {public_ip}\n"
                f"{rdns_line}"
                f"[dim]Private IP:[/dim] {private_ip}\n"
                f"[dim]Region:[/dim] {region}\n"
                f"[dim]State:[/dim] {self._colorize_state(state)}\n"
                f"[dim]OS:[/dim] {os_label}\n"
                f"[dim]RAM:[/dim] {ram} GB\n\n"
                f"{credential_line}"
                f"[$text-accent]Direct Connection[/$text-accent]\n"
                f"[dim]Target:[/dim] {public_ip}"
            )

        if self._instance.get('is_custom'):
            provider = field('provider', 'custom')
            group = field('group', '-')
            port = escape(str(self._instance.get('port', 22)))
            username = field('username', 'root')
            return (
                f"[bold $text-accent]Server: {name}[/bold $text-accent]\n\n"
                f"[dim]Host:[/dim] {public_ip}\n"
                f"[dim]Port:[/dim] {port}\n"
                f"[dim]Username:[/dim] {username}\n"
                f"[dim]Provider:[/dim] {provider}\n"
                f"[dim]Group:[/dim] {group}\n"
                f"[dim]State:[/dim] [dim]N/A (custom server)[/dim]\n\n"
                f"{credential_line}"
                f"[$text-accent]Direct Connection[/$text-accent]\n"
                f"[dim]Target:[/dim] {public_ip}"
            )

        instance_id = field('id', 'unknown')
        private_ip = field('private_ip', 'N/A')
        region = field('region', 'unknown')
        state = self._instance.get('state', 'unknown')

        # Resolve connection method for AWS instances. Connection rules match
        # the real record (names, tags); the bastion is shown redacted.
        profile = self.app.connection_service.resolve_profile(
            connection_instance(self.app, self._instance)
        )
        if profile and profile.bastion_host:
            bastion = str(profile.bastion_host)
            if self.app.demo_mode and self.app.redaction_service:
                bastion = self.app.redaction_service.redact_host(bastion)
            connection_info = f"[$text-accent]via Bastion:[/$text-accent] {escape(bastion)}"
            target_ip = private_ip
        else:
            connection_info = "[$text-accent]Direct Connection[/$text-accent]"
            target_ip = public_ip

        return (
            f"[bold $text-accent]Server: {name}[/bold $text-accent]\n\n"
            f"{account_line}"
            f"[dim]Instance ID:[/dim] {instance_id}\n"
            f"[dim]Public IP:[/dim] {public_ip}\n"
            f"[dim]Private IP:[/dim] {private_ip}\n"
            f"[dim]Region:[/dim] {region}\n"
            f"[dim]State:[/dim] {self._colorize_state(state)}\n\n"
            f"{credential_line}"
            f"{connection_info}\n"
            f"[dim]Target:[/dim] {target_ip}"
        )

    def _credential_source_line(self) -> str:
        """Describe the configured SSH credential without exposing its reference."""
        binding = self._instance.get("credential_binding")
        source = binding.get("source") if isinstance(binding, dict) else None
        labels = {
            "servonaut_vault": "Servonaut Vault",
            "bitwarden": "Bitwarden",
        }
        label = labels.get(source, "Automatic resolution")
        return f"[dim]SSH credential:[/dim] {label}\n"

    def _colorize_state(self, state: str) -> str:
        """Add color markup to instance state.

        Args:
            state: Instance state string.

        Returns:
            Colorized state string with markup.
        """
        state_colors = {
            'running': '[$text-success]running[/$text-success]',
            'stopped': '[$text-error]stopped[/$text-error]',
            'stopping': '[$text-warning]stopping[/$text-warning]',
            'pending': '[$text-accent]pending[/$text-accent]',
            'terminated': '[dim]terminated[/dim]',
        }
        return state_colors.get(state, escape(str(state)))

    async def _fetch_rdns(self) -> None:
        """Fetch the VPS's reverse DNS and show it in the server info pane.

        OVH is asked about the real VPS and address: in demo mode the row
        holds stand-ins OVH has never heard of. Only what is drawn is
        redacted (see ``_display_reverse_dns``). The VPS is looked up in
        the OVH account it belongs to.
        """
        has_real = getattr(self.app, "has_real_record", None)
        if callable(has_real) and has_real(self._instance) is False:
            return  # a stand-in with no real VPS behind it is never sent to OVH
        vps_service = self._ovh_service("vps")
        if vps_service is None:
            return
        real = connection_instance(self.app, self._instance)
        vps_name = real.get('id', '')
        public_ip = real.get('public_ip', '')
        if not vps_name or not public_ip:
            return
        reverse = await vps_service.get_reverse_dns(vps_name, public_ip)
        if reverse:
            self._reverse_dns = reverse
            self._render_server_info()

    def _display_reverse_dns(self) -> str:
        reverse = getattr(self, "_reverse_dns", "")
        if reverse and self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_hostname(reverse)
        return reverse

    def _render_server_info(self) -> None:
        """Redraw the identity pane from the row (and any reverse DNS known).

        Rebuilt from its source rather than edited in place, so a demo-mode
        toggle and a late reverse-DNS answer both land in one consistent text.
        """
        self._server_info_text = self._build_server_info()
        self.query_one("#server_info", Static).update(self._server_info_text)

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

        if getattr(self.app, "live_stats_service", None) is None:
            self.app.notify(
                "SSH monitoring is unavailable.",
                severity="warning",
                markup=False,
            )
            return
        if not self._validate_instance_connection():
            return

        self._live_on = True
        try:
            self.query_one("#live_stats", Static).update("[$text-accent]Live stats: connecting…[/$text-accent]")
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
        service = self.app.live_stats_service
        if service is None:
            return
        try:
            async for stats in service.watch(self._instance):
                self._set_live_text(format_live_stats(stats))
        except LiveStatsError as exc:
            self._set_live_text(f"[$text-error]{escape(str(exc))}[/$text-error]\n[dim]Press L to retry.[/dim]")
            self._live_on = False

    def _set_live_text(self, markup: str) -> None:
        """Update the live-stats pane defensively (screen may be torn down)."""
        try:
            self.query_one("#live_stats", Static).update(markup)
        except Exception:  # noqa: BLE001
            pass

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
        elif button_id == "btn_findings":
            self.action_open_findings()
        elif (button_id or "").startswith("btn_ovh_") and self._refuse_if_unresolved():
            return
        elif button_id == "btn_ovh_reinstall":
            from servonaut.screens.ovh_reinstall import OVHReinstallScreen
            self.app.push_screen(OVHReinstallScreen(self._instance))
        elif button_id == "btn_ovh_resize":
            from servonaut.screens.ovh_resize import OVHResizeScreen
            self.app.push_screen(OVHResizeScreen(self._instance))
        elif button_id == "btn_ovh_snapshots":
            from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
            self.app.push_screen(OVHSnapshotsScreen(self._instance))
        elif button_id == "btn_ovh_firewall":
            from servonaut.screens.ovh_firewall import OVHFirewallScreen
            self.app.push_screen(OVHFirewallScreen(self._instance))
        elif button_id == "btn_manage_ssh_ref":
            self.action_manage_ssh_ref()
        elif button_id == "btn_use_vault_key":
            self.action_use_vault_key()
        elif button_id == "btn_verify_ssh":
            self.action_verify_ssh()
        elif button_id == "btn_back":
            self.action_back()

    def _refuse_if_unresolved(self) -> bool:
        """True (and the user is told) when demo mode cannot name the real server."""
        try:
            app = self.app
        except Exception:  # noqa: BLE001 — not attached to an app: nothing to resolve
            return False
        return refuse_unresolved(app, self._instance)

    def _validate_instance_connection(self) -> bool:
        """Validate instance has required data for connection.

        Returns:
            True if instance can be connected to, False otherwise.
        """
        if self._refuse_if_unresolved():
            return False
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

        # Demo mode redacts the row we display; connect to the real record.
        instance = connection_instance(self.app, self._instance)
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
            vault_runtime=getattr(self.app, "vault_command_service", None),
        )

        try:
            resolved = await resolver.resolve(instance)
        except Exception as exc:  # Configured native credentials fail closed.
            logger.warning("Native Vault SSH resolution failed: %s", type(exc).__name__)
            from servonaut.services.vault.errors import vault_failure_reason

            self.app.notify(
                f"The configured Vault SSH credential could not be used ({vault_failure_reason(exc)}).",
                severity="error",
                markup=False,
            )
            return

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

        if source in ("ca", "vault"):
            if (
                not resolved.identity_agent
                or not getattr(resolved, "identity_file", None)
                or not resolved.known_hosts_path
            ):
                self.app.notify(
                    "The configured Vault SSH credential is incomplete.",
                    severity="error",
                    markup=False,
                )
                return
            profile = self.app.connection_service.resolve_profile(instance)
            host = self.app.connection_service.get_target_host(instance, profile)
            host = host or instance.get("public_ip") or instance.get("private_ip") or instance.get("host") or instance.get("hostname")
            # Connect exactly where the pinned known_hosts entry points.
            host = getattr(resolved.lease, "target_host", None) or host
            if not host:
                self.app.notify("No IP address available for this instance.", severity="error")
                return
            proxy_args = self.app.connection_service.get_proxy_args(
                profile, identity_agent=resolved.identity_agent
            ) if profile else []
            username = (
                resolved.login_user
                or (profile.username if profile else None)
                or instance.get("username")
                or self.app.config_manager.get().default_username
                or "ubuntu"
            )
            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=host,
                username=username,
                proxy_args=proxy_args,
                port=getattr(resolved.lease, "target_port", None) or instance.get("port"),
                extra_options=self.app.connection_service.get_extra_options(instance, profile),
                identity_agent=resolved.identity_agent,
                identity_file=getattr(resolved, "identity_file", None),
                certificate_file=resolved.certificate_path,
                known_hosts_file=resolved.known_hosts_path,
            )
            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                # The terminal is detached. The runtime owns this lease and
                # keeps its private agent alive until process shutdown/TTL.
                self.app.notify(
                    f"Connected (resolution tier: {source}): {rich_escape(name)}", markup=True
                )
            else:
                self.app.notify("Could not launch the terminal.", severity="error", markup=False)
            return

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
                # Pin a cloud instance by its alias, as every other path does.
                extra_options=host_key_alias_options(
                    instance, self.app.connection_service.host_key_policy(),
                ),
            )

            tier_label = "personal" if source == "personal" else "team"
            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                self.app.notify(
                    f"Connected via BW (resolution tier: {tier_label}): {rich_escape(name)}",
                    markup=True,
                )
                logger.info(
                    "SSH connect (BW %s): host=%s, user=%s, item=%s",
                    tier_label, host, username, resolved.item_id,
                )
            else:
                terminal_error = getattr(self.app.terminal_service, "last_error", None)
                self.app.notify(
                    terminal_error
                    if isinstance(terminal_error, str) and terminal_error
                    else "Could not detect terminal emulator. Set 'terminal_emulator' in settings.",
                    severity="error",
                    markup=False,
                )

        else:
            # source == "local" — existing per-provider logic
            try:
                if instance.get("is_ovh"):
                    options = self.app.connection_service.resolve_ovh_connection(
                        instance, resolved.local_key_path,
                    )
                    host = options["host"]
                    username = options["username"]
                    key_path = options["key_path"]
                    ssh_cmd = self.app.ssh_service.build_ssh_command(**options)

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
                    self.app.notify(
                        f"Local SSH fallback selected (resolution tier: local): {rich_escape(name)}",
                        severity="warning",
                        markup=True,
                    )
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
                    terminal_error = getattr(self.app.terminal_service, "last_error", None)
                    self.app.notify(
                        terminal_error
                        if isinstance(terminal_error, str) and terminal_error
                        else "Could not detect terminal emulator. Set 'terminal_emulator' in settings.",
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
        if self._refuse_if_unresolved():
            return
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
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.ai_analysis import AIAnalysisScreen
        self.app.push_screen(AIAnalysisScreen(text="", instance=self._instance))

    def action_action_8(self) -> None:
        """Ban IP — open IP ban manager pre-filled with this instance's public IP."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.ip_ban import IPBanScreen
        # Pre-fill what the screen shows; a ban of it targets the real address.
        shown_ip = self._instance.get('public_ip') or ""
        real_ip = connection_instance(self.app, self._instance).get('public_ip') or ""
        self.app.push_screen(IPBanScreen(prefill_ip=shown_ip, prefill_real_ip=real_ip))

    def action_open_memory(self) -> None:
        """Open MemoryScreen for this instance."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.memory import MemoryScreen
        self.app.push_screen(MemoryScreen(self._instance))

    def action_scan_db_creds(self) -> None:
        """Open the DB-credential scan → review → store surface (B2)."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.db_credential_scan import DbCredentialScanScreen
        self.app.push_screen(DbCredentialScanScreen(self._instance))

    def action_open_findings(self) -> None:
        """Open the findings inbox scoped to this instance."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.findings import FindingsScreen
        self.app.push_screen(FindingsScreen(instance=self._instance))

    def _display_host(self) -> str:
        """The address as shown on this screen — a demo-mode fake when redacted."""
        return (
            self._instance.get("public_ip")
            or self._instance.get("private_ip")
            or self._instance.get("id", "")
        )

    def action_manage_ssh_ref(self) -> None:
        """Push SshRefEditorModal directly to add/edit/delete the BW SSH ref."""
        if self._refuse_if_unresolved():
            return
        self.run_worker(
            self._manage_ssh_ref_flow(),
            group="ssh_verify",
            exclusive=True,
        )

    def action_use_vault_key(self) -> None:
        """Bind a native-vault SSH item with the server's verified host pins."""
        if self._refuse_if_unresolved():
            return

        async def flow() -> None:
            service = getattr(self.app, "vault_command_service", None)
            if service is None:
                self.app.notify("Vault services are unavailable.", severity="warning", markup=False)
                return
            instance = connection_instance(self.app, self._instance)
            server = str(instance.get("id") or "")
            if not server:
                self.app.notify("This server has no usable identifier.", severity="error", markup=False)
                return
            values = await self.app.push_screen_wait(VaultBindingModal(service, instance))
            if not values:
                return
            host_keys = [key.strip() for key in values["host_keys"].split(",") if key.strip()]
            try:
                if values["team"]:
                    # Without typed keys, the keys this machine already trusts are pinned.
                    result = await service.bind(
                        vault_id=values["vault_id"], server=server, item_id=values["item_id"],
                        team=values["team"], login=values["login"], pin_host_key=True,
                        host_keys=tuple(host_keys),
                    )
                else:
                    if not host_keys:
                        self.app.notify(
                            "Personal-server binding requires verified OpenSSH host keys.",
                            severity="warning",
                            markup=False,
                        )
                        return
                    # A custom server is addressed by name (provider "custom").
                    custom = instance.get("is_custom") is True
                    provider = "custom" if custom else str(instance.get("provider") or "")
                    hostname = str(
                        instance.get("hostname") or instance.get("host") or instance.get("public_ip") or ""
                    )
                    port = instance.get("port", 22)
                    login = values["login"] or instance.get("username")
                    if not isinstance(port, int) or not isinstance(login, str) or not login:
                        self.app.notify(
                            "The personal server needs a numeric port and login user.",
                            severity="warning",
                            markup=False,
                        )
                        return
                    result = await service.bind_personal(
                        vault_id=values["vault_id"],
                        item_id=values["item_id"],
                        provider=provider,
                        instance_id=str(instance.get("name") or "") if custom else server,
                        hostname=hostname,
                        port=port,
                        login=login,
                        host_keys=host_keys,
                    )
            except Exception as exc:
                from servonaut.services.vault.errors import vault_failure_reason

                self.app.notify(f"Vault key binding failed: {vault_failure_reason(exc)}", severity="error", markup=False)
                return
            source = result.get("source", "servonaut_vault") if isinstance(result, dict) else "servonaut_vault"
            self.app.notify(f"SSH credential source: {source}", markup=False)

        self.run_worker(flow(), group="vault", exclusive=True)

    async def _manage_ssh_ref_flow(self) -> None:
        """Fetch existing ref then open SshRefEditorModal in add or edit mode."""
        if not getattr(self.app, "bw_ssh_config_service", None):
            self.app.notify(
                "BW SSH service not available (sign in required)",
                severity="warning",
                markup=False,
            )
            return

        conn = connection_instance(self.app, self._instance)
        provider = conn.get("provider", "aws").lower()
        instance_id = conn.get("id")

        try:
            existing = await self.app.bw_ssh_config_service.get_personal_instance_ref(
                provider, instance_id
            )
        except Exception as exc:
            from servonaut.services.api_client import APIError
            if (
                isinstance(exc, APIError)
                and exc.status == 500
                and exc.code == "decrypt_failed"
            ):
                # A ref IS stored, but the server couldn't decrypt it — don't
                # collapse this to "no ref" and open the editor in add mode.
                self.app.notify(
                    "An SSH ref is stored for this instance, but the server "
                    "could not decrypt it (the vault key or enrollment likely "
                    "changed). Re-enroll this device or re-save the ref to fix.",
                    severity="error",
                    markup=False,
                )
                return
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
        if self._refuse_if_unresolved():
            return
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

        conn = connection_instance(self.app, self._instance)
        provider = conn.get("provider", "aws").lower()
        instance_id = conn.get("id", "")
        host = (
            conn.get("public_ip")
            or conn.get("private_ip")
            or instance_id
        )
        # The confirm dialog is on screen: it shows the row as displayed
        # (a demo-mode fake); the probe itself uses the real host above.
        shown_host = self._display_host()

        # Check if a BW ref is stored for this instance.
        try:
            ref_row = await bw_service.get_personal_instance_ref(provider, instance_id)
        except Exception as exc:
            from servonaut.services.api_client import APIError
            if (
                isinstance(exc, APIError)
                and exc.status == 500
                and exc.code == "decrypt_failed"
            ):
                # A ref IS stored, but the server couldn't decrypt it — don't
                # collapse this to "no ref" and reopen the editor.
                self.app.notify(
                    "An SSH ref is stored for this instance, but the server "
                    "could not decrypt it (the vault key or enrollment likely "
                    "changed). Re-enroll this device or re-save the ref to fix.",
                    severity="error",
                    markup=False,
                )
                return
            logger.debug("SSH verify ref lookup failed: %s", exc)
            ref_row = None

        has_ref = ref_row is not None

        # Push the confirm modal and await user's choice.
        confirmed = await self.app.push_screen_wait(
            ConfirmSshVerifyModal(host=shown_host, has_ref=has_ref)
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
                "this device — using the local fallback (resolution tier: local) "
                "for verification. Re-save the ref here to enable Bitwarden-backed verify.",
                severity="warning",
                markup=False,
            )

        resolution_tier = "personal" if item_id is not None else "local"
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
                resolution_tier=resolution_tier,
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
        host_key_message = getattr(self, "_ssh_probe_host_key_message", None)
        if host_key_message:
            # A refused host key is reported as such, not as "unreachable".
            self.app.notify(
                host_key_message, severity="error", markup=False, timeout=20,
            )
        else:
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
        import tempfile
        import os
        import stat
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

        self._ssh_probe_host_key_message = None
        try:
            conn = connection_instance(self.app, self._instance)
            host_key_policy = HostKeyPolicy.from_ssh_config(
                self.app.config_manager.get().ssh
            )
            cmd = [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                # ``off`` keeps this probe's previous argv (no /dev/null).
                *host_key_policy.ssh_options(off_options=OFF_OPTIONS_KEEP_KNOWN_HOSTS),
            ]
            for option in host_key_alias_options(conn, host_key_policy):
                cmd += ["-o", option]
            if tmp_key_path:
                cmd += [*identity_file_args(tmp_key_path), "-o", "IdentitiesOnly=yes"]
            port = self.app.connection_service.get_target_port(conn)
            if port is not None and port != 22:
                cmd += ["-p", str(port)]
            # Use the configured username or default.
            username = (
                self._instance.get("username")
                or self.app.config_manager.get().default_username
                or "root"
            )
            # "--" ends option parsing before the destination.
            cmd += ["--", f"{username}@{host}", "true"]

            # No terminal to prompt on; ssh's messages go to a private log.
            proc = await asyncio.to_thread(
                run_ssh,
                cmd,
                capture_output=True,
                timeout=15,
            )
            rc = proc.returncode
            if rc == 0:
                return "verified"
            problem = detect_host_key_problem(
                getattr(proc, "diagnostics", "") or "", rc,
                HostKeyTarget.for_connection(host, port, instance=conn),
                host_key_policy, stdout=proc.stdout,
            )
            if problem is not None:
                self._ssh_probe_host_key_message = problem.message
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

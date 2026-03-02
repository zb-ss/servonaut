"""IP Ban Manager screen for Servonaut v2.0."""

from __future__ import annotations

from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    RichLog,
    Select,
    Static,
)


class IPBanScreen(Screen):
    """IP Ban Manager: ban/unban IPs via WAF, Security Groups, or NACLs."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh_banned", "Refresh", show=True),
        Binding("y", "copy_output", "Copy", show=True),
    ]

    def __init__(self, prefill_ip: str = "") -> None:
        """Initialize the IP ban screen.

        Args:
            prefill_ip: Optional IP address to pre-fill in the input field.
        """
        super().__init__()
        self._prefill_ip = prefill_ip
        self._selected_config: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static("[bold cyan]IP Ban Manager[/bold cyan]", id="ip_ban_title"),
            Static("[dim]Ban IP addresses via WAF, Security Groups, or NACLs[/dim]", id="ip_ban_subtitle"),
            Vertical(
                Static("Select Ban Configuration:", classes="field_label"),
                Select(
                    options=self._get_config_options(),
                    prompt="-- Select a ban configuration --",
                    id="ban_config_selector",
                ),
                Static("IP Address to Ban/Unban:", classes="field_label"),
                Input(
                    placeholder="e.g. 1.2.3.4",
                    id="ip_input",
                    value=self._prefill_ip,
                ),
                Horizontal(
                    Button("Ban IP", id="btn_ban", variant="error"),
                    Button("Unban IP", id="btn_unban", variant="warning"),
                    Button("Refresh List", id="btn_refresh"),
                    Button("Back", id="btn_back", variant="default"),
                    id="ip_ban_actions",
                ),
                Static("Currently Banned IPs:", classes="field_label"),
                DataTable(id="banned_table"),
                Static("Audit Log (recent):", classes="field_label"),
                RichLog(id="audit_log", highlight=True, markup=True),
                id="ip_ban_form",
            ),
            id="ip_ban_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self._setup_table()
        self._load_audit_log()
        if self._prefill_ip:
            self.query_one("#ip_input", Input).focus()
        else:
            self.query_one("#ban_config_selector", Select).focus()

    def _get_config_options(self) -> List[tuple]:
        configs = self.app.ip_ban_service.get_configs()
        if not configs:
            return []
        return [(f"{c.name} ({c.method})", c.name) for c in configs]

    def _setup_table(self) -> None:
        table = self.query_one("#banned_table", DataTable)
        table.add_columns("IP / CIDR", "Config", "Method")

    def _load_audit_log(self) -> None:
        """Load recent audit log entries into the RichLog widget."""
        import json
        from pathlib import Path
        audit_log = self.query_one("#audit_log", RichLog)
        audit_log.clear()
        try:
            audit_path = Path(
                self.app.config_manager.get().ip_ban_audit_path
            ).expanduser()
            if not audit_path.exists():
                audit_log.write("[dim]No audit log entries yet.[/dim]")
                return
            entries = json.loads(audit_path.read_text())
            for entry in reversed(entries[-20:]):
                ts = entry.get('timestamp', '')[:19].replace('T', ' ')
                action = entry.get('action', '').upper()
                ip = entry.get('ip_address', '')
                config = entry.get('config', '')
                success = entry.get('success', False)
                msg = entry.get('message', '')
                color = "green" if success else "red"
                audit_log.write(
                    f"[{color}]{ts} {action}[/{color}] "
                    f"[cyan]{ip}[/cyan] via [yellow]{config}[/yellow] — {msg}"
                )
        except Exception as e:
            audit_log.write(f"[red]Error loading audit log: {e}[/red]")

    def _get_selected_config(self) -> Optional[str]:
        selector = self.query_one("#ban_config_selector", Select)
        value = selector.value
        if value is Select.BLANK:
            return None
        return value

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "ban_config_selector":
            config_name = event.value
            if config_name is not Select.BLANK:
                self._selected_config = config_name
                self.run_worker(
                    self._load_banned_ips(config_name),
                    name="load_banned",
                    exclusive=True,
                )

    async def _load_banned_ips(self, config_name: str) -> None:
        table = self.query_one("#banned_table", DataTable)
        table.clear()
        configs = self.app.ip_ban_service.get_configs()
        method = next((c.method for c in configs if c.name == config_name), "unknown")
        try:
            banned = await self.app.ip_ban_service.list_banned(config_name)
            for ip in banned:
                table.add_row(ip, config_name, method)
            if not banned:
                self.app.notify(f"No IPs currently banned in '{config_name}'")
        except Exception as e:
            self.app.notify(f"Error loading banned IPs: {e}", severity="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn_ban":
            self._do_ban()
        elif button_id == "btn_unban":
            self._do_unban()
        elif button_id == "btn_refresh":
            self.action_refresh_banned()
        elif button_id == "btn_back":
            self.action_back()

    def _do_ban(self) -> None:
        config_name = self._get_selected_config()
        ip = self.query_one("#ip_input", Input).value.strip()
        if not config_name:
            self.app.notify("Select a ban configuration first.", severity="warning")
            return
        if not ip:
            self.app.notify("Enter an IP address to ban.", severity="warning")
            return
        self.run_worker(self._ban_ip(ip, config_name), name="ban_ip", exclusive=True)

    def _do_unban(self) -> None:
        config_name = self._get_selected_config()
        ip = self.query_one("#ip_input", Input).value.strip()
        if not config_name:
            self.app.notify("Select a ban configuration first.", severity="warning")
            return
        if not ip:
            self.app.notify("Enter an IP address to unban.", severity="warning")
            return
        self.run_worker(self._unban_ip(ip, config_name), name="unban_ip", exclusive=True)

    async def _ban_ip(self, ip: str, config_name: str) -> None:
        result = await self.app.ip_ban_service.ban_ip(ip, config_name)
        if result.get('success'):
            self.app.notify(result['message'], severity="information")
            await self._load_banned_ips(config_name)
            self._load_audit_log()
        else:
            self.app.notify(result['message'], severity="error")

    async def _unban_ip(self, ip: str, config_name: str) -> None:
        result = await self.app.ip_ban_service.unban_ip(ip, config_name)
        if result.get('success'):
            self.app.notify(result['message'], severity="information")
            await self._load_banned_ips(config_name)
            self._load_audit_log()
        else:
            self.app.notify(result['message'], severity="error")

    def action_refresh_banned(self) -> None:
        config_name = self._get_selected_config()
        if config_name:
            self.run_worker(
                self._load_banned_ips(config_name),
                name="load_banned",
                exclusive=True,
            )
        self._load_audit_log()

    def action_copy_output(self) -> None:
        """Copy the banned IP list to the clipboard."""
        table = self.query_one("#banned_table", DataTable)
        if table.row_count == 0:
            self.notify("No banned IPs to copy", severity="warning")
            return
        lines = []
        for row_key in table.rows:
            row = table.get_row(row_key)
            # row[0] is "IP / CIDR", row[1] is Config, row[2] is Method
            ip = str(row[0]) if row else ""
            if ip:
                lines.append(ip)
        if lines:
            self.app.copy_to_clipboard("\n".join(lines))
            self.notify(f"Copied {len(lines)} IP(s) to clipboard")
        else:
            self.notify("Nothing to copy", severity="warning")

    def action_back(self) -> None:
        self.app.pop_screen()

"""IP Ban Manager screen for Servonaut v2.0."""

from __future__ import annotations

from typing import List, Optional, Tuple

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical

from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    RichLog,
    Select,
    Static,
)

from servonaut.screens._binding_guard import check_action_passthrough


class AmbiguousAddress(ValueError):
    """A shown stand-in address that stands for more than one real address."""


class IPBanScreen(Screen):
    """IP Ban Manager: ban/unban IPs via WAF, Security Groups, or NACLs."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh_banned", "Refresh", show=True),
        Binding("y", "copy_output", "Copy IP", show=True),
        Binding("enter", "use_selected_ip", "Use IP", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self, prefill_ip: str = "", prefill_real_ip: str = "") -> None:
        """Initialize the IP ban screen.

        Args:
            prefill_ip: Optional IP address to pre-fill in the input field,
                as the caller displays it (a demo-mode stand-in when on).
            prefill_real_ip: The real address behind ``prefill_ip`` when the
                two differ; a ban of the untouched pre-fill targets it.
        """
        super().__init__()
        self._prefill_ip = prefill_ip
        self._prefill_real_ip = prefill_real_ip or prefill_ip
        self._selected_config: Optional[str] = None
        # The address field may hold a demo-mode stand-in. Stand-in addresses
        # come from a small range, so two real addresses can share one: the
        # real address travels with the value that was put in the field
        # (the pre-fill, or the table row picked by position), never looked
        # up by the stand-in alone.
        self._field_binding: Optional[Tuple[str, str]] = (
            (prefill_ip.strip(), self._prefill_real_ip.strip()) if prefill_ip else None
        )
        # Real addresses of the banned-IP table, in row order.
        self._banned_real: List[str] = []

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static("[bold cyan]IP Ban Manager[/bold cyan]", id="ip_ban_title"),
            Static("[dim]Ban IP addresses via WAF, Security Groups, or NACLs[/dim]", id="ip_ban_subtitle"),
            Horizontal(
                Vertical(
                    Static("Select Ban Configuration:", classes="field_label"),
                    Select(
                        options=self._get_config_options(),
                        prompt="-- Select a ban configuration --",
                        id="ban_config_selector",
                    ),
                    id="ip_ban_config_col",
                ),
                Vertical(
                    Static("IP Address to Ban/Unban:", classes="field_label"),
                    Input(
                        placeholder="e.g. 1.2.3.4",
                        id="ip_input",
                        value=self._prefill_ip,
                    ),
                    id="ip_ban_input_col",
                ),
                id="ip_ban_top_row",
            ),
            Horizontal(
                Button("Ban IP", id="btn_ban", variant="error"),
                Button("Unban IP", id="btn_unban", variant="warning"),
                Button("Refresh List", id="btn_refresh"),
                Button("Back", id="btn_back", variant="default"),
                id="ip_ban_actions",
            ),
            Horizontal(
                Vertical(
                    Static("[bold]Banned IPs[/bold]", classes="field_label"),
                    DataTable(id="banned_table"),
                    id="ip_ban_table_col",
                ),
                Vertical(
                    Static("[bold]Audit Log[/bold]", classes="field_label"),
                    RichLog(id="audit_log", highlight=True, markup=True),
                    id="ip_ban_audit_col",
                ),
                id="ip_ban_main_content",
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

    def _demo_config_name(self, name: str) -> str:
        """Ban configurations are named by the operator (often after the
        site they protect); demo mode shows a pool name instead. Values
        and lookups keep the real name."""
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_name(name)
        return name

    def _get_config_options(self) -> List[tuple]:
        configs = self.app.ip_ban_service.get_configs()
        if not configs:
            return []
        return [(f"{self._demo_config_name(c.name)} ({c.method})", c.name) for c in configs]

    def _setup_table(self) -> None:
        table = self.query_one("#banned_table", DataTable)
        table.add_columns("IP / CIDR", "Bans", "Config", "Method")

    def _get_ban_counts(self) -> dict:
        """Count how many times each IP was banned from the audit log."""
        import json
        from collections import Counter
        from pathlib import Path

        counts: Counter = Counter()
        try:
            audit_path = Path(
                self.app.config_manager.get().ip_ban_audit_path
            ).expanduser()
            if audit_path.exists():
                entries = json.loads(audit_path.read_text())
                for entry in entries:
                    if entry.get("action") == "ban" and entry.get("success"):
                        ip = entry.get("ip_address", "")
                        if ip:
                            counts[ip] += 1
                            # Also count without CIDR suffix
                            if "/" not in ip:
                                counts[f"{ip}/32"] += counts[ip]
        except Exception:
            pass
        return dict(counts)

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
            for entry in reversed(entries[-30:]):
                ts = entry.get('timestamp', '')[:19].replace('T', ' ')
                action = entry.get('action', '').upper()
                ip = entry.get('ip_address', '')
                config = entry.get('config', '')
                success = entry.get('success', False)
                msg = entry.get('message', '')
                # Scrub ip, msg, and config BEFORE embedding in f-string markup.
                if self.app.demo_mode and self.app.redaction_service:
                    ip = self.app.redaction_service.redact_ip(ip)
                    msg = self.app.redaction_service.scrub_stream(msg)
                    config = self._demo_config_name(config)
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
        if value is Select.NULL:
            return None
        return value

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "ban_config_selector":
            config_name = event.value
            if config_name is not Select.NULL:
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
        ban_counts = self._get_ban_counts()
        self._banned_real = []
        try:
            banned = await self.app.ip_ban_service.list_banned(config_name)
            # Rows are read back by position: stand-ins may repeat.
            self._banned_real = [str(ip) for ip in banned]
            for ip in banned:
                # Look up count by CIDR or bare IP (use raw ip for lookup)
                bare_ip = ip.split("/")[0] if "/" in ip else ip
                count = ban_counts.get(bare_ip, 0) or ban_counts.get(ip, 0)
                # display_ip is redacted; ip (raw) used for ban_counts lookup above.
                display_ip = self.redact_display_ip(ip)
                table.add_row(
                    display_ip, str(count) if count else "-",
                    self._demo_config_name(config_name), method,
                )
            if not banned:
                self.app.notify(
                    f"No IPs currently banned in '{self._demo_config_name(config_name)}'",
                    markup=False,
                )
        except Exception as e:
            self.app.notify(f"Error loading banned IPs: {e}", severity="error", markup=False)

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

    def _input_ip(self) -> str:
        """The address to act on: the real one behind a shown stand-in.

        The value pre-filled or picked from the table carries its real
        address. A typed stand-in of a listed address maps back only when a
        single real address has that stand-in; otherwise the action is
        refused (raises ``AmbiguousAddress``) rather than guessed.
        Anything else was typed by the user and is used as typed.
        """
        ip = self.query_one("#ip_input", Input).value.strip()
        if self._field_binding is not None and ip == self._field_binding[0]:
            return self._field_binding[1]
        known = {
            real for real in self._banned_real + [self._prefill_real_ip.strip()] if real
        }
        if "/" not in ip:
            known = {real.split("/")[0] for real in known}
        candidates = {
            real for real in known if real != ip and self.redact_display_ip(real) == ip
        }
        if len(candidates) > 1:
            raise AmbiguousAddress(ip)
        return candidates.pop() if candidates else ip

    def redact_display_ip(self, ip: str) -> str:
        """*ip* as the screen shows it (a stand-in in demo mode)."""
        if not (self.app.demo_mode and self.app.redaction_service):
            return ip
        # IPv4 or IPv6, with or without a /prefix; other text is left alone.
        return self.app.redaction_service.redact_host(ip)

    def _notify_result(self, ip: str, config_name: str, result: dict) -> None:
        """Report a ban or unban; in demo mode without the real address."""
        message = str(result.get("message") or "")
        if self.app.demo_mode and self.app.redaction_service:
            bare = ip.split("/")[0]
            message = message.replace(ip, self.redact_display_ip(ip)).replace(
                bare, self.redact_display_ip(bare)
            ).replace(config_name, self._demo_config_name(config_name))
            message = self.app.redaction_service.scrub_stream(message)
        severity = "information" if result.get("success") else "error"
        self.app.notify(message, severity=severity, markup=False)

    def _input_ip_or_refuse(self) -> Optional[str]:
        try:
            return self._input_ip()
        except AmbiguousAddress:
            self.app.notify(
                "That address stands for more than one banned address in demo "
                "mode, so nothing was sent. Pick the row in the table, or press "
                "ctrl+shift+d to turn demo mode off.",
                severity="error",
                markup=False,
            )
            return None

    def _do_ban(self) -> None:
        config_name = self._get_selected_config()
        ip = self._input_ip_or_refuse()
        if ip is None:
            return
        if not config_name:
            self.app.notify("Select a ban configuration first.", severity="warning")
            return
        if not ip:
            self.app.notify("Enter an IP address to ban.", severity="warning")
            return
        self.run_worker(self._ban_ip(ip, config_name), name="ban_ip", exclusive=True)

    def _do_unban(self) -> None:
        config_name = self._get_selected_config()
        ip = self._input_ip_or_refuse()
        if ip is None:
            return
        if not config_name:
            self.app.notify("Select a ban configuration first.", severity="warning")
            return
        if not ip:
            self.app.notify("Enter an IP address to unban.", severity="warning")
            return
        self.run_worker(self._unban_ip(ip, config_name), name="unban_ip", exclusive=True)

    async def _ban_ip(self, ip: str, config_name: str) -> None:
        result = await self.app.ip_ban_service.ban_ip(ip, config_name)
        self._notify_result(ip, config_name, result)
        if result.get('success'):
            await self._load_banned_ips(config_name)
            self._load_audit_log()

    async def _unban_ip(self, ip: str, config_name: str) -> None:
        result = await self.app.ip_ban_service.unban_ip(ip, config_name)
        self._notify_result(ip, config_name, result)
        if result.get('success'):
            await self._load_banned_ips(config_name)
            self._load_audit_log()

    def action_refresh_banned(self) -> None:
        config_name = self._get_selected_config()
        if config_name:
            self.run_worker(
                self._load_banned_ips(config_name),
                name="load_banned",
                exclusive=True,
            )
        self._load_audit_log()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw config labels, the address field, banned list and audit log."""
        selector = self.query_one("#ban_config_selector", Select)
        selected = selector.value
        selector.set_options(self._get_config_options())
        if selected is not Select.NULL:
            selector.value = selected
        field = self.query_one("#ip_input", Input)
        try:
            real = self._input_ip()
        except AmbiguousAddress:
            real = ""  # leave it: acting on it is refused until it is picked again
        if real:
            field.value = self.redact_display_ip(real)
            self._field_binding = (field.value, real)
        self.action_refresh_banned()

    def _get_selected_ip_from_table(self) -> Optional[str]:
        """Get the IP from the currently selected table row."""
        table = self.query_one("#banned_table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_data = table.get_row_at(table.cursor_row)
            return str(row_data[0]).strip() if row_data else None
        except Exception:
            return None

    def action_copy_output(self) -> None:
        """Copy the selected IP to the clipboard."""
        ip = self._get_selected_ip_from_table()
        if not ip:
            self.notify("Select an IP from the table first", severity="warning")
            return

        from servonaut.utils.platform_utils import copy_to_clipboard

        if copy_to_clipboard(ip):
            self.notify(f"Copied {ip} to clipboard")
        else:
            self.app.copy_to_clipboard(ip)
            self.notify(f"Copied {ip} to clipboard")

    def action_use_selected_ip(self) -> None:
        """Copy the selected IP into the input field (bound to its real address)."""
        table = self.query_one("#banned_table", DataTable)
        row = table.cursor_row
        if table.row_count == 0 or not 0 <= row < len(self._banned_real):
            self.notify("Select an IP from the table first", severity="warning")
            return
        # Strip CIDR suffix for the input field
        real = self._banned_real[row].split("/")[0]
        shown = self.redact_display_ip(real)
        field = self.query_one("#ip_input", Input)
        field.value = shown
        self._field_binding = (shown, real)
        field.focus()
        self.notify(f"Selected {shown}", markup=False)

    def action_back(self) -> None:
        self.app.pop_screen()

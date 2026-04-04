"""OVH firewall management screen — view state, toggle, manage rules."""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class OVHFirewallScreen(Screen):
    """Firewall management for an OVH VPS or dedicated server IP."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def __init__(self, instance: dict) -> None:
        """Initialize the firewall screen.

        Args:
            instance: Instance dict from the instance list.  Must contain
                ``public_ip`` (or ``ip``) with the IP to manage.
        """
        super().__init__()
        self._instance = instance
        self._ip: str = str(
            instance.get("public_ip") or instance.get("ip") or ""
        )
        self._firewall_enabled: bool = False
        self._rules: List[dict] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        instance_name = (
            self._instance.get("name") or self._instance.get("id") or "Unknown"
        )

        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with ScrollableContainer(id="firewall_container"):
                yield Static(
                    f"[bold cyan]Firewall: {instance_name}[/bold cyan]",
                    id="firewall_title",
                )
                yield Static(
                    "[dim]Loading firewall state...[/dim]",
                    id="firewall_status",
                )
                yield Button(
                    "Toggle Firewall", variant="default", id="btn_toggle"
                )
                yield DataTable(id="rules_table")
                with Horizontal(id="firewall_actions"):
                    yield Button(
                        "Add Rule", variant="primary", id="btn_add_rule"
                    )
                    yield Button(
                        "Delete Rule", variant="error", id="btn_delete_rule"
                    )
                    yield Button("Back", variant="default", id="btn_back")

                # Add Rule inline form (hidden until "Add Rule" pressed)
                yield Static(
                    "[bold]Add Firewall Rule[/bold]",
                    id="add_rule_title",
                    classes="form_section hidden",
                )
                yield Input(
                    placeholder="action (permit / deny)",
                    id="input_action",
                    classes="hidden",
                )
                yield Input(
                    placeholder="protocol (tcp / udp / icmp)",
                    id="input_protocol",
                    classes="hidden",
                )
                yield Input(
                    placeholder="port (e.g. 80, or leave blank for ICMP)",
                    id="input_port",
                    classes="hidden",
                )
                yield Input(
                    placeholder="source IP (e.g. 1.2.3.4/32 or empty for any)",
                    id="input_source",
                    classes="hidden",
                )
                yield Input(
                    placeholder="sequence (0–19)",
                    id="input_sequence",
                    classes="hidden",
                )
                yield Button(
                    "Save Rule",
                    variant="primary",
                    id="btn_save_rule",
                    classes="hidden",
                )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        table = self.query_one("#rules_table", DataTable)
        table.add_columns("Seq", "Action", "Protocol", "Port", "Source")
        table.cursor_type = "row"

        if not self._ip:
            self.notify(
                "No IP address found for this instance.", severity="error"
            )
            return

        self.run_worker(self._load_firewall(), exclusive=True)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""

        if button_id == "btn_back":
            self.action_back()

        elif button_id == "btn_toggle":
            await self._on_toggle_firewall()

        elif button_id == "btn_add_rule":
            self._show_add_form()

        elif button_id == "btn_save_rule":
            await self._on_save_rule()

        elif button_id == "btn_delete_rule":
            await self._on_delete_rule()

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Form visibility helpers
    # ------------------------------------------------------------------

    _ADD_FORM_IDS = (
        "add_rule_title",
        "input_action",
        "input_protocol",
        "input_port",
        "input_source",
        "input_sequence",
        "btn_save_rule",
    )

    def _show_add_form(self) -> None:
        for wid in self._ADD_FORM_IDS:
            self.query_one(f"#{wid}").remove_class("hidden")
        self.query_one("#input_action", Input).focus()

    def _hide_add_form(self) -> None:
        for wid in self._ADD_FORM_IDS:
            self.query_one(f"#{wid}").add_class("hidden")

    def _clear_add_form(self) -> None:
        for input_id in (
            "input_action",
            "input_protocol",
            "input_port",
            "input_source",
            "input_sequence",
        ):
            self.query_one(f"#{input_id}", Input).value = ""

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    async def _load_firewall(self) -> None:
        svc = getattr(self.app, "ovh_ip_service", None)
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        try:
            fw = await svc.get_firewall(self._ip)
            self._firewall_enabled = bool(fw.get("enabled"))
            self._update_status_widget()
        except Exception as exc:
            logger.error("Error loading firewall state for %s: %s", self._ip, exc)
            self.notify(f"Failed to load firewall state: {exc}", severity="error")

        try:
            self._rules = await svc.list_firewall_rules(self._ip)
        except Exception as exc:
            logger.error("Error loading firewall rules for %s: %s", self._ip, exc)
            self.notify(f"Failed to load firewall rules: {exc}", severity="error")
            self._rules = []

        self._populate_rules_table()

    def _update_status_widget(self) -> None:
        status_widget = self.query_one("#firewall_status", Static)
        if self._firewall_enabled:
            status_widget.update("[green]Firewall: Enabled[/green]")
        else:
            status_widget.update("[red]Firewall: Disabled[/red]")

    def _populate_rules_table(self) -> None:
        table = self.query_one("#rules_table", DataTable)
        table.clear()

        if not self._rules:
            self.notify("No firewall rules configured.", severity="information")
            return

        for rule in sorted(self._rules, key=lambda r: r.get("sequence", 0)):
            seq = str(rule.get("sequence", "—"))
            action = str(rule.get("action", "—"))
            protocol = str(rule.get("protocol", "—"))
            port = str(rule.get("destinationPort") or rule.get("port") or "—")
            source = str(rule.get("source") or rule.get("sourcePort") or "any")
            table.add_row(seq, action, protocol, port, source)

    # ------------------------------------------------------------------
    # Toggle firewall
    # ------------------------------------------------------------------

    async def _on_toggle_firewall(self) -> None:
        new_state = not self._firewall_enabled
        action_word = "Enable" if new_state else "Disable"

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title=f"{action_word} Firewall",
                description=(
                    f"{action_word} the OVH firewall for "
                    f"[bold]{self._ip}[/bold]."
                ),
                consequences=[
                    f"The firewall will be {'enabled' if new_state else 'disabled'}",
                    "Traffic filtering rules will {'take effect' if new_state else 'be suspended'}",
                ],
                confirm_text="confirm",
                action_label=f"{action_word} Firewall",
                severity="warning",
            )
        )

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            ovh_audit.log_action(
                action="firewall_toggle",
                target=self._ip,
                details={"enabled": new_state},
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        self.run_worker(
            self._do_toggle_firewall(new_state),
            exclusive=False,
        )

    async def _do_toggle_firewall(self, enabled: bool) -> None:
        svc = getattr(self.app, "ovh_ip_service", None)
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        try:
            await svc.toggle_firewall(self._ip, enabled)
            self._firewall_enabled = enabled
            self._update_status_widget()
            state_str = "enabled" if enabled else "disabled"
            self.notify(f"Firewall {state_str} for {self._ip}.", severity="information")
        except Exception as exc:
            logger.error("Error toggling firewall for %s: %s", self._ip, exc)
            self.notify(f"Toggle failed: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Add rule
    # ------------------------------------------------------------------

    async def _on_save_rule(self) -> None:
        action = self.query_one("#input_action", Input).value.strip().lower()
        protocol = self.query_one("#input_protocol", Input).value.strip().lower()
        port_raw = self.query_one("#input_port", Input).value.strip()
        source = self.query_one("#input_source", Input).value.strip()
        seq_raw = self.query_one("#input_sequence", Input).value.strip()

        # Validation
        if action not in ("permit", "deny"):
            self.notify("Action must be 'permit' or 'deny'.", severity="warning")
            return
        if protocol not in ("tcp", "udp", "icmp"):
            self.notify("Protocol must be 'tcp', 'udp', or 'icmp'.", severity="warning")
            return
        if not seq_raw.isdigit() or not (0 <= int(seq_raw) <= 19):
            self.notify("Sequence must be a number between 0 and 19.", severity="warning")
            return

        sequence = int(seq_raw)

        rule: dict = {
            "action": action,
            "protocol": protocol,
            "sequence": sequence,
        }
        if port_raw:
            rule["destinationPort"] = port_raw
        if source:
            rule["source"] = source

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Add Firewall Rule",
                description=(
                    f"Add rule [bold]#{sequence}[/bold]: "
                    f"{action.upper()} {protocol.upper()}"
                    + (f" port {port_raw}" if port_raw else "")
                    + (f" from {source}" if source else "")
                    + f" on [bold]{self._ip}[/bold]."
                ),
                consequences=[
                    "The new rule will be applied to incoming traffic immediately",
                ],
                confirm_text="confirm",
                action_label="Add Rule",
                severity="warning",
            )
        )

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            ovh_audit.log_action(
                action="firewall_add_rule",
                target=self._ip,
                details=rule,
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        self.run_worker(
            self._do_add_rule(rule),
            exclusive=False,
        )

    async def _do_add_rule(self, rule: dict) -> None:
        svc = getattr(self.app, "ovh_ip_service", None)
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        try:
            await svc.add_firewall_rule(self._ip, rule)
            self.notify("Firewall rule added.", severity="information")
            self._hide_add_form()
            self._clear_add_form()
            await self._load_firewall()
        except Exception as exc:
            logger.error("Error adding firewall rule for %s: %s", self._ip, exc)
            self.notify(f"Add rule failed: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Delete rule
    # ------------------------------------------------------------------

    async def _on_delete_rule(self) -> None:
        table = self.query_one("#rules_table", DataTable)
        row_index = table.cursor_row

        if row_index < 0 or row_index >= len(self._rules):
            self.notify("Please select a rule to delete.", severity="warning")
            return

        sorted_rules = sorted(self._rules, key=lambda r: r.get("sequence", 0))
        rule = sorted_rules[row_index]
        sequence = rule.get("sequence")
        if sequence is None:
            self.notify("Selected rule has no sequence number.", severity="warning")
            return

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete Firewall Rule",
                description=(
                    f"Delete firewall rule [bold]#{sequence}[/bold] "
                    f"from [bold]{self._ip}[/bold]."
                ),
                consequences=[
                    "The rule will be permanently removed",
                    "Traffic previously matched by this rule will no longer be filtered",
                ],
                confirm_text="confirm",
                action_label="Delete Rule",
                severity="warning",
            )
        )

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            ovh_audit.log_action(
                action="firewall_delete_rule",
                target=self._ip,
                details={"sequence": sequence},
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        self.run_worker(
            self._do_delete_rule(int(sequence)),
            exclusive=False,
        )

    async def _do_delete_rule(self, sequence: int) -> None:
        svc = getattr(self.app, "ovh_ip_service", None)
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        try:
            await svc.delete_firewall_rule(self._ip, sequence)
            self.notify(f"Firewall rule #{sequence} deleted.", severity="information")
            await self._load_firewall()
        except Exception as exc:
            logger.error(
                "Error deleting firewall rule #%s for %s: %s", sequence, self._ip, exc
            )
            self.notify(f"Delete rule failed: {exc}", severity="error")

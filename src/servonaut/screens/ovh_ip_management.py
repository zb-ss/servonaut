"""OVH IP management screen — list IPs, move failover IPs, manage reverse DNS."""

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


class OVHIPManagementScreen(Screen):
    """IP management — list IPs, move failover IPs, configure reverse DNS."""

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

    def __init__(self) -> None:
        super().__init__()
        self._ips: List[dict] = []
        self._selected_ip: Optional[dict] = None

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with ScrollableContainer(id="ip_mgmt_container"):
                yield Static(
                    "[bold cyan]OVH IP Management[/bold cyan]",
                    id="ip_mgmt_title",
                )
                yield DataTable(id="ip_table")
                with Horizontal(id="ip_actions"):
                    yield Button("Move IP", variant="default", id="btn_move")
                    yield Button(
                        "Set Reverse DNS", variant="default", id="btn_rdns"
                    )
                    yield Button("Back", variant="default", id="btn_back")

                # Move IP inline form (hidden until "Move IP" pressed)
                yield Static(
                    "[bold]Move Failover IP[/bold]",
                    id="move_form_title",
                    classes="form_section hidden",
                )
                yield Input(
                    placeholder="Target service (e.g. vps-abc123.ovh.net)",
                    id="input_move_target",
                    classes="hidden",
                )
                yield Button(
                    "Confirm Move",
                    variant="warning",
                    id="btn_move_confirm",
                    classes="hidden",
                )

                # Reverse DNS inline form (hidden until "Set Reverse DNS" pressed)
                yield Static(
                    "[bold]Reverse DNS[/bold]",
                    id="rdns_form_title",
                    classes="form_section hidden",
                )
                yield Input(
                    placeholder="server.example.com",
                    id="input_rdns",
                    classes="hidden",
                )
                with Horizontal(id="rdns_btn_row", classes="hidden"):
                    yield Button(
                        "Set", variant="default", id="btn_rdns_set"
                    )
                    yield Button(
                        "Delete", variant="error", id="btn_rdns_delete"
                    )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        table = self.query_one("#ip_table", DataTable)
        table.add_columns("IP", "Type", "Routed To", "Reverse DNS")
        table.cursor_type = "row"
        self.run_worker(self._load_ips(), exclusive=True)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""

        if button_id == "btn_back":
            self.action_back()

        elif button_id == "btn_move":
            self._show_move_form()

        elif button_id == "btn_move_confirm":
            await self._on_confirm_move()

        elif button_id == "btn_rdns":
            self._show_rdns_form()

        elif button_id == "btn_rdns_set":
            await self._on_set_rdns()

        elif button_id == "btn_rdns_delete":
            await self._on_delete_rdns()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_index = event.cursor_row
        if 0 <= row_index < len(self._ips):
            self._selected_ip = self._ips[row_index]

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Form visibility helpers
    # ------------------------------------------------------------------

    def _show_move_form(self) -> None:
        """Show the Move IP inline form and hide the rDNS form."""
        self._hide_rdns_form()
        for widget_id in ("move_form_title", "input_move_target", "btn_move_confirm"):
            self.query_one(f"#{widget_id}").remove_class("hidden")
        self.query_one("#input_move_target", Input).focus()

    def _hide_move_form(self) -> None:
        for widget_id in ("move_form_title", "input_move_target", "btn_move_confirm"):
            self.query_one(f"#{widget_id}").add_class("hidden")

    def _show_rdns_form(self) -> None:
        """Show the reverse DNS inline form and hide the Move form."""
        self._hide_move_form()
        for widget_id in ("rdns_form_title", "input_rdns", "rdns_btn_row"):
            self.query_one(f"#{widget_id}").remove_class("hidden")
        self.query_one("#input_rdns", Input).focus()

    def _hide_rdns_form(self) -> None:
        for widget_id in ("rdns_form_title", "input_rdns", "rdns_btn_row"):
            self.query_one(f"#{widget_id}").add_class("hidden")

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    async def _load_ips(self) -> None:
        svc = getattr(self.app, "ovh_ip_service", None)
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        try:
            self._ips = await svc.list_ips()
        except Exception as exc:
            logger.error("Error loading OVH IPs: %s", exc)
            self.notify(f"Failed to load IPs: {exc}", severity="error")
            return

        self._populate_table()

    def _populate_table(self) -> None:
        table = self.query_one("#ip_table", DataTable)
        table.clear()

        if not self._ips:
            self.notify("No IPs found on this account.", severity="information")
            return

        for ip in self._ips:
            ip_addr = str(ip.get("ip") or ip.get("routedTo") or "—")
            ip_type = str(ip.get("type") or "—")
            routed_to = str(
                (ip.get("routedTo") or {}).get("serviceName") or "—"
                if isinstance(ip.get("routedTo"), dict)
                else ip.get("routedTo") or "—"
            )
            reverse = str(ip.get("reverse") or "—")
            table.add_row(ip_addr, ip_type, routed_to, reverse)

    # ------------------------------------------------------------------
    # Move failover IP
    # ------------------------------------------------------------------

    async def _on_confirm_move(self) -> None:
        """Validate selection and target, then confirm move via modal."""
        if self._selected_ip is None:
            self.notify("Please select an IP from the table first.", severity="warning")
            return

        ip_addr = str(self._selected_ip.get("ip") or "")
        if not ip_addr:
            self.notify("Selected IP has no address.", severity="warning")
            return

        target = self.query_one("#input_move_target", Input).value.strip()
        if not target:
            self.notify("Please enter a target service name.", severity="warning")
            return

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Move Failover IP",
                description=(
                    f"Move [bold]{ip_addr}[/bold] to "
                    f"[bold]{target}[/bold]."
                ),
                consequences=[
                    "The IP will be detached from its current service",
                    "Connectivity to the current service via this IP will be lost",
                ],
                confirm_text=ip_addr,
                action_label="Move IP",
                severity="warning",
            )
        )

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            ovh_audit.log_action(
                action="ip_move",
                target=ip_addr,
                details={"target_service": target},
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        self.run_worker(
            self._do_move_ip(ip_addr, target),
            exclusive=False,
        )

    async def _do_move_ip(self, ip: str, target: str) -> None:
        svc = getattr(self.app, "ovh_ip_service", None)
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        try:
            await svc.move_failover_ip(ip, target)
            self.notify(f"IP {ip} is being moved to {target}.", severity="information")
            self._hide_move_form()
            self.query_one("#input_move_target", Input).value = ""
            await self._load_ips()
        except Exception as exc:
            logger.error("Error moving IP %s: %s", ip, exc)
            self.notify(f"Move failed: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Reverse DNS
    # ------------------------------------------------------------------

    def _get_selected_ips_for_rdns(self) -> tuple[str, str]:
        """Return (ip_block, ip) for the selected row, or ("", "") if unavailable."""
        if self._selected_ip is None:
            return "", ""

        ip_block = str(self._selected_ip.get("ip") or "")
        # For a host IP (/32 or /128), the host address equals the block prefix.
        if "/" in ip_block:
            ip = ip_block.split("/")[0]
        else:
            ip = ip_block
        return ip_block, ip

    async def _on_set_rdns(self) -> None:
        """Set reverse DNS for the selected IP."""
        ip_block, ip = self._get_selected_ips_for_rdns()
        if not ip_block:
            self.notify("Please select an IP from the table first.", severity="warning")
            return

        reverse = self.query_one("#input_rdns", Input).value.strip()
        if not reverse:
            self.notify("Please enter a reverse DNS hostname.", severity="warning")
            return

        svc = getattr(self.app, "ovh_ip_service", None)
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            ovh_audit.log_action(
                action="ip_set_reverse_dns",
                target=ip,
                details={"ip_block": ip_block, "reverse": reverse},
                confirmed=True,
            )

        self.run_worker(
            self._do_set_rdns(svc, ip_block, ip, reverse),
            exclusive=False,
        )

    async def _do_set_rdns(self, svc, ip_block: str, ip: str, reverse: str) -> None:
        try:
            await svc.set_reverse_dns(ip_block, ip, reverse)
            self.notify(f"Reverse DNS set to {reverse!r} for {ip}.", severity="information")
            self._hide_rdns_form()
            self.query_one("#input_rdns", Input).value = ""
            await self._load_ips()
        except Exception as exc:
            logger.error("Error setting reverse DNS for %s: %s", ip, exc)
            self.notify(f"Set reverse DNS failed: {exc}", severity="error")

    async def _on_delete_rdns(self) -> None:
        """Delete reverse DNS for the selected IP after confirmation."""
        ip_block, ip = self._get_selected_ips_for_rdns()
        if not ip_block:
            self.notify("Please select an IP from the table first.", severity="warning")
            return

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete Reverse DNS",
                description=f"Remove the reverse DNS record for [bold]{ip}[/bold].",
                consequences=[
                    "The existing PTR record will be deleted",
                    "Reverse DNS lookups for this IP will return no result",
                ],
                confirm_text=ip,
                action_label="Delete rDNS",
                severity="warning",
            )
        )

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            ovh_audit.log_action(
                action="ip_delete_reverse_dns",
                target=ip,
                details={"ip_block": ip_block},
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        svc = getattr(self.app, "ovh_ip_service", None)
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        self.run_worker(
            self._do_delete_rdns(svc, ip_block, ip),
            exclusive=False,
        )

    async def _do_delete_rdns(self, svc, ip_block: str, ip: str) -> None:
        try:
            await svc.delete_reverse_dns(ip_block, ip)
            self.notify(f"Reverse DNS deleted for {ip}.", severity="information")
            self._hide_rdns_form()
            await self._load_ips()
        except Exception as exc:
            logger.error("Error deleting reverse DNS for %s: %s", ip, exc)
            self.notify(f"Delete reverse DNS failed: {exc}", severity="error")

"""OVH IP management screen — list IPs, move failover IPs, manage reverse DNS.

IP blocks belong to one OVH account: with several accounts configured, a
picker chooses the account listed and changed.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, DataTable, Footer, Input, Static

from servonaut.screens._busy_work import BusyWork
from servonaut.utils.markup import literal, with_bold_values
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._provider_accounts import (
    UnknownAccountError,
    ovh_services,
    registry_for,
    show_account_labels,
    with_account,
)
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class OVHIPManagementScreen(WorkspaceScreen):
    """IP management — list IPs, move failover IPs, configure reverse DNS."""

    DEFAULT_CSS = """
    OVHIPManagementScreen .workspace-content > BusyIndicator.read-loading {
        dock: top;
        height: 1;
    }
    """

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 64
    CONTENT_NARROW_WIDTH = 104

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    # Label of the chosen account; "" is the default account.
    _account: str = ""
    # Counts list loads; see _load_ips.
    _loads: int = 0

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        super().__init__()
        self._read_loading = BusyWork(self, "#read_loading")
        self._ips: List[dict] = []
        self._selected_ip: Optional[dict] = None

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("IP management")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield ScrollableContainer(
                BusyIndicator(id="read_loading", classes="read-loading"),
                Horizontal(
                    Vertical(
                        Static(
                            "[bold $text-accent]OVH IP Management[/bold $text-accent]",
                            id="ip_mgmt_title",
                        ),
                        Static(
                            "Select an IP to move its routing or manage its reverse DNS.",
                            classes="resource-context",
                        ),
                        classes="provider-account-heading",
                    ),
                    AccountPicker.for_provider(
                        registry_for(self.app, "ovh"), "ovh", id="ip_mgmt_account",
                    ),
                    classes="provider-account-heading-row",
                ),
                Horizontal(
                    Vertical(
                        Static("IP inventory", classes="resource-section-title"),
                        DataTable(id="ip_table"),
                        classes="resource-panel provider-account-inventory",
                    ),
                    Vertical(
                        Static("IP operations", classes="resource-section-title"),
                        Static(
                            "Choose a row with Enter or a row click before applying a change.",
                            classes="resource-context",
                        ),
                        Static(
                            "No IP selected.", id="ip_selected_context",
                            classes="provider-account-selection", markup=False,
                        ),
                        Horizontal(
                            Button("Move IP", variant="default", id="btn_move"),
                            Button(
                                "Set Reverse DNS", variant="default", id="btn_rdns"
                            ),
                            Button("Back", variant="default", id="btn_back"),
                            id="ip_actions",
                        ),
                        Container(
                            Static(
                                "[bold]Move Failover IP[/bold]",
                                id="move_form_title",
                            ),
                            Input(
                                placeholder="Target service (e.g. vps-abc123.ovh.net)",
                                id="input_move_target",
                            ),
                            Button(
                                "Confirm Move",
                                variant="warning",
                                id="btn_move_confirm",
                            ),
                            id="move_form_panel", classes="ip_form_panel hidden",
                        ),
                        Container(
                            Static(
                                "[bold]Reverse DNS[/bold]",
                                id="rdns_form_title",
                            ),
                            Input(
                                placeholder="server.example.com",
                                id="input_rdns",
                            ),
                            Horizontal(
                                Button(
                                    "Set", variant="default", id="btn_rdns_set"
                                ),
                                Button(
                                    "Delete", variant="error", id="btn_rdns_delete"
                                ),
                                id="rdns_btn_row",
                            ),
                            id="rdns_form_panel", classes="ip_form_panel hidden",
                        ),
                        classes="provider-account-operations",
                    ),
                    classes="provider-account-body",
                ),
                id="ip_mgmt_container",
                classes="workspace-content resource-workspace-content provider-account-workspace",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        table = self.query_one("#ip_table", DataTable)
        table.add_columns("IP", "Type", "Routed To", "Reverse DNS")
        table.cursor_type = "row"
        picker = self.query_one("#ip_mgmt_account", AccountPicker)
        self._account = picker.account
        show_account_labels(picker)
        self._start_load()

    def on_account_picker_changed(self, event: AccountPicker.Changed) -> None:
        """Another account was picked: list its IPs instead."""
        self._account = event.account
        self._ips = []
        self._selected_ip = None
        self._update_selected_context()
        self._hide_move_form()
        self._hide_rdns_form()
        self.query_one("#ip_table", DataTable).clear()
        self._start_load()

    def _start_load(self) -> None:
        """Load the IPs in a group of their own.

        A reload cancels an older load, never an IP move or a reverse DNS
        change that is still running.
        """
        self.run_worker(self._load_ips(), group="ovh_ip_load", exclusive=True)

    def _ip_service(self):
        """The chosen account's IP service (None when unavailable)."""
        try:
            return ovh_services(self.app, self._account).ip
        except UnknownAccountError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return None

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # The confirm-action handlers below all call ``push_screen_wait``
        # — Textual 8.x rejects that outside a worker context, so spawn
        # one rather than awaiting directly here.
        button_id = event.button.id or ""

        if button_id == "btn_back":
            self.action_back()
        elif button_id == "btn_move":
            self._show_move_form()
        elif button_id == "btn_move_confirm":
            self.run_worker(
                self._on_confirm_move(),
                exclusive=True, name="ovh_ip_move",
            )
        elif button_id == "btn_rdns":
            self._show_rdns_form()
        elif button_id == "btn_rdns_set":
            self.run_worker(
                self._on_set_rdns(),
                exclusive=True, name="ovh_ip_set_rdns",
            )
        elif button_id == "btn_rdns_delete":
            self.run_worker(
                self._on_delete_rdns(),
                exclusive=True, name="ovh_ip_delete_rdns",
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_index = event.cursor_row
        if 0 <= row_index < len(self._ips):
            self._selected_ip = self._ips[row_index]
            self._update_selected_context()

    def _update_selected_context(self) -> None:
        """Show the operation target without changing the chosen IP."""
        try:
            context = self.query_one("#ip_selected_context", Static)
        except NoMatches:
            return
        if self._selected_ip is None:
            context.update("No IP selected.")
            return
        address = str(self._selected_ip.get("ip") or "—")
        if self.app.demo_mode:
            redactor = self.app.redaction_service
            address = redactor.redact_host(address) if redactor else "Hidden"
        context.update(literal(f"Selected IP\n{address}"))

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Form visibility helpers
    # ------------------------------------------------------------------

    def _show_move_form(self) -> None:
        """Show the Move IP inline form and hide the rDNS form."""
        self._hide_rdns_form()
        self.query_one("#move_form_panel").remove_class("hidden")
        self.query_one("#input_move_target", Input).focus()

    def _hide_move_form(self) -> None:
        self.query_one("#move_form_panel").add_class("hidden")

    def _show_rdns_form(self) -> None:
        """Show the reverse DNS inline form and hide the Move form."""
        self._hide_move_form()
        self.query_one("#rdns_form_panel").remove_class("hidden")
        self.query_one("#input_rdns", Input).focus()

    def _hide_rdns_form(self) -> None:
        self.query_one("#rdns_form_panel").add_class("hidden")

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    async def _load_ips(self) -> None:
        svc = self._ip_service()
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        # Only the latest load draws: a change reloads the list itself, and an
        # older load still running must not draw over it.
        self._loads += 1
        load = self._loads
        with self._read_loading.running('Loading IPs…'):
            try:
                ips = await svc.list_ips()
            except Exception as exc:
                logger.error("Error loading OVH IPs: %s", exc)
                if load == self._loads:
                    self.notify(f"Failed to load IPs: {exc}", severity="error", markup=False)
                return
            if load != self._loads:
                return
            self._ips = ips
            self._populate_table()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the fetched IP blocks for the new demo-mode state."""
        show_account_labels(self.query_one("#ip_mgmt_account", AccountPicker))
        if self._ips:
            self._populate_table()

    def _populate_table(self) -> None:
        table = self.query_one("#ip_table", DataTable)
        table.clear()
        self._update_selected_context()

        if not self._ips:
            self.notify("No IPs found on this account.", severity="information")
            return

        def _h(x: str, *, is_service: bool = False) -> str:
            # Cloud routes identify a project; VPS routes identify a hostname.
            if self.app.demo_mode:
                redactor = self.app.redaction_service
                if redactor is None:
                    return "Hidden"
                value = redactor.redact_instance_id(x) if is_service else x
                return redactor.redact_host(value)
            return x

        for ip in self._ips:
            ip_addr = str(ip.get("ip") or ip.get("routedTo") or "—")
            ip_type = str(ip.get("type") or "—")
            routed_to = str(
                (ip.get("routedTo") or {}).get("serviceName") or "—"
                if isinstance(ip.get("routedTo"), dict)
                else ip.get("routedTo") or "—"
            )
            reverse = str(ip.get("reverse") or "—")
            table.add_row(_h(ip_addr), ip_type, _h(routed_to, is_service=True), _h(reverse))

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
                description=with_bold_values("Move {} to {}.", ip_addr, target),
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
                details=with_account(self.app, "ovh", self._account, {"target_service": target}),
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        self.run_worker(
            self._do_move_ip(ip_addr, target),
            exclusive=False,
        )

    async def _do_move_ip(self, ip: str, target: str) -> None:
        svc = self._ip_service()
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
            self.notify(f"Move failed: {exc}", severity="error", markup=False)

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

        svc = self._ip_service()
        if svc is None:
            self.notify("OVH IP service is not available.", severity="error")
            return

        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is not None:
            ovh_audit.log_action(
                action="ip_set_reverse_dns",
                target=ip,
                details=with_account(
                    self.app, "ovh", self._account, {"ip_block": ip_block, "reverse": reverse},
                ),
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
            self.notify(f"Set reverse DNS failed: {exc}", severity="error", markup=False)

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
                description=with_bold_values("Remove the reverse DNS record for {}.", ip),
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
                details=with_account(self.app, "ovh", self._account, {"ip_block": ip_block}),
                confirmed=bool(confirmed),
            )

        if not confirmed:
            return

        svc = self._ip_service()
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
            self.notify(f"Delete reverse DNS failed: {exc}", severity="error", markup=False)

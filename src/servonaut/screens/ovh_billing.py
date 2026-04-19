"""OVH Billing Dashboard screen for Servonaut."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


def _format_current_usage(usage: dict) -> str:
    """Render current usage / forecast as a readable string."""
    if not usage:
        return "  [dim]No data available.[/dim]"

    lines: List[str] = []
    current = usage.get("current_spend", {})
    forecast = usage.get("forecast", {})

    def _extract_value(blob: dict) -> str:
        if not blob:
            return "n/a"
        total = blob.get("total") or {}
        if isinstance(total, dict):
            value = total.get("value")
            currency = total.get("currencyCode", "")
            if value is not None:
                return f"{float(value):.2f} {currency}".strip()
        return "n/a"

    lines.append(f"  Current spend : [cyan]{_extract_value(current)}[/cyan]")
    lines.append(f"  Forecast      : [yellow]{_extract_value(forecast)}[/yellow]")
    return "\n".join(lines)


def _format_spend_history(history: List[dict]) -> str:
    """Render monthly spend history as an ASCII table with a simple bar."""
    if not history:
        return "  [dim]No history available.[/dim]"

    max_total = max((h.get("total", 0) for h in history), default=1) or 1
    bar_width = 20

    lines: List[str] = []
    lines.append(f"  {'Month':<10}  {'Total':>10}  {'':^{bar_width}}")
    lines.append("  " + "-" * (10 + 2 + 10 + 2 + bar_width))
    for entry in history:
        month = entry.get("month", "")
        total = entry.get("total", 0.0)
        currency = entry.get("currency", "")
        filled = int((total / max_total) * bar_width)
        bar = "#" * filled + "." * (bar_width - filled)
        lines.append(f"  {month:<10}  {total:>8.2f} {currency:<3}  [{bar}]")

    return "\n".join(lines)


_PAGE_SIZE = 15


class OVHBillingScreen(Screen):
    """OVH Billing Dashboard — shows usage, history, invoices, and services."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    _all_invoices: List[dict]
    _invoice_page: int

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]OVH Billing Dashboard[/bold cyan]", id="billing_title"),

                Static("[bold]Current Month[/bold]", classes="section_header"),
                Static("[dim]Loading...[/dim]", id="current_usage"),

                Static("[bold]Monthly History[/bold]", classes="section_header"),
                Static("[dim]Loading...[/dim]", id="spend_history"),

                Static("[bold]Invoices[/bold]", classes="section_header"),
                DataTable(id="invoices_table"),
                Static("", id="invoices_page_info"),
                Horizontal(
                    Button("Previous", id="btn_prev_page", variant="default"),
                    Button("Next", id="btn_next_page", variant="default"),
                    id="invoice_pagination",
                ),

                Static("[bold]Services[/bold]", classes="section_header"),
                DataTable(id="services_table"),

                Button("Back", id="btn_back", variant="default"),
                id="billing_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._all_invoices = []
        self._invoice_page = 0
        self._setup_tables()
        self.run_worker(self._load_current_usage(), exclusive=False)
        self.run_worker(self._load_spend_history(), exclusive=False)
        self.run_worker(self._load_invoices(), exclusive=False)
        self.run_worker(self._load_services(), exclusive=False)

    # ------------------------------------------------------------------
    # Table setup
    # ------------------------------------------------------------------

    def _setup_tables(self) -> None:
        invoices_tbl = self.query_one("#invoices_table", DataTable)
        invoices_tbl.add_columns("Date", "ID", "Amount", "Status")

        services_tbl = self.query_one("#services_table", DataTable)
        services_tbl.add_columns("Service", "Type", "State", "Expiry", "Auto-renew")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "btn_back":
            self.app.pop_screen()
        elif button_id == "btn_prev_page":
            if self._invoice_page > 0:
                self._invoice_page -= 1
                self._render_invoice_page()
        elif button_id == "btn_next_page":
            max_page = max(0, (len(self._all_invoices) - 1) // _PAGE_SIZE)
            if self._invoice_page < max_page:
                self._invoice_page += 1
                self._render_invoice_page()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        tbl: DataTable = event.data_table
        if tbl.id == "invoices_table":
            try:
                row_data = tbl.get_row(event.row_key)
                bill_id = str(row_data[1]) if len(row_data) > 1 else ""
                if bill_id:
                    self.notify(f"Invoice selected: {bill_id}", title="Invoice")
            except Exception:
                pass

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    async def _load_current_usage(self) -> None:
        svc = getattr(self.app, "ovh_billing_service", None)
        widget = self.query_one("#current_usage", Static)
        if svc is None:
            widget.update("[red]OVH billing service not available.[/red]")
            return
        try:
            usage = await svc.get_current_usage()
            widget.update(_format_current_usage(usage))
        except Exception as exc:
            logger.error("Failed to load OVH current usage: %s", exc)
            widget.update(f"[red]Error: {exc}[/red]")

    async def _load_spend_history(self) -> None:
        svc = getattr(self.app, "ovh_billing_service", None)
        widget = self.query_one("#spend_history", Static)
        if svc is None:
            widget.update("[red]OVH billing service not available.[/red]")
            return
        try:
            history = await svc.get_monthly_spend_history(months=6)
            widget.update(_format_spend_history(history))
        except Exception as exc:
            logger.error("Failed to load OVH spend history: %s", exc)
            widget.update(f"[red]Error: {exc}[/red]")

    async def _load_invoices(self) -> None:
        svc = getattr(self.app, "ovh_billing_service", None)
        if svc is None:
            return
        try:
            self._all_invoices = await svc.get_invoices()
            self._invoice_page = 0
            self._render_invoice_page()
        except Exception as exc:
            logger.error("Failed to load OVH invoices: %s", exc)
            self.notify(f"Error loading invoices: {exc}", severity="error")

    def _render_invoice_page(self) -> None:
        """Render the current page of invoices into the table."""
        tbl = self.query_one("#invoices_table", DataTable)
        tbl.clear()

        total = len(self._all_invoices)
        start = self._invoice_page * _PAGE_SIZE
        end = start + _PAGE_SIZE
        page_invoices = self._all_invoices[start:end]

        for inv in page_invoices:
            date = str(inv.get("date") or inv.get("billDate") or "")[:10]
            bill_id = str(inv.get("billId") or inv.get("id") or "")
            amount_raw = inv.get("priceWithTax") or inv.get("amount") or {}
            if isinstance(amount_raw, dict):
                value = amount_raw.get("value", "")
                currency = amount_raw.get("currencyCode", "")
                amount = f"{value} {currency}".strip() if value != "" else "n/a"
            else:
                amount = str(amount_raw) if amount_raw else "n/a"
            status = str(inv.get("status") or inv.get("pdfUrl") and "PDF" or "")
            tbl.add_row(date, bill_id, amount, status)

        max_page = max(0, (total - 1) // _PAGE_SIZE) if total else 0
        self.query_one("#invoices_page_info", Static).update(
            f"[dim]Page {self._invoice_page + 1} of {max_page + 1} ({total} invoices)[/dim]"
        )
        self.query_one("#btn_prev_page", Button).disabled = self._invoice_page <= 0
        self.query_one("#btn_next_page", Button).disabled = self._invoice_page >= max_page

    async def _load_services(self) -> None:
        svc = getattr(self.app, "ovh_billing_service", None)
        tbl = self.query_one("#services_table", DataTable)
        if svc is None:
            return
        try:
            services = await svc.get_service_list()
            if not services:
                tbl.add_row("[dim]No services found[/dim]", "", "", "", "")
                return
            for service in services:
                name = str(service.get("name", ""))
                svc_type = str(service.get("type", ""))
                status = str(service.get("status", ""))
                status_display = {
                    "ok": "[green]ok[/green]",
                    "expired": "[red]expired[/red]",
                    "unpaid": "[red]unpaid[/red]",
                    "pending": "[cyan]pending[/cyan]",
                }.get(status, status)
                expiry = str(service.get("expiration", ""))[:10]
                auto_renew = "[green]yes[/green]" if service.get("auto_renew") else "[dim]no[/dim]"
                tbl.add_row(name, svc_type, status_display, expiry, auto_renew)
        except Exception as exc:
            logger.error("Failed to load OVH services: %s", exc)
            self.notify(f"Error loading services: {exc}", severity="error")

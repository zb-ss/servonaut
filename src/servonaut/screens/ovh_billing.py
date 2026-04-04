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


class OVHBillingScreen(Screen):
    """OVH Billing Dashboard — shows usage, history, invoices, and services."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

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

                Static("[bold]Recent Invoices[/bold]", classes="section_header"),
                DataTable(id="invoices_table"),

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
        services_tbl.add_columns("Service", "Type", "Renewal", "Price")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if (event.button.id or "") == "btn_back":
            self.app.pop_screen()

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
        tbl = self.query_one("#invoices_table", DataTable)
        if svc is None:
            return
        try:
            invoices = await svc.get_invoices(limit=10)
            for inv in invoices:
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
        except Exception as exc:
            logger.error("Failed to load OVH invoices: %s", exc)
            self.notify(f"Error loading invoices: {exc}", severity="error")

    async def _load_services(self) -> None:
        svc = getattr(self.app, "ovh_billing_service", None)
        tbl = self.query_one("#services_table", DataTable)
        if svc is None:
            return
        try:
            services = await svc.get_service_list()
            for service in services:
                name = str(
                    service.get("serviceId")
                    or service.get("domain")
                    or service.get("serviceName")
                    or ""
                )
                svc_type = str(service.get("serviceType") or service.get("type") or "")
                renew_raw = service.get("renew") or {}
                if isinstance(renew_raw, dict):
                    renewal = str(renew_raw.get("nextDate") or renew_raw.get("period") or "")
                else:
                    renewal = str(renew_raw)
                price_raw = service.get("price") or {}
                if isinstance(price_raw, dict):
                    price = f"{price_raw.get('value', '')} {price_raw.get('currencyCode', '')}".strip()
                else:
                    price = str(price_raw)
                tbl.add_row(name, svc_type, renewal, price)
        except Exception as exc:
            logger.error("Failed to load OVH services: %s", exc)
            self.notify(f"Error loading services: {exc}", severity="error")

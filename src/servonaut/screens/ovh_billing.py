"""OVH billing dashboard screen for Servonaut.

Billing is per OVH account: with several accounts configured, a picker
chooses whose usage, invoices and services are shown.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, List

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.content import Content
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.widgets import Button, DataTable, Footer, Static


from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._provider_accounts import (
    UnknownAccountError,
    ovh_services,
    registry_for,
    show_account_labels,
)
from servonaut.services.ovh_billing_service import spend_history_from_invoices, usage_figures
from servonaut.utils.markup import literal
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


def _format_current_usage(usage: dict, *, redact: bool = False) -> str:
    """Render current usage / forecast as a readable string."""
    if not usage:
        return "  [dim]No data available.[/dim]"

    current, forecast = usage_figures(usage)
    if redact:
        current, forecast = (
            fig if fig in ("unavailable", "n/a") else "Hidden in demo mode"
            for fig in (current, forecast)
        )
    return (
        f"  Current spend : [$text-accent]{current}[/$text-accent]\n"
        f"  Forecast      : [$text-warning]{forecast}[/$text-warning]"
    )


def _format_spend_history(history: List[dict], *, redact: bool = False) -> str:
    """Render monthly spend history as an ASCII table with a simple bar."""
    if not history:
        return "  [dim]No history available.[/dim]"
    if redact:
        # Bar lengths also disclose the relative amounts spent each month.
        return "  [dim]Spend history hidden in demo mode.[/dim]"

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

# Longest a summary card may stay on "Loading..." before it reports a failure.
_CARD_TIMEOUT_SECONDS = 45

# Every worker that loads billing data, so an account switch can cancel
# the loads still running for the previous account.
_LOAD_GROUP = "ovh_billing_load"


class OVHBillingScreen(WorkspaceScreen):
    """OVH billing dashboard — shows usage, history, invoices, and services."""

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 64
    CONTENT_NARROW_WIDTH = 96

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    _all_invoices: List[dict]
    _invoice_page: int
    # Label of the chosen account; "" is the default account.
    _account: str = ""

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Billing")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield ScrollableContainer(
                Horizontal(
                    Vertical(
                        Static("OVH billing dashboard", id="billing_title", classes="screen-title"),
                        Static("Account usage, invoice history and billed services.", classes="resource-context"),
                        classes="provider-account-heading",
                    ),
                    AccountPicker.for_provider(
                        registry_for(self.app, "ovh"), "ovh", id="billing_account",
                    ),
                    classes="provider-account-heading-row",
                ),
                Horizontal(
                    Vertical(
                        Static("[bold]Current month[/bold]", classes="section_header"),
                        Static("[dim]Loading...[/dim]", id="current_usage"),
                        classes="resource-panel provider-billing-current",
                    ),
                    Vertical(
                        Static("[bold]Monthly history[/bold]", classes="section_header"),
                        Static("[dim]Loading...[/dim]", id="spend_history"),
                        classes="resource-panel provider-billing-history",
                    ),
                    classes="resource-billing-summary provider-billing-summary",
                ),
                Horizontal(
                    Vertical(
                        Static("[bold]Invoices[/bold]", classes="section_header"),
                        DataTable(id="invoices_table"),
                        Static("", id="invoices_page_info"),
                        Horizontal(
                            Button("Previous", id="btn_prev_page", variant="default"),
                            Button("Next", id="btn_next_page", variant="default"),
                            id="invoice_pagination",
                        ),
                        classes="resource-panel provider-billing-invoices",
                    ),
                    Vertical(
                        Static("[bold]Services[/bold]", classes="section_header"),
                        DataTable(id="services_table"),
                        classes="resource-panel provider-billing-services",
                    ),
                    classes="provider-billing-ledgers",
                ),
                Horizontal(
                    Button("Back", id="btn_back", variant="default"),
                    classes="resource-back-actions",
                ),
                id="billing_container",
                classes="workspace-content resource-workspace-content provider-account-workspace",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._all_invoices = []
        self._invoice_page = 0
        self._setup_tables()
        picker = self.query_one("#billing_account", AccountPicker)
        self._account = picker.account
        show_account_labels(picker)
        self.run_worker(self._gate_then_load(), group=_LOAD_GROUP, exclusive=False)

    def on_account_picker_changed(self, event: AccountPicker.Changed) -> None:
        """Another account was picked: show its billing instead."""
        self._account = event.account
        self._reload()

    def _reload(self) -> None:
        """Clear every panel and load it again for the chosen account."""
        self.workers.cancel_group(self, _LOAD_GROUP)
        for selector in ("#current_usage", "#spend_history"):
            self.query_one(selector, Static).update("[dim]Loading...[/dim]")
        self._all_invoices = []
        self._invoice_page = 0
        self._render_invoice_page()
        self.query_one("#services_table", DataTable).clear()
        self.run_worker(self._gate_then_load(), group=_LOAD_GROUP, exclusive=False)

    def _services(self):
        """The chosen account's services, or None after telling the user why."""
        try:
            return ovh_services(self.app, self._account)
        except UnknownAccountError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return None

    def _billing_service(self):
        services = self._services()
        return services.billing if services is not None else None

    async def _gate_then_load(self) -> None:
        """Verify OVH credentials once, then load every billing section.

        A revoked credential makes every billing endpoint return empty, so
        without this gate the screen would render four misleading "no data"
        panels. The one extra ``GET /me`` runs only at screen open.
        """
        services = self._services()
        if services is None:
            return
        ovh_svc = services.ovh
        if ovh_svc is not None:
            cred_error = await ovh_svc.check_credentials()
            if cred_error:
                self._show_credential_error(cred_error)
                return
        for loader in (
            self._load_current_usage, self._load_invoices, self._load_services,
        ):
            self.run_worker(loader(), group=_LOAD_GROUP, exclusive=False)

    def _show_credential_error(self, message: str) -> None:
        """Render an OVH credential failure across the billing panels.

        Args:
            message: Classified, user-facing error from ``check_credentials``.
        """
        if self.app.demo_mode:
            message = "Unable to verify OVH credentials. See logs for details."
        self.query_one("#current_usage", Static).update(
            literal(f"⚠ {message}", "$text-error")
        )
        self.query_one("#spend_history", Static).update("[dim]—[/dim]")

    def _display_error(self, error: Exception) -> str:
        """Keep arbitrary provider diagnostics out of public demo displays."""
        if self.app.demo_mode:
            return "Unable to load billing data. See logs for details."
        return str(error)

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

    def refresh_after_demo_toggle(self) -> None:
        """Remove already-rendered private values before asynchronous reloads."""
        show_account_labels(self.query_one("#billing_account", AccountPicker))
        for selector in ("#current_usage", "#spend_history"):
            self.query_one(selector, Static).update("[dim]Loading...[/dim]")
        self._render_invoice_page()
        self.query_one("#services_table", DataTable).clear()
        self.run_worker(self._gate_then_load(), group=_LOAD_GROUP, exclusive=False)

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _show_card_error(self, widget: Static, what: str) -> None:
        """End a card's loading state with a short, actionable line."""
        message = f"Could not load {what}. Reopen this screen to retry; details are in the log."
        widget.update(literal(f"  {message}", "$text-error"))

    def _show_unreadable_bill(self, widget: Static, what: str) -> None:
        """End a card's state when the bill data could not be read."""
        message = f"Could not read the bill data for {what}. Reopen this screen to retry; details are in the log."
        widget.update(literal(f"  {message}", "$text-error"))

    def _log_load_failure(self, what: str, exc: Exception) -> None:
        if isinstance(exc, asyncio.TimeoutError):
            logger.warning("Loading OVH %s timed out after %s s", what, _CARD_TIMEOUT_SECONDS)
        else:
            logger.exception("Failed to load OVH %s: %s", what, exc)

    async def _load_current_usage(self) -> None:
        svc = self._billing_service()
        widget = self.query_one("#current_usage", Static)
        if svc is None:
            widget.update("[$text-error]OVH billing service not available.[/$text-error]")
            return
        try:
            usage = await asyncio.wait_for(
                svc.get_current_usage(), timeout=_CARD_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            self._log_load_failure("current usage", exc)
            self._show_card_error(widget, "the current month")
            return
        try:
            widget.update(_format_current_usage(usage, redact=self.app.demo_mode))
        except Exception as exc:
            logger.exception("Could not read the OVH usage: %s", exc)
            self._show_unreadable_bill(widget, "the current month")

    async def _load_invoices(self) -> None:
        """Fetch each bill once and fill both the invoice list and the history."""
        svc = self._billing_service()
        history = self.query_one("#spend_history", Static)
        page_info = self.query_one("#invoices_page_info", Static)
        if svc is None:
            history.update("[$text-error]OVH billing service not available.[/$text-error]")
            page_info.update("")
            return
        page_info.update("[dim]Loading...[/dim]")
        try:
            self._all_invoices = await asyncio.wait_for(
                svc.get_invoices(), timeout=_CARD_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            self._log_load_failure("invoices", exc)
            self._show_card_error(history, "the monthly history")
            self._show_card_error(page_info, "the invoices")
            return
        self._invoice_page = 0
        try:
            self._render_invoice_page()
            history.update(_format_spend_history(
                spend_history_from_invoices(self._all_invoices, months=6),
                redact=self.app.demo_mode,
            ))
        except Exception as exc:
            # A bill the parser cannot read must not end the app.
            logger.exception("Could not read the OVH bills: %s", exc)
            self._all_invoices = []
            self.query_one("#invoices_table", DataTable).clear()
            self._show_unreadable_bill(history, "the monthly history")
            self._show_unreadable_bill(page_info, "the invoices")
            for name in ("#btn_prev_page", "#btn_next_page"):
                self.query_one(name, Button).disabled = True

    def _render_invoice_page(self) -> None:
        """Render the current page of invoices into the table."""
        tbl = self.query_one("#invoices_table", DataTable)
        tbl.clear()

        total = len(self._all_invoices)
        start = self._invoice_page * _PAGE_SIZE
        end = start + _PAGE_SIZE
        page_invoices = self._all_invoices[start:end]

        for index, inv in enumerate(page_invoices, start=start + 1):
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
            if self.app.demo_mode:
                bill_id = f"invoice-{index:03d}"
                amount = "Hidden"
            # API text, and the table parses str cells as markup when it paints.
            tbl.add_row(Text(date), Text(bill_id), Text(amount), Text(status))

        max_page = max(0, (total - 1) // _PAGE_SIZE) if total else 0
        self.query_one("#invoices_page_info", Static).update(
            f"[dim]Page {self._invoice_page + 1} of {max_page + 1} ({total} invoices)[/dim]"
        )
        self.query_one("#btn_prev_page", Button).disabled = self._invoice_page <= 0
        self.query_one("#btn_next_page", Button).disabled = self._invoice_page >= max_page

    async def _load_services(self) -> None:
        svc = self._billing_service()
        tbl = self.query_one("#services_table", DataTable)
        if svc is None:
            return
        try:
            services = await svc.get_service_list()
            if not services:
                tbl.add_row("[dim]No services found[/dim]", "", "", "", "")
                return
            def _h(x: str) -> str:
                # Service names are domains or dashed-IP hostnames.
                if self.app.demo_mode:
                    if self.app.redaction_service:
                        return self.app.redaction_service.redact_host(x)
                    return "Hidden"
                return x

            for service in services:
                name = _h(str(service.get("name", "")))
                svc_type = str(service.get("type", ""))
                status = str(service.get("status", ""))
                status_display = {
                    "ok": Content.styled("ok", "$text-success"),
                    "expired": Content.styled("expired", "$text-error"),
                    "unpaid": Content.styled("unpaid", "$text-error"),
                    "pending": Content.styled("pending", "$text-accent"),
                }.get(status) or literal(status)
                expiry = str(service.get("expiration", ""))[:10]
                auto_renew = (
                    Content.styled("yes", "$text-success") if service.get("auto_renew")
                    else Content.styled("no", "$text-muted")
                )
                tbl.add_row(name, svc_type, status_display, expiry, auto_renew)
        except Exception as exc:
            logger.error("Failed to load OVH services: %s", exc)
            self.notify(f"Error loading services: {self._display_error(exc)}", severity="error", markup=False)

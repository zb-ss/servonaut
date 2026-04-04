"""OVH DNS zone and record management screen for Servonaut."""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class OVHDNSScreen(Screen):
    """OVH DNS Management — browse zones and manage DNS records."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Internal state
    # ------------------------------------------------------------------

    _domains: List[str]
    _records: List[dict]
    _selected_zone: Optional[str]
    _edit_record_id: Optional[int]

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]OVH DNS Management[/bold cyan]", id="dns_title"),

                Static("[bold]Domains[/bold]", classes="section_header"),
                DataTable(id="domains_table"),

                Static("[bold]DNS Records[/bold]", classes="section_header", id="records_section_header"),
                Static("", id="selected_zone"),
                DataTable(id="records_table"),

                Horizontal(
                    Button("Add Record", variant="primary", id="btn_add"),
                    Button("Edit Record", variant="default", id="btn_edit"),
                    Button("Delete Record", variant="error", id="btn_delete"),
                    Button("Refresh Zone", variant="default", id="btn_refresh_zone"),
                    Button("Back", variant="default", id="btn_back"),
                    id="dns_actions",
                ),

                # Add / Edit form — hidden by default
                Container(
                    Static("[bold]Record Details[/bold]", classes="section_header"),
                    Input(placeholder="A, AAAA, CNAME, MX, TXT, SRV", id="input_type"),
                    Input(placeholder="www, mail, @", id="input_subdomain"),
                    Input(placeholder="1.2.3.4 or hostname", id="input_target"),
                    Input(placeholder="3600", id="input_ttl"),
                    Horizontal(
                        Button("Save Record", variant="primary", id="btn_save"),
                        Button("Cancel", variant="default", id="btn_cancel_form"),
                        classes="add_row",
                    ),
                    id="record_form",
                ),

                id="dns_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._domains = []
        self._records = []
        self._selected_zone = None
        self._edit_record_id = None
        self._setup_tables()
        self._hide_form()
        self.run_worker(self._load_domains(), exclusive=True)

    def _setup_tables(self) -> None:
        domains_tbl = self.query_one("#domains_table", DataTable)
        domains_tbl.cursor_type = "row"
        domains_tbl.add_columns("Domain")

        records_tbl = self.query_one("#records_table", DataTable)
        records_tbl.cursor_type = "row"
        records_tbl.add_columns("Type", "Subdomain", "Target", "TTL")

    # ------------------------------------------------------------------
    # Form visibility helpers
    # ------------------------------------------------------------------

    def _hide_form(self) -> None:
        self.query_one("#record_form").display = False

    def _show_add_form(self) -> None:
        self._edit_record_id = None
        self.query_one("#input_type", Input).value = ""
        self.query_one("#input_subdomain", Input).value = ""
        self.query_one("#input_target", Input).value = ""
        self.query_one("#input_ttl", Input).value = "3600"
        self.query_one("#record_form").display = True
        self.query_one("#input_type", Input).focus()

    def _show_edit_form(self, record: dict) -> None:
        self._edit_record_id = record.get("id")
        self.query_one("#input_type", Input).value = str(record.get("fieldType", ""))
        self.query_one("#input_subdomain", Input).value = str(record.get("subDomain", ""))
        self.query_one("#input_target", Input).value = str(record.get("target", ""))
        self.query_one("#input_ttl", Input).value = str(record.get("ttl", 3600))
        self.query_one("#record_form").display = True
        self.query_one("#input_target", Input).focus()

    # ------------------------------------------------------------------
    # Data helpers
    # ------------------------------------------------------------------

    def _get_dns_service(self):
        return getattr(self.app, "ovh_dns_service", None)

    def _get_selected_domain(self) -> Optional[str]:
        tbl = self.query_one("#domains_table", DataTable)
        row = tbl.cursor_row
        if tbl.row_count == 0 or row < 0 or row >= len(self._domains):
            return None
        return self._domains[row]

    def _get_selected_record(self) -> Optional[dict]:
        tbl = self.query_one("#records_table", DataTable)
        row = tbl.cursor_row
        if tbl.row_count == 0 or row < 0 or row >= len(self._records):
            return None
        return self._records[row]

    # ------------------------------------------------------------------
    # Workers — data loading
    # ------------------------------------------------------------------

    async def _load_domains(self) -> None:
        svc = self._get_dns_service()
        tbl = self.query_one("#domains_table", DataTable)
        tbl.clear()

        if svc is None:
            self.notify("OVH DNS service not available", severity="error")
            return

        try:
            domains = await svc.list_domains()
            self._domains = domains
            for domain in domains:
                tbl.add_row(domain)
        except Exception as exc:
            logger.error("_load_domains failed: %s", exc)
            self.notify(f"Error loading domains: {exc}", severity="error")

    async def _load_records(self, zone_name: str) -> None:
        svc = self._get_dns_service()
        tbl = self.query_one("#records_table", DataTable)
        tbl.clear()
        self._records = []

        if svc is None:
            return

        self.query_one("#selected_zone", Static).update(
            f"Records for: [bold]{zone_name}[/bold]"
        )

        try:
            records = await svc.list_records(zone_name)
            self._records = records
            for rec in records:
                sub = rec.get("subDomain") or "@"
                tbl.add_row(
                    str(rec.get("fieldType", "")),
                    sub,
                    str(rec.get("target", "")),
                    str(rec.get("ttl", "")),
                )
        except Exception as exc:
            logger.error("_load_records(%r) failed: %s", zone_name, exc)
            self.notify(f"Error loading records: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "domains_table":
            zone = self._get_selected_domain()
            if zone:
                self._selected_zone = zone
                self._hide_form()
                self.run_worker(self._load_records(zone), exclusive=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""

        if button_id == "btn_back":
            self.action_back()
        elif button_id == "btn_add":
            self._action_add()
        elif button_id == "btn_edit":
            self._action_edit()
        elif button_id == "btn_delete":
            self._action_delete()
        elif button_id == "btn_refresh_zone":
            self._action_refresh_zone()
        elif button_id == "btn_save":
            self._action_save()
        elif button_id == "btn_cancel_form":
            self._hide_form()

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Add record
    # ------------------------------------------------------------------

    def _action_add(self) -> None:
        if not self._selected_zone:
            self.notify("Select a domain first", severity="warning")
            return
        self._show_add_form()

    # ------------------------------------------------------------------
    # Edit record
    # ------------------------------------------------------------------

    def _action_edit(self) -> None:
        if not self._selected_zone:
            self.notify("Select a domain first", severity="warning")
            return
        record = self._get_selected_record()
        if record is None:
            self.notify("No record selected", severity="warning")
            return
        self._show_edit_form(record)

    # ------------------------------------------------------------------
    # Save (create or update)
    # ------------------------------------------------------------------

    def _action_save(self) -> None:
        if not self._selected_zone:
            self.notify("No zone selected", severity="warning")
            return

        field_type = self.query_one("#input_type", Input).value.strip().upper()
        sub_domain = self.query_one("#input_subdomain", Input).value.strip()
        target = self.query_one("#input_target", Input).value.strip()
        ttl_str = self.query_one("#input_ttl", Input).value.strip()

        if not field_type:
            self.notify("Record type is required", severity="error")
            self.query_one("#input_type", Input).focus()
            return
        if not target:
            self.notify("Target is required", severity="error")
            self.query_one("#input_target", Input).focus()
            return

        ttl = 3600
        if ttl_str:
            if not ttl_str.isdigit() or int(ttl_str) <= 0:
                self.notify("TTL must be a positive integer", severity="error")
                self.query_one("#input_ttl", Input).focus()
                return
            ttl = int(ttl_str)

        self._hide_form()

        if self._edit_record_id is not None:
            self.run_worker(
                self._update_record(
                    self._selected_zone,
                    self._edit_record_id,
                    sub_domain,
                    target,
                    ttl,
                ),
                exclusive=False,
            )
        else:
            self.run_worker(
                self._create_record(self._selected_zone, field_type, sub_domain, target, ttl),
                exclusive=False,
            )

    async def _create_record(
        self,
        zone_name: str,
        field_type: str,
        sub_domain: str,
        target: str,
        ttl: int,
    ) -> None:
        svc = self._get_dns_service()
        if svc is None:
            self.notify("OVH DNS service not available", severity="error")
            return
        try:
            await svc.create_record(zone_name, field_type, sub_domain, target, ttl)
            audit = getattr(self.app, "ovh_audit", None)
            if audit:
                audit.log_action(
                    "dns_create_record",
                    zone_name,
                    {"fieldType": field_type, "subDomain": sub_domain, "target": target, "ttl": ttl},
                    confirmed=True,
                )
            await svc.refresh_zone(zone_name)
            self.notify(f"Record created in {zone_name}", severity="information")
            await self._load_records(zone_name)
        except Exception as exc:
            logger.error("_create_record failed: %s", exc)
            self.notify(f"Error creating record: {exc}", severity="error")

    async def _update_record(
        self,
        zone_name: str,
        record_id: int,
        sub_domain: str,
        target: str,
        ttl: int,
    ) -> None:
        svc = self._get_dns_service()
        if svc is None:
            self.notify("OVH DNS service not available", severity="error")
            return
        try:
            await svc.update_record(zone_name, record_id, sub_domain=sub_domain, target=target, ttl=ttl)
            audit = getattr(self.app, "ovh_audit", None)
            if audit:
                audit.log_action(
                    "dns_update_record",
                    zone_name,
                    {"record_id": record_id, "subDomain": sub_domain, "target": target, "ttl": ttl},
                    confirmed=True,
                )
            await svc.refresh_zone(zone_name)
            self.notify(f"Record {record_id} updated in {zone_name}", severity="information")
            await self._load_records(zone_name)
        except Exception as exc:
            logger.error("_update_record failed: %s", exc)
            self.notify(f"Error updating record: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Delete record
    # ------------------------------------------------------------------

    def _action_delete(self) -> None:
        if not self._selected_zone:
            self.notify("Select a domain first", severity="warning")
            return
        record = self._get_selected_record()
        if record is None:
            self.notify("No record selected", severity="warning")
            return

        zone_name = self._selected_zone
        record_id = record.get("id")
        confirm_text = str(record.get("target", str(record_id)))

        async def _confirm_and_delete() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Delete DNS Record",
                    description=(
                        f"Permanently delete [bold]{record.get('fieldType', '')}[/bold] record "
                        f"[bold]{record.get('subDomain') or '@'}[/bold] pointing to "
                        f"[bold]{confirm_text}[/bold]."
                    ),
                    consequences=[
                        "This record will be removed from the zone immediately after refresh",
                        "DNS propagation may take time depending on upstream TTL caching",
                    ],
                    confirm_text=confirm_text,
                    action_label="Delete Record",
                    severity="warning",
                )
            )
            if confirmed:
                audit = getattr(self.app, "ovh_audit", None)
                if audit:
                    audit.log_action(
                        "dns_delete_record",
                        zone_name,
                        {"record_id": record_id, "target": confirm_text},
                        confirmed=True,
                    )
                await self._delete_record(zone_name, record_id)

        self.run_worker(_confirm_and_delete(), exclusive=False)

    async def _delete_record(self, zone_name: str, record_id: int) -> None:
        svc = self._get_dns_service()
        if svc is None:
            self.notify("OVH DNS service not available", severity="error")
            return
        try:
            await svc.delete_record(zone_name, record_id)
            await svc.refresh_zone(zone_name)
            self.notify(f"Record deleted from {zone_name}", severity="information")
            await self._load_records(zone_name)
        except Exception as exc:
            logger.error("_delete_record failed: %s", exc)
            self.notify(f"Error deleting record: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Refresh zone
    # ------------------------------------------------------------------

    def _action_refresh_zone(self) -> None:
        if not self._selected_zone:
            self.notify("Select a domain first", severity="warning")
            return
        self.run_worker(self._do_refresh_zone(self._selected_zone), exclusive=False)

    async def _do_refresh_zone(self, zone_name: str) -> None:
        svc = self._get_dns_service()
        if svc is None:
            self.notify("OVH DNS service not available", severity="error")
            return
        try:
            await svc.refresh_zone(zone_name)
            self.notify(f"Zone {zone_name} refreshed", severity="information")
            await self._load_records(zone_name)
        except Exception as exc:
            logger.error("_do_refresh_zone(%r) failed: %s", zone_name, exc)
            self.notify(f"Error refreshing zone: {exc}", severity="error")

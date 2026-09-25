"""OVH DNS zone and record management screen for Servonaut."""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from rich.markup import escape

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._demo_resolve import keep_cursor
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
    _edit_target_raw: str
    _edit_target_display: str
    _edit_subdomain_raw: str
    _edit_subdomain_display: str
    _rdns_entries: List[dict]
    _edit_rdns_ip_block: Optional[str]
    _edit_rdns_ip: Optional[str]
    _edit_rdns_hostname: str
    _edit_rdns_display_hostname: str

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]OVH DNS Management[/bold cyan]", id="dns_title"),

                Static(
                    "[bold]Domains[/bold]", classes="section_header",
                    id="domains_section_header",
                ),
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
                    Input(placeholder="192.0.2.1 or hostname", id="input_target"),
                    Input(placeholder="3600", id="input_ttl"),
                    Horizontal(
                        Button("Save Record", variant="primary", id="btn_save"),
                        Button("Cancel", variant="default", id="btn_cancel_form"),
                        classes="add_row",
                    ),
                    id="record_form",
                ),

                # Reverse DNS section
                Static("[bold cyan]Reverse DNS[/bold cyan]", classes="section_header", id="rdns_section_header"),
                Static("[dim]PTR records for all IPs on this account[/dim]"),
                DataTable(id="rdns_table"),

                Horizontal(
                    Button("Edit rDNS", variant="default", id="btn_rdns_edit"),
                    Button("Delete rDNS", variant="error", id="btn_rdns_delete"),
                    Button("Reload rDNS", variant="default", id="btn_rdns_reload"),
                    id="rdns_actions",
                ),

                # rDNS edit form — hidden by default
                Container(
                    Static("[bold]Reverse DNS Details[/bold]", classes="section_header"),
                    Static("", id="rdns_form_ip_label"),
                    Input(placeholder="server.example.com", id="input_rdns_hostname"),
                    Horizontal(
                        Button("Save rDNS", variant="primary", id="btn_rdns_save"),
                        Button("Cancel", variant="default", id="btn_rdns_cancel"),
                        classes="add_row",
                    ),
                    id="rdns_form",
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
        self._rdns_entries = []
        self._rdns_loaded = False
        self._edit_rdns_ip_block = None
        self._edit_rdns_ip = None
        self._setup_tables()
        self._hide_form()
        self._hide_rdns_form()
        self.run_worker(self._load_domains(), exclusive=False)
        self.run_worker(self._load_rdns(), exclusive=False)

    def _setup_tables(self) -> None:
        domains_tbl = self.query_one("#domains_table", DataTable)
        domains_tbl.cursor_type = "row"
        domains_tbl.add_columns("Domain")

        records_tbl = self.query_one("#records_table", DataTable)
        records_tbl.cursor_type = "row"
        records_tbl.add_columns("Type", "Subdomain", "Target", "TTL")

        rdns_tbl = self.query_one("#rdns_table", DataTable)
        rdns_tbl.cursor_type = "row"
        rdns_tbl.add_columns("IP Address", "Hostname", "IP Block")

    # ------------------------------------------------------------------
    # Form visibility helpers
    # ------------------------------------------------------------------

    def _hide_form(self) -> None:
        self.query_one("#record_form").display = False

    def _hide_rdns_form(self) -> None:
        self.query_one("#rdns_form").display = False

    def _show_rdns_form(self, ip: str, ip_block: str, current_hostname: str = "") -> None:
        self._edit_rdns_ip = ip
        self._edit_rdns_ip_block = ip_block
        self._edit_rdns_hostname = current_hostname
        self._edit_rdns_display_hostname = self.redact_rdns_host(current_hostname)
        self.query_one("#rdns_form_ip_label", Static).update(
            f"[dim]IP:[/dim] {escape(self.redact_rdns_host(ip))}  "
            f"[dim]Block:[/dim] {escape(self.redact_rdns_host(ip_block))}"
        )
        self.query_one("#input_rdns_hostname", Input).value = self._edit_rdns_display_hostname
        self.query_one("#rdns_form").display = True
        self.query_one("#input_rdns_hostname", Input).focus(scroll_visible=False)
        # The hidden form has no usable geometry until the next layout pass.
        self.call_after_refresh(
            self.query_one("#dns_container").scroll_end, animate=False,
        )

    def redact_rdns_host(self, value: str) -> str:
        """Render hosts consistently without changing provider operation targets."""
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_host(value)
        return value

    def _display_subdomain(self, sub_domain: str) -> str:
        """A record's zone-relative name; a demo-mode stand-in when redacted.

        Sub-domains are often single labels (``api``, a project name) that
        no host rule recognises, so they get the DNS-label redactor.
        """
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_dns_label(sub_domain)
        return sub_domain

    def refresh_after_demo_toggle(self) -> None:
        """Redraw zones, records and reverse DNS from what was fetched.

        Open forms hold values rendered for the previous mode, so they close.
        """
        self._hide_form()
        self._hide_rdns_form()
        with keep_cursor(self):
            self._render_domains()
            if self._selected_zone:
                self._render_records(self._selected_zone)
            if self._rdns_loaded:
                self._render_rdns()

    def _provider_error(self, error: Exception) -> str:
        """Provider diagnostics may contain identifiers outside the current row."""
        if self.app.demo_mode:
            return "Provider request failed. See logs for details."
        return str(error)

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
        self._edit_target_raw = str(record.get("target", ""))
        self._edit_target_display = self._display_record_target(record)
        self._edit_subdomain_raw = str(record.get("subDomain", ""))
        self._edit_subdomain_display = self._display_subdomain(self._edit_subdomain_raw)
        self.query_one("#input_type", Input).value = str(record.get("fieldType", ""))
        self.query_one("#input_subdomain", Input).value = self._edit_subdomain_display
        self.query_one("#input_target", Input).value = self._edit_target_display
        self.query_one("#input_ttl", Input).value = str(record.get("ttl", 3600))
        self.query_one("#record_form").display = True
        self.query_one("#input_target", Input).focus()

    def _display_record_target(self, record: dict) -> str:
        """Free-form DNS values may contain verification tokens or embedded hosts."""
        target = str(record.get("target", ""))
        if not self.app.demo_mode:
            return target
        if not self.app.redaction_service:
            return "Hidden"
        if record.get("fieldType") in {"A", "AAAA", "CNAME", "NS", "PTR"}:
            return self.redact_rdns_host(target)
        return "Hidden"

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

    def _get_ip_service(self):
        return getattr(self.app, "ovh_ip_service", None)

    def _get_selected_rdns(self) -> Optional[dict]:
        tbl = self.query_one("#rdns_table", DataTable)
        row = tbl.cursor_row
        if tbl.row_count == 0 or row < 0 or row >= len(self._rdns_entries):
            return None
        return self._rdns_entries[row]

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
            self._render_domains()
            if domains:
                self._set_domains_status(None)
            else:
                # list_domains() swallows API errors and returns [] — an
                # empty result might be a revoked credential, not zero zones.
                ovh_svc = getattr(self.app, "ovh_service", None)
                cred_error = (
                    await ovh_svc.check_credentials() if ovh_svc else None
                )
                self._set_domains_status(cred_error)
        except Exception as exc:
            logger.error("_load_domains failed: %s", exc)
            self.notify(
                f"Error loading domains: {self._provider_error(exc)}",
                severity="error", markup=False,
            )

    def _render_domains(self) -> None:
        tbl = self.query_one("#domains_table", DataTable)
        tbl.clear()
        for domain in self._domains:
            # Zone names are hostnames by definition -- the stream scrubber
            # has no bare-hostname rule, so they go through redact_host.
            tbl.add_row(self.redact_rdns_host(domain))

    def _set_domains_status(self, error: Optional[str]) -> None:
        """Show or clear an OVH credential error under the Domains header.

        Args:
            error: Classified error message, or None to restore the plain
                header (no credential problem).
        """
        try:
            header = self.query_one("#domains_section_header", Static)
        except Exception:  # pragma: no cover - defensive
            return
        if not error:
            header.update("[bold]Domains[/bold]")
            return
        if self.app.demo_mode and self.app.redaction_service:
            error = self.app.redaction_service.scrub_stream(error)
        header.update(f"[bold]Domains[/bold]\n[red]⚠ {escape(error)}[/red]")

    async def _load_records(self, zone_name: str) -> None:
        svc = self._get_dns_service()
        self.query_one("#records_table", DataTable).clear()
        self._records = []

        if svc is None:
            return

        self._render_records(zone_name)
        try:
            self._records = await svc.list_records(zone_name)
            self._render_records(zone_name)
        except Exception as exc:
            logger.error("_load_records(%r) failed: %s", zone_name, exc)
            self.notify(f"Error loading records: {self._provider_error(exc)}", severity="error")

    def _render_records(self, zone_name: str) -> None:
        self.query_one("#selected_zone", Static).update(
            f"Records for: [bold]{escape(self.redact_rdns_host(zone_name))}[/bold]"
        )
        tbl = self.query_one("#records_table", DataTable)
        tbl.clear()
        for rec in self._records:
            tbl.add_row(
                str(rec.get("fieldType", "")),
                self._display_subdomain(rec.get("subDomain") or "@"),
                self._display_record_target(rec),
                str(rec.get("ttl", "")),
            )

    async def _load_rdns(self) -> None:
        """Load reverse DNS entries for all IP blocks on the account."""
        ip_svc = self._get_ip_service()
        self.query_one("#rdns_table", DataTable).clear()
        self._rdns_entries = []
        self._rdns_loaded = False

        if ip_svc is None:
            return

        try:
            ip_blocks = await ip_svc.list_ips()
        except Exception as exc:
            logger.error("_load_rdns: list_ips failed: %s", exc)
            return

        entries_found: List[dict] = []
        for ip_info in ip_blocks:
            ip_block = ip_info.get("ip", "")
            if not ip_block:
                continue
            try:
                entries = await ip_svc.list_reverse_dns(ip_block)
                for entry in entries:
                    ip_addr = entry.get("ipReverse", "")
                    if ip_addr:
                        entries_found.append({
                            "ip": ip_addr,
                            "hostname": entry.get("reverse", ""),
                            "ip_block": ip_block,
                        })
            except Exception as exc:
                logger.error("_load_rdns: list_reverse_dns(%r) failed: %s", ip_block, exc)

        self._rdns_entries = entries_found
        self._rdns_loaded = True
        self._render_rdns()

    def _render_rdns(self) -> None:
        tbl = self.query_one("#rdns_table", DataTable)
        tbl.clear()
        for record in self._rdns_entries:
            hostname = record.get("hostname", "")
            tbl.add_row(
                self.redact_rdns_host(record.get("ip", "")),
                self.redact_rdns_host(hostname) if hostname else "[dim]not set[/dim]",
                self.redact_rdns_host(record.get("ip_block", "")),
            )
        if not self._rdns_entries:
            tbl.add_row("[dim]No reverse DNS entries found[/dim]", "", "")

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
        # Reverse DNS buttons
        elif button_id == "btn_rdns_edit":
            self._action_rdns_edit()
        elif button_id == "btn_rdns_delete":
            self._action_rdns_delete()
        elif button_id == "btn_rdns_reload":
            self.run_worker(self._load_rdns(), exclusive=False)
        elif button_id == "btn_rdns_save":
            self._action_rdns_save()
        elif button_id == "btn_rdns_cancel":
            self._hide_rdns_form()

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
            if target == self._edit_target_display:
                target = self._edit_target_raw
            if sub_domain == self._edit_subdomain_display:
                sub_domain = self._edit_subdomain_raw
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
            self.notify(f"Record created in {self.redact_rdns_host(zone_name)}", severity="information")
            await self._load_records(zone_name)
        except Exception as exc:
            logger.error("_create_record failed: %s", exc)
            self.notify(f"Error creating record: {self._provider_error(exc)}", severity="error")

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
            label = "Record" if self.app.demo_mode else f"Record {record_id}"
            self.notify(f"{label} updated in {self.redact_rdns_host(zone_name)}", severity="information")
            await self._load_records(zone_name)
        except Exception as exc:
            logger.error("_update_record failed: %s", exc)
            self.notify(f"Error updating record: {self._provider_error(exc)}", severity="error")

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
        raw_target = str(record.get("target", str(record_id)))
        confirm_text = self._display_record_target(record) if self.app.demo_mode else raw_target
        display_subdomain = self._display_subdomain(record.get("subDomain") or "@")

        async def _confirm_and_delete() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Delete DNS Record",
                    description=(
                        f"Permanently delete [bold]{record.get('fieldType', '')}[/bold] record "
                        f"[bold]{display_subdomain}[/bold] pointing to "
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
                        {"record_id": record_id, "target": raw_target},
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
            self.notify(f"Record deleted from {self.redact_rdns_host(zone_name)}", severity="information")
            await self._load_records(zone_name)
        except Exception as exc:
            logger.error("_delete_record failed: %s", exc)
            self.notify(f"Error deleting record: {self._provider_error(exc)}", severity="error")

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
            self.notify(f"Zone {self.redact_rdns_host(zone_name)} refreshed", severity="information")
            await self._load_records(zone_name)
        except Exception as exc:
            logger.error("_do_refresh_zone(%r) failed: %s", zone_name, exc)
            self.notify(f"Error refreshing zone: {self._provider_error(exc)}", severity="error")

    # ------------------------------------------------------------------
    # Reverse DNS — edit
    # ------------------------------------------------------------------

    def _action_rdns_edit(self) -> None:
        entry = self._get_selected_rdns()
        if entry is None:
            self.notify("No rDNS entry selected", severity="warning")
            return
        self._hide_form()
        self._show_rdns_form(
            ip=entry.get("ip", ""),
            ip_block=entry.get("ip_block", ""),
            current_hostname=entry.get("hostname", ""),
        )

    def _action_rdns_save(self) -> None:
        if not self._edit_rdns_ip or not self._edit_rdns_ip_block:
            self.notify("No rDNS entry selected for editing", severity="warning")
            return

        hostname = self.query_one("#input_rdns_hostname", Input).value.strip()
        if not hostname:
            self.notify("Hostname is required", severity="error")
            self.query_one("#input_rdns_hostname", Input).focus()
            return

        # An unchanged demo alias is presentation, never a replacement PTR.
        if hostname == self._edit_rdns_display_hostname.strip():
            hostname = self._edit_rdns_hostname

        self._hide_rdns_form()
        self.run_worker(
            self._save_rdns(self._edit_rdns_ip_block, self._edit_rdns_ip, hostname),
            exclusive=False,
        )

    async def _save_rdns(self, ip_block: str, ip: str, hostname: str) -> None:
        ip_svc = self._get_ip_service()
        if ip_svc is None:
            self.notify("OVH IP service not available", severity="error")
            return
        try:
            await ip_svc.set_reverse_dns(ip_block, ip, hostname)
            audit = getattr(self.app, "ovh_audit", None)
            if audit:
                audit.log_action(
                    "rdns_set",
                    ip_block,
                    {"ip": ip, "reverse": hostname},
                    confirmed=True,
                )
            self.notify(f"Reverse DNS set for {self.redact_rdns_host(ip)}", severity="information")
            await self._load_rdns()
        except Exception as exc:
            logger.error("_save_rdns failed: %s", exc)
            self.notify(f"Error setting rDNS: {self._provider_error(exc)}", severity="error")

    # ------------------------------------------------------------------
    # Reverse DNS — delete
    # ------------------------------------------------------------------

    def _action_rdns_delete(self) -> None:
        entry = self._get_selected_rdns()
        if entry is None:
            self.notify("No rDNS entry selected", severity="warning")
            return

        ip = entry.get("ip", "")
        ip_block = entry.get("ip_block", "")
        hostname = entry.get("hostname", "")
        display_ip = self.redact_rdns_host(ip)
        display_hostname = self.redact_rdns_host(hostname)

        async def _confirm_and_delete_rdns() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Delete Reverse DNS",
                    description=(
                        f"Remove reverse DNS for [bold]{escape(display_ip)}[/bold] "
                        f"(currently [bold]{escape(display_hostname or 'not set')}[/bold])."
                    ),
                    consequences=[
                        "The PTR record will be removed",
                        "Mail servers may reject email from this IP without valid rDNS",
                    ],
                    confirm_text=display_ip,
                    action_label="Delete rDNS",
                    severity="warning",
                )
            )
            if confirmed:
                audit = getattr(self.app, "ovh_audit", None)
                if audit:
                    audit.log_action(
                        "rdns_delete",
                        ip_block,
                        {"ip": ip, "hostname": hostname},
                        confirmed=True,
                    )
                await self._do_delete_rdns(ip_block, ip)

        self.run_worker(_confirm_and_delete_rdns(), exclusive=False)

    async def _do_delete_rdns(self, ip_block: str, ip: str) -> None:
        ip_svc = self._get_ip_service()
        if ip_svc is None:
            self.notify("OVH IP service not available", severity="error")
            return
        try:
            await ip_svc.delete_reverse_dns(ip_block, ip)
            self.notify(f"Reverse DNS deleted for {self.redact_rdns_host(ip)}", severity="information")
            await self._load_rdns()
        except Exception as exc:
            logger.error("_do_delete_rdns failed: %s", exc)
            self.notify(f"Error deleting rDNS: {self._provider_error(exc)}", severity="error")

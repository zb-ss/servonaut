"""DbFleetScanScreen — fleet / bulk DB-credential scan review (Layer B3).

Drives :class:`DbFleetScanService`: scan the fleet (concurrency-bounded)
into ONE review table with an "already-vaulted?" column, then commit all
committable rows (or the selected one). Skips already-vaulted instances
and isolates per-box failures — one bad box never aborts the batch.

Only ``redact()`` previews (masked passwords) are ever rendered; plaintext
stays server-side in staging, committed by token via ``db_setup_save``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.services.db_fleet_scan_service import (
    DbFleetScanService,
    FleetDbScanResult,
    FleetDbScanRow,
)
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class DbFleetScanScreen(Screen):
    """Bulk-scan the fleet for DB credentials and commit them to the vault."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("s", "rescan", "Rescan", show=True),
        Binding("a", "commit_all", "Commit all", show=True),
    ]

    def __init__(self, instances: List[Dict[str, Any]]) -> None:
        super().__init__()
        self._instances = instances
        self._result: Optional[FleetDbScanResult] = None
        self._rows_by_id: Dict[str, FleetDbScanRow] = {}

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static("🔐 Fleet DB-credential scan", id="fleet_db_title"),
                Static(
                    f"Read-only scan of {len(self._instances)} instance(s). "
                    "Review the redacted candidates, then commit all (skips "
                    "servers already in the vault) or the selected row.",
                    id="fleet_db_subtitle",
                ),
                VerticalScroll(
                    Static("Scanning…", id="fleet_db_status"),
                    DataTable(id="fleet_db_table", cursor_type="row"),
                    Horizontal(
                        Button("Commit all", id="fleet_commit_all", variant="success"),
                        Button("Commit selected", id="fleet_commit_selected"),
                        Button("Rescan", id="fleet_rescan"),
                        id="fleet_db_buttons",
                    ),
                    id="fleet_db_body",
                ),
                id="fleet_db_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#fleet_db_table", DataTable)
        table.add_columns("Server", "Engine", "User", "DB", "Password", "Vaulted", "Status")
        self._start_scan()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_status(self, message: str, *, error: bool = False) -> None:
        # Demo mode: scrub IP/host/path identifiers from the status line.
        if self.app.demo_mode and self.app.redaction_service:
            message = self.app.redaction_service.scrub_stream(message)
        colour = "red" if error else ""
        markup = f"[{colour}]{escape(message)}[/{colour}]" if colour else escape(message)
        try:
            self.query_one("#fleet_db_status", Static).update(markup)
        except Exception:  # noqa: BLE001
            pass

    def _service(self) -> Optional[DbFleetScanService]:
        tools = getattr(self.app, "servonaut_tools", None)
        cm = getattr(self.app, "config_manager", None)
        if tools is None or cm is None:
            return None
        return DbFleetScanService(tools, cm)

    def _repaint_table(self) -> None:
        table = self.query_one("#fleet_db_table", DataTable)
        table.clear()
        self._rows_by_id = {}
        if self._result is None:
            return
        demo = self.app.demo_mode and self.app.redaction_service
        for row in self._result.rows:
            top = row.top_candidate or {}
            self._rows_by_id[row.instance_id] = row
            # Demo mode: server names + on-box hosts are workspace identifiers
            # — redact them before they land in the review table.
            name = row.instance_name
            host = str(top.get("host", "")) if top else ""
            if demo:
                name = self.app.redaction_service.redact_name(name)
                host = self.app.redaction_service.scrub_stream(host)
            table.add_row(
                escape(name),
                escape(str(top.get("engine", "—"))) if top else "—",
                escape(str(top.get("user", "—"))) if top else "—",
                escape(str(top.get("database", "—") or "—")) if top else "—",
                escape(str(top.get("password_preview", "—"))) if top else "—",
                "yes" if row.already_vaulted else "—",
                escape(row.status),
                key=row.instance_id,
            )

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _start_scan(self) -> None:
        self.run_worker(
            self._scan_worker(),
            group="db_fleet_scan", exclusive=True, name="db_fleet_scan",
        )

    async def _scan_worker(self) -> None:
        svc = self._service()
        if svc is None:
            self._set_status(
                "DB tooling unavailable — sign in (secret store is a "
                "Solo/Teams feature) and retry.",
                error=True,
            )
            return
        self._set_status(f"Scanning {len(self._instances)} instance(s)…")

        def _progress(done: int, total: int, name: str) -> None:
            # Called from the worker's own task — safe to touch the widget.
            self._set_status(f"Scanning… {done}/{total} ({name})")

        self._result = await svc.scan(self._instances, on_progress=_progress)
        self._repaint_table()
        n_found = len(self._result.committable)
        n_vaulted = sum(1 for r in self._result.rows if r.already_vaulted)
        self._set_status(
            f"Done. {n_found} instance(s) with new credentials, "
            f"{n_vaulted} already vaulted."
        )

    async def _commit_all_worker(self) -> None:
        if self._result is None:
            return
        svc = self._service()
        if svc is None:
            self._set_status("DB tooling unavailable.", error=True)
            return
        self._set_status("Committing all…")
        summary = await svc.commit_all(self._result)
        self._repaint_table()
        msg = (
            f"Committed {summary.stored}, skipped {summary.skipped}, "
            f"failed {summary.failed}."
        )
        self._set_status(msg, error=summary.failed > 0)
        self.notify(msg, severity="information")

    async def _commit_selected_worker(self, instance_id: str) -> None:
        row = self._rows_by_id.get(instance_id)
        if row is None:
            return
        svc = self._service()
        if svc is None:
            self._set_status("DB tooling unavailable.", error=True)
            return
        ok, why = await svc.commit_row(row)
        if ok:
            self._repaint_table()
            self._set_status(f"Stored credential for {row.instance_name}.")
            self.notify(f"Stored {row.instance_name}.", severity="information")
        else:
            self._set_status(f"{row.instance_name}: {why}", error=True)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def _selected_instance_id(self) -> Optional[str]:
        table = self.query_one("#fleet_db_table", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        try:
            row_key = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key
            return row_key.value
        except Exception:  # noqa: BLE001
            return None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "fleet_commit_all":
            self.run_worker(
                self._commit_all_worker(),
                group="db_fleet_scan", exclusive=True, name="db_fleet_commit",
            )
        elif event.button.id == "fleet_commit_selected":
            iid = self._selected_instance_id()
            if not iid:
                self._set_status("Select a row first.", error=True)
                return
            self.run_worker(
                self._commit_selected_worker(iid),
                group="db_fleet_scan", exclusive=True, name="db_fleet_commit_one",
            )
        elif event.button.id == "fleet_rescan":
            self._start_scan()

    def action_commit_all(self) -> None:
        self.run_worker(
            self._commit_all_worker(),
            group="db_fleet_scan", exclusive=True, name="db_fleet_commit",
        )

    def action_rescan(self) -> None:
        self._start_scan()

    def action_back(self) -> None:
        self.app.pop_screen()
